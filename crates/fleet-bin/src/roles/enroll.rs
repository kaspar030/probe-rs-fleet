//! The `coordinator enroll` subcommand: issue client credentials for a
//! principal (agent / ctl / sidecar user) signed by the coordinator's client CA.
//!
//! The coordinator is the trust root: agents, sidecars, and ctl all
//! authenticate with mTLS using client certs signed by the coordinator's
//! client CA (`client-ca.pem`, created by `coordinator init`). Because the CA
//! private key lives on the coordinator host, the other roles cannot
//! self-generate credentials. `enroll` issues a leaf keypair + cert and emits a
//! transferable bundle that `agent init` / `ctl init` import on the target host.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::CertificateDer;

use crate::cli::{EnrollArgs, EnrollKind};
use crate::paths;
use crate::secrets::{
    decode_seed_hex, token_pubkey_hex_from_seed, write_public, write_secret,
};

/// Filenames inside an enrollment bundle.
const BUNDLE_CERT_FILE: &str = "cert.pem";
const BUNDLE_KEY_FILE: &str = "key.pem";
const BUNDLE_CA_FILE: &str = "client-ca.pem";
const BUNDLE_MANIFEST_FILE: &str = "bundle.toml";

/// Filenames written by `coordinator init` under the data dir.
const CLIENT_CA_CERT_FILE: &str = "client-ca.pem";
const CLIENT_CA_KEY_FILE: &str = "client-ca-key.pem";
const SIGNING_SEED_FILE: &str = "signing.seed";
const COORDINATOR_CONFIG_FILE: &str = "coordinator.toml";

/// The result of issuing a leaf cert from the loaded CA.
pub(crate) struct IssuedCert {
    /// The leaf certificate (PEM).
    pub cert_pem: String,
    /// The leaf private key (PEM).
    pub key_pem: String,
    /// The leaf certificate's DER bytes (for fingerprinting).
    pub cert_der: Vec<u8>,
}

/// Issue a client leaf cert for `principal_id`, signed by the CA loaded from
/// `ca_cert_pem` / `ca_key_pem`.
///
/// The CA is reconstructed via `CertificateParams::from_ca_cert_pem` (requires
/// rcgen's `x509-parser` feature) + `KeyPair::from_pem`, rebuilt into an issuer
/// `Certificate` via `self_signed`, then used to `signed_by` the leaf. The leaf
/// sets CN = `<principal_id>` and a DNS SAN = `<principal_id>` so that
/// `fleet_tls::{agent_id_from_cert, principal_from_cert}` derive exactly
/// `principal_id`.
///
/// # Errors
///
/// Returns an error if the CA material cannot be parsed or signing fails.
pub(crate) fn issue_client_cert(
    principal_id: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<IssuedCert> {
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .context("parsing client CA cert (needs rcgen x509-parser feature)")?;
    let ca_key = KeyPair::from_pem(ca_key_pem).context("parsing client CA key")?;
    // Reconstruct an issuer Certificate: `signed_by` only reads the issuer's
    // distinguished name, key-identifier method, key usages, and key pair, all
    // of which `from_ca_cert_pem` repopulates.
    let issuer = ca_params
        .self_signed(&ca_key)
        .context("reconstructing issuer certificate from loaded CA")?;

    let mut leaf_params = CertificateParams::new(vec![principal_id.to_owned()])
        .context("building leaf cert params")?;
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, principal_id);
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let leaf_key = KeyPair::generate().context("generating leaf key")?;
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer, &ca_key)
        .context("signing leaf cert with client CA")?;

    Ok(IssuedCert {
        cert_pem: leaf.pem(),
        key_pem: leaf_key.serialize_pem(),
        cert_der: leaf.der().to_vec(),
    })
}

/// Compute the `fleet_tls` fingerprint of a leaf cert's DER bytes.
#[must_use]
pub(crate) fn fingerprint(cert_der: &[u8]) -> String {
    let der = CertificateDer::from(cert_der.to_vec());
    fleet_tls::cert_fingerprint(&der)
}

/// Run `coordinator enroll`.
///
/// # Errors
///
/// Returns an error if the CA / seed material cannot be located or parsed, the
/// cert cannot be issued, the bundle cannot be written, or (for `--write`) the
/// coordinator config cannot be updated.
pub fn run(args: EnrollArgs) -> Result<()> {
    let EnrollArgs {
        principal_id,
        kind,
        out,
        write,
        config_dir,
        data_dir,
    } = args;

    let config_dir = match config_dir {
        Some(dir) => dir,
        None => paths::config_dir()?,
    };
    let data_dir = match data_dir {
        Some(dir) => dir,
        None => paths::data_dir()?,
    };

    let ca_cert_path = data_dir.join(CLIENT_CA_CERT_FILE);
    let ca_key_path = data_dir.join(CLIENT_CA_KEY_FILE);
    let ca_cert_pem = std::fs::read_to_string(&ca_cert_path).with_context(|| {
        format!(
            "reading client CA cert {} (run `coordinator init` first)",
            ca_cert_path.display()
        )
    })?;
    let ca_key_pem = std::fs::read_to_string(&ca_key_path)
        .with_context(|| format!("reading client CA key {}", ca_key_path.display()))?;

    let issued = issue_client_cert(&principal_id, &ca_cert_pem, &ca_key_pem)?;
    let fp = fingerprint(&issued.cert_der);

    // For agents, derive the coordinator token pubkey from the signing seed so
    // the bundle can populate the agent's `coordinator_token_pubkey`.
    let token_pubkey = match kind {
        EnrollKind::Agent => {
            let seed_path = data_dir.join(SIGNING_SEED_FILE);
            let seed_hex = std::fs::read_to_string(&seed_path)
                .with_context(|| format!("reading signing seed {}", seed_path.display()))?;
            let seed = decode_seed_hex(seed_hex.trim())?;
            Some(token_pubkey_hex_from_seed(&seed))
        }
        EnrollKind::Client => None,
    };

    // Resolve and create the output directory.
    let out_dir = out.unwrap_or_else(|| PathBuf::from(format!("{principal_id}-bundle")));
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("creating bundle dir {}", out_dir.display()))?;

    // Write the bundle files.
    let cert_path = out_dir.join(BUNDLE_CERT_FILE);
    let key_path = out_dir.join(BUNDLE_KEY_FILE);
    let bundle_ca_path = out_dir.join(BUNDLE_CA_FILE);
    let manifest_path = out_dir.join(BUNDLE_MANIFEST_FILE);

    write_public(&cert_path, issued.cert_pem.as_bytes())
        .with_context(|| format!("writing {}", cert_path.display()))?;
    write_secret(&key_path, issued.key_pem.as_bytes())
        .with_context(|| format!("writing {}", key_path.display()))?;
    write_public(&bundle_ca_path, ca_cert_pem.as_bytes())
        .with_context(|| format!("writing {}", bundle_ca_path.display()))?;

    let manifest = render_manifest(&principal_id, kind, &fp, token_pubkey.as_deref());
    write_public(&manifest_path, manifest.as_bytes())
        .with_context(|| format!("writing {}", manifest_path.display()))?;

    // Pinning for agents.
    let pin_line = format!("\"{fp}\" = \"{principal_id}\"");
    if kind == EnrollKind::Agent && write {
        let coordinator_config = config_dir.join(COORDINATOR_CONFIG_FILE);
        append_pinned_agent(&coordinator_config, &pin_line)?;
    }

    print_summary(
        &principal_id,
        kind,
        write,
        &out_dir,
        &fp,
        &pin_line,
        token_pubkey.as_deref(),
    );
    Ok(())
}

/// Render the bundle manifest TOML.
fn render_manifest(
    principal_id: &str,
    kind: EnrollKind,
    fingerprint: &str,
    token_pubkey: Option<&str>,
) -> String {
    let kind_str = match kind {
        EnrollKind::Agent => "agent",
        EnrollKind::Client => "client",
    };
    let mut out = format!(
        "# probe-rs-fleet enrollment bundle manifest\n\
         # Generated by `probe-rs-fleet coordinator enroll`.\n\
         principal_id = {principal}\n\
         kind = {kind}\n\
         fingerprint = {fp}\n",
        principal = toml::Value::String(principal_id.to_owned()),
        kind = toml::Value::String(kind_str.to_owned()),
        fp = toml::Value::String(fingerprint.to_owned()),
    );
    if let Some(pk) = token_pubkey {
        use std::fmt::Write as _;
        let _ = writeln!(
            out,
            "coordinator_token_pubkey = {}",
            toml::Value::String(pk.to_owned())
        );
    }
    out
}

/// Append a `[pinned_agents]` line to the coordinator config, inserting the
/// section header if absent. Verifies the result still loads.
fn append_pinned_agent(config_path: &Path, pin_line: &str) -> Result<()> {
    let existing = std::fs::read_to_string(config_path).with_context(|| {
        format!(
            "reading coordinator config {} for --write",
            config_path.display()
        )
    })?;

    let mut updated = existing.clone();
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    if updated.contains("[pinned_agents]") {
        // Append the line at the end of the file; the [pinned_agents] table is
        // the last table in the generated config, so appending keeps it valid.
        updated.push_str(pin_line);
        updated.push('\n');
    } else {
        updated.push_str("\n[pinned_agents]\n");
        updated.push_str(pin_line);
        updated.push('\n');
    }

    // Validate before committing the change.
    crate::config::load_coordinator_config_from_str(&updated).with_context(|| {
        format!(
            "updated coordinator config {} would not parse; aborting --write",
            config_path.display()
        )
    })?;

    write_public(config_path, updated.as_bytes())
        .with_context(|| format!("writing updated coordinator config {}", config_path.display()))?;
    Ok(())
}

/// Print a summary of the bundle + next steps.
fn print_summary(
    principal_id: &str,
    kind: EnrollKind,
    write: bool,
    out_dir: &Path,
    fingerprint: &str,
    pin_line: &str,
    token_pubkey: Option<&str>,
) {
    println!("Enrolled principal '{principal_id}':");
    println!("  bundle dir   {}", out_dir.display());
    println!("  fingerprint  {fingerprint}");
    if let Some(pk) = token_pubkey {
        println!("  token pubkey {pk}");
    }
    println!();
    match kind {
        EnrollKind::Agent => {
            if write {
                println!("Added pinned-agent line to coordinator.toml:");
            } else {
                println!("Add this line under [pinned_agents] in coordinator.toml");
                println!("(or re-run with --write to append it automatically):");
            }
            println!("    {pin_line}");
            println!();
            println!("Next steps:");
            println!("  1. Transfer the bundle to the agent host, e.g.:");
            println!("       scp -r {} pi@host:~/", out_dir.display());
            println!("  2. On the agent host:");
            println!(
                "       probe-rs-fleet agent init --bundle {} --coordinator <host:port>",
                out_dir.display()
            );
            println!("  3. probe-rs-fleet agent");
        }
        EnrollKind::Client => {
            println!("Next steps:");
            println!("  1. Transfer the bundle to the client host, e.g.:");
            println!("       scp -r {} user@host:~/", out_dir.display());
            println!("  2. On the client host:");
            println!(
                "       probe-rs-fleet ctl init --bundle {} --coordinator <host:port>",
                out_dir.display()
            );
            println!("  3. probe-rs-fleet ctl list");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, IsCa};

    /// Mint a CA the same way `coordinator init` does, returning its PEMs.
    fn mint_ca() -> (String, String) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "probe-rs-fleet client CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        (ca_cert.pem(), ca_key.serialize_pem())
    }

    #[test]
    fn issued_cert_cn_maps_to_principal_and_fingerprint_format_matches() {
        let (ca_cert_pem, ca_key_pem) = mint_ca();
        let issued = issue_client_cert("rpi-lab-1", &ca_cert_pem, &ca_key_pem).unwrap();

        let der = CertificateDer::from(issued.cert_der.clone());

        // CN → principal / agent id parity (the acceptance requirement).
        let agent_id = fleet_tls::agent_id_from_cert(&der).unwrap();
        assert_eq!(agent_id, fleet_proto::ids::AgentId("rpi-lab-1".to_owned()));
        let principal = fleet_tls::principal_from_cert(&der).unwrap();
        assert_eq!(
            principal,
            fleet_proto::ids::Principal("rpi-lab-1".to_owned())
        );

        // Fingerprint format: 64 lowercase hex, no colons / sha256 prefix.
        let fp = fingerprint(&issued.cert_der);
        assert_eq!(fp, fleet_tls::cert_fingerprint(&der));
        assert_eq!(fp.len(), 64);
        assert!(!fp.contains(':'));
        assert!(!fp.contains("sha256"));
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn leaf_from_reloaded_ca_chains_to_that_ca() {
        // Exercise the from_ca_cert_pem -> self_signed -> signed_by path and
        // verify the issued leaf actually chains to the reloaded CA, using the
        // client-cert verifier (the same mTLS path the coordinator uses, which
        // accepts the ClientAuth EKU our leaf carries).
        use std::sync::Arc;

        let (ca_cert_pem, ca_key_pem) = mint_ca();
        let issued = issue_client_cert("alice", &ca_cert_pem, &ca_key_pem).unwrap();

        let ca_der = CertificateParams::from_ca_cert_pem(&ca_cert_pem)
            .unwrap()
            .self_signed(&KeyPair::from_pem(&ca_key_pem).unwrap())
            .unwrap()
            .der()
            .to_vec();
        let roots =
            fleet_tls::root_store_from_certs(vec![CertificateDer::from(ca_der)]).unwrap();

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider,
        )
        .build()
        .unwrap();

        let leaf = CertificateDer::from(issued.cert_der.clone());
        let now = rustls::pki_types::UnixTime::now();
        let outcome = rustls::server::danger::ClientCertVerifier::verify_client_cert(
            verifier.as_ref(),
            &leaf,
            &[],
            now,
        );
        assert!(
            outcome.is_ok(),
            "issued leaf should chain to the reloaded CA: {outcome:?}"
        );
    }

    #[test]
    fn manifest_carries_token_pubkey_for_agents() {
        let manifest = render_manifest(
            "rpi-lab-1",
            EnrollKind::Agent,
            "ab".repeat(32).as_str(),
            Some(&"cd".repeat(32)),
        );
        assert!(manifest.contains("kind = \"agent\""));
        assert!(manifest.contains("coordinator_token_pubkey"));
        let parsed: toml::Value = toml::from_str(&manifest).unwrap();
        assert_eq!(parsed["principal_id"].as_str(), Some("rpi-lab-1"));
    }

    #[test]
    fn client_manifest_omits_token_pubkey() {
        let manifest = render_manifest("alice", EnrollKind::Client, &"ab".repeat(32), None);
        assert!(manifest.contains("kind = \"client\""));
        assert!(!manifest.contains("coordinator_token_pubkey"));
    }

    #[test]
    fn end_to_end_init_then_enroll_agent_write() {
        use crate::cli::{EnrollArgs, InitArgs};
        use std::net::{IpAddr, Ipv4Addr};

        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("config");
        let data_dir = tmp.path().join("data");

        crate::roles::init::run(InitArgs {
            config_dir: Some(config_dir.clone()),
            data_dir: Some(data_dir.clone()),
            hostname: vec!["localhost".to_owned()],
            ip: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            force: false,
        })
        .unwrap();

        let out = tmp.path().join("rpi-lab-1-bundle");
        run(EnrollArgs {
            principal_id: "rpi-lab-1".to_owned(),
            kind: EnrollKind::Agent,
            out: Some(out.clone()),
            write: true,
            config_dir: Some(config_dir.clone()),
            data_dir: Some(data_dir.clone()),
        })
        .unwrap();

        // Bundle files exist.
        assert!(out.join(BUNDLE_CERT_FILE).exists());
        assert!(out.join(BUNDLE_KEY_FILE).exists());
        assert!(out.join(BUNDLE_CA_FILE).exists());
        assert!(out.join(BUNDLE_MANIFEST_FILE).exists());

        // The bundle's token pubkey matches the coordinator's signing seed.
        let seed_hex = std::fs::read_to_string(data_dir.join(SIGNING_SEED_FILE)).unwrap();
        let seed = decode_seed_hex(seed_hex.trim()).unwrap();
        let expected_pubkey = token_pubkey_hex_from_seed(&seed);
        let manifest_pubkey = read_manifest_token_pubkey(&out.join(BUNDLE_MANIFEST_FILE));
        assert_eq!(manifest_pubkey.as_deref(), Some(expected_pubkey.as_str()));

        // coordinator.toml now pins the agent by its cert fingerprint and still
        // loads.
        let config_path = config_dir.join(COORDINATOR_CONFIG_FILE);
        let cfg = crate::config::load_coordinator_config(&config_path).unwrap();
        cfg.validate().unwrap();
        let cert_pem = std::fs::read(out.join(BUNDLE_CERT_FILE)).unwrap();
        let der = {
            let mut reader = std::io::BufReader::new(cert_pem.as_slice());
            let cert = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
            cert
        };
        let fp = fleet_tls::cert_fingerprint(&der);
        assert_eq!(
            cfg.agent_for_fingerprint(&fp),
            Some(&fleet_proto::ids::AgentId("rpi-lab-1".to_owned()))
        );
    }

    fn read_manifest_token_pubkey(path: &Path) -> Option<String> {
        let text = std::fs::read_to_string(path).unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        value
            .get("coordinator_token_pubkey")
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
    }
}
