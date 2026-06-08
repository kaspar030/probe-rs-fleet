//! The `agent init` subcommand: import an enrollment bundle and scaffold a
//! ready-to-run agent config (`agent.toml` + a starter `boards.toml`).
//!
//! Run on the Raspberry Pi after `coordinator enroll <agent-id> --kind agent`
//! has produced a bundle (transferred here). Imports the client cert/key/CA
//! into the data dir, derives the `agent_id` from the cert CN (so it matches
//! exactly what the coordinator pins), and writes a populated `agent.toml`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rustls::pki_types::CertificateDer;

use fleet_agent::config::AgentConfig;

use crate::cli::AgentInitArgs;
use crate::paths;
use crate::secrets::{import_public, import_secret, toml_path, write_public};

/// Imported credential filenames under the data dir.
const AGENT_CERT_FILE: &str = "agent-cert.pem";
const AGENT_KEY_FILE: &str = "agent-key.pem";
const CLIENT_CA_FILE: &str = "client-ca.pem";
const AGENT_CONFIG_FILE: &str = "agent.toml";
const BOARDS_FILE: &str = "boards.toml";

/// Bundle filenames produced by `coordinator enroll`.
const BUNDLE_CERT_FILE: &str = "cert.pem";
const BUNDLE_KEY_FILE: &str = "key.pem";
const BUNDLE_CA_FILE: &str = "client-ca.pem";
const BUNDLE_MANIFEST_FILE: &str = "bundle.toml";

/// Resolved credential source paths + token pubkey.
struct Sources {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
    token_pubkey: String,
}

/// Run `agent init`.
///
/// # Errors
///
/// Returns an error if the bundle / explicit credentials cannot be resolved,
/// any file cannot be imported, the cert CN cannot be derived, or (without
/// `--force`) a target file already exists.
pub fn run(args: AgentInitArgs) -> Result<()> {
    let AgentInitArgs {
        bundle,
        cert,
        key,
        ca,
        coordinator_token_pubkey,
        coordinator,
        config_dir,
        data_dir,
        boards_path,
        force,
    } = args;

    let config_dir = match config_dir {
        Some(dir) => dir,
        None => paths::config_dir()?,
    };
    let data_dir = match data_dir {
        Some(dir) => dir,
        None => paths::data_dir()?,
    };

    let sources = resolve_sources(bundle.as_deref(), cert, key, ca, coordinator_token_pubkey)?;

    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("creating config dir {}", config_dir.display()))?;
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    let cert_path = data_dir.join(AGENT_CERT_FILE);
    let key_path = data_dir.join(AGENT_KEY_FILE);
    let ca_path = data_dir.join(CLIENT_CA_FILE);
    let config_path = config_dir.join(AGENT_CONFIG_FILE);
    let boards_path = boards_path.unwrap_or_else(|| config_dir.join(BOARDS_FILE));

    // Idempotency guard.
    if !force {
        let existing: Vec<&Path> = [
            cert_path.as_path(),
            key_path.as_path(),
            ca_path.as_path(),
            config_path.as_path(),
        ]
        .into_iter()
        .filter(|p| p.exists())
        .collect();
        if !existing.is_empty() {
            let list = existing
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("\n  ");
            bail!("refusing to overwrite existing file(s); pass --force to regenerate:\n  {list}");
        }
    }

    // Import credentials.
    import_public(&sources.cert, &cert_path)
        .with_context(|| format!("importing agent cert from {}", sources.cert.display()))?;
    import_secret(&sources.key, &key_path)
        .with_context(|| format!("importing agent key from {}", sources.key.display()))?;
    import_public(&sources.ca, &ca_path)
        .with_context(|| format!("importing CA from {}", sources.ca.display()))?;

    // Derive agent_id from the imported cert's CN (source of truth).
    let agent_id = agent_id_from_cert_file(&cert_path)?;

    // Write the populated agent config.
    let config_toml = render_agent_config(
        &agent_id,
        &coordinator,
        &cert_path,
        &key_path,
        &ca_path,
        &sources.token_pubkey,
        &boards_path,
    );
    write_public(&config_path, config_toml.as_bytes())
        .with_context(|| format!("writing agent config {}", config_path.display()))?;

    // Validate the written config round-trips.
    AgentConfig::from_path(&config_path)
        .with_context(|| format!("validating written agent config {}", config_path.display()))?;

    // Scaffold a starter boards.toml (skip if present unless --force).
    if force || !boards_path.exists() {
        write_public(&boards_path, starter_boards_toml().as_bytes())
            .with_context(|| format!("writing boards scaffold {}", boards_path.display()))?;
    }

    print_summary(&agent_id, &config_path, &boards_path, &cert_path, &key_path, &ca_path);
    Ok(())
}

/// Resolve cert/key/ca paths and the coordinator token pubkey from the bundle
/// and/or explicit flags. Explicit flags override bundle files.
fn resolve_sources(
    bundle: Option<&Path>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    ca: Option<PathBuf>,
    coordinator_token_pubkey: Option<String>,
) -> Result<Sources> {
    let mut manifest_pubkey: Option<String> = None;

    let (bundle_cert, bundle_key, bundle_ca) = if let Some(bundle) = bundle {
        let manifest_path = bundle.join(BUNDLE_MANIFEST_FILE);
        if manifest_path.exists() {
            manifest_pubkey = read_manifest_pubkey(&manifest_path)?;
        }
        (
            Some(bundle.join(BUNDLE_CERT_FILE)),
            Some(bundle.join(BUNDLE_KEY_FILE)),
            Some(bundle.join(BUNDLE_CA_FILE)),
        )
    } else {
        (None, None, None)
    };

    let cert = cert
        .or(bundle_cert)
        .context("provide --bundle or an explicit --cert")?;
    let key = key
        .or(bundle_key)
        .context("provide --bundle or an explicit --key")?;
    let ca = ca
        .or(bundle_ca)
        .context("provide --bundle or an explicit --ca")?;

    let token_pubkey = coordinator_token_pubkey.or(manifest_pubkey).context(
        "coordinator token pubkey is required: use a --bundle from `coordinator enroll \
         --kind agent` or pass --coordinator-token-pubkey",
    )?;

    Ok(Sources {
        cert,
        key,
        ca,
        token_pubkey,
    })
}

/// Read `coordinator_token_pubkey` from a bundle manifest, if present.
fn read_manifest_pubkey(path: &Path) -> Result<Option<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading bundle manifest {}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&text).with_context(|| format!("parsing bundle manifest {}", path.display()))?;
    Ok(value
        .get("coordinator_token_pubkey")
        .and_then(toml::Value::as_str)
        .map(str::to_owned))
}

/// Derive the agent id (cert CN) from an imported cert PEM file.
fn agent_id_from_cert_file(cert_path: &Path) -> Result<String> {
    let pem = std::fs::read(cert_path)
        .with_context(|| format!("reading cert {}", cert_path.display()))?;
    let der = rustls_pemfile_first_cert(&pem)
        .with_context(|| format!("no certificate found in {}", cert_path.display()))?;
    let agent_id = fleet_tls::agent_id_from_cert(&der)
        .with_context(|| format!("deriving agent id from cert {}", cert_path.display()))?;
    Ok(agent_id.0)
}

/// Extract the first certificate's DER from PEM bytes.
fn rustls_pemfile_first_cert(pem: &[u8]) -> Result<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem);
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .context("no certificate found in PEM")?;
    first.context("parsing PEM certificate")
}

/// Render a populated `agent.toml`.
fn render_agent_config(
    agent_id: &str,
    coordinator: &str,
    cert: &Path,
    key: &Path,
    ca: &Path,
    token_pubkey: &str,
    boards_path: &Path,
) -> String {
    format!(
        r"# probe-rs-fleet agent config
#
# Generated by `probe-rs-fleet agent init`. Paths are absolute and point at the
# credentials imported from the enrollment bundle. The agent is discovered at
# the XDG path ~/.config/probe-rs-fleet/agent.toml unless overridden with
# --config / PROBE_RS_FLEET_AGENT_CONFIG.

# This agent's id. Derived from the client cert CN, which the coordinator pins.
agent_id = {agent_id}

# `host:port` of the coordinator to dial out to.
coordinator_endpoint = {coordinator}

# Client mTLS certificate chain + private key (issued by `coordinator enroll`).
tls_cert = {tls_cert}
tls_key = {tls_key}

# CA used to verify the coordinator's server certificate (PEM).
tls_ca = {tls_ca}

# Hex-encoded ed25519 public key of the coordinator's token signer. Carried in
# the enrollment bundle; used to verify capability tokens.
coordinator_token_pubkey = {token_pubkey}

# Path to this agent's boards.toml inventory.
boards_path = {boards_path}

# Heartbeat interval, seconds (default 15).
# heartbeat_secs = 15

# Erase the target's flash on lease release (default false).
# erase_on_release = false
",
        agent_id = toml::Value::String(agent_id.to_owned()),
        coordinator = toml::Value::String(coordinator.to_owned()),
        tls_cert = toml_path(cert),
        tls_key = toml_path(key),
        tls_ca = toml_path(ca),
        token_pubkey = toml::Value::String(token_pubkey.to_owned()),
        boards_path = toml_path(boards_path),
    )
}

/// A commented starter `boards.toml` with one example `[[board]]`.
fn starter_boards_toml() -> String {
    r#"# probe-rs-fleet agent board inventory
#
# Each [[board]] maps a physical probe serial to a leasable board. Uncomment and
# adapt the example below for each board attached to this agent.

# [[board]]
# # Stable board id, unique across the fleet.
# id        = "nrf52840-dk-3"
# # Physical probe serial bound to this board.
# serial    = "001050257890"
# # probe-rs target/chip name (informational).
# chip      = "nRF52840_xxAA"
# # Free-form selection tags.
# tags      = ["nrf52", "bluetooth"]
# # Whether the board admits only one lease at a time (default true).
# exclusive = true
#
# # USB power control: kind = "uhubctl" | "gpio" | "none".
# [board.power]
# kind = "uhubctl"
# hub  = "1-1"
# port = 2
"#
    .to_owned()
}

/// Print a summary + next steps.
fn print_summary(
    agent_id: &str,
    config_path: &Path,
    boards_path: &Path,
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) {
    println!("Initialised agent '{agent_id}':");
    println!("  config      {}", config_path.display());
    println!("  boards      {}", boards_path.display());
    println!("  cert        {}", cert_path.display());
    println!("  key         {}", key_path.display());
    println!("  ca          {}", ca_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Edit {} to declare your boards.", boards_path.display());
    println!("  2. Start the agent (no --config needed):");
    println!("       probe-rs-fleet agent");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roles::enroll::issue_client_cert;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    };

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

    /// Write a minimal bundle dir for `agent_id`, return its path.
    fn make_bundle(dir: &Path, agent_id: &str, token_pubkey: &str) {
        let (ca_pem, ca_key_pem) = mint_ca();
        let issued = issue_client_cert(agent_id, &ca_pem, &ca_key_pem).unwrap();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(BUNDLE_CERT_FILE), issued.cert_pem).unwrap();
        std::fs::write(dir.join(BUNDLE_KEY_FILE), issued.key_pem).unwrap();
        std::fs::write(dir.join(BUNDLE_CA_FILE), ca_pem).unwrap();
        std::fs::write(
            dir.join(BUNDLE_MANIFEST_FILE),
            format!(
                "principal_id = \"{agent_id}\"\nkind = \"agent\"\nfingerprint = \"{}\"\ncoordinator_token_pubkey = \"{token_pubkey}\"\n",
                "ab".repeat(32)
            ),
        )
        .unwrap();
    }

    fn args_for(tmp: &Path, bundle: &Path) -> AgentInitArgs {
        AgentInitArgs {
            bundle: Some(bundle.to_path_buf()),
            cert: None,
            key: None,
            ca: None,
            coordinator_token_pubkey: None,
            coordinator: "coord.example:7000".to_owned(),
            config_dir: Some(tmp.join("config")),
            data_dir: Some(tmp.join("data")),
            boards_path: None,
            force: false,
        }
    }

    #[test]
    fn writes_valid_agent_config_with_cn_agent_id() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        let pubkey = "cd".repeat(32);
        make_bundle(&bundle, "rpi-lab-1", &pubkey);

        run(args_for(tmp.path(), &bundle)).unwrap();

        let config_path = tmp.path().join("config").join(AGENT_CONFIG_FILE);
        let cfg = AgentConfig::from_path(&config_path).unwrap();
        assert_eq!(cfg.agent_id, "rpi-lab-1");
        assert_eq!(cfg.coordinator_endpoint, "coord.example:7000");
        assert_eq!(cfg.coordinator_token_pubkey, pubkey);

        // boards.toml scaffolded and parseable.
        let boards_path = tmp.path().join("config").join(BOARDS_FILE);
        assert!(boards_path.exists());
        fleet_agent::config::BoardsConfig::from_path(&boards_path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn imported_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        make_bundle(&bundle, "rpi-lab-1", &"cd".repeat(32));
        run(args_for(tmp.path(), &bundle)).unwrap();
        let key = tmp.path().join("data").join(AGENT_KEY_FILE);
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn refuses_overwrite_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        make_bundle(&bundle, "rpi-lab-1", &"cd".repeat(32));
        run(args_for(tmp.path(), &bundle)).unwrap();
        assert!(run(args_for(tmp.path(), &bundle)).is_err());

        let mut forced = args_for(tmp.path(), &bundle);
        forced.force = true;
        run(forced).unwrap();
    }

    #[test]
    fn errors_without_token_pubkey() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        // Bundle without a manifest pubkey.
        let (ca_pem, ca_key_pem) = mint_ca();
        let issued = issue_client_cert("rpi-lab-1", &ca_pem, &ca_key_pem).unwrap();
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join(BUNDLE_CERT_FILE), issued.cert_pem).unwrap();
        std::fs::write(bundle.join(BUNDLE_KEY_FILE), issued.key_pem).unwrap();
        std::fs::write(bundle.join(BUNDLE_CA_FILE), ca_pem).unwrap();
        // no bundle.toml

        assert!(run(args_for(tmp.path(), &bundle)).is_err());
    }
}
