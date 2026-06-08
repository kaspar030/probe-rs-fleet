//! The `coordinator init` subcommand: scaffold a ready-to-run coordinator.
//!
//! Generates a fresh signing seed, a development client CA, a coordinator
//! server cert/key signed by that CA, and a populated `coordinator.toml`
//! pointing at all of it — under the XDG config/data directories (or explicit
//! overrides). Secrets are written with `0600` permissions on unix.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
};

use fleet_core::policy::Policy;

use crate::cli::InitArgs;
use crate::paths;
use crate::secrets::{generate_seed_hex, toml_path, write_public, write_secret};

/// Names of the files `init` writes, relative to the config / data dirs.
const SIGNING_SEED_FILE: &str = "signing.seed";
const CLIENT_CA_CERT_FILE: &str = "client-ca.pem";
const CLIENT_CA_KEY_FILE: &str = "client-ca-key.pem";
const SERVER_CERT_FILE: &str = "coordinator-cert.pem";
const SERVER_KEY_FILE: &str = "coordinator-key.pem";
const SQLITE_FILE: &str = "coordinator.sqlite";
const CONFIG_FILE: &str = "coordinator.toml";

/// Run `coordinator init`.
///
/// # Errors
///
/// Returns an error if directories cannot be created, key/cert generation
/// fails, or (without `--force`) any target file already exists.
pub fn run(args: InitArgs) -> Result<()> {
    let config_dir = match args.config_dir {
        Some(dir) => dir,
        None => paths::config_dir()?,
    };
    let data_dir = match args.data_dir {
        Some(dir) => dir,
        None => paths::data_dir()?,
    };

    let hostnames = if args.hostname.is_empty() {
        vec!["localhost".to_owned()]
    } else {
        args.hostname
    };
    let ips = if args.ip.is_empty() {
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
    } else {
        args.ip
    };

    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("creating config dir {}", config_dir.display()))?;
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    let config_path = config_dir.join(CONFIG_FILE);
    let seed_path = data_dir.join(SIGNING_SEED_FILE);
    let ca_cert_path = data_dir.join(CLIENT_CA_CERT_FILE);
    let ca_key_path = data_dir.join(CLIENT_CA_KEY_FILE);
    let server_cert_path = data_dir.join(SERVER_CERT_FILE);
    let server_key_path = data_dir.join(SERVER_KEY_FILE);
    let sqlite_path = data_dir.join(SQLITE_FILE);

    // Idempotency guard: refuse to clobber existing files unless --force.
    if !args.force {
        let existing: Vec<&Path> = [
            config_path.as_path(),
            seed_path.as_path(),
            ca_cert_path.as_path(),
            ca_key_path.as_path(),
            server_cert_path.as_path(),
            server_key_path.as_path(),
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
            bail!(
                "refusing to overwrite existing file(s); pass --force to regenerate:\n  {list}"
            );
        }
    }

    // 1. Signing seed: 32 random bytes -> 64 lowercase hex chars.
    let seed_hex = generate_seed_hex();
    write_secret(&seed_path, seed_hex.as_bytes())
        .with_context(|| format!("writing signing seed {}", seed_path.display()))?;

    // 2. TLS material: a client CA and a server cert signed by it.
    let tls = generate_tls_material(&hostnames, &ips).context("generating TLS material")?;
    write_public(&ca_cert_path, tls.ca_cert.as_bytes())
        .with_context(|| format!("writing CA cert {}", ca_cert_path.display()))?;
    write_secret(&ca_key_path, tls.ca_key.as_bytes())
        .with_context(|| format!("writing CA key {}", ca_key_path.display()))?;
    write_public(&server_cert_path, tls.server_cert.as_bytes())
        .with_context(|| format!("writing server cert {}", server_cert_path.display()))?;
    write_secret(&server_key_path, tls.server_key.as_bytes())
        .with_context(|| format!("writing server key {}", server_key_path.display()))?;

    // 3. Populated config pointing at the generated material.
    let config_toml = render_coordinator_config(
        &server_cert_path,
        &server_key_path,
        &ca_cert_path,
        &sqlite_path,
        &seed_path,
        &Policy::default(),
    )?;
    write_public(&config_path, config_toml.as_bytes())
        .with_context(|| format!("writing config {}", config_path.display()))?;

    print_summary(
        &config_path,
        &seed_path,
        &ca_cert_path,
        &ca_key_path,
        &server_cert_path,
        &server_key_path,
        &sqlite_path,
    );

    Ok(())
}

/// Generated TLS material: a client CA and a server cert signed by it.
struct TlsMaterial {
    ca_cert: String,
    ca_key: String,
    server_cert: String,
    server_key: String,
}

/// Generate a self-signed client CA and a coordinator server cert (with the
/// given SANs) signed by that CA, all in one pass.
fn generate_tls_material(hostnames: &[String], ips: &[IpAddr]) -> Result<TlsMaterial> {
    // Client CA.
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).context("building CA params")?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "probe-rs-fleet client CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().context("generating CA key")?;
    let ca_cert = ca_params.self_signed(&ca_key).context("self-signing CA")?;

    // Coordinator server cert, signed by the CA.
    let mut params =
        CertificateParams::new(hostnames.to_vec()).context("building server params")?;
    for ip in ips {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }
    let cn = hostnames.first().map_or("localhost", String::as_str);
    params.distinguished_name.push(DnType::CommonName, cn);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    let server_key = KeyPair::generate().context("generating server key")?;
    let server_cert = params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .context("signing server cert")?;

    Ok(TlsMaterial {
        ca_cert: ca_cert.pem(),
        ca_key: ca_key.serialize_pem(),
        server_cert: server_cert.pem(),
        server_key: server_key.serialize_pem(),
    })
}

/// Render a populated `coordinator.toml` referencing the generated files.
fn render_coordinator_config(
    tls_cert: &Path,
    tls_key: &Path,
    client_ca: &Path,
    sqlite_path: &Path,
    signing_key_path: &Path,
    policy: &Policy,
) -> Result<String> {
    let policy_toml = toml::to_string(policy).context("serialising default policy")?;
    let mut policy_block = String::new();
    for line in policy_toml.lines() {
        policy_block.push_str(line);
        policy_block.push('\n');
    }

    let config = format!(
        r#"# probe-rs-fleet coordinator config
#
# Generated by `probe-rs-fleet coordinator init`. Paths are absolute and point
# at the material generated alongside this file.

# TCP address the coordinator listens on for inbound mTLS connections.
listen_addr = "0.0.0.0:7000"

# Coordinator server certificate chain + private key (PEM).
tls_cert = {tls_cert}
tls_key = {tls_key}

# CA used to verify client (agent / sidecar) certificates (PEM).
client_ca = {client_ca}

# SQLite database file (created on first run).
sqlite_path = {sqlite_path}

# ed25519 capability-token signing seed (64 hex chars / 32 bytes).
# Alternatively inline the seed with `signing_key_hex = "<64 hex chars>"`.
signing_key_path = {signing_key_path}

# How often (seconds) the lease-expiry sweep runs.
# sweep_interval_secs = 5

# Lease scheduling policy (defaults shown).
[policy]
{policy_block}
# Pinned agents: map a client certificate fingerprint to the agent id it is
# allowed to claim. The key is the LOWERCASE HEX SHA-256 of the agent
# certificate's DER bytes — no `sha256:` prefix, no colons (exactly what
# `fleet_tls::cert_fingerprint` produces). Reproduce it from a PEM with:
#
#   openssl x509 -in agent.pem -outform der | openssl dgst -sha256
#
# (or `openssl x509 -in agent.pem -noout -fingerprint -sha256`, then strip the
# colons and lowercase). Example (64 hex chars):
#
#   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" = "agent-01"
[pinned_agents]
"#,
        tls_cert = toml_path(tls_cert),
        tls_key = toml_path(tls_key),
        client_ca = toml_path(client_ca),
        sqlite_path = toml_path(sqlite_path),
        signing_key_path = toml_path(signing_key_path),
    );
    Ok(config)
}

/// Print a summary of what was written and the next steps.
fn print_summary(
    config_path: &Path,
    seed_path: &Path,
    ca_cert_path: &Path,
    ca_key_path: &Path,
    server_cert_path: &Path,
    server_key_path: &Path,
    sqlite_path: &Path,
) {
    println!("Created coordinator scaffold:");
    println!("  config         {}", config_path.display());
    println!("  signing seed   {}", seed_path.display());
    println!("  client CA cert {}", ca_cert_path.display());
    println!("  client CA key  {}", ca_key_path.display());
    println!("  server cert    {}", server_cert_path.display());
    println!("  server key     {}", server_key_path.display());
    println!("  sqlite (db)    {} (created on first run)", sqlite_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Start the coordinator (no --config needed):");
    println!("       probe-rs-fleet coordinator");
    println!("  2. Enroll an agent by issuing it a client cert from the CA above");
    println!("     ({}), then pin it:", ca_cert_path.display());
    println!("       - compute the cert fingerprint (lowercase hex SHA-256 of the");
    println!("         DER, no `sha256:` prefix, no colons):");
    println!(
        "           openssl x509 -in agent.pem -outform der | openssl dgst -sha256"
    );
    println!(
        "       - add `\"<fingerprint>\" = \"<agent-id>\"` under [pinned_agents] in"
    );
    println!("         {}", config_path.display());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn init_into(dir: &Path, force: bool) -> Result<()> {
        run(InitArgs {
            config_dir: Some(dir.join("config")),
            data_dir: Some(dir.join("data")),
            hostname: vec!["localhost".to_owned()],
            ip: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            force,
        })
    }

    #[test]
    fn init_writes_all_files() {
        let tmp = tempfile::tempdir().unwrap();
        init_into(tmp.path(), false).unwrap();

        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        assert!(config.join(CONFIG_FILE).exists(), "missing {CONFIG_FILE}");
        for f in [
            SIGNING_SEED_FILE,
            CLIENT_CA_CERT_FILE,
            CLIENT_CA_KEY_FILE,
            SERVER_CERT_FILE,
            SERVER_KEY_FILE,
        ] {
            assert!(data.join(f).exists(), "missing {f}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn secrets_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        init_into(tmp.path(), false).unwrap();
        let data = tmp.path().join("data");
        for f in [SIGNING_SEED_FILE, CLIENT_CA_KEY_FILE, SERVER_KEY_FILE] {
            let mode = std::fs::metadata(data.join(f)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{f} perms = {:o}", mode & 0o777);
        }
    }

    #[test]
    fn generated_config_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        init_into(tmp.path(), false).unwrap();
        let config_path = tmp.path().join("config").join(CONFIG_FILE);
        let cfg = config::load_coordinator_config(&config_path).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.listen_addr.port(), 7000);
        assert!(cfg.pinned_agents.is_empty());
    }

    #[test]
    fn refuses_overwrite_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        init_into(tmp.path(), false).unwrap();

        let seed_path = tmp.path().join("data").join(SIGNING_SEED_FILE);
        let before = std::fs::read_to_string(&seed_path).unwrap();

        // Second run without --force must fail and leave files untouched.
        assert!(init_into(tmp.path(), false).is_err());
        let after = std::fs::read_to_string(&seed_path).unwrap();
        assert_eq!(before, after);

        // With --force, regeneration succeeds and rewrites the seed.
        init_into(tmp.path(), true).unwrap();
        let forced = std::fs::read_to_string(&seed_path).unwrap();
        assert_ne!(before, forced);
    }

    #[test]
    fn fingerprint_format_matches_fleet_tls() {
        use rustls::pki_types::CertificateDer;

        // Mint a CA + leaf the same way `init` does, then assert the fingerprint
        // format matches exactly what `fleet_tls::cert_fingerprint` produces and
        // what the generated config's [pinned_agents] comment documents.
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "probe-rs-fleet client CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut params =
            CertificateParams::new(vec!["agent-01.fleet.test".to_owned()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, "agent-01");
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        let der = CertificateDer::from(leaf.der().to_vec());
        let fp = fleet_tls::cert_fingerprint(&der);
        assert_eq!(fp.len(), 64, "fingerprint must be 64 hex chars");
        assert!(!fp.contains(':'), "no colons");
        assert!(!fp.contains("sha256"), "no sha256: prefix");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lowercase hex only"
        );
    }
}
