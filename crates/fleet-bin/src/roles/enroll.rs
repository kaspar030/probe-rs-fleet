//! The `coordinator enroll` subcommand: mint a one-time bootstrap enrollment
//! token for a principal (agent / ctl / sidecar user).
//!
//! The token is a single opaque, copy-pasteable string carrying three things:
//! the coordinator address (`host:port`), the SHA-256 hash of the coordinator's
//! server certificate (for bootstrap server-cert pinning), and a random
//! single-use auth secret. `agent init` / `ctl init` redeem the token over a
//! pinned bootstrap TLS connection: they generate a keypair + CSR locally and
//! receive a CA-signed client certificate. Runtime authentication stays mTLS;
//! the token is bootstrap-only.
//!
//! The coordinator stores only the secret's hash (single-use, TTL'd) in its
//! `SQLite` database; this runs on the coordinator host, so it talks to the
//! same database directly.

use anyhow::{Context, Result};

use fleet_proto::enroll::EnrollmentToken;

use crate::cli::{EnrollArgs, EnrollKind};
use crate::paths;
use crate::secrets::generate_secret;

/// Filenames written by `coordinator init` under the data dir.
const SERVER_CERT_FILE: &str = "coordinator-cert.pem";

/// Run `coordinator enroll`.
///
/// # Errors
///
/// Returns an error if the coordinator config / server cert cannot be located
/// or parsed, or the token cannot be recorded in the database.
pub async fn run(args: EnrollArgs) -> Result<()> {
    let EnrollArgs {
        principal_id,
        kind,
        ttl,
        config_dir,
        data_dir,
    } = args;

    let config_path = match config_dir {
        Some(dir) => dir.join("coordinator.toml"),
        None => paths::coordinator_config_path()?,
    };
    let data_dir = match data_dir {
        Some(dir) => dir,
        None => paths::coordinator_data_dir()?,
    };

    let compact = mint_token(&principal_id, kind, ttl, &config_path, &data_dir).await?;
    print_summary(&principal_id, kind, ttl, &compact);
    Ok(())
}

/// Mint a bootstrap enrollment token for `principal_id`: record its hashed
/// secret (single-use, TTL'd) in the coordinator database and return the
/// compact token string.
///
/// # Errors
///
/// Returns an error if the coordinator config / server cert cannot be located
/// or parsed, or the token cannot be recorded in the database.
pub async fn mint_token(
    principal_id: &str,
    kind: EnrollKind,
    ttl: u64,
    config_path: &std::path::Path,
    data_dir: &std::path::Path,
) -> Result<String> {
    // Load the coordinator config to learn the listen address and the SQLite
    // path. The server cert lives in the data dir.
    let coord_cfg = crate::config::load_coordinator_config(config_path)
        .with_context(|| format!("loading coordinator config {}", config_path.display()))?;

    let coordinator_addr = coord_cfg.listen_addr.to_string();

    // Compute the SHA-256 of the coordinator's server-certificate DER, so the
    // client can pin the bootstrap server leaf.
    let server_cert_path = data_dir.join(SERVER_CERT_FILE);
    let server_cert_sha256 = server_cert_sha256(&server_cert_path)?;

    // Mint a random single-use secret; store only its hash with a TTL.
    let secret = generate_secret();
    let secret_hash = fleet_coordinator::enroll::hash_secret(&secret);

    let kind_str = match kind {
        EnrollKind::Agent => "agent",
        EnrollKind::Client => "client",
    };

    let sqlite_path = coord_cfg
        .sqlite_path
        .to_str()
        .context("coordinator sqlite_path is not UTF-8")?;
    let db = fleet_coordinator::Db::connect(sqlite_path)
        .await
        .with_context(|| format!("opening coordinator database {sqlite_path}"))?;

    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX);
    let expires_at = now.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX));

    db.insert_enroll_token(&secret_hash, principal_id, kind_str, now, expires_at)
        .await
        .context("recording enrollment token")?;

    let token = EnrollmentToken {
        coordinator_addr,
        server_cert_sha256,
        secret,
    };
    token.to_compact_string().context("encoding enrollment token")
}

/// Compute the SHA-256 of the first certificate in a PEM file.
fn server_cert_sha256(path: &std::path::Path) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let pem = std::fs::read(path).with_context(|| {
        format!(
            "reading coordinator server cert {} (run `coordinator init` first)",
            path.display()
        )
    })?;
    let mut reader = std::io::BufReader::new(pem.as_slice());
    let der = rustls_pemfile::certs(&mut reader)
        .next()
        .with_context(|| format!("no certificate found in {}", path.display()))?
        .with_context(|| format!("parsing certificate in {}", path.display()))?;
    Ok(Sha256::digest(der.as_ref()).into())
}

/// Print the token plus a ready-to-paste init command.
fn print_summary(principal_id: &str, kind: EnrollKind, ttl: u64, token: &str) {
    println!("Enrolled principal '{principal_id}' (valid for {ttl}s):");
    println!();
    println!("  Enrollment token (one-time, single-use):");
    println!("    {token}");
    println!();
    println!("On the target host, redeem it with:");
    match kind {
        EnrollKind::Agent => {
            println!("    probe-rs-fleet agent init --profile <name> --token {token}");
            println!();
            println!("Then run the agent:");
            println!("    probe-rs-fleet agent --profile <name>");
        }
        EnrollKind::Client => {
            println!("    probe-rs-fleet ctl init --profile <name> --token {token}");
            println!();
            println!("Then use ctl:");
            println!("    probe-rs-fleet ctl --profile <name> list");
        }
    }
}
