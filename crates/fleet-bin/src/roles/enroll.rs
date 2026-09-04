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
        coordinator_addr,
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

    let compact = mint_token(
        &principal_id,
        kind,
        ttl,
        coordinator_addr.as_deref(),
        &config_path,
        &data_dir,
    )
    .await?;
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
    coordinator_addr: Option<&str>,
    config_path: &std::path::Path,
    data_dir: &std::path::Path,
) -> Result<String> {
    // Load the coordinator config to learn the listen address and the SQLite
    // path. The server cert lives in the data dir.
    let coord_cfg = crate::config::load_coordinator_config(config_path)
        .with_context(|| format!("loading coordinator config {}", config_path.display()))?;

    // Resolve the *dialable advertised* address to embed into the token. The
    // listen address is frequently a wildcard (`0.0.0.0` / `::`) which is not
    // routable from another host, so we never silently embed it.
    //
    // Precedence: `--coordinator-addr` > config `advertise_addr` >
    // `listen_addr` fallback (rejected if it is a wildcard).
    let coordinator_addr = resolve_advertise_addr(
        coordinator_addr,
        coord_cfg.advertise_addr.as_deref(),
        coord_cfg.listen_addr,
    )?;

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

    // Enrollment mints an identity inside one org; a single-user deployment
    // uses the coordinator's configured default.
    db.insert_enroll_token(
        &coord_cfg.default_org,
        &secret_hash,
        principal_id,
        kind_str,
        now,
        expires_at,
    )
        .await
        .context("recording enrollment token")?;

    let token = EnrollmentToken {
        coordinator_addr,
        server_cert_sha256,
        secret,
    };
    token.to_compact_string().context("encoding enrollment token")
}

/// Resolve the dialable advertised address to embed into an enrollment token.
///
/// Precedence (highest first): explicit `--coordinator-addr` override, then the
/// config `advertise_addr`, then the `listen_addr` fallback. The resulting
/// address is validated to ensure it is not a wildcard / unspecified IP
/// (`0.0.0.0` / `::`), which clients cannot dial; such an address is rejected
/// with a clear, actionable error.
///
/// # Errors
///
/// Returns an error if the resolved address would be a wildcard / unspecified
/// IP, or if an explicit override / `advertise_addr` is empty.
fn resolve_advertise_addr(
    override_addr: Option<&str>,
    config_addr: Option<&str>,
    listen_addr: std::net::SocketAddr,
) -> Result<String> {
    let (addr, source) = match (override_addr, config_addr) {
        (Some(a), _) => (a.trim().to_owned(), "--coordinator-addr"),
        (None, Some(a)) => (a.trim().to_owned(), "advertise_addr in coordinator.toml"),
        (None, None) => (listen_addr.to_string(), "listen_addr"),
    };

    if addr.is_empty() {
        anyhow::bail!("{source} is empty; expected a dialable `host:port`");
    }

    if addr_is_wildcard(&addr) {
        anyhow::bail!(
            "refusing to embed wildcard/unspecified address `{addr}` (from {source}) into the \
             enrollment token: it is not routable from another host. Pass \
             `--coordinator-addr <host:port>` (e.g. the coordinator's LAN IP) or set \
             `advertise_addr` in coordinator.toml to a dialable address."
        );
    }

    Ok(addr)
}

/// Whether `addr` (a `host:port` string) has a wildcard / unspecified IP host
/// (`0.0.0.0` or `::`). Hostnames and concrete IPs are not wildcards.
fn addr_is_wildcard(addr: &str) -> bool {
    // Only `SocketAddr`-parseable inputs can have an unspecified IP host; a
    // DNS hostname:port never parses as a `SocketAddr` and is always dialable.
    addr.parse::<std::net::SocketAddr>()
        .is_ok_and(|sa| sa.ip().is_unspecified())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn listen(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn override_is_honored() {
        let addr =
            resolve_advertise_addr(Some("192.168.1.163:7000"), None, listen("0.0.0.0:7000"))
                .unwrap();
        assert_eq!(addr, "192.168.1.163:7000");
    }

    #[test]
    fn override_wins_over_config_and_listen() {
        let addr = resolve_advertise_addr(
            Some("10.0.0.5:7000"),
            Some("203.0.113.1:7000"),
            listen("0.0.0.0:7000"),
        )
        .unwrap();
        assert_eq!(addr, "10.0.0.5:7000");
    }

    #[test]
    fn config_advertise_used_when_no_override() {
        let addr =
            resolve_advertise_addr(None, Some("coord.example:7000"), listen("0.0.0.0:7000"))
                .unwrap();
        assert_eq!(addr, "coord.example:7000");
    }

    #[test]
    fn listen_fallback_used_when_concrete() {
        let addr = resolve_advertise_addr(None, None, listen("127.0.0.1:7000")).unwrap();
        assert_eq!(addr, "127.0.0.1:7000");
    }

    #[test]
    fn wildcard_listen_fallback_rejected() {
        let err = resolve_advertise_addr(None, None, listen("0.0.0.0:7000")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("0.0.0.0"), "message was: {msg}");
        assert!(msg.contains("--coordinator-addr"), "message was: {msg}");
    }

    #[test]
    fn wildcard_ipv6_listen_fallback_rejected() {
        let err = resolve_advertise_addr(None, None, listen("[::]:7000")).unwrap_err();
        assert!(err.to_string().contains("--coordinator-addr"));
    }

    #[test]
    fn wildcard_override_rejected() {
        assert!(
            resolve_advertise_addr(Some("0.0.0.0:7000"), None, listen("127.0.0.1:7000")).is_err()
        );
    }

    #[test]
    fn wildcard_config_advertise_rejected() {
        assert!(
            resolve_advertise_addr(None, Some("[::]:7000"), listen("127.0.0.1:7000")).is_err()
        );
    }

    #[test]
    fn empty_override_rejected() {
        assert!(resolve_advertise_addr(Some("  "), None, listen("127.0.0.1:7000")).is_err());
    }

    #[test]
    fn hostname_is_not_wildcard() {
        assert!(!addr_is_wildcard("coordinator.local:7000"));
        assert!(addr_is_wildcard("0.0.0.0:7000"));
        assert!(!addr_is_wildcard("127.0.0.1:7000"));
    }
}
