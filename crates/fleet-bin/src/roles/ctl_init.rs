//! The `ctl init` subcommand: write `client.toml` so both `ctl` and the
//! `probe-rs` sidecar shim discover the coordinator and the session token from
//! one place.
//!
//! Run on a workstation / CI host with a token from `coordinator user-token`.
//! There is no certificate to fetch and no keypair to generate any more: the
//! session token is the whole credential, so `init` is a file write plus
//! validation.
//!
//! The file is written 0600 — it holds a bearer credential, and anyone who can
//! read it can act as this user until the token expires.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::cli::CtlInitArgs;
use crate::config::render_client_config;
use crate::paths;
use crate::secrets::write_secret;

const CLIENT_CONFIG_FILE: &str = "client.toml";

/// Run `ctl init` for the given profile.
///
/// # Errors
///
/// Returns an error if the token or pin is malformed, the file cannot be
/// written, or (without `--force`) it already exists.
#[allow(clippy::unused_async)] // Symmetric with `agent_init::run`, which does
                               // make a network call; the dispatcher awaits both.
pub async fn run(args: CtlInitArgs, profile: String) -> Result<()> {
    let CtlInitArgs {
        fleet_url,
        token,
        server_cert_sha256,
        config_dir,
        force,
    } = args;

    // Validate before writing: a config file that cannot be used is worse than
    // an error, because it fails later and further from the mistake.
    anyhow::ensure!(
        fleet_auth::OpaqueToken::parse(&token)
            .is_ok_and(|t| t.kind() == fleet_auth::TokenKind::Session),
        "--token must be a session token (`prfs1_…`); mint one with \
         `probe-rs-fleet coordinator user-token <login>`"
    );
    if let Some(pin) = &server_cert_sha256 {
        anyhow::ensure!(
            fleet_tls::parse_fingerprint(pin).is_some(),
            "--server-cert-sha256 must be 64 hex characters"
        );
    }

    let config_dir = match config_dir {
        Some(dir) => dir,
        None => paths::client_config_dir(&profile)?,
    };
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("creating config dir {}", config_dir.display()))?;

    let config_path = config_dir.join(CLIENT_CONFIG_FILE);
    if !force && config_path.exists() {
        bail!(
            "refusing to overwrite existing file; pass --force to replace it:\n  {}",
            config_path.display()
        );
    }

    let config_toml =
        render_client_config(&fleet_url, &token, server_cert_sha256.as_deref());
    write_secret(&config_path, config_toml.as_bytes())
        .with_context(|| format!("writing client config {}", config_path.display()))?;

    // Round-trip what we just wrote.
    crate::config::load_client_config(&config_path)
        .with_context(|| format!("validating written client config {}", config_path.display()))?;

    print_summary(&config_path, &fleet_url);
    Ok(())
}

/// Print a summary + next steps.
fn print_summary(config_path: &Path, fleet_url: &str) {
    println!("Initialised client config for coordinator '{fleet_url}':");
    println!("  config  {} (0600)", config_path.display());
    println!();
    println!("This configures both `ctl` and the `probe-rs` sidecar shim for this profile.");
    println!("Next steps:");
    println!("  probe-rs-fleet ctl --profile <name> list");
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_auth::{OpaqueToken, TokenKind};

    fn args(token: &str, pin: Option<&str>, dir: &Path) -> CtlInitArgs {
        CtlInitArgs {
            fleet_url: "https://fleet.example".to_owned(),
            token: token.to_owned(),
            server_cert_sha256: pin.map(ToOwned::to_owned),
            config_dir: Some(dir.to_path_buf()),
            force: false,
        }
    }

    #[tokio::test]
    async fn writes_a_usable_0600_client_config() {
        let tmp = tempfile::tempdir().unwrap();
        let token = OpaqueToken::mint(TokenKind::Session).to_secret_string();
        run(args(&token, None, tmp.path()), "default".to_owned())
            .await
            .unwrap();

        let path = tmp.path().join(CLIENT_CONFIG_FILE);
        let cfg = crate::config::load_client_config(&path).unwrap();
        assert_eq!(cfg.fleet_url, "https://fleet.example");
        assert_eq!(cfg.token, token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A node token in `client.toml` would authenticate against `/agent` and be
    /// refused with a 403 on `/client` — a confusing failure a long way from the
    /// mistake. Reject it here, where the operator can see what they typed.
    #[tokio::test]
    async fn refuses_a_token_of_the_wrong_kind() {
        let tmp = tempfile::tempdir().unwrap();
        let node = OpaqueToken::mint(TokenKind::Node).to_secret_string();
        assert!(run(args(&node, None, tmp.path()), "default".to_owned())
            .await
            .is_err());
        assert!(run(args("garbage", None, tmp.path()), "default".to_owned())
            .await
            .is_err());
        assert!(!tmp.path().join(CLIENT_CONFIG_FILE).exists());
    }

    #[tokio::test]
    async fn refuses_a_malformed_pin_and_an_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let token = OpaqueToken::mint(TokenKind::Session).to_secret_string();
        assert!(
            run(args(&token, Some("nope"), tmp.path()), "default".to_owned())
                .await
                .is_err()
        );

        run(args(&token, None, tmp.path()), "default".to_owned())
            .await
            .unwrap();
        assert!(run(args(&token, None, tmp.path()), "default".to_owned())
            .await
            .is_err());

        let mut forcing = args(&token, None, tmp.path());
        forcing.force = true;
        run(forcing, "default".to_owned()).await.unwrap();
    }
}
