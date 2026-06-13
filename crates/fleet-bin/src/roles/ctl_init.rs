//! The `ctl init` subcommand: redeem an enrollment token for a CA-signed client
//! cert and write `client.toml` so both `ctl` and the `probe-rs` sidecar shim
//! discover the coordinator endpoint + client credentials from one place.
//!
//! Run on a workstation / CI host after `coordinator enroll <user> --kind
//! client` has printed a token. The coordinator address, server-cert pin, and
//! one-time secret all come from the token; the keypair + CSR are generated
//! locally (the private key never leaves this host).

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::cli::CtlInitArgs;
use crate::config::render_client_config;
use crate::paths;
use crate::secrets::{write_public, write_secret};

/// Issued credential filenames under the profile data dir.
const CLIENT_CERT_FILE: &str = "client-cert.pem";
const CLIENT_KEY_FILE: &str = "client-key.pem";
const CLIENT_CA_FILE: &str = "client-ca.pem";
const CLIENT_CONFIG_FILE: &str = "client.toml";

/// Run `ctl init` for the given profile.
///
/// # Errors
///
/// Returns an error if the token cannot be redeemed, any file cannot be
/// written, or (without `--force`) a target file already exists.
pub async fn run(args: CtlInitArgs, profile: String) -> Result<()> {
    let CtlInitArgs {
        token,
        config_dir,
        data_dir,
        force,
    } = args;

    let config_dir = match config_dir {
        Some(dir) => dir,
        None => paths::client_config_dir(&profile)?,
    };
    let data_dir = match data_dir {
        Some(dir) => dir,
        None => paths::client_data_dir(&profile)?,
    };

    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("creating config dir {}", config_dir.display()))?;
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    let cert_path = data_dir.join(CLIENT_CERT_FILE);
    let key_path = data_dir.join(CLIENT_KEY_FILE);
    let ca_path = data_dir.join(CLIENT_CA_FILE);
    let config_path = config_dir.join(CLIENT_CONFIG_FILE);

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

    // Redeem the token: pinned bootstrap TLS -> local CSR -> CA-signed cert.
    let enrolled = crate::roles::bootstrap::enroll(&token)
        .await
        .context("enrolling client via bootstrap token")?;

    write_public(&cert_path, enrolled.client_cert_pem.as_bytes())
        .with_context(|| format!("writing client cert {}", cert_path.display()))?;
    write_secret(&key_path, enrolled.client_key_pem.as_bytes())
        .with_context(|| format!("writing client key {}", key_path.display()))?;
    write_public(&ca_path, enrolled.ca_cert_pem.as_bytes())
        .with_context(|| format!("writing CA {}", ca_path.display()))?;

    let config_toml =
        render_client_config(&enrolled.coordinator_addr, &cert_path, &key_path, &ca_path);
    write_public(&config_path, config_toml.as_bytes())
        .with_context(|| format!("writing client config {}", config_path.display()))?;

    print_summary(&config_path, &enrolled.coordinator_addr, &cert_path, &key_path, &ca_path);
    Ok(())
}

/// Print a summary + next steps.
fn print_summary(
    config_path: &Path,
    coordinator: &str,
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) {
    println!("Initialised client config for coordinator '{coordinator}':");
    println!("  config  {}", config_path.display());
    println!("  cert    {}", cert_path.display());
    println!("  key     {}", key_path.display());
    println!("  ca      {}", ca_path.display());
    println!();
    println!("This configures both `ctl` and the `probe-rs` sidecar shim for this profile.");
    println!("Next steps:");
    println!("  probe-rs-fleet ctl --profile <name> list");
}
