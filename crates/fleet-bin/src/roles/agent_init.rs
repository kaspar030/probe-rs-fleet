//! The `agent init` subcommand: redeem an enrollment token for a CA-signed
//! client cert and scaffold a ready-to-run agent config (`agent.toml` + a
//! starter `boards.toml`) under the per-profile XDG paths.
//!
//! Run on the Raspberry Pi after `coordinator enroll <agent-id> --kind agent`
//! has printed a token. The token carries the coordinator address, a server-
//! cert pin, and a one-time secret. `init` generates a keypair + CSR locally
//! (the private key never leaves this host), redeems the secret over a pinned
//! bootstrap TLS connection, writes the returned cert/key/CA into the profile
//! data dir, derives `agent_id` from the issued cert CN (matching the pin the
//! coordinator records automatically), and writes a populated `agent.toml`.

use std::path::Path;

use anyhow::{bail, Context, Result};
use rustls::pki_types::CertificateDer;

use fleet_agent::config::AgentConfig;

use crate::cli::AgentInitArgs;
use crate::paths;
use crate::secrets::{toml_path, write_public, write_secret};

/// Issued credential filenames under the profile data dir.
const AGENT_CERT_FILE: &str = "agent-cert.pem";
const AGENT_KEY_FILE: &str = "agent-key.pem";
const CLIENT_CA_FILE: &str = "client-ca.pem";
const AGENT_CONFIG_FILE: &str = "agent.toml";
const BOARDS_FILE: &str = "boards.toml";

/// Run `agent init` for the given profile.
///
/// # Errors
///
/// Returns an error if the token cannot be redeemed, any file cannot be
/// written, the cert CN cannot be derived, or (without `--force`) a target file
/// already exists.
pub async fn run(args: AgentInitArgs, profile: String) -> Result<()> {
    let AgentInitArgs {
        token,
        config_dir,
        data_dir,
        boards_path,
        force,
    } = args;

    let config_dir = match config_dir {
        Some(dir) => dir,
        None => paths::agent_config_dir(&profile)?,
    };
    let data_dir = match data_dir {
        Some(dir) => dir,
        None => paths::agent_data_dir(&profile)?,
    };

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

    // Redeem the token: pinned bootstrap TLS -> local CSR -> CA-signed cert.
    let enrolled = crate::roles::bootstrap::enroll(&token)
        .await
        .context("enrolling agent via bootstrap token")?;

    // Write issued credentials (the key was generated locally).
    write_public(&cert_path, enrolled.client_cert_pem.as_bytes())
        .with_context(|| format!("writing agent cert {}", cert_path.display()))?;
    write_secret(&key_path, enrolled.client_key_pem.as_bytes())
        .with_context(|| format!("writing agent key {}", key_path.display()))?;
    write_public(&ca_path, enrolled.ca_cert_pem.as_bytes())
        .with_context(|| format!("writing CA {}", ca_path.display()))?;

    // Derive agent_id from the issued cert's CN (source of truth, matches the
    // coordinator's auto-pin).
    let agent_id = agent_id_from_cert_file(&cert_path)?;

    let config_toml = render_agent_config(
        &agent_id,
        &enrolled.coordinator_addr,
        &cert_path,
        &key_path,
        &ca_path,
        &enrolled.coordinator_token_pubkey,
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

/// Derive the agent id (cert CN) from an issued cert PEM file.
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
# credentials issued during bootstrap enrollment. The agent is discovered at
# the per-profile XDG path
#   ~/.config/probe-rs-fleet/agent/<profile>/agent.toml
# unless overridden with --config / PROBE_RS_FLEET_AGENT_CONFIG.

# This agent's id. Derived from the issued client cert CN, which the
# coordinator pins automatically.
agent_id = {agent_id}

# `host:port` of the coordinator to dial out to (runtime is mTLS).
coordinator_endpoint = {coordinator}

# Client mTLS certificate chain + private key (issued via bootstrap enrollment;
# the private key was generated locally and never left this host).
tls_cert = {tls_cert}
tls_key = {tls_key}

# CA used to verify the coordinator's server certificate (PEM).
tls_ca = {tls_ca}

# Hex-encoded ed25519 public key of the coordinator's token signer. Returned by
# enrollment; used to verify per-lease capability tokens.
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
    println!("  2. Start the agent:");
    println!("       probe-rs-fleet agent --profile <name>");
}
