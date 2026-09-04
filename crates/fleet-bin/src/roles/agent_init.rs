//! The `agent init` subcommand: redeem an auth key for a node token and
//! scaffold a ready-to-run agent config (`agent.toml` + a starter
//! `boards.toml`) under the per-profile XDG paths.
//!
//! Run on the Raspberry Pi after `coordinator auth-key` has printed a key. It
//! POSTs the key to `<fleet-url>/auth/token`, receives a node token and the
//! coordinator's capability-token public key, and writes `agent.toml` (0600 —
//! it holds a bearer credential).
//!
//! There is no key material, no CSR, and no certificate any more. The honest
//! trade: a node token is a pure bearer credential, so anyone who reads
//! `agent.toml` can impersonate this node until the token rotates or the `node`
//! row is deleted — unlike a private key that never left the host. Rotation
//! (`CoordinatorCommand::RotateNodeToken`) is what bounds that window.

use std::path::Path;

use anyhow::{bail, Context, Result};

use fleet_agent::config::AgentConfig;

use crate::cli::AgentInitArgs;
use crate::paths;
use crate::secrets::{toml_path, write_public, write_secret};

const AGENT_CONFIG_FILE: &str = "agent.toml";
const BOARDS_FILE: &str = "boards.toml";

/// Run `agent init` for the given profile.
///
/// # Errors
///
/// Returns an error if the auth key cannot be redeemed, any file cannot be
/// written, or (without `--force`) a target file already exists.
pub async fn run(args: AgentInitArgs, profile: String) -> Result<()> {
    let AgentInitArgs {
        fleet_url,
        auth_key,
        node_name,
        tag,
        server_cert_sha256,
        config_dir,
        boards_path,
        force,
    } = args;

    let pin = match &server_cert_sha256 {
        Some(hex) => Some(
            fleet_tls::parse_fingerprint(hex)
                .context("--server-cert-sha256 must be 64 hex characters")?,
        ),
        None => None,
    };

    let config_dir = match config_dir {
        Some(dir) => dir,
        None => paths::agent_config_dir(&profile)?,
    };
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("creating config dir {}", config_dir.display()))?;

    let config_path = config_dir.join(AGENT_CONFIG_FILE);
    let boards_path = boards_path.unwrap_or_else(|| config_dir.join(BOARDS_FILE));

    // Idempotency guard.
    if !force && config_path.exists() {
        bail!(
            "refusing to overwrite existing file; pass --force to re-enroll:\n  {}",
            config_path.display()
        );
    }

    let node_name = match node_name {
        Some(name) => name,
        None => default_node_name(),
    };

    let response =
        fleet_auth::http_client::exchange_auth_key(&fleet_url, pin, &auth_key, &node_name, tag)
            .await
            .context("redeeming the auth key at <fleet-url>/auth/token")?;

    let node_id = response
        .node_id
        .clone()
        .unwrap_or_else(|| node_name.clone());
    let token_pubkey = response.coordinator_token_pubkey.clone().context(
        "the coordinator did not return its capability-token public key; \
         it is required to verify per-lease tokens",
    )?;

    let config_toml = render_agent_config(
        &node_id,
        &fleet_url,
        &response.token,
        server_cert_sha256.as_deref(),
        &token_pubkey,
        &boards_path,
    );
    // 0600: this file holds the node's bearer credential. A world-readable
    // bearer credential is equivalent to no credential at all.
    write_secret(&config_path, config_toml.as_bytes())
        .with_context(|| format!("writing agent config {}", config_path.display()))?;

    // Validate the written config round-trips.
    AgentConfig::from_path(&config_path)
        .with_context(|| format!("validating written agent config {}", config_path.display()))?;

    // Scaffold a starter boards.toml (skip if present unless --force).
    if force || !boards_path.exists() {
        write_public(&boards_path, starter_boards_toml().as_bytes())
            .with_context(|| format!("writing boards scaffold {}", boards_path.display()))?;
    }

    print_summary(&node_id, &response.org, &config_path, &boards_path);
    Ok(())
}

/// The machine's hostname, or a neutral placeholder.
///
/// Advisory only: it names the `node` row, it does not grant anything.
fn default_node_name() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "node".to_owned())
}

/// Render a populated `agent.toml`.
fn render_agent_config(
    node_id: &str,
    fleet_url: &str,
    node_token: &str,
    pin: Option<&str>,
    token_pubkey: &str,
    boards_path: &Path,
) -> String {
    let pin_block = pin.map_or_else(
        || {
            "\n# Optional: pin the coordinator's server certificate by its SHA-256, for a\n\
             # self-hosted deployment with no publicly trusted certificate.\n\
             # server_cert_sha256 = \"<64 hex chars>\"\n"
                .to_owned()
        },
        |p| {
            format!(
                "\n# Pinned coordinator server certificate (self-hosted deployment).\n\
                 server_cert_sha256 = {}\n",
                toml::Value::String(p.to_owned())
            )
        },
    );
    format!(
        r"# probe-rs-fleet agent config
#
# Generated by `probe-rs-fleet agent init`. Discovered at the per-profile XDG
# path
#   ~/.config/probe-rs-fleet/agent/<profile>/agent.toml
# unless overridden with --config / PROBE_RS_FLEET_AGENT_CONFIG.
#
# THIS FILE HOLDS A BEARER CREDENTIAL and is written 0600. Anyone who can read
# `node_token` can act as this node until the token rotates or the node's row is
# deleted on the coordinator.

# This node's id, as assigned by the coordinator at enrollment.
#
# Advisory: the coordinator identifies this node by the token it presents, and
# refuses the connection if this field contradicts it.
agent_id = {node_id}

# Base URL of the coordinator to dial out to.
fleet_url = {fleet_url}

# This node's bearer token. The coordinator rotates it over the established
# connection; the agent rewrites this file when it does.
node_token = {node_token}
{pin_block}
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
        node_id = toml::Value::String(node_id.to_owned()),
        fleet_url = toml::Value::String(fleet_url.to_owned()),
        node_token = toml::Value::String(node_token.to_owned()),
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
fn print_summary(node_id: &str, org: &str, config_path: &Path, boards_path: &Path) {
    println!("Enrolled node '{node_id}' in org '{org}':");
    println!("  config  {} (0600)", config_path.display());
    println!("  boards  {}", boards_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Edit {} to declare your boards.", boards_path.display());
    println!("  2. Start the agent:");
    println!("       probe-rs-fleet agent --profile <name>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_config_round_trips_through_agent_config() {
        let rendered = render_agent_config(
            "default/rpi-lab-1",
            "https://fleet.example",
            "prfn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            None,
            &"ab".repeat(32),
            Path::new("/etc/fleet/boards.toml"),
        );
        let cfg = AgentConfig::from_str(&rendered).unwrap();
        assert_eq!(cfg.agent_id, "default/rpi-lab-1");
        assert_eq!(cfg.fleet_url, "https://fleet.example");
        assert!(cfg.node_token.starts_with("prfn1_"));
        assert!(cfg.server_pin().is_none());
        assert!(cfg.previous_node_token.is_none());
    }

    #[test]
    fn rendered_config_carries_a_pin_when_given() {
        let pin = "cd".repeat(32);
        let rendered = render_agent_config(
            "default/rpi",
            "https://fleet.example",
            "prfn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            Some(&pin),
            &"ab".repeat(32),
            Path::new("/b.toml"),
        );
        let cfg = AgentConfig::from_str(&rendered).unwrap();
        assert_eq!(cfg.server_pin(), Some([0xcdu8; 32]));
    }

    /// The node name is a label, not a credential, so a machine with no
    /// resolvable hostname must still enroll rather than failing.
    #[test]
    fn default_node_name_is_never_empty() {
        assert!(!default_node_name().is_empty());
    }
}
