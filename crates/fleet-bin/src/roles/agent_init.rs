//! The `agent init` subcommand: redeem an auth key for a node token, record it
//! in the fleet file's `[node]` table, and scaffold the node-local settings.
//!
//! Run on the Raspberry Pi after `coordinator auth-key` has printed a key. It
//! POSTs the key to `<fleet-url>/auth/token`, receives a node token and the
//! coordinator's capability-token public key, and writes them into
//! `~/.config/probe-rs-fleet/fleets/<name>.toml` (0600 — it holds a bearer
//! credential), **preserving any `[user]` table** so a laptop can be both.
//!
//! Non-credential node settings (`node.toml`, `boards.toml`) are scaffolded
//! under `~/.config/probe-rs-fleet/node/`: they describe the machine, not the
//! fleet, and would be duplicated for nothing if they were per-fleet.
//!
//! There is no key material, no CSR, and no certificate any more. The honest
//! trade: a node token is a pure bearer credential, so anyone who reads the
//! fleet file can impersonate this node until the token rotates or the `node`
//! row is deleted — unlike a private key that never left the host. Rotation is
//! what bounds that window.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::cli::AgentInitArgs;
use crate::fleet_config::{self, NodeSection};
use crate::paths;
use crate::secrets::write_public;

/// Run `agent init` for the given fleet.
///
/// `config_dir` overrides the XDG config root (test and packaging support); the
/// fleet file then lives at `<config_dir>/<fleet>.toml` and node settings under
/// `<config_dir>/node/`.
///
/// # Errors
///
/// Returns an error if the auth key cannot be redeemed, any file cannot be
/// written, or (without `--force`) the fleet already has a `[node]` credential.
pub async fn run(args: AgentInitArgs, fleet: &str, config_dir: Option<PathBuf>) -> Result<()> {
    let AgentInitArgs {
        fleet_url,
        auth_key,
        node_name,
        tag,
        server_cert_sha256,
        force,
    } = args;

    let pin = match &server_cert_sha256 {
        Some(hex) => Some(
            fleet_tls::parse_fingerprint(hex)
                .context("--server-cert-sha256 must be 64 hex characters")?,
        ),
        None => None,
    };

    let (fleet_path, node_dir) = match &config_dir {
        Some(dir) => (dir.join(format!("{fleet}.toml")), dir.join("node")),
        None => (paths::fleet_config_path(fleet)?, paths::node_config_dir()?),
    };

    // Idempotency guard. Re-enrolling is a deliberate act: the old token stops
    // working, and on a headless node that is a physical visit if it was a
    // mistake.
    if !force && fleet_path.exists() {
        if let Ok(existing) = fleet_config::load(&fleet_path) {
            if existing.node.is_some() {
                bail!(
                    "fleet `{fleet}` already has a [node] credential; pass --force to re-enroll:\n  {}",
                    fleet_path.display()
                );
            }
        }
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

    // Read-modify-write: a `[user]` table (this machine's human) must survive an
    // enrollment, exactly as `login` must not drop `[node]`.
    //
    // `url` is overwritten here, where `login` prefers a remembered one. That
    // asymmetry is deliberate: `login`'s URL is optional (a repeat login should
    // need no flags), whereas `agent init --fleet-url` is required and names the
    // coordinator this node just enrolled *with* — the one that issued the token
    // we are about to store. Keeping a stale URL beside a token minted elsewhere
    // would be the contradiction.
    fleet_config::update(&fleet_path, |f| {
        f.url.clone_from(&fleet_url);
        if server_cert_sha256.is_some() {
            f.server_cert_sha256.clone_from(&server_cert_sha256);
        }
        f.node = Some(NodeSection {
            node_token: response.token.clone(),
            node_id: node_id.clone(),
            coordinator_token_pubkey: token_pubkey.clone(),
            previous_node_token: None,
        });
    })
    .with_context(|| format!("writing fleet config {}", fleet_path.display()))?;

    std::fs::create_dir_all(&node_dir)
        .with_context(|| format!("creating node config dir {}", node_dir.display()))?;
    let boards_path = node_dir.join("boards.toml");
    let node_settings_path = node_dir.join("node.toml");

    // These carry no credential, so they are written world-readable and only
    // scaffolded when absent: they are the operator's to edit, and clobbering a
    // hand-written board inventory on a re-enrollment would be hostile.
    if force || !boards_path.exists() {
        write_public(&boards_path, starter_boards_toml().as_bytes())
            .with_context(|| format!("writing boards scaffold {}", boards_path.display()))?;
    }
    if force || !node_settings_path.exists() {
        write_public(&node_settings_path, starter_node_toml().as_bytes())
            .with_context(|| format!("writing node settings {}", node_settings_path.display()))?;
    }

    print_summary(
        &node_id,
        &response.org,
        fleet,
        &fleet_path,
        &boards_path,
        &node_settings_path,
    );
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

/// A commented starter `node.toml`.
fn starter_node_toml() -> String {
    r#"# probe-rs-fleet node settings
#
# Node-LOCAL, non-credential settings: facts about this machine, the same
# whichever fleet it is enrolled in. The node's *credential* lives in
# ~/.config/probe-rs-fleet/fleets/<name>.toml under [node].

# Path to this node's board inventory.
# boards_path = "~/.config/probe-rs-fleet/node/boards.toml"

# Heartbeat interval, seconds (default 15).
# heartbeat_secs = 15

# Erase the target's flash on lease release (default false).
# erase_on_release = false
"#
    .to_owned()
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
    node_id: &str,
    org: &str,
    fleet: &str,
    fleet_path: &Path,
    boards_path: &Path,
    node_settings_path: &Path,
) {
    println!("Enrolled node '{node_id}' in org '{org}' (fleet `{fleet}`):");
    println!("  credential  {} (0600)", fleet_path.display());
    println!("  settings    {}", node_settings_path.display());
    println!("  boards      {}", boards_path.display());
    println!();
    println!("Next steps:");
    println!(
        "  1. Edit {} to declare your boards.",
        boards_path.display()
    );
    println!("  2. Start the agent:");
    println!("       probe-rs-fleet agent --fleet {fleet}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node name is a label, not a credential, so a machine with no
    /// resolvable hostname must still enroll rather than failing.
    #[test]
    fn default_node_name_is_never_empty() {
        assert!(!default_node_name().is_empty());
    }

    /// The scaffolds must parse as what they claim to be, or the first `agent`
    /// run fails on a file this command wrote.
    #[test]
    fn the_scaffolds_are_valid_toml() {
        fleet_agent::config::BoardsConfig::from_str(&starter_boards_toml()).unwrap();
        let settings: crate::roles::agent::NodeSettings =
            toml::from_str(&starter_node_toml()).unwrap();
        assert!(settings.boards_path.is_none());
    }
}
