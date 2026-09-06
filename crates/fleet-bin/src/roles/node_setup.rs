//! Shared node-enrollment mechanics for `share` and `agent up`.
//!
//! Both verbs end at the same place — a `[node]` credential in the fleet file
//! and scaffolded node-local settings under `node/` — and differ only in *how*
//! they obtained the node token (a `[user]` session versus an auth key). The
//! common half lives here so the two paths cannot drift: a machine shared by
//! its owner and a machine enrolled from an image must end up with the same
//! files, or the second one to be touched behaves differently for reasons
//! nobody can see.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use fleet_auth::api::TokenResponse;
use fleet_proto::AdoptPolicy;

use crate::fleet_config::{self, NodeSection};
use crate::paths;
use crate::secrets::write_public;

/// The machine's hostname, or a neutral placeholder.
///
/// Advisory only: it names the `node` row, it does not grant anything. A
/// machine with no resolvable hostname must still enroll rather than failing on
/// a label.
#[must_use]
pub fn default_node_name() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "node".to_owned())
}

/// Resolve the fleet file and the node-settings directory.
///
/// `config_dir` overrides the XDG config root (test and packaging support); the
/// fleet file then lives at `<config_dir>/<fleet>.toml` and node settings under
/// `<config_dir>/node/`.
///
/// # Errors
///
/// Returns an error if the XDG config root cannot be resolved.
pub fn resolve_paths(fleet: &str, config_dir: Option<&Path>) -> Result<(PathBuf, PathBuf)> {
    match config_dir {
        Some(dir) => Ok((dir.join(format!("{fleet}.toml")), dir.join("node"))),
        None => Ok((paths::fleet_config_path(fleet)?, paths::node_config_dir()?)),
    }
}

/// Refuse to re-enroll a fleet that already holds a `[node]` credential,
/// unless `force`.
///
/// Re-enrolling is a deliberate act: the old token stops working, and on a
/// headless node that is a physical visit if it was a mistake.
///
/// # Errors
///
/// Returns an error naming `--force` when a `[node]` table already exists.
pub fn refuse_if_already_enrolled(fleet: &str, fleet_path: &Path, force: bool) -> Result<()> {
    if force || !fleet_path.exists() {
        return Ok(());
    }
    if let Ok(existing) = fleet_config::load(fleet_path) {
        anyhow::ensure!(
            existing.node.is_none(),
            "fleet `{fleet}` already has a [node] credential; pass --force to re-enroll:\n  {}",
            fleet_path.display()
        );
    }
    Ok(())
}

/// Write a freshly minted node credential into the fleet file's `[node]` table.
///
/// **Read-modify-write, never a whole-file rewrite.** A `[user]` table (this
/// machine's human) must survive an enrollment, exactly as `login` must not
/// drop `[node]`. Building a fresh `FleetFile` and calling `save_atomic` would
/// silently destroy the other credential — precisely the bug the one-file
/// layout exists to prevent.
///
/// `url` is overwritten when `fleet_url` is `Some`, because a URL passed to an
/// enrollment names the coordinator that just issued the token we are about to
/// store; keeping a stale URL beside it would be the contradiction. When the
/// token came from a session already in the file, there is no new URL and the
/// existing one stands.
///
/// # Errors
///
/// Returns an error if the coordinator did not return its capability-token
/// public key, or the file cannot be written.
pub fn record_node_credential(
    fleet_path: &Path,
    response: &TokenResponse,
    node_name: &str,
    fleet_url: Option<&str>,
    server_cert_sha256: Option<&str>,
) -> Result<String> {
    let node_id = response
        .node_id
        .clone()
        .unwrap_or_else(|| node_name.to_owned());
    let token_pubkey = response.coordinator_token_pubkey.clone().context(
        "the coordinator did not return its capability-token public key; \
         it is required to verify per-lease tokens",
    )?;

    let node_id_for_write = node_id.clone();
    fleet_config::update(fleet_path, |f| {
        if let Some(url) = fleet_url {
            url.clone_into(&mut f.url);
        }
        if let Some(pin) = server_cert_sha256 {
            f.server_cert_sha256 = Some(pin.to_owned());
        }
        f.node = Some(NodeSection {
            node_token: response.token.clone(),
            node_id: node_id_for_write,
            coordinator_token_pubkey: token_pubkey,
            previous_node_token: None,
        });
    })
    .with_context(|| format!("writing fleet config {}", fleet_path.display()))?;

    Ok(node_id)
}

/// Scaffold `node/node.toml` and `node/boards.toml` if they are absent.
///
/// These carry no credential, so they are written world-readable.
///
/// # What `force` does and does not cover
///
/// `force` is a **credential-level** flag: it means "re-enroll this machine,
/// replacing its node token". It deliberately does not reach `boards.toml`,
/// which is never overwritten once it exists. That file is now *the* place an
/// operator records stable ids, chip names, curated tags and power wiring for
/// auto-adopted boards (§8) — losing it is losing user data, and `share
/// --force` is the documented way to re-share a machine, so it would be lost
/// exactly when someone was trying to fix something.
///
/// `node.toml` *is* rewritten under `force`, and only then, because `force` is
/// how `--adopt` is changed on an already-enrolled machine: leaving a stale
/// `adopt =` behind would have the file contradict the coordinator row it is
/// supposed to mirror. It holds settings rather than inventory, and the starter
/// is fully commented apart from that one key.
///
/// Returns `(boards_path, node_settings_path)`.
///
/// # Errors
///
/// Returns an error if the directory or either file cannot be written.
pub fn scaffold_node_dir(
    node_dir: &Path,
    adopt: AdoptPolicy,
    force: bool,
) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(node_dir)
        .with_context(|| format!("creating node config dir {}", node_dir.display()))?;
    let boards_path = node_dir.join("boards.toml");
    let node_settings_path = node_dir.join("node.toml");

    if !boards_path.exists() {
        write_public(&boards_path, starter_boards_toml().as_bytes())
            .with_context(|| format!("writing boards scaffold {}", boards_path.display()))?;
    }
    if force || !node_settings_path.exists() {
        write_public(&node_settings_path, starter_node_toml(adopt).as_bytes())
            .with_context(|| format!("writing node settings {}", node_settings_path.display()))?;
    }
    Ok((boards_path, node_settings_path))
}

/// A commented starter `node.toml`, with `adopt` written out uncommented.
///
/// `adopt` is the one key here whose value the enrolling command actually
/// decided, so it is the one key that is *not* left commented: an operator
/// reading this file should be able to see which policy their machine was
/// enrolled with without going to the coordinator.
#[must_use]
pub fn starter_node_toml(adopt: AdoptPolicy) -> String {
    format!(
        r#"# probe-rs-fleet node settings
#
# Node-LOCAL, non-credential settings: facts about this machine, the same
# whichever fleet it is enrolled in. The node's *credential* lives in
# ~/.config/probe-rs-fleet/fleets/<name>.toml under [node].

# What this node does with a probe `boards.toml` does not declare.
#
#   "auto"     — adopt it: derive a stable id, infer tags, make it leasable.
#   "declared" — report it, but keep it unleasable until it is declared.
#
# ADVISORY. The coordinator's node row is what actually decides; this setting
# only governs whether this agent bothers to synthesise board metadata for
# undeclared probes. Editing it here does NOT change what the coordinator will
# adopt — re-run `probe-rs-fleet share --adopt <policy>` (or `agent up --adopt
# <policy>`) for that.
adopt = "{adopt}"

# Path to this node's board inventory.
# boards_path = "~/.config/probe-rs-fleet/node/boards.toml"

# Heartbeat interval, seconds (default 15).
# heartbeat_secs = 15

# How often (seconds) to re-enumerate attached probes (default 30). Each pass
# shells out to `probe-rs list`, so this is not free.
# discovery_secs = 30

# Erase the target's flash on lease release (default false).
# erase_on_release = false
"#
    )
}

/// A commented starter `boards.toml` with one example `[[board]]`.
#[must_use]
pub fn starter_boards_toml() -> String {
    r#"# probe-rs-fleet agent board inventory
#
# Easiest way to add an entry: `probe-rs-fleet node board add`, which discovers
# attached probes and APPENDS a [[board]] table here (your comments survive;
# editing and removing are still hand-edits).
#
# ANNOTATION AND OVERRIDE, not admission control. Whether an undeclared probe
# becomes leasable is this node's `adopt` policy (see node.toml):
#
#   adopt = "auto"     — undeclared probes are adopted automatically, with a
#                        derived id, inferred tags, and NO `chip` and NO
#                        `model` (the agent cannot know what target, or what
#                        board, is attached to a probe). Add a [[board]] here
#                        to give one a stable id, a chip name, a board model,
#                        curated tags, or power wiring.
#   adopt = "declared" — only the boards below are leasable.
#
# Uncomment and adapt the example below for each board you want to annotate.

# [[board]]
# # Stable board id. Unique WITHIN THIS NODE, not across the fleet: a board is
# # identified fleet-wide by (org, node, id).
# id        = "nrf52840-dk-3"
# # Physical probe serial bound to this board.
# serial    = "001050257890"
# # probe-rs target/chip name (informational, but `ctl lease --select 'chip=…'`
# # matches on it — an auto-adopted board has none until you set it here).
# chip      = "nRF52840_xxAA"
# # Board MODEL (board type) — what `--select 'board=<model>'` matches. This is
# # the word developers use ("I need an nrf52840dk"), and it is NOT the chip: a
# # Nordic DK and a custom nRF52840 board share `nRF52840_xxAA` and are not
# # interchangeable. The agent cannot infer it (`probe-rs list` reports the
# # probe, never the board wired to it), so without this line no `board=`
# # selector will ever match this board.
# model     = "nrf52840dk"
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

/// What an enrollment produced, for [`print_summary`].
///
/// A struct rather than eight positional arguments because three of them are
/// paths and one is a bare `bool`: at a call site, `(…, &boards, &settings,
/// true)` is exactly the shape that gets silently transposed.
pub struct Enrollment<'a> {
    /// The node id the coordinator assigned.
    pub node_id: &'a str,
    /// The org the node joined.
    pub org: &'a str,
    /// The fleet name (what `--fleet` would take).
    pub fleet: &'a str,
    /// The probe adoption policy the node was registered with.
    pub adopt: AdoptPolicy,
    /// The fleet file the credential was written to.
    pub fleet_path: &'a Path,
    /// The scaffolded `boards.toml`.
    pub boards_path: &'a Path,
    /// The scaffolded `node.toml`.
    pub node_settings_path: &'a Path,
    /// Whether to tell the reader how to start the agent.
    ///
    /// `share` sets this: it deliberately does not start the agent, so "plug in
    /// a board and it is leasable" is still one step away and saying so is the
    /// difference between a working machine and a confused one. `agent up`
    /// does not, because it is about to run the agent itself.
    pub run_hint: bool,
}

/// Print an enrollment summary and the next step.
pub fn print_summary(e: &Enrollment<'_>) {
    let Enrollment {
        node_id,
        org,
        fleet,
        adopt,
        fleet_path,
        boards_path,
        node_settings_path,
        run_hint,
    } = *e;
    println!("Enrolled node '{node_id}' in org '{org}' (fleet `{fleet}`):");
    println!("  credential  {} (0600)", fleet_path.display());
    println!("  settings    {}", node_settings_path.display());
    println!("  boards      {}", boards_path.display());
    println!("  adopt       {adopt}");
    println!();
    match adopt {
        AdoptPolicy::Auto => {
            println!("Probes you plug in are adopted automatically and become leasable.");
            println!(
                "Annotate them in {} for a stable id, a chip name, or power wiring \
                 — or run `probe-rs-fleet node board add`.",
                boards_path.display()
            );
        }
        AdoptPolicy::Declared => {
            println!(
                "Undeclared probes are reported but NOT leasable. Declare each board in\n  {}\n\
                 or run `probe-rs-fleet node board add`, which discovers attached probes\n\
                 and writes the declaration for you.",
                boards_path.display()
            );
        }
    }
    if run_hint {
        println!();
        println!("The agent is not running yet. Start it with:");
        println!("       probe-rs-fleet agent --fleet {fleet}");
    }
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
        for adopt in [AdoptPolicy::Auto, AdoptPolicy::Declared] {
            let settings: crate::roles::agent::NodeSettings =
                toml::from_str(&starter_node_toml(adopt)).unwrap();
            assert!(settings.boards_path.is_none());
            assert_eq!(settings.adopt, Some(adopt));
        }
    }

    /// The scaffold has to name the command that fills it in: this file is
    /// where an operator is standing when they need it, and under `adopt =
    /// "declared"` hand-editing it is otherwise the only path.
    #[test]
    fn the_boards_scaffold_names_the_helper_verb() {
        let text = starter_boards_toml();
        assert!(text.contains("node board add"), "{text}");
        // And it must say what the helper will not do, or the first person who
        // wants to remove a board goes looking for `node board remove`.
        assert!(text.contains("APPENDS"), "{text}");
    }

    /// The scaffolded `adopt` must be the policy the node was actually enrolled
    /// with. A scaffold that always said `declared` would have an operator read
    /// the wrong answer off their own disk.
    #[test]
    fn the_scaffolded_adopt_is_not_commented_out() {
        assert!(starter_node_toml(AdoptPolicy::Auto).contains("\nadopt = \"auto\""));
        assert!(starter_node_toml(AdoptPolicy::Declared).contains("\nadopt = \"declared\""));
    }

    #[test]
    fn scaffolding_does_not_clobber_an_existing_inventory() {
        let tmp = tempfile::tempdir().unwrap();
        let node_dir = tmp.path().join("node");
        std::fs::create_dir_all(&node_dir).unwrap();
        let boards = node_dir.join("boards.toml");
        std::fs::write(&boards, "# mine\n").unwrap();

        scaffold_node_dir(&node_dir, AdoptPolicy::Auto, false).unwrap();
        assert_eq!(std::fs::read_to_string(&boards).unwrap(), "# mine\n");
        assert!(node_dir.join("node.toml").exists());
    }

    /// **`--force` must not eat a hand-written `boards.toml`.**
    ///
    /// `force` is a credential-level flag — "replace this machine's node
    /// token" — and `share --force` is the documented way to re-share a
    /// machine. `boards.toml` is now *the* place stable ids, chip names and
    /// power wiring for auto-adopted boards live, so overwriting it would
    /// destroy user data exactly when someone was trying to fix something.
    #[test]
    fn force_re_enrollment_preserves_a_hand_written_boards_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let node_dir = tmp.path().join("node");
        std::fs::create_dir_all(&node_dir).unwrap();
        let boards = node_dir.join("boards.toml");
        let mine = "[[board]]\nid = \"my-dk\"\nserial = \"ZZZ\"\nchip = \"nRF52840_xxAA\"\n";
        std::fs::write(&boards, mine).unwrap();

        scaffold_node_dir(&node_dir, AdoptPolicy::Auto, true).unwrap();

        assert_eq!(
            std::fs::read_to_string(&boards).unwrap(),
            mine,
            "--force is about the credential, not the operator's inventory"
        );
    }

    /// `node.toml` *is* rewritten under `--force`, because that is how
    /// `--adopt` is changed on an already-enrolled machine. Leaving a stale
    /// `adopt =` behind would have the file contradict the coordinator row it
    /// exists to mirror.
    #[test]
    fn force_re_enrollment_updates_the_recorded_adopt_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let node_dir = tmp.path().join("node");

        scaffold_node_dir(&node_dir, AdoptPolicy::Auto, false).unwrap();
        let settings: crate::roles::agent::NodeSettings =
            toml::from_str(&std::fs::read_to_string(node_dir.join("node.toml")).unwrap()).unwrap();
        assert_eq!(settings.adopt, Some(AdoptPolicy::Auto));

        scaffold_node_dir(&node_dir, AdoptPolicy::Declared, true).unwrap();
        let settings: crate::roles::agent::NodeSettings =
            toml::from_str(&std::fs::read_to_string(node_dir.join("node.toml")).unwrap()).unwrap();
        assert_eq!(settings.adopt, Some(AdoptPolicy::Declared));
    }
}
