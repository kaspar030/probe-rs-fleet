//! The shipped `examples/*.toml` must parse through the real loaders.
//!
//! An example that has drifted from the code is worse than no example: it is
//! read as documentation and copied verbatim, so the first person to use it
//! discovers a bug that looks like theirs. These are cheap and they fail the
//! moment a field is renamed.

use std::path::PathBuf;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
}

/// `examples/fleet.toml` is the reference for the per-fleet layout, and it
/// deliberately shows a laptop: both `[user]` and `[node]` populated.
#[test]
fn fleet_example_parses_with_both_tables() {
    let path = examples_dir().join("fleet.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let file: fleet_bin::fleet_config::FleetFile = toml::from_str(&text).unwrap();

    assert_eq!(file.url, "https://fleet.example.com");
    let user = file.user.expect("[user] table");
    // The org is the immutable-id-derived one, not the login: the example is
    // where people learn which of the two goes here.
    assert_eq!(user.org, "gh-4242");
    assert_eq!(user.login.as_deref(), Some("kaspar"));

    let node = file.node.expect("[node] table");
    assert_eq!(node.node_id, "gh-4242/rpi-lab-1");
    assert_eq!(node.coordinator_token_pubkey.len(), 64);
    // The two credentials are distinct values, which is the property the
    // example's prose is about.
    assert_ne!(user.session_token, node.node_token);
}

/// `examples/node.toml` is entirely commented out, so it must parse as the
/// all-defaults case the agent treats an absent file as.
#[test]
fn node_example_parses_as_all_defaults() {
    let path = examples_dir().join("node.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let settings: fleet_bin::roles::agent::NodeSettings = toml::from_str(&text).unwrap();
    assert!(settings.boards_path.is_none());
    assert!(settings.heartbeat_secs.is_none());
    assert!(!settings.erase_on_release);
}

/// `examples/coordinator.toml` must load through the real loader, including the
/// `[github]` block once uncommented — the block is the one part of it a reader
/// has to edit, so a typo there costs the most.
#[test]
fn coordinator_example_loads_and_its_github_block_works_uncommented() {
    let path = examples_dir().join("coordinator.toml");
    // The example points `signing_key_path` at a deployment path that does not
    // exist in a checkout, so swap in an inline seed. Everything else — every
    // key a reader might typo — is loaded verbatim.
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with("signing_key_path") {
                format!("signing_key_hex = \"{}\"", "ab".repeat(32))
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let cfg = fleet_bin::config::load_coordinator_config_from_str(&text).unwrap();
    cfg.validate().unwrap();
    // Commented out, so login is unconfigured — which the example says is a
    // supported deployment.
    assert!(cfg.github.is_none());

    // Uncomment the `[github]` block the way a reader would.
    let uncommented: String = text
        .lines()
        .map(|line| {
            let t = line.trim_start();
            if t.starts_with("# [github]")
                || t.starts_with("# client_id")
                || t.starts_with("# scope")
                || t.starts_with("# device_code_url")
                || t.starts_with("# access_token_url")
                || t.starts_with("# api_base")
            {
                t.trim_start_matches("# ").to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let cfg = fleet_bin::config::load_coordinator_config_from_str(&uncommented).unwrap();
    cfg.validate().unwrap();
    let gh = cfg.github.expect("[github] parsed once uncommented");
    assert_eq!(gh.client_id, "Iv1.0123456789abcdef");
    assert_eq!(gh.device_code_url, "https://github.com/login/device/code");
    assert_eq!(gh.api_base, "https://api.github.com");
}

/// `examples/boards.toml` is a full worked inventory, not a stub, so it must
/// pass the agent's validation as well as its parser.
#[test]
fn boards_example_parses_and_validates() {
    let path = examples_dir().join("boards.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let boards = fleet_agent::config::BoardsConfig::from_str(&text).unwrap();
    boards.validate().unwrap();
    assert!(!boards.boards.is_empty());
}

/// The deleted files must stay deleted: leaving them would send a reader
/// straight back to the layout revision 2 replaced.
#[test]
fn the_superseded_examples_are_gone() {
    assert!(!examples_dir().join("client.toml").exists());
    assert!(!examples_dir().join("agent.toml").exists());
}
