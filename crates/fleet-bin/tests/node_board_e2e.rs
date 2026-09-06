//! `node board add` / `node board list` end to end, through the **real**
//! `probe-rs list` shell-out.
//!
//! The unit tests in `roles::node_board` inject a `ProbeLister`, so they never
//! exercise `ProbeRsListLister` → `parse_probe_list_line` → the picker. That
//! chain is where the format of somebody else's output lives, and it is the
//! part that breaks silently when probe-rs changes its printing. Here a fake
//! `probe-rs` shell script prints probe-rs 0.32's exact lines and the command
//! is driven through its public entry point, config dir and all.
//!
//! Unix-only: the fake is a `#!/bin/sh` script. There is nothing
//! platform-specific about the code under test.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use fleet_bin::cli::{NodeBoardAddArgs, NodeBoardListArgs};

/// The one executable this file ever writes: a `sh` script that prints the
/// contents of a data file sitting beside the name it was invoked as.
///
/// Written exactly once per process, before any test can exec it. Writing a
/// fresh executable per test would race: these tests run on parallel threads,
/// and a `fork` for one test's `probe-rs` spawn inherits the write handle
/// another thread still holds open on *its* script, so the `exec` fails with
/// `ETXTBSY` ("Text file busy"). Symlinking to an already-closed master and
/// varying only a plain data file has no such window.
fn master_script() -> &'static Path {
    static MASTER: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    let (_dir, path) = MASTER.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe-rs-master");
        std::fs::write(&path, "#!/bin/sh\ncat \"$0.out\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, path)
    });
    path
}

/// A stand-in for `probe-rs` in `dir` that prints `stdout` for any arguments.
///
/// Character-for-character probe-rs 0.32's `list` output, including the
/// `" (inaccessible)"` marker, because that is the thing being tested.
fn fake_probe_rs(dir: &Path, stdout: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("fake-probe-rs");
    std::fs::write(dir.join("fake-probe-rs.out"), format!("{stdout}\n")).unwrap();
    std::os::unix::fs::symlink(master_script(), &path).unwrap();
    path
}

fn add_args(config_dir: &Path, probe_rs: &Path) -> NodeBoardAddArgs {
    NodeBoardAddArgs {
        serial: None,
        id: None,
        chip: None,
        model: None,
        tags: Vec::new(),
        no_exclusive: false,
        dry_run: false,
        interactive: false,
        // No terminal in a test harness, and none needed: every value is a flag.
        no_interactive: true,
        boards_path: None,
        config_dir: Some(config_dir.to_path_buf()),
        probe_rs: probe_rs.display().to_string(),
    }
}

const TWO_PROBES: &str = "The following debug probes were found:\n\
    [0]: J-Link -- 1366:0101:000776543210 (J-Link)\n\
    [1]: CMSIS-DAP -- 0d28:0204:001050047405 (CMSIS-DAP)";

/// The whole scriptable path: discover a probe by its real `probe-rs list`
/// line, declare it, and end up with a file the agent's own loader accepts at
/// the path `node.toml` resolution says the agent will read.
#[tokio::test]
async fn a_discovered_probe_is_declared_through_the_real_lister() {
    let tmp = tempfile::tempdir().unwrap();
    let probe_rs = fake_probe_rs(tmp.path(), TWO_PROBES);
    let config_dir = tmp.path().join("config");

    let mut args = add_args(&config_dir, &probe_rs);
    args.serial = Some("001050047405".to_owned());
    args.id = Some("nrf52840-dk-1".to_owned());
    args.chip = Some("nRF52840_xxAA".to_owned());
    args.model = Some("nrf52840dk".to_owned());
    args.tags = vec!["nrf52".to_owned()];

    fleet_bin::roles::node_board::add(&args).await.unwrap();

    let boards_path = config_dir.join("node").join("boards.toml");
    let text = std::fs::read_to_string(&boards_path).unwrap();
    let cfg = fleet_agent::config::BoardsConfig::from_str(&text).unwrap();
    cfg.validate().unwrap();
    assert_eq!(cfg.boards.len(), 1);
    assert_eq!(cfg.boards[0].id, "nrf52840-dk-1");
    assert_eq!(cfg.boards[0].serial, "001050047405");
    assert_eq!(cfg.boards[0].model.as_deref(), Some("nrf52840dk"));

    // `list` must run over the same files without erroring, which is the other
    // half of the verb group.
    fleet_bin::roles::node_board::list(&NodeBoardListArgs {
        boards_path: None,
        config_dir: Some(config_dir.clone()),
        probe_rs: probe_rs.display().to_string(),
    })
    .await
    .unwrap();

    // A second add against the same serial must be refused by the agent's own
    // validator, with the file left exactly as it was.
    let before = std::fs::read_to_string(&boards_path).unwrap();
    let mut dup = add_args(&config_dir, &probe_rs);
    dup.serial = Some("001050047405".to_owned());
    dup.id = Some("another".to_owned());
    let err = fleet_bin::roles::node_board::add(&dup).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("duplicate probe serial"),
        "{err:#}"
    );
    assert_eq!(std::fs::read_to_string(&boards_path).unwrap(), before);
}

/// A serial the fake does not print is a typo, and the error must name what is
/// actually attached rather than declaring a board that can never come online.
#[tokio::test]
async fn an_unattached_serial_is_refused_with_the_attached_ones() {
    let tmp = tempfile::tempdir().unwrap();
    let probe_rs = fake_probe_rs(tmp.path(), TWO_PROBES);
    let config_dir = tmp.path().join("config");

    let mut args = add_args(&config_dir, &probe_rs);
    args.serial = Some("NOPE".to_owned());
    args.id = Some("b1".to_owned());

    let err = fleet_bin::roles::node_board::add(&args).await.unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("NOPE"), "{text}");
    assert!(text.contains("000776543210"), "{text}");
    assert!(text.contains("001050047405"), "{text}");
    assert!(!config_dir.join("node").join("boards.toml").exists());
}

/// `boards_path` in `node.toml` is where the agent will look, so it is where
/// `add` must write — the scaffolded default must not even be created.
#[tokio::test]
async fn the_node_toml_boards_path_override_is_honoured() {
    let tmp = tempfile::tempdir().unwrap();
    let probe_rs = fake_probe_rs(tmp.path(), TWO_PROBES);
    let config_dir = tmp.path().join("config");
    let node_dir = config_dir.join("node");
    std::fs::create_dir_all(&node_dir).unwrap();
    // Absolute: nothing in this tree expands `~`, so a test using a relative
    // `~/…` would be asserting a bug.
    let elsewhere = tmp.path().join("inventory.toml");
    std::fs::write(
        node_dir.join("node.toml"),
        format!("boards_path = \"{}\"\n", elsewhere.display()),
    )
    .unwrap();

    let mut args = add_args(&config_dir, &probe_rs);
    args.serial = Some("000776543210".to_owned());
    args.id = Some("j-link-1".to_owned());
    fleet_bin::roles::node_board::add(&args).await.unwrap();

    assert!(elsewhere.exists(), "the override must be what was written");
    assert!(
        !node_dir.join("boards.toml").exists(),
        "the default path must not be created behind the override"
    );
    let cfg =
        fleet_agent::config::BoardsConfig::from_str(&std::fs::read_to_string(&elsewhere).unwrap())
            .unwrap();
    assert_eq!(cfg.boards[0].id, "j-link-1");
}

/// An inaccessible probe is declarable — the operator may be about to fix the
/// udev rule — and the parse of the `" (inaccessible)"` marker is what makes
/// the warning reachable at all.
#[tokio::test]
async fn an_inaccessible_probe_is_still_declarable() {
    let tmp = tempfile::tempdir().unwrap();
    let probe_rs = fake_probe_rs(
        tmp.path(),
        "The following debug probes were found:\n\
         [0]: J-Link -- 1366:0101:000776543210 (J-Link) (inaccessible)",
    );
    let config_dir = tmp.path().join("config");

    let mut args = add_args(&config_dir, &probe_rs);
    args.serial = Some("000776543210".to_owned());
    args.id = Some("j-link-1".to_owned());
    fleet_bin::roles::node_board::add(&args).await.unwrap();

    let text = std::fs::read_to_string(config_dir.join("node").join("boards.toml")).unwrap();
    let cfg = fleet_agent::config::BoardsConfig::from_str(&text).unwrap();
    assert_eq!(cfg.boards[0].serial, "000776543210");
}

/// A machine with nothing plugged in gets a clear "nothing to declare" rather
/// than a prompt for a serial that cannot exist.
#[tokio::test]
async fn no_probes_at_all_is_a_clear_refusal() {
    let tmp = tempfile::tempdir().unwrap();
    let probe_rs = fake_probe_rs(tmp.path(), "No debug probes were found.");
    let config_dir = tmp.path().join("config");

    let mut args = add_args(&config_dir, &probe_rs);
    args.id = Some("b1".to_owned());
    let err = fleet_bin::roles::node_board::add(&args).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("no probes are attached"),
        "{err:#}"
    );
}

/// A `probe-rs` that is not there must say so and name the flag that points at
/// one, because "command not found" from a shell-out is the least actionable
/// error this command can produce.
#[tokio::test]
async fn a_missing_probe_rs_binary_names_the_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("config");
    let mut args = add_args(&config_dir, &tmp.path().join("definitely-not-here"));
    args.id = Some("b1".to_owned());

    let err = fleet_bin::roles::node_board::add(&args).await.unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("--probe-rs"), "{text}");
}
