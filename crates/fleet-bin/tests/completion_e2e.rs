//! Shell completion end to end, through the **real** `COMPLETE=<shell>`
//! protocol.
//!
//! The unit tests in `fleet_bin::completion` call the candidate providers
//! directly, so they never exercise the part that actually has to work: the
//! shell setting `COMPLETE`, the binary noticing before it does anything else,
//! and clap's engine mapping a half-typed command line onto our candidates.
//! That chain is a contract with `clap_complete`'s unstable dynamic engine,
//! which is exactly the kind of thing that breaks silently on an upgrade.
//!
//! So these tests spawn the **built binary** as a subprocess, the way a shell
//! does, with a scratch `XDG_CONFIG_HOME` holding known fleets and boards.
//!
//! Unix-only: the argv0 test symlinks the binary to `probe-rs`. Nothing about
//! the code under test is platform-specific.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

/// The separator the bash stub asks for between candidates.
///
/// The stub sets `IFS=$'\013'` and forwards it as `_CLAP_IFS`, so a candidate
/// containing a space survives as one word. Passing it here (rather than
/// letting it default to a newline) is what makes this test exercise the same
/// protocol the shell does.
const IFS: char = '\u{b}';

/// A scratch config tree with two fleets and two declared boards.
///
/// Deliberately concrete: the whole point of dynamic completion is that these
/// values come from the machine's own files, so the assertions below check for
/// *these* strings and would fail if the completers fell back to something
/// static.
fn config_tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("probe-rs-fleet");
    std::fs::create_dir_all(root.join("fleets")).unwrap();
    std::fs::create_dir_all(root.join("node")).unwrap();
    std::fs::write(root.join("fleets/default.toml"), "url = \"https://a\"\n").unwrap();
    std::fs::write(root.join("fleets/lab.toml"), "url = \"https://b\"\n").unwrap();
    std::fs::write(
        root.join("node/boards.toml"),
        r#"
[[board]]
id = "nrf52840-dk-1"
serial = "ABC123"
chip = "nRF52840_xxAA"
model = "nrf52840dk"
tags = ["lab", "nrf"]

[[board]]
id = "rpi-pico-2"
serial = "DEF456"
chip = "RP2040"
tags = ["lab"]
"#,
    )
    .unwrap();
    dir
}

/// Ask the binary to complete `words`, with the cursor on the last one.
///
/// This is precisely what the generated bash stub does: set `COMPLETE`, pass
/// the index of the word being completed, and hand over the words after `--`.
fn complete_with(bin: &Path, config_home: &Path, words: &[&str]) -> Vec<String> {
    let index = words.len() - 1;
    let output = Command::new(bin)
        .arg("--")
        .args(words)
        .env("COMPLETE", "bash")
        .env("_CLAP_IFS", IFS.to_string())
        .env("_CLAP_COMPLETE_INDEX", index.to_string())
        .env("XDG_CONFIG_HOME", config_home)
        // Neither completer may consult these, but a stray inherited value
        // would make a failure look like a completion bug.
        .env_remove("PROBE_RS_FLEET")
        .env_remove("PROBE_RS_FLEET_COORDINATOR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "completion request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .split(IFS)
        .map(|s| s.trim_end_matches('\n').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Path to the binary under test, as cargo built it.
fn bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_probe-rs-fleet"))
}

#[test]
fn the_shell_stub_is_emitted_for_every_supported_shell() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = Command::new(bin()).env("COMPLETE", shell).output().unwrap();
        assert!(output.status.success(), "{shell}: stub generation failed");
        let stub = String::from_utf8_lossy(&output.stdout);
        assert!(!stub.trim().is_empty(), "{shell}: empty stub");
        // The stub's whole job is to call back into us with COMPLETE set.
        assert!(
            stub.contains("COMPLETE"),
            "{shell}: stub does not re-invoke the binary"
        );
    }
}

#[test]
fn an_unknown_shell_is_refused_rather_than_guessed() {
    let output = Command::new(bin())
        .env("COMPLETE", "tcsh")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tcsh"),
        "stderr should name the shell: {stderr}"
    );
}

#[test]
fn top_level_subcommands_complete() {
    let dir = config_tree();
    let got = complete_with(bin(), dir.path(), &["probe-rs-fleet", ""]);
    for verb in [
        "coordinator",
        "node",
        "sidecar",
        "ctl",
        "login",
        "completions",
    ] {
        assert!(got.contains(&verb.to_owned()), "missing {verb} in {got:?}");
    }
}

#[test]
fn the_agent_group_completes_but_its_deprecated_subcommands_do_not() {
    // Tab teaches the vocabulary, and it should teach the current one. That cuts
    // both ways since `agent login` shipped: the *group* is now current and must
    // be offered, while the deprecated node spellings under it (`agent up`, and
    // the bare `agent` that runs a node) stay hidden — they are deployed service
    // units, so they keep parsing, but nothing should teach them.
    let dir = config_tree();
    let got = complete_with(bin(), dir.path(), &["probe-rs-fleet", ""]);
    assert!(
        got.contains(&"agent".to_owned()),
        "the agent group is current now that `agent login` exists: {got:?}"
    );

    let under_agent = complete_with(bin(), dir.path(), &["probe-rs-fleet", "agent", ""]);
    assert!(
        under_agent.contains(&"login".to_owned()),
        "`agent login` must be offered: {under_agent:?}"
    );
    assert!(
        !under_agent.contains(&"up".to_owned()),
        "the deprecated `agent up` must stay hidden: {under_agent:?}"
    );

    // ...and every spelling still runs, hidden or not.
    for argv in [
        ["agent", "--help"].as_slice(),
        ["agent", "up", "--help"].as_slice(),
    ] {
        let output = Command::new(bin())
            .args(argv)
            .env("XDG_CONFIG_HOME", dir.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{argv:?} stopped working");
    }
}

#[test]
fn fleet_flag_completes_the_fleets_this_machine_has() {
    let dir = config_tree();
    let got = complete_with(bin(), dir.path(), &["probe-rs-fleet", "ctl", "--fleet", ""]);
    assert!(got.contains(&"default".to_owned()), "{got:?}");
    assert!(got.contains(&"lab".to_owned()), "{got:?}");
}

#[test]
fn board_arguments_complete_from_boards_toml() {
    let dir = config_tree();
    let got = complete_with(bin(), dir.path(), &["probe-rs-fleet", "ctl", "release", ""]);
    assert!(got.contains(&"nrf52840-dk-1".to_owned()), "{got:?}");
    assert!(got.contains(&"rpi-pico-2".to_owned()), "{got:?}");
}

#[test]
fn a_selector_offers_prefixes_and_then_local_values() {
    let dir = config_tree();
    let got = complete_with(bin(), dir.path(), &["probe-rs-fleet", "ctl", "lease", ""]);
    for prefix in ["id=", "board=", "chip=", "tag="] {
        assert!(
            got.contains(&prefix.to_owned()),
            "missing {prefix} in {got:?}"
        );
    }
    assert!(got.contains(&"chip=nRF52840_xxAA".to_owned()), "{got:?}");
    assert!(got.contains(&"board=nrf52840dk".to_owned()), "{got:?}");
    assert!(got.contains(&"tag=lab".to_owned()), "{got:?}");

    // Once a prefix is typed, only that family survives — clap's engine filters
    // on the partial word, so this also proves the candidates carry the prefix
    // rather than being bare values.
    let narrowed = complete_with(
        bin(),
        dir.path(),
        &["probe-rs-fleet", "ctl", "lease", "chip="],
    );
    assert!(narrowed.contains(&"chip=RP2040".to_owned()), "{narrowed:?}");
    assert!(
        !narrowed.contains(&"tag=lab".to_owned()),
        "a chip= prefix should exclude tags: {narrowed:?}"
    );
}

#[test]
fn ops_complete_from_the_protocol_definition() {
    let dir = config_tree();
    let got = complete_with(
        bin(),
        dir.path(),
        &["probe-rs-fleet", "ctl", "delegate", "--ops", ""],
    );
    for op in fleet_proto::token::AllowedOp::all() {
        assert!(
            got.contains(&op.as_str().to_owned()),
            "missing {op} in {got:?}"
        );
    }
}

#[test]
fn tags_and_models_complete_from_the_declared_boards() {
    let dir = config_tree();
    let tags = complete_with(
        bin(),
        dir.path(),
        &["probe-rs-fleet", "node", "board", "add", "--tag", ""],
    );
    assert!(tags.contains(&"lab".to_owned()), "{tags:?}");
    assert!(tags.contains(&"nrf".to_owned()), "{tags:?}");

    let models = complete_with(
        bin(),
        dir.path(),
        &["probe-rs-fleet", "node", "board", "add", "--model", ""],
    );
    assert!(models.contains(&"nrf52840dk".to_owned()), "{models:?}");
}

#[test]
fn a_missing_or_malformed_boards_file_completes_to_nothing_not_an_error() {
    // A machine that has never declared a board is the common case, and a
    // half-written boards.toml is a plausible one. Neither may make Tab fail.
    let dir = tempfile::tempdir().unwrap();
    let empty = complete_with(bin(), dir.path(), &["probe-rs-fleet", "ctl", "release", ""]);
    assert!(
        !empty.iter().any(|c| c.contains("nrf")),
        "unexpected board candidates: {empty:?}"
    );

    let root = dir.path().join("probe-rs-fleet/node");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("boards.toml"), "[[board]\nid = \"broken\"\n").unwrap();
    let broken = complete_with(bin(), dir.path(), &["probe-rs-fleet", "ctl", "release", ""]);
    assert!(
        !broken.contains(&"broken".to_owned()),
        "a malformed file must yield nothing: {broken:?}"
    );
}

#[test]
fn the_probe_rs_shim_never_completes_our_flags() {
    // Invoked as `probe-rs`, the binary forwards argv verbatim to the real
    // probe-rs. Answering a completion request there would offer fleet flags
    // for somebody else's CLI.
    let dir = config_tree();
    let link_dir = tempfile::tempdir().unwrap();
    let link = link_dir.path().join("probe-rs");
    std::os::unix::fs::symlink(bin(), &link).unwrap();

    let output = Command::new(&link)
        .arg("--")
        .args(["probe-rs", ""])
        .env("COMPLETE", "bash")
        .env("_CLAP_COMPLETE_INDEX", "1")
        .env("XDG_CONFIG_HOME", dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("coordinator") && !stdout.contains("--fleet"),
        "the shim leaked fleet completions: {stdout}"
    );
}

#[test]
fn an_ordinary_run_is_unaffected_by_the_completion_hook() {
    // The hook sits in front of every invocation; it must be invisible when
    // COMPLETE is unset.
    let dir = config_tree();
    let output = Command::new(bin())
        .arg("fleets")
        .env("XDG_CONFIG_HOME", dir.path())
        .env_remove("COMPLETE")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.lines().collect::<Vec<_>>(), vec!["default", "lab"]);
}

#[test]
fn the_completions_verb_prints_an_installable_line() {
    let output = Command::new(bin())
        .args(["completions", "bash"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("source <(COMPLETE=bash probe-rs-fleet)"),
        "instructions should carry the exact line to paste: {stdout}"
    );

    // `--print` emits the stub itself, which must be the same thing the
    // COMPLETE protocol produces — a packager's copy and the self-sourced one
    // cannot be allowed to differ.
    let printed = Command::new(bin())
        .args(["completions", "zsh", "--print"])
        .output()
        .unwrap();
    assert!(printed.status.success());
    let printed = String::from_utf8_lossy(&printed.stdout);
    assert!(printed.contains("compdef"), "not a zsh stub: {printed}");
}
