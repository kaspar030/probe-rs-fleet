//! Run the frontend's JavaScript unit tests, if `node` is on `PATH`.
//!
//! The task's constraint is that `cargo build` works with no node/npm
//! installed; this file keeps `cargo test` node-free too, by skipping loudly
//! rather than failing when node is absent. The honest cost, recorded here and
//! in `docs/web-ui.md` D3: on a machine (or a future CI runner) without node,
//! that coverage silently disappears. A pipeline that ever exists should
//! install node — one line, no npm, no network. There is no `package.json` and
//! no lockfile anywhere in this repository, and the frontend modules are all
//! `.mjs`, so node needs no configuration to treat them as modules on any
//! version.
//!
//! Three details are load-bearing and were each verified against node 22:
//!
//! 1. **explicit file arguments, never a directory and never a glob string.**
//!    `node --test <dir>` resolves its argument as a *module* and fails with
//!    `Cannot find module`, i.e. a red test rather than a skip; a quoted glob
//!    relies on node's own expansion, which has moved across versions.
//!    Enumerating here depends on neither.
//! 2. **`CARGO_MANIFEST_DIR`, never a workspace-relative path.** An integration
//!    test's working directory is the *crate* directory.
//! 3. **the non-empty assertion.** Without it, a rename or a bad filter turns
//!    the whole JS suite into a silent green — the real failure mode of an
//!    optional runner.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Every `*.test.mjs` in `web-tests/`, sorted.
fn test_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("web-tests");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?;
            if name.ends_with(".test.mjs") {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    files.sort();
    files
}

#[test]
fn the_frontend_unit_tests_pass() {
    let files = test_files();
    assert!(
        !files.is_empty(),
        "web-tests/ has no *.test.mjs — the JavaScript suite silently vanished"
    );

    let mut command = Command::new("node");
    command.arg("--test");
    for file in &files {
        command.arg(file);
    }

    let output = match command.output() {
        Ok(output) => output,
        Err(e) => {
            // Not a failure: `cargo test` must not require a JavaScript
            // toolchain. Loud, so nobody reads a green run as coverage.
            println!(
                "SKIPPING the frontend JavaScript tests: could not run `node` ({e}). \
                 Install node to run {} test file(s) in crates/fleet-coordinator/web-tests/.",
                files.len()
            );
            return;
        }
    };

    assert!(
        output.status.success(),
        "node --test failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The tests must live outside the embedded tree.
///
/// `include_dir!("$CARGO_MANIFEST_DIR/web")` embeds *everything* under `web/`,
/// so a test file placed there would ship in the binary, be publicly served,
/// enter the asset hash (a test edit busting every client's cache), and trip
/// the static-analysis lints in `tests/ui_assets.rs` that it exists to assert.
/// Pinned here because the mistake is invisible at the call site.
#[test]
fn the_javascript_tests_are_not_inside_the_embedded_tree() {
    let web = Path::new(env!("CARGO_MANIFEST_DIR")).join("web");
    for file in test_files() {
        assert!(
            !file.starts_with(&web),
            "{} is inside the embedded asset tree",
            file.display()
        );
    }
}
