//! Layering guard: `fleet-agent` must not depend on an HTTP *server* framework.
//!
//! The agent is a library that discovers probes and moves bytes over a
//! connection it dials out. It speaks `WebSocket`s through `fleet-wire`'s
//! `tokio-tungstenite` adapter; the `axum` adapter deliberately lives in
//! `fleet-coordinator` instead ([`fleet_coordinator::ws_axum`]).
//!
//! To be precise about what this test is and is not: it is a **layering** rule,
//! not what keeps the Raspberry Pi build alive. `fleet-bin` links the
//! coordinator, so axum ships on the Pi regardless. What the rule buys is that
//! the wire abstraction stays honest — the moment `fleet-agent` can reach for
//! `axum::extract::ws::WebSocket`, the `WireTx`/`WireRx` seam stops being load
//! bearing and the next transport change has to be made twice.
//!
//! The check shells out to `cargo tree`, so it is skipped when cargo is not
//! usable (a vendored or offline build), rather than failing spuriously.

use std::process::Command;

/// Crates that would mean an HTTP server framework has crept into the agent.
const FORBIDDEN: &[&str] = &["axum", "axum-core", "hyper", "hyper-util", "tower-http"];

#[test]
fn agent_does_not_depend_on_an_http_server_framework() {
    for crate_name in FORBIDDEN {
        let output = Command::new(env!("CARGO"))
            .args([
                "tree",
                "-p",
                "fleet-agent",
                "--edges",
                "normal,build",
                "-i",
                crate_name,
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output();

        let Ok(output) = output else {
            eprintln!("skipping: `cargo tree` could not be run");
            return;
        };

        // `cargo tree -i` exits non-zero when the package is not in the graph,
        // which is exactly the outcome we want.
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim().is_empty() {
                continue;
            }
            panic!(
                "fleet-agent depends on `{crate_name}`, which breaks the layering rule that \
                 keeps the WireTx/WireRx seam honest. The axum adapter belongs in \
                 fleet-coordinator (see crates/fleet-coordinator/src/ws_axum.rs).\n\n{stdout}"
            );
        }
    }
}
