//! Single multi-role binary for probe-rs-fleet.
//!
//! One binary, four roles selected by clap subcommand —
//! `coordinator`, `agent`, `sidecar`, `ctl` (see `docs/architecture.md` §2).
//!
//! In addition to explicit subcommands, the binary supports **argv0 dispatch**:
//! when invoked under the name `probe-rs` (typically via a symlink on `PATH`),
//! it transparently behaves as the sidecar shim and forwards the probe-rs
//! arguments verbatim. This lets `probe-rs <args>` route through the fleet
//! without the caller knowing the difference.

mod cli;
mod config;
mod logging;
mod paths;
mod roles;
mod signal;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::main()
}
