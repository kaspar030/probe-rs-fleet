//! `probe-rs-fleet completions <shell>` — tell the user how to turn completion
//! on.
//!
//! Completion itself is **dynamic** (see [`crate::completion`]): the shell
//! stub calls back into this binary on every Tab. So this verb does not
//! generate a completion script — there is none to generate. It prints the one
//! line that installs the stub, and by default appends nothing anywhere:
//! editing somebody's `~/.bashrc` behind their back is not this program's
//! business.
//!
//! `--print` emits the stub itself (what `COMPLETE=<shell> probe-rs-fleet`
//! would print), for a packager who wants to ship it in
//! `/usr/share/bash-completion/completions/`. That is explicitly the
//! *discouraged* path — a shipped stub can drift out of step with the binary
//! that answers it — so it is a flag, not the default.

use std::io::Write as _;

use anyhow::{Context, Result};

use crate::cli::CompletionsArgs;
use crate::completion::CompletionShell;

/// The binary name the printed instructions refer to.
const BIN: &str = "probe-rs-fleet";

/// Print completion setup instructions, or the stub itself with `--print`.
///
/// # Errors
///
/// Returns an error only if stdout cannot be written, or if generating the
/// stub fails.
pub fn run(args: &CompletionsArgs) -> Result<()> {
    if args.print {
        return print_stub(args.shell);
    }

    let line = args.shell.install_line(BIN);
    println!("# Dynamic completion for {BIN} ({}).", args.shell.as_str());
    println!(
        "# Add this line to {} and restart your shell:",
        args.shell.rc_file()
    );
    println!();
    println!("{line}");
    println!();
    println!("# Or, to try it in this shell only, run the line above now.");
    println!(
        "# Completions are computed by {BIN} itself, so they stay correct across upgrades\n\
         # and know your local fleets, boards, chips and tags."
    );
    Ok(())
}

/// Emit the shell stub by re-invoking our own completion entry point with
/// `COMPLETE` set.
///
/// Done by calling `clap_complete`'s registration writer rather than spawning
/// ourselves: the stub is a pure function of (shell, binary name), and forking
/// a child just to set an environment variable would add a failure mode for
/// nothing.
fn print_stub(shell: CompletionShell) -> Result<()> {
    let mut buf = Vec::new();
    crate::completion::write_registration(shell, BIN, &mut buf)
        .context("generating the completion stub")?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&buf).context("writing to stdout")?;
    stdout.flush().context("flushing stdout")?;
    Ok(())
}
