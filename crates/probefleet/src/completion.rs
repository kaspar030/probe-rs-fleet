//! Shell completion, computed at runtime by the binary itself.
//!
//! # Why dynamic rather than a generated script
//!
//! `clap_complete` offers two shapes. The classic one (`aot`) emits a static
//! script per shell, which the user installs; the script knows the flags that
//! existed when it was generated and nothing else. The dynamic one — used here
//! — installs a *stub* that calls back into `probe-rs-fleet` on every Tab, with
//! the shell's current word buffer, and this process answers.
//!
//! For this CLI the second is the only one that can be correct, because the
//! interesting completions are not static:
//!
//! * `--fleet <name>` completes the fleets **this machine has a config for**
//!   (`~/.config/probe-rs-fleet/fleets/*.toml`);
//! * `ctl release <board>` / `node board add --serial` complete from local
//!   state (`boards.toml`, attached probes);
//! * `--ops` completes the op labels [`probefleet_proto::token::AllowedOp`] actually
//!   defines, so adding an op cannot leave a stale script behind.
//!
//! A generated script would freeze all of that at build time.
//!
//! # Activation
//!
//! Completion is driven by the `COMPLETE` environment variable, which the shell
//! stub sets: `COMPLETE=bash probe-rs-fleet` prints the registration script,
//! and thereafter each Tab re-enters the binary with `COMPLETE=<shell>` and the
//! current words. [`try_complete`] must therefore run **before any other
//! output**, and before the tokio runtime is built — it exits the process when
//! it handles a request.
//!
//! Users install it with, e.g.:
//!
//! ```bash
//! echo 'source <(COMPLETE=bash probe-rs-fleet)' >> ~/.bashrc
//! ```
//!
//! `probe-rs-fleet completions <shell>` prints that one-liner (see
//! [`crate::roles::completions`]) rather than making people remember it.
//!
//! # The `probe-rs` argv0 shim is deliberately excluded
//!
//! Invoked as `probe-rs`, this binary forwards every argument verbatim to the
//! real probe-rs (`cli::dispatch_from_argv0`). Completing *our* flags there
//! would be actively wrong — the arguments are not ours — so [`try_complete`]
//! is only called on the clap path.

use std::ffi::OsStr;

use clap::CommandFactory as _;
use clap_complete::engine::{ArgValueCandidates, CompletionCandidate};
use clap_complete::CompleteEnv;

/// Handle a completion request if the shell made one.
///
/// Returns `true` when a request was handled and the process should exit
/// successfully; `false` for an ordinary run, in which case nothing was
/// printed.
///
/// Not `complete()` (which would `exit(0)` itself): `cli::main` owns the exit
/// code path, and a function that sometimes never returns is worse to reason
/// about than one that reports what happened.
pub fn try_complete<I, T>(args: I) -> bool
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString>,
{
    let current_dir = std::env::current_dir().ok();
    CompleteEnv::with_factory(crate::cli::Cli::command)
        .try_complete(args, current_dir.as_deref())
        .unwrap_or_else(|e| e.exit())
}

/// The shells the dynamic completer supports, for `completions <shell>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CompletionShell {
    /// GNU bash.
    Bash,
    /// Z shell.
    Zsh,
    /// fish.
    Fish,
    /// Elvish.
    Elvish,
    /// PowerShell.
    Powershell,
}

impl CompletionShell {
    /// The value the shell stub must set `COMPLETE` to.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CompletionShell::Bash => "bash",
            CompletionShell::Zsh => "zsh",
            CompletionShell::Fish => "fish",
            CompletionShell::Elvish => "elvish",
            CompletionShell::Powershell => "powershell",
        }
    }

    /// The line to add to the shell's startup file.
    ///
    /// Sourcing the stub afresh on every shell start, rather than writing a
    /// generated file once, is what `clap_complete` recommends and what keeps
    /// the stub and the binary from drifting apart across an upgrade: the
    /// protocol between them is not stable.
    #[must_use]
    pub fn install_line(self, bin: &str) -> String {
        match self {
            CompletionShell::Bash => format!("source <(COMPLETE=bash {bin})"),
            CompletionShell::Zsh => format!("source <(COMPLETE=zsh {bin})"),
            CompletionShell::Fish => format!("COMPLETE=fish {bin} | source"),
            CompletionShell::Elvish => format!("eval (E:COMPLETE=elvish {bin} | slurp)"),
            CompletionShell::Powershell => format!(
                "$env:COMPLETE = \"powershell\"; {bin} | Out-String | Invoke-Expression; \
                 Remove-Item Env:\\COMPLETE"
            ),
        }
    }

    /// Where that line belongs.
    #[must_use]
    pub fn rc_file(self) -> &'static str {
        match self {
            CompletionShell::Bash => "~/.bashrc",
            CompletionShell::Zsh => "~/.zshrc",
            CompletionShell::Fish => "~/.config/fish/completions/probe-rs-fleet.fish",
            CompletionShell::Elvish => "~/.elvish/rc.elv",
            CompletionShell::Powershell => "$PROFILE",
        }
    }
}

// --- dynamic candidate sources ----------------------------------------------
//
// Every one of these runs inside a Tab keypress, so each is written to be
// *fast* and *silent*: local files only, never a network call to the
// coordinator, and any error becomes an empty candidate list. A completer that
// blocks on an unreachable coordinator would hang the user's terminal, and one
// that prints a diagnostic would corrupt the completion stream.

/// Candidates for `--fleet`: the fleets this machine has a config file for.
#[must_use]
pub fn fleet_candidates() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        crate::paths::list_fleets()
            .unwrap_or_default()
            .into_iter()
            .map(CompletionCandidate::new)
            .collect()
    })
}

/// Candidates for an operation list (`--ops`), comma-separated.
///
/// The completed word is the whole `flash,attach` list, so each candidate
/// carries the prefix already typed and only the final element varies. Ops
/// already named are dropped: offering `flash,flash` is noise.
#[must_use]
pub fn ops_candidates() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        probefleet_proto::token::AllowedOp::all()
            .into_iter()
            .map(|op| CompletionCandidate::new(op.as_str()))
            .collect()
    })
}

/// Candidates for a board reference: the ids declared in this machine's
/// `boards.toml`.
///
/// Node-local, and therefore partial by construction — it cannot know about
/// boards on other nodes or ones shared with you, which live coordinator-side.
/// Offering the local ones is still worth it: they are what an operator running
/// `ctl release` / `node board` on their own machine types most, and a
/// completion that is a subset is a help, whereas one that dials the network on
/// Tab is a hazard.
#[must_use]
pub fn board_id_candidates() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        local_board_ids()
            .into_iter()
            .map(CompletionCandidate::new)
            .collect()
    })
}

/// Candidates for a board **selector** (`id=…`, `board=…`, `chip=…`, `tag=…`).
///
/// Offers the selector prefixes, then — once a prefix is typed — the local
/// values for it. `chip=nRF` completing to the chips actually declared here is
/// the difference between the flag being usable and being a spelling test.
#[must_use]
pub fn selector_candidates() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        let boards = local_boards();
        let mut out = Vec::new();
        for (prefix, help) in [
            ("id=", "one specific board, by node-local name"),
            ("board=", "any idle board of a model"),
            ("chip=", "any idle board with a probe-rs target"),
            ("tag=", "any idle board carrying a tag"),
        ] {
            out.push(CompletionCandidate::new(prefix).help(Some(help.into())));
        }
        for board in &boards {
            out.push(CompletionCandidate::new(format!("id={}", board.id)));
        }
        let mut models: Vec<&str> = boards
            .iter()
            .filter_map(|b| b.model.as_deref())
            .filter(|m| !m.is_empty())
            .collect();
        models.sort_unstable();
        models.dedup();
        for model in models {
            out.push(CompletionCandidate::new(format!("board={model}")));
        }
        let mut chips: Vec<&str> = boards
            .iter()
            .map(|b| b.chip.as_str())
            .filter(|c| !c.is_empty())
            .collect();
        chips.sort_unstable();
        chips.dedup();
        for chip in chips {
            out.push(CompletionCandidate::new(format!("chip={chip}")));
        }
        let mut tags: Vec<&str> = boards
            .iter()
            .flat_map(|b| b.tags.iter())
            .map(String::as_str)
            .collect();
        tags.sort_unstable();
        tags.dedup();
        for tag in tags {
            out.push(CompletionCandidate::new(format!("tag={tag}")));
        }
        out
    })
}

/// Candidates for `--chip`: the probe-rs targets declared locally.
#[must_use]
pub fn chip_candidates() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        let mut chips: Vec<String> = local_boards()
            .into_iter()
            .map(|b| b.chip)
            .filter(|c| !c.is_empty())
            .collect();
        chips.sort_unstable();
        chips.dedup();
        chips.into_iter().map(CompletionCandidate::new).collect()
    })
}

/// Candidates for a board **model** (`--model`, `--board`).
#[must_use]
pub fn model_candidates() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        let mut models: Vec<String> = local_boards().into_iter().filter_map(|b| b.model).collect();
        models.sort_unstable();
        models.dedup();
        models.into_iter().map(CompletionCandidate::new).collect()
    })
}

/// Candidates for `--tag`: the tags already used by this machine's boards.
///
/// Tags are free-form, so this cannot be exhaustive; it exists to stop the
/// third board in a lab acquiring `nrf52` when the other two say `nrf-52`.
#[must_use]
pub fn tag_candidates() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        let mut tags: Vec<String> = local_boards().into_iter().flat_map(|b| b.tags).collect();
        tags.sort_unstable();
        tags.dedup();
        tags.into_iter().map(CompletionCandidate::new).collect()
    })
}

/// Candidates for `node board add --serial`: probes physically attached to
/// this machine that are **not declared yet**.
///
/// The one completer here that shells out (`probe-rs list`), because a serial
/// is a long opaque string nobody should retype from a sticker, and no file on
/// disk knows it before the board is declared. It is therefore hard-bounded by
/// [`PROBE_LIST_TIMEOUT`]: a missing or wedged `probe-rs` costs the user that
/// long and then yields nothing, rather than hanging their terminal.
///
/// Already-declared serials are filtered out: this flag exists to declare a
/// board that has none, and re-offering a taken serial only leads to the
/// duplicate-serial error `BoardsConfig::validate` raises.
#[must_use]
pub fn probe_serial_candidates() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        let declared: Vec<String> = local_boards().into_iter().map(|b| b.serial).collect();
        attached_probes()
            .into_iter()
            .filter(|p| !declared.iter().any(|s| s == &p.serial))
            .map(|probe| {
                let help = probe.product.clone().map(Into::into);
                CompletionCandidate::new(probe.serial).help(help)
            })
            .collect()
    })
}

/// How long a completer may wait for `probe-rs list` before giving up.
///
/// Short on purpose: this is spent inside a Tab keypress.
const PROBE_LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Probes currently attached, or none if enumeration fails or is too slow.
///
/// Builds its own single-threaded runtime: the completion hook runs before
/// `cli::main` creates the real one, and a current-thread runtime for one
/// bounded subprocess is cheaper than moving the hook after runtime setup
/// (which would put runtime-init errors ahead of the shell's stdout).
fn attached_probes() -> Vec<probefleet_proto::node_api::DiscoveredProbe> {
    use probefleet_agent::discovery::{ProbeLister as _, ProbeRsListLister};

    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Vec::new();
    };
    let lister = ProbeRsListLister::default();
    runtime
        .block_on(async {
            tokio::time::timeout(PROBE_LIST_TIMEOUT, lister.list_probes())
                .await
                .ok()
                .and_then(Result::ok)
        })
        .unwrap_or_default()
}

/// The boards declared in this machine's `boards.toml`, or none.
///
/// Silent on every failure (no node config, malformed file, unreadable path):
/// this runs on a keypress, and the only sane response to "I cannot tell" is to
/// offer nothing.
fn local_boards() -> Vec<probefleet_agent::config::BoardSpec> {
    let Ok(node_dir) = crate::paths::node_config_dir() else {
        return Vec::new();
    };
    let Ok(path) = crate::roles::node_run::resolve_boards_path(&node_dir, None) else {
        return Vec::new();
    };
    probefleet_agent::config::BoardsConfig::from_path(&path)
        .map(|cfg| cfg.boards)
        .unwrap_or_default()
}

/// Just the ids from [`local_boards`], sorted.
fn local_board_ids() -> Vec<String> {
    let mut ids: Vec<String> = local_boards().into_iter().map(|b| b.id).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Write the shell stub for `shell` (what `COMPLETE=<shell> probe-rs-fleet`
/// prints) into `buf`.
///
/// Backs `completions --print`. The stub is a function of (shell, binary name)
/// only — it contains no knowledge of our flags, which is the whole point of
/// the dynamic scheme.
///
/// # Errors
///
/// Propagates a write failure from `buf`.
pub fn write_registration(
    shell: CompletionShell,
    bin: &str,
    buf: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    use clap_complete::env::{Bash, Elvish, EnvCompleter, Fish, Powershell, Zsh};

    let completer: &dyn EnvCompleter = match shell {
        CompletionShell::Bash => &Bash,
        CompletionShell::Zsh => &Zsh,
        CompletionShell::Fish => &Fish,
        CompletionShell::Elvish => &Elvish,
        CompletionShell::Powershell => &Powershell,
    };
    // `name` is the identifier the script uses internally; `bin` the command
    // being completed; `completer` the command to call back into. All three
    // are this binary: the shim name `probe-rs` is deliberately never
    // registered (see the module docs).
    completer.write_registration("COMPLETE", bin, bin, bin, buf)
}

/// Whether `name` names a shell the dynamic completer knows, for diagnostics.
#[must_use]
pub fn is_known_shell(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some("bash" | "zsh" | "fish" | "elvish" | "powershell")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_lines_name_the_binary_and_shell() {
        assert_eq!(
            CompletionShell::Bash.install_line("probe-rs-fleet"),
            "source <(COMPLETE=bash probe-rs-fleet)"
        );
        assert!(CompletionShell::Fish
            .install_line("probe-rs-fleet")
            .starts_with("COMPLETE=fish probe-rs-fleet"));
        assert!(CompletionShell::Powershell
            .install_line("probe-rs-fleet")
            .contains("powershell"));
    }

    #[test]
    fn every_shell_has_an_rc_file_and_a_complete_value() {
        for shell in [
            CompletionShell::Bash,
            CompletionShell::Zsh,
            CompletionShell::Fish,
            CompletionShell::Elvish,
            CompletionShell::Powershell,
        ] {
            assert!(!shell.rc_file().is_empty());
            assert!(is_known_shell(OsStr::new(shell.as_str())));
            assert!(shell.install_line("bin").contains(shell.as_str()));
        }
    }

    #[test]
    fn ops_candidates_cover_every_allowed_op() {
        let got: Vec<String> = ops_candidates()
            .candidates()
            .into_iter()
            .map(|c| c.get_value().to_string_lossy().into_owned())
            .collect();
        for op in probefleet_proto::token::AllowedOp::all() {
            assert!(got.contains(&op.as_str().to_owned()), "missing {op}");
        }
    }

    #[test]
    fn selector_candidates_always_offer_the_prefixes() {
        let got: Vec<String> = selector_candidates()
            .candidates()
            .into_iter()
            .map(|c| c.get_value().to_string_lossy().into_owned())
            .collect();
        for prefix in ["id=", "board=", "chip=", "tag="] {
            assert!(got.contains(&prefix.to_owned()), "missing {prefix}");
        }
    }

    #[test]
    fn no_completion_request_means_no_output_and_a_normal_run() {
        // With COMPLETE unset, `try_complete` must be a no-op: the binary's
        // ordinary argv path has to survive the completion hook sitting in
        // front of it.
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var_os("COMPLETE");
        // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
        std::env::remove_var("COMPLETE");
        assert!(!try_complete(["probe-rs-fleet", "ctl", "list"]));
        if let Some(prev) = prev {
            std::env::set_var("COMPLETE", prev);
        }
    }
}
