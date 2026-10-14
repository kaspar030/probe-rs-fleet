//! Parsing of the vanilla `probe-rs` CLI surface that laze invokes.
//!
//! The sidecar presents a *vanilla* probe-rs CLI so that `ariel-os`/`laze`
//! invoke it unmodified (see `docs/architecture.md` §4.3). We do not
//! re-implement probe-rs — we only need to understand each invocation well
//! enough to:
//!
//! * extract the `--chip <name>` selector (the only board selector laze
//!   passes; it flows through to the real client untouched), and
//! * recognise the long-lived / streaming shapes (`attach`, `gdb`, `run`) so
//!   the session driver knows how to behave, and
//! * preserve *every* original argument — including unknown flags and the
//!   `$@` passthrough laze appends — so we can hand the genuine probe-rs
//!   client an unaltered argv.
//!
//! Ground truth (from `ariel-os/laze-project.yml`), the shapes we must handle:
//!
//! ```text
//! probe-rs run ${PROTOCOL} --chip ${CHIP} --preverify <elf>   # flash+RTT+embedded-test; exit code == test result
//! probe-rs download --chip <C> <elf>                          # flash
//! probe-rs reset --chip <C>
//! probe-rs erase --chip <C> --allow-erase-all
//! probe-rs attach --chip <C> <elf>                            # long-lived RTT
//! probe-rs gdb --chip <C>                                     # long-lived gdb TCP server
//! ```
//!
//! Anything else (e.g. `probe-rs debug …`, `probe-rs list`, `--version`) is
//! captured as [`ProbeRsInvocation::Passthrough`] and forwarded verbatim.

use std::ffi::OsString;

/// A parsed probe-rs invocation.
///
/// Every variant keeps an `extra: Vec<String>` of arguments we did not
/// individually model (unknown flags, the trailing `$@`, protocol tokens,
/// etc.) so the original argv can be faithfully reconstructed for the genuine
/// probe-rs client. The `--chip` value is lifted out where present because the
/// fleet selector / board lease keys off it, but it is *also* preserved so the
/// reconstructed argv is byte-for-byte equivalent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeRsInvocation {
    /// `probe-rs run [PROTOCOL] --chip <C> [--preverify] <elf>`.
    ///
    /// Flash + RTT + embedded-test. The process exit code is the test result
    /// and MUST be propagated.
    Run {
        chip: Option<String>,
        elf: Option<String>,
        preverify: bool,
        extra: Vec<String>,
    },
    /// `probe-rs download --chip <C> <elf>` — flash firmware.
    Download {
        chip: Option<String>,
        elf: Option<String>,
        extra: Vec<String>,
    },
    /// `probe-rs reset --chip <C>` — reset the target.
    Reset {
        chip: Option<String>,
        extra: Vec<String>,
    },
    /// `probe-rs erase --chip <C> --allow-erase-all` — erase flash.
    Erase {
        chip: Option<String>,
        allow_erase_all: bool,
        extra: Vec<String>,
    },
    /// `probe-rs attach --chip <C> <elf>` — long-lived RTT stream.
    Attach {
        chip: Option<String>,
        elf: Option<String>,
        extra: Vec<String>,
    },
    /// `probe-rs gdb --chip <C> [--gdb-connection-string <addr>]` — long-lived
    /// local gdb TCP server. Not remote-capable in probe-rs 0.32, so the fleet
    /// path tunnels raw gdbremote TCP as a second relay channel: the sidecar
    /// opens a local listener (default `127.0.0.1:1337`, overridable via
    /// `--gdb-connection-string`) the user's gdb client connects to (see the
    /// `gdb` module).
    Gdb {
        chip: Option<String>,
        /// The local address the sidecar should listen on for the user's gdb
        /// client, parsed from `--gdb-connection-string`. `None` ⇒ default
        /// `127.0.0.1:1337`.
        connection_string: Option<String>,
        extra: Vec<String>,
    },
    /// Any invocation we do not individually model. Forwarded verbatim.
    Passthrough { argv: Vec<String> },
}

/// Errors that can arise while parsing a probe-rs argv.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliError {
    /// An argument was not valid UTF-8. probe-rs argv is always UTF-8 in
    /// practice (chip names, ELF paths), so we reject non-UTF-8 cleanly rather
    /// than guess.
    #[error("argument {0} is not valid UTF-8")]
    NonUtf8Argument(usize),
}

impl ProbeRsInvocation {
    /// The `--chip` board selector, if this invocation carries one.
    #[must_use]
    pub fn chip(&self) -> Option<&str> {
        match self {
            Self::Run { chip, .. }
            | Self::Download { chip, .. }
            | Self::Reset { chip, .. }
            | Self::Erase { chip, .. }
            | Self::Attach { chip, .. }
            | Self::Gdb { chip, .. } => chip.as_deref(),
            Self::Passthrough { .. } => None,
        }
    }

    /// Whether this invocation is long-lived / streaming (`run`, `attach`,
    /// `gdb`). One-shot commands (`download`, `reset`, `erase`) return
    /// promptly; streaming ones hold the session open and stream stdout.
    #[must_use]
    pub fn is_streaming(&self) -> bool {
        matches!(
            self,
            Self::Run { .. } | Self::Attach { .. } | Self::Gdb { .. }
        )
    }
}

/// Parse a full probe-rs argv (including `argv[0]`) into a [`ProbeRsInvocation`].
///
/// `args` is the complete process argv: the first element is the program name
/// (e.g. `probe-rs`) and is ignored for subcommand dispatch but preserved in
/// the [`ProbeRsInvocation::Passthrough`] case so the original argv round-trips.
///
/// # Errors
///
/// Returns [`CliError::NonUtf8Argument`] if any argument is not valid UTF-8.
pub fn parse<I, S>(args: I) -> Result<ProbeRsInvocation, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let tokens: Vec<String> = args
        .into_iter()
        .enumerate()
        .map(|(i, s)| {
            s.into()
                .into_string()
                .map_err(|_| CliError::NonUtf8Argument(i))
        })
        .collect::<Result<_, _>>()?;

    // tokens[0] is the program name; the subcommand is tokens[1].
    let Some(subcommand) = tokens.get(1) else {
        return Ok(ProbeRsInvocation::Passthrough { argv: tokens });
    };

    match subcommand.as_str() {
        "run" => Ok(parse_run(&tokens[2..])),
        "download" => Ok(parse_download(&tokens[2..])),
        "reset" => Ok(parse_reset(&tokens[2..])),
        "erase" => Ok(parse_erase(&tokens[2..])),
        "attach" => Ok(parse_attach(&tokens[2..])),
        "gdb" => Ok(parse_gdb(&tokens[2..])),
        _ => Ok(ProbeRsInvocation::Passthrough { argv: tokens }),
    }
}

/// Pull the value of a `--chip` option (in either `--chip X` or `--chip=X`
/// form) out of the remaining argument stream, pushing everything else into
/// `extra`. Returns the collected positional (non-flag) arguments separately so
/// callers can recover the ELF path.
struct ArgScan {
    chip: Option<String>,
    positionals: Vec<String>,
    extra: Vec<String>,
}

/// Generic scanner: extracts `--chip` (returned in [`ArgScan::chip`]), records
/// named boolean flags found in `bool_flags` (consumed, returned separately),
/// and splits the remaining tokens into positionals (returned in
/// [`ArgScan::positionals`]) vs. unmodelled tokens such as unknown flags and
/// their values (returned in [`ArgScan::extra`]). Callers rebuild a faithful
/// argv from these typed parts, so `extra` holds only the truly unmodelled
/// tokens.
fn scan(args: &[String], bool_flags: &[&str]) -> (ArgScan, Vec<String>) {
    let mut chip = None;
    let mut positionals = Vec::new();
    let mut extra = Vec::new();
    let mut found_bool = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--chip" {
            if let Some(value) = args.get(i + 1) {
                chip = Some(value.clone());
                i += 2;
                continue;
            }
            // Dangling `--chip` with no value: keep it as extra.
            extra.push(arg.clone());
            i += 1;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--chip=") {
            chip = Some(value.to_owned());
            i += 1;
            continue;
        }
        if bool_flags.contains(&arg.as_str()) {
            found_bool.push(arg.clone());
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            // Unknown flag: preserve verbatim. We do not know its arity, so we
            // keep it as a standalone token; any value it consumes will appear
            // as the next token (also preserved). This is sufficient because we
            // never need to *interpret* unknown flags — only round-trip them.
            extra.push(arg.clone());
            i += 1;
            continue;
        }
        positionals.push(arg.clone());
        i += 1;
    }

    (
        ArgScan {
            chip,
            positionals,
            extra,
        },
        found_bool,
    )
}

fn parse_run(args: &[String]) -> ProbeRsInvocation {
    // `run [PROTOCOL] --chip <C> [--preverify] <elf>`. PROTOCOL (e.g. `swd`)
    // and the ELF are both positionals. In laze's emitted shapes the ELF is
    // the last *known* positional, but a trailing `$@` may append further
    // positional-looking tokens (e.g. an unknown flag's value). We treat the
    // ELF as the FIRST positional after the protocol token, and keep the rest
    // (protocol + any `$@` leftovers) in `extra`. probe-rs disambiguates the
    // protocol itself; we only need a faithful round-trip plus the `--chip`.
    let (scan, found_bool) = scan(args, &["--preverify"]);
    let preverify = found_bool.iter().any(|f| f == "--preverify");
    let (elf, others) = split_elf(scan.positionals);
    let mut extra = scan.extra;
    extra.extend(others);
    ProbeRsInvocation::Run {
        chip: scan.chip,
        elf,
        preverify,
        extra,
    }
}

fn parse_download(args: &[String]) -> ProbeRsInvocation {
    let (scan, _) = scan(args, &[]);
    let (elf, leading) = split_elf(scan.positionals);
    let mut extra = scan.extra;
    extra.extend(leading);
    ProbeRsInvocation::Download {
        chip: scan.chip,
        elf,
        extra,
    }
}

fn parse_reset(args: &[String]) -> ProbeRsInvocation {
    let (scan, _) = scan(args, &[]);
    let mut extra = scan.extra;
    extra.extend(scan.positionals);
    ProbeRsInvocation::Reset {
        chip: scan.chip,
        extra,
    }
}

fn parse_erase(args: &[String]) -> ProbeRsInvocation {
    let (scan, found_bool) = scan(args, &["--allow-erase-all"]);
    let allow_erase_all = found_bool.iter().any(|f| f == "--allow-erase-all");
    let mut extra = scan.extra;
    extra.extend(scan.positionals);
    ProbeRsInvocation::Erase {
        chip: scan.chip,
        allow_erase_all,
        extra,
    }
}

fn parse_attach(args: &[String]) -> ProbeRsInvocation {
    let (scan, _) = scan(args, &[]);
    let (elf, leading) = split_elf(scan.positionals);
    let mut extra = scan.extra;
    extra.extend(leading);
    ProbeRsInvocation::Attach {
        chip: scan.chip,
        elf,
        extra,
    }
}

fn parse_gdb(args: &[String]) -> ProbeRsInvocation {
    // Pull `--gdb-connection-string <addr>` / `--gdb-connection-string=<addr>`
    // out of the stream: in the fleet path it configures the sidecar's *local*
    // listener and is NOT forwarded to the agent (the agent picks its own
    // ephemeral loopback port). Everything else round-trips via the scanner.
    let (connection_string, rest) = extract_value_flag(args, "--gdb-connection-string");
    let (scan, _) = scan(&rest, &[]);
    let mut extra = scan.extra;
    extra.extend(scan.positionals);
    ProbeRsInvocation::Gdb {
        chip: scan.chip,
        connection_string,
        extra,
    }
}

/// Extract a `--flag <value>` / `--flag=<value>` option from `args`, returning
/// its value (if present) and the remaining args with the flag removed. The
/// first occurrence wins; later occurrences are left in the remainder.
fn extract_value_flag(args: &[String], flag: &str) -> (Option<String>, Vec<String>) {
    let eq_prefix = format!("{flag}=");
    let mut value = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if value.is_none() && arg == flag {
            if let Some(v) = args.get(i + 1) {
                value = Some(v.clone());
                i += 2;
                continue;
            }
            // Dangling flag with no value: drop it (no value to capture).
            i += 1;
            continue;
        }
        if value.is_none() {
            if let Some(v) = arg.strip_prefix(&eq_prefix) {
                value = Some(v.to_owned());
                i += 1;
                continue;
            }
        }
        rest.push(arg.clone());
        i += 1;
    }
    (value, rest)
}

/// Treat the ELF path as the positional that looks like a path (ends in an
/// ELF-ish extension or contains a path separator), falling back to the first
/// positional. Returns the ELF plus the remaining positionals (e.g. a `run`
/// protocol token, or `$@` leftovers) in their original order.
///
/// We deliberately do not assume a fixed position: laze prepends a protocol
/// token to `run` and appends `$@` to every shape, so neither "first" nor
/// "last" is reliable. Matching the ELF by shape is robust for the real
/// invocations and keeps every other token in `extra` for a faithful argv
/// round-trip.
fn split_elf(positionals: Vec<String>) -> (Option<String>, Vec<String>) {
    let elf_idx =
        positionals
            .iter()
            .position(|p| looks_like_elf(p))
            .or(if positionals.is_empty() {
                None
            } else {
                Some(0)
            });
    match elf_idx {
        Some(idx) => {
            let mut rest = positionals;
            let elf = rest.remove(idx);
            (Some(elf), rest)
        }
        None => (None, positionals),
    }
}

/// Heuristic: does this positional look like a firmware path (an ELF the
/// command operates on) rather than a bare token like a protocol or a numeric
/// flag value?
fn looks_like_elf(arg: &str) -> bool {
    if arg.contains('/') || arg.contains('\\') {
        return true;
    }
    std::path::Path::new(arg)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            ["elf", "bin", "hex", "axf"]
                .iter()
                .any(|known| ext.eq_ignore_ascii_case(known))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(args: &[&str]) -> ProbeRsInvocation {
        parse(args.iter().map(|s| (*s).to_owned())).unwrap()
    }

    #[test]
    fn parses_run_with_protocol_preverify_and_chip() {
        // probe-rs run swd --chip nRF52840_xxAA --preverify firmware.elf
        let inv = parse_str(&[
            "probe-rs",
            "run",
            "swd",
            "--chip",
            "nRF52840_xxAA",
            "--preverify",
            "firmware.elf",
        ]);
        assert_eq!(
            inv,
            ProbeRsInvocation::Run {
                chip: Some("nRF52840_xxAA".to_owned()),
                elf: Some("firmware.elf".to_owned()),
                preverify: true,
                extra: vec!["swd".to_owned()],
            }
        );
        assert_eq!(inv.chip(), Some("nRF52840_xxAA"));
        assert!(inv.is_streaming());
    }

    #[test]
    fn parses_run_chip_eq_form() {
        let inv = parse_str(&["probe-rs", "run", "--chip=STM32F407", "fw.elf"]);
        assert_eq!(inv.chip(), Some("STM32F407"));
        let ProbeRsInvocation::Run { elf, preverify, .. } = inv else {
            panic!("expected Run");
        };
        assert_eq!(elf.as_deref(), Some("fw.elf"));
        assert!(!preverify);
    }

    #[test]
    fn parses_download() {
        let inv = parse_str(&["probe-rs", "download", "--chip", "nrf52", "app.elf"]);
        assert_eq!(
            inv,
            ProbeRsInvocation::Download {
                chip: Some("nrf52".to_owned()),
                elf: Some("app.elf".to_owned()),
                extra: vec![],
            }
        );
        assert!(!inv.is_streaming());
    }

    #[test]
    fn parses_reset() {
        let inv = parse_str(&["probe-rs", "reset", "--chip", "nrf52"]);
        assert_eq!(
            inv,
            ProbeRsInvocation::Reset {
                chip: Some("nrf52".to_owned()),
                extra: vec![],
            }
        );
    }

    #[test]
    fn parses_erase_with_allow_erase_all() {
        let inv = parse_str(&["probe-rs", "erase", "--chip", "nrf52", "--allow-erase-all"]);
        assert_eq!(
            inv,
            ProbeRsInvocation::Erase {
                chip: Some("nrf52".to_owned()),
                allow_erase_all: true,
                extra: vec![],
            }
        );
    }

    #[test]
    fn parses_attach() {
        let inv = parse_str(&["probe-rs", "attach", "--chip", "nrf52", "app.elf"]);
        assert_eq!(
            inv,
            ProbeRsInvocation::Attach {
                chip: Some("nrf52".to_owned()),
                elf: Some("app.elf".to_owned()),
                extra: vec![],
            }
        );
        assert!(inv.is_streaming());
    }

    #[test]
    fn parses_gdb() {
        let inv = parse_str(&["probe-rs", "gdb", "--chip", "nrf52"]);
        assert_eq!(
            inv,
            ProbeRsInvocation::Gdb {
                chip: Some("nrf52".to_owned()),
                connection_string: None,
                extra: vec![],
            }
        );
        assert!(inv.is_streaming());
    }

    #[test]
    fn parses_gdb_connection_string_and_keeps_it_out_of_extra() {
        let inv = parse_str(&[
            "probe-rs",
            "gdb",
            "--chip",
            "nrf52",
            "--gdb-connection-string",
            "127.0.0.1:3333",
        ]);
        let ProbeRsInvocation::Gdb {
            chip,
            connection_string,
            extra,
        } = inv
        else {
            panic!("expected Gdb");
        };
        assert_eq!(chip.as_deref(), Some("nrf52"));
        assert_eq!(connection_string.as_deref(), Some("127.0.0.1:3333"));
        // The flag is consumed, not forwarded as passthrough.
        assert!(!extra.iter().any(|a| a == "--gdb-connection-string"));
        assert!(!extra.iter().any(|a| a == "127.0.0.1:3333"));
    }

    #[test]
    fn parses_gdb_connection_string_eq_form() {
        let inv = parse_str(&[
            "probe-rs",
            "gdb",
            "--chip",
            "nrf52",
            "--gdb-connection-string=0.0.0.0:1337",
        ]);
        let ProbeRsInvocation::Gdb {
            connection_string, ..
        } = inv
        else {
            panic!("expected Gdb");
        };
        assert_eq!(connection_string.as_deref(), Some("0.0.0.0:1337"));
    }

    #[test]
    fn unknown_subcommand_is_passthrough() {
        let inv = parse_str(&["probe-rs", "debug", "--chip", "nrf52", "--exe", "app.elf"]);
        assert_eq!(
            inv,
            ProbeRsInvocation::Passthrough {
                argv: vec![
                    "probe-rs".to_owned(),
                    "debug".to_owned(),
                    "--chip".to_owned(),
                    "nrf52".to_owned(),
                    "--exe".to_owned(),
                    "app.elf".to_owned(),
                ],
            }
        );
        assert_eq!(inv.chip(), None);
        assert!(!inv.is_streaming());
    }

    #[test]
    fn no_subcommand_is_passthrough() {
        let inv = parse_str(&["probe-rs", "--version"]);
        assert_eq!(
            inv,
            ProbeRsInvocation::Passthrough {
                argv: vec!["probe-rs".to_owned(), "--version".to_owned()],
            }
        );
    }

    #[test]
    fn preserves_trailing_passthrough_and_unknown_flags() {
        // laze appends `$@`; here it expands to an extra `--speed 4000` plus a
        // bare `--connect-under-reset`. All must survive into `extra`.
        let inv = parse_str(&[
            "probe-rs",
            "download",
            "--chip",
            "nrf52",
            "app.elf",
            "--speed",
            "4000",
            "--connect-under-reset",
        ]);
        let ProbeRsInvocation::Download { chip, elf, extra } = inv else {
            panic!("expected Download");
        };
        assert_eq!(chip.as_deref(), Some("nrf52"));
        assert_eq!(elf.as_deref(), Some("app.elf"));
        // `--speed` (unknown flag), `4000` (its value, seen as a positional),
        // and `--connect-under-reset` are all preserved.
        assert!(extra.contains(&"--speed".to_owned()));
        assert!(extra.contains(&"4000".to_owned()));
        assert!(extra.contains(&"--connect-under-reset".to_owned()));
    }

    #[test]
    fn run_without_chip_yields_none() {
        let inv = parse_str(&["probe-rs", "run", "fw.elf"]);
        assert_eq!(inv.chip(), None);
    }
}
