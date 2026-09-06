//! `node board add` / `node board list` — declare a board without hand-editing
//! `boards.toml`.
//!
//! Declaring a board used to mean: run `probe-rs list` on the node, copy the
//! serial by eye, invent an id, look up the chip name, write a `[[board]]`
//! table, restart the agent. Under `adopt = "declared"` — the recommended
//! policy for a lab or CI node — that is the *mandatory* path for every board.
//! This module does the discovery and the writing; the operator still supplies
//! the two things the machine cannot know (`chip` and `model`) and the one
//! thing it must not invent (`id`).
//!
//! # Why this appends instead of re-serialising
//!
//! `boards.toml` ships as a heavily commented reference (`examples/boards.toml`)
//! and the scaffold [`crate::roles::node_setup::starter_boards_toml`] writes is
//! commented too — the comments are how an operator learns what `chip` versus
//! `model` versus `tags` mean. `toml` 0.8 is **not** format-preserving, so
//! deserialising to [`BoardsConfig`] and re-serialising would silently delete
//! every comment, reorder the tables and normalise the aligned `id        =`
//! style. That is data loss, not a formatting nit.
//!
//! So [`append_board`] only ever *adds bytes*: the previous contents are a
//! byte-for-byte prefix of what is written. The price is that `add` is the only
//! verb — **editing or removing a declaration stays a hand-edit** — which is an
//! acceptable v1 and is stated in the command's own output.
//!
//! # Validation
//!
//! There is no second set of rules here. The candidate text (existing file plus
//! the new table) is parsed with [`BoardsConfig::from_str`], which validates,
//! and its message is surfaced verbatim — so `duplicate board id` and
//! `duplicate probe serial` read the same from this command as from the agent
//! that refuses to start. Nothing is written unless that parse succeeds, so a
//! rejected add leaves the file byte-identical.
//!
//! # The agent does not reload
//!
//! `boards.toml` is read **once at agent startup** (see
//! [`crate::roles::agent::run`]); there is no file watcher and this module does
//! not add one. Every successful add therefore prints that the agent must be
//! restarted.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use fleet_agent::config::BoardsConfig;
use fleet_agent::discovery::{reconcile, ProbeLister, ProbeRsListLister};
use fleet_proto::{AdoptPolicy, BoardPresence, DiscoveredProbe};

use crate::cli::{NodeBoardAddArgs, NodeBoardListArgs};
use crate::roles::agent::{load_node_settings, resolve_boards_path};
use crate::roles::node_setup::starter_boards_toml;

/// Discover attached probes and append a `[[board]]` declaration for one.
///
/// # Errors
///
/// Returns an error if probes cannot be enumerated, the existing `boards.toml`
/// does not parse, the requested serial is not attached, a required value is
/// missing with no terminal to prompt on, the resulting file would be invalid
/// (duplicate id / serial), or the write fails.
pub async fn add(args: &NodeBoardAddArgs) -> Result<()> {
    let node_dir = node_dir(args.config_dir.as_deref())?;
    let boards_path = resolve_boards_path(&node_dir, args.boards_path.as_deref())?;
    let lister = ProbeRsListLister::new(args.probe_rs.clone());
    let interactive = args
        .interactive_choice()
        .unwrap_or_else(|| std::io::stdin().is_terminal() && std::io::stdout().is_terminal());
    add_with(&lister, &boards_path, args, interactive).await
}

/// Show what this node declares and what is attached but undeclared.
///
/// # Errors
///
/// Returns an error if probes cannot be enumerated or `boards.toml` does not
/// parse.
pub async fn list(args: &NodeBoardListArgs) -> Result<()> {
    let node_dir = node_dir(args.config_dir.as_deref())?;
    let boards_path = resolve_boards_path(&node_dir, args.boards_path.as_deref())?;
    let adopt = load_node_settings(&node_dir.join("node.toml"))?
        .adopt
        .unwrap_or_default();
    let lister = ProbeRsListLister::new(args.probe_rs.clone());
    list_with(&lister, &boards_path, adopt).await
}

/// The node-settings directory: `<config_dir>/node`, or the XDG default.
fn node_dir(config_dir: Option<&Path>) -> Result<PathBuf> {
    match config_dir {
        Some(dir) => Ok(dir.join("node")),
        None => crate::paths::node_config_dir(),
    }
}

/// A board declaration as the operator described it, before it is rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BoardDraft {
    /// Stable board id.
    id: String,
    /// Probe serial to bind.
    serial: String,
    /// probe-rs chip name; empty is allowed (see [`render_board_table`]).
    chip: String,
    /// Board model; `None` when the operator declared none.
    model: Option<String>,
    /// Free-form selection tags.
    tags: Vec<String>,
    /// Whether the board admits only one lease at a time.
    exclusive: bool,
}

/// A stable, filesystem-safe id derived from a probe, offered as the prompt
/// default.
///
/// Deliberately the same shape as `fleet_agent::discovery`'s auto-adoption id
/// (`{product-slug}-{serial}`, else `probe-{vid:04x}{pid:04x}-{serial}`), but a
/// *reimplementation*: that helper is private, and exporting it would drag
/// fleet-agent into a change this task does not need.
///
/// The duplication is safe because this value is **cosmetic**: it is only ever
/// shown as a prompt default that the operator sees and confirms, never used
/// behind their back. If it ever diverges from the adoption id, nothing an
/// operator relies on changes — which is why the fix is not to export the
/// original.
fn derived_id(probe: &DiscoveredProbe) -> String {
    let serial = slugify(&probe.serial);
    match probe.product.as_deref().map(slugify) {
        Some(product) if !product.is_empty() => format!("{product}-{serial}"),
        _ => format!("probe-{:04x}{:04x}-{serial}", probe.vid, probe.pid),
    }
}

/// Lowercase and collapse everything outside `[a-z0-9]` into a single `-`.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}

/// A TOML string literal for `value`, correctly escaped.
///
/// Never `format!("\"{value}\"")`: a product-derived id or a chip name
/// containing a quote or a backslash would produce a file that does not parse,
/// and the operator would be looking at a command that broke their config.
fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

/// Render a `[[board]]` table for `draft`.
///
/// # Which keys are always written
///
/// `chip` is **required** by [`fleet_agent::config::BoardSpec`] — unlike `tags`,
/// `exclusive` and `power` it has no `#[serde(default)]` — so it is always
/// emitted, as `chip = ""` when the operator declared none. An empty value
/// parses and validates; an absent key is a `missing field` parse error.
///
/// `model` is the mirror image: it is `Option<String>` with `#[serde(default)]`,
/// and `BoardsConfig::validate` **rejects** an empty declared model (a board
/// whose model is the empty string could never be selected). So it is omitted
/// entirely rather than written empty.
///
/// `[board.power]` is emitted as a commented template. Prompting for uhubctl
/// hub/port or gpio chip/line would be a second wizard for wiring this command
/// cannot verify; a template keeps `boards.toml`-as-annotation intact and
/// leaves the default (`kind = "none"`) in force.
fn render_board_table(draft: &BoardDraft) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    out.push_str("# added by `probe-rs-fleet node board add`\n");
    out.push_str("[[board]]\n");
    let _ = writeln!(out, "id        = {}", toml_string(&draft.id));
    let _ = writeln!(out, "serial    = {}", toml_string(&draft.serial));
    // Always present: `chip` has no serde default, so omitting the key makes
    // the file fail to parse. Empty is fine, and is what "not known yet" is.
    let _ = writeln!(out, "chip      = {}", toml_string(&draft.chip));
    if draft.chip.is_empty() {
        out.push_str("# no chip declared: `ctl lease chip=…` will not match this board.\n");
    }
    match &draft.model {
        // Omitted rather than empty: an empty `model` is rejected by
        // `BoardsConfig::validate`.
        Some(model) => {
            let _ = writeln!(out, "model     = {}", toml_string(model));
        }
        None => out.push_str(
            "# no model declared: `ctl lease board=<model>` will not match this board.\n\
             # model     = \"nrf52840dk\"\n",
        ),
    }
    let tags = draft
        .tags
        .iter()
        .map(|t| toml_string(t))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(out, "tags      = [{tags}]");
    let _ = writeln!(out, "exclusive = {}", draft.exclusive);
    out.push_str(
        "# USB power control (default: none). Uncomment and adapt one of these:\n\
         # [board.power]\n\
         # kind = \"uhubctl\"\n\
         # hub  = \"1-1\"\n\
         # port = 2\n\
         # [board.power]\n\
         # kind = \"gpio\"\n\
         # chip = \"gpiochip0\"\n\
         # line = 17\n",
    );
    out
}

/// The candidate file contents: `existing` with `table` appended.
///
/// **Append-only: this may add bytes, never remove them.** `existing` is a
/// byte-for-byte prefix of the result, which is what makes "your comments
/// survive" an invariant rather than a coincidence. A missing trailing newline
/// is fixed by *adding* one, and the tables are separated by one blank line;
/// nothing is trimmed, reordered or reformatted.
fn append_board(existing: &str, table: &str) -> String {
    let mut out = String::with_capacity(existing.len() + table.len() + 2);
    out.push_str(existing);
    if !existing.is_empty() {
        if !existing.ends_with('\n') {
            out.push('\n');
        }
        if !existing.ends_with("\n\n") {
            out.push('\n');
        }
    }
    out.push_str(table);
    out
}

/// The core of `node board add`, with the probe lister and the target path
/// injected so it is testable without a `probe-rs` binary.
async fn add_with(
    lister: &dyn ProbeLister,
    boards_path: &Path,
    args: &NodeBoardAddArgs,
    interactive: bool,
) -> Result<()> {
    let probes = enumerate(lister, &args.probe_rs).await?;

    // A file that is already invalid is reported before anything is appended,
    // with its own message: otherwise the operator sees a duplicate-id error
    // for a duplicate they did not just create.
    //
    // A file that does not exist yet is seeded with the same commented
    // reference the enrollment scaffold writes, so declaring the first board on
    // an unscaffolded machine does not leave behind a file with no explanation
    // in it. It is still an append: the seed is all comments.
    let creating = !boards_path.exists();
    let existing = if creating {
        starter_boards_toml()
    } else {
        read_existing(boards_path)?
    };
    let declared = BoardsConfig::from_str(&existing).with_context(|| {
        format!(
            "the existing {} does not parse; fix it before adding to it",
            boards_path.display()
        )
    })?;

    let probe = choose_probe(&probes, &declared, args, interactive)?;
    if probe.inaccessible {
        eprintln!(
            "warning: probe {} is attached but `probe-rs` cannot open it \
             (\"inaccessible\" — a USB device-node permissions problem, usually udev).",
            probe.serial
        );
        eprintln!(
            "         The board will be declared, but it will report Offline until \
             those permissions are fixed."
        );
    }

    let draft = draft_from(probe, args, interactive)?;
    let table = render_board_table(&draft);
    let candidate = append_board(&existing, &table);

    // The one validation gate. Reuses the agent's rules and its messages, so a
    // duplicate is refused here exactly as the agent would refuse to start.
    BoardsConfig::from_str(&candidate)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| {
            format!(
                "declaring board {:?} would make {} invalid; nothing was written",
                draft.id,
                boards_path.display()
            )
        })?;

    if args.dry_run {
        println!("--dry-run: would append to {}:\n", boards_path.display());
        print!("{table}");
        return Ok(());
    }

    write_atomic(boards_path, &candidate)?;

    if creating {
        // Printed absolutely: `boards_path` may have come from a `boards_path =`
        // in node.toml, which gets no `~` expansion anywhere in this tree, so a
        // literal `~/…` there yields a directory named `~`. Better seen than
        // silent.
        println!("created {}", absolute(boards_path).display());
    }
    println!(
        "declared board {:?} in {}:\n",
        draft.id,
        boards_path.display()
    );
    print!("{table}");
    println!();
    println!("The agent reads boards.toml once at startup, so restart it for this to");
    println!("take effect (`systemctl --user restart …`, or re-run `probe-rs-fleet agent`).");
    if draft.chip.is_empty() || draft.model.is_none() {
        println!();
        if draft.chip.is_empty() {
            println!("No chip declared: `ctl lease --select 'chip=…'` will not match this board.");
        }
        if draft.model.is_none() {
            println!(
                "No model declared: `ctl lease --select 'board=…'` will not match this board."
            );
        }
        println!("Add them by editing the table above — `node board add` only appends.");
    }
    Ok(())
}

/// The core of `node board list`, with the lister and path injected.
async fn list_with(lister: &dyn ProbeLister, boards_path: &Path, adopt: AdoptPolicy) -> Result<()> {
    let probes = enumerate(lister, "probe-rs").await?;
    let existing = read_existing(boards_path)?;
    let boards = BoardsConfig::from_str(&existing).with_context(|| {
        format!(
            "the existing {} does not parse; fix it before inspecting it",
            boards_path.display()
        )
    })?;
    print!("{}", render_list(&boards, &probes, adopt, boards_path));
    Ok(())
}

/// Render the two-section `node board list` report.
///
/// Reuses [`reconcile`] rather than recomputing "declared but absent" and
/// "attached but undeclared": this view and the one the agent reports upward
/// must not be able to disagree.
fn render_list(
    boards: &BoardsConfig,
    probes: &[DiscoveredProbe],
    adopt: AdoptPolicy,
    boards_path: &Path,
) -> String {
    use std::fmt::Write as _;

    let inventory = reconcile(boards, probes);
    let mut out = String::new();

    let _ = writeln!(out, "DECLARED ({})", boards_path.display());
    if inventory.boards.is_empty() {
        out.push_str("  (none)\n");
    } else {
        let _ = writeln!(
            out,
            "{:<24} {:<18} {:<18} {:<14} PRESENCE",
            "ID", "SERIAL", "CHIP", "MODEL"
        );
        for b in &inventory.boards {
            let chip = if b.chip.is_empty() { "-" } else { &b.chip };
            let model = b.model.as_deref().unwrap_or("-");
            let presence = match b.presence {
                BoardPresence::Online => "Online",
                BoardPresence::Offline => "Offline",
            };
            let _ = writeln!(
                out,
                "{:<24} {:<18} {:<18} {:<14} {}",
                b.board.0, b.serial, chip, model, presence
            );
        }
    }

    out.push('\n');
    // `reconcile` is adopt-blind: `unknown` means "not in boards.toml", which
    // under `adopt = "auto"` does NOT mean "unusable". Saying which policy this
    // node runs is the difference between an accurate report and one that reads
    // as an alarm on every laptop.
    let policy_note = match adopt {
        AdoptPolicy::Auto => {
            "adopt = \"auto\": these are adopted automatically with a derived id, \
             no chip and no model"
        }
        AdoptPolicy::Declared => {
            "adopt = \"declared\": these are NOT leasable until they are declared"
        }
    };
    let _ = writeln!(
        out,
        "UNDECLARED PROBES (attached, not in boards.toml) — this node's {policy_note}"
    );
    if inventory.unknown.is_empty() {
        out.push_str("  (none)\n");
    } else {
        let _ = writeln!(
            out,
            "{:<18} {:<12} {:<20} NOTE",
            "SERIAL", "VID:PID", "PRODUCT"
        );
        for p in &inventory.unknown {
            let note = if p.inaccessible {
                "inaccessible — check USB permissions"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "{:<18} {:04x}:{:04x}   {:<20} {}",
                p.serial,
                p.vid,
                p.pid,
                p.product.as_deref().unwrap_or("-"),
                note
            );
        }
        out.push('\n');
        out.push_str("Declare one with:\n");
        let _ = writeln!(
            out,
            "  probe-rs-fleet node board add --serial {}",
            inventory.unknown[0].serial
        );
    }
    // The policy is this node's setting; the coordinator's node row is what
    // actually decides. Say so, so nobody edits node.toml expecting a change.
    out.push_str(
        "\nNote: `adopt` here is this node's setting (node.toml). The coordinator's\n\
         node row is authoritative for what it will actually adopt.\n",
    );
    out
}

/// Enumerate attached probes, turning the lister's string error into one that
/// says what to do about it.
async fn enumerate(lister: &dyn ProbeLister, program: &str) -> Result<Vec<DiscoveredProbe>> {
    lister.list_probes().await.map_err(|e| {
        anyhow::anyhow!(
            "{e}\nIs `{program}` on PATH? Pass --probe-rs <path> to point at it explicitly."
        )
    })
}

/// Read `boards.toml`, treating an absent file as empty.
///
/// Absent is not an error: declaring the first board on a machine that was
/// never scaffolded has to work.
fn read_existing(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Pick the probe to declare: `--serial`, or a prompt.
fn choose_probe<'a>(
    probes: &'a [DiscoveredProbe],
    declared: &BoardsConfig,
    args: &NodeBoardAddArgs,
    interactive: bool,
) -> Result<&'a DiscoveredProbe> {
    anyhow::ensure!(
        !probes.is_empty(),
        "no probes are attached to this machine (`{} list` found none), so there is \
         nothing to declare",
        args.probe_rs
    );
    if let Some(serial) = &args.serial {
        return probes
            .iter()
            .find(|p| &p.serial == serial)
            .with_context(|| {
                format!(
                    "no attached probe has serial {serial:?}. Attached: {}",
                    attached_list(probes)
                )
            });
    }
    anyhow::ensure!(
        interactive,
        "--serial is required without a terminal to pick on. Attached: {}",
        attached_list(probes)
    );

    println!("Attached probes:");
    for (i, p) in probes.iter().enumerate() {
        println!("  [{}] {}", i + 1, describe_probe(p, declared));
    }
    let answer = prompt("Declare which probe?", "1")?;
    let index: usize = answer
        .parse()
        .ok()
        .filter(|n| (1..=probes.len()).contains(n))
        .with_context(|| format!("{answer:?} is not one of the listed probes"))?;
    Ok(&probes[index - 1])
}

/// A comma-separated list of attached serials, for an error message.
fn attached_list(probes: &[DiscoveredProbe]) -> String {
    probes
        .iter()
        .map(|p| {
            if p.serial.is_empty() {
                "(no serial)".to_owned()
            } else {
                p.serial.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// One picker line: identity, plus the two facts that change what declaring it
/// means (already declared, or inaccessible).
fn describe_probe(probe: &DiscoveredProbe, declared: &BoardsConfig) -> String {
    let mut line = format!(
        "{:<18} {:04x}:{:04x}  {}",
        if probe.serial.is_empty() {
            "(no serial)"
        } else {
            &probe.serial
        },
        probe.vid,
        probe.pid,
        probe.product.as_deref().unwrap_or("-")
    );
    if let Some(existing) = declared.boards.iter().find(|b| b.serial == probe.serial) {
        use std::fmt::Write as _;
        let _ = write!(line, "  [already declared as {:?}]", existing.id);
    }
    if probe.inaccessible {
        line.push_str("  [inaccessible — will report Offline until USB permissions are fixed]");
    }
    line
}

/// Assemble the declaration from flags, prompting for what is missing.
fn draft_from(
    probe: &DiscoveredProbe,
    args: &NodeBoardAddArgs,
    interactive: bool,
) -> Result<BoardDraft> {
    anyhow::ensure!(
        !probe.serial.is_empty(),
        "that probe reports no serial number, so there is nothing to bind a board to. \
         `boards.toml` matches probes by serial."
    );

    let id = if let Some(id) = &args.id {
        id.clone()
    } else {
        anyhow::ensure!(
            interactive,
            "--id is required without a terminal to prompt on. It is the stable name \
             `ctl lease id=…` and grants use, so it is never invented for you \
             (suggestion for this probe: {})",
            derived_id(probe)
        );
        prompt("Board id", &derived_id(probe))?
    };
    anyhow::ensure!(!id.trim().is_empty(), "the board id must not be empty");

    let chip = match &args.chip {
        Some(chip) => chip.clone(),
        None if interactive => prompt_optional(
            "probe-rs chip name (e.g. nRF52840_xxAA; blank if unknown — \
             `chip=` selectors will not match)",
        )?,
        None => String::new(),
    };

    let model = match &args.model {
        Some(model) if model.trim().is_empty() => None,
        Some(model) => Some(model.clone()),
        None if interactive => {
            let answer = prompt_optional(
                "board model (e.g. nrf52840dk; blank if unknown — \
                 `board=` selectors will not match)",
            )?;
            (!answer.trim().is_empty()).then_some(answer)
        }
        None => None,
    };

    let tags = if args.tags.is_empty() && interactive {
        let answer = prompt_optional("tags, comma-separated (blank for none)")?;
        answer
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect()
    } else {
        args.tags.clone()
    };

    Ok(BoardDraft {
        id: id.trim().to_owned(),
        serial: probe.serial.clone(),
        chip: chip.trim().to_owned(),
        model: model.map(|m| m.trim().to_owned()),
        tags,
        exclusive: !args.no_exclusive,
    })
}

/// Prompt with a default, returning the default on an empty answer.
fn prompt(question: &str, default: &str) -> Result<String> {
    let answer = read_line(&format!("{question} [{default}]: "))?;
    Ok(if answer.trim().is_empty() {
        default.to_owned()
    } else {
        answer.trim().to_owned()
    })
}

/// Prompt where an empty answer is a real answer.
fn prompt_optional(question: &str) -> Result<String> {
    Ok(read_line(&format!("{question}: "))?.trim().to_owned())
}

/// Write `question` and read one line, the same shape `node_approve::confirm`
/// uses (no prompting crate for one wizard).
fn read_line(question: &str) -> Result<String> {
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading your answer")?;
    Ok(answer)
}

/// Write `text` to `path` via a temp file in the same directory + rename.
///
/// A half-written `boards.toml` would break the agent at its next start, and
/// this file carries no credential, so it is written world-readable exactly as
/// the scaffold is.
fn write_atomic(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("boards.toml");
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    crate::secrets::write_public(&tmp, text.as_bytes())?;
    std::fs::rename(&tmp, path).with_context(|| {
        format!(
            "renaming {} onto {} (boards.toml write)",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

/// `path` made absolute if it can be, for a message about a file just created.
fn absolute(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    /// The stub `fleet-agent`'s own one is `#[cfg(test)]`-private, so it cannot
    /// be borrowed from here.
    struct StubLister(Vec<DiscoveredProbe>);

    #[async_trait]
    impl ProbeLister for StubLister {
        async fn list_probes(&self) -> Result<Vec<DiscoveredProbe>, String> {
            Ok(self.0.clone())
        }
    }

    fn probe(serial: &str) -> DiscoveredProbe {
        DiscoveredProbe {
            serial: serial.to_owned(),
            vid: 0x1366,
            pid: 0x0101,
            product: Some("J-Link".to_owned()),
            inaccessible: false,
        }
    }

    fn args(serial: &str, id: &str) -> NodeBoardAddArgs {
        NodeBoardAddArgs {
            serial: Some(serial.to_owned()),
            id: Some(id.to_owned()),
            chip: None,
            model: None,
            tags: Vec::new(),
            no_exclusive: false,
            dry_run: false,
            interactive: false,
            no_interactive: true,
            boards_path: None,
            config_dir: None,
            probe_rs: "probe-rs".to_owned(),
        }
    }

    async fn run_add(
        probes: Vec<DiscoveredProbe>,
        path: &Path,
        a: &NodeBoardAddArgs,
    ) -> Result<()> {
        add_with(&StubLister(probes), path, a, false).await
    }

    /// The base case: a scripted add produces a table the agent's own loader
    /// accepts, with the documented defaults.
    #[tokio::test]
    async fn non_interactive_add_writes_a_parsable_declaration() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let mut a = args("001050047405", "nrf52840-dk-1");
        a.chip = Some("nRF52840_xxAA".to_owned());
        a.model = Some("nrf52840dk".to_owned());
        a.tags = vec!["nrf52".to_owned(), "lab".to_owned()];

        run_add(vec![probe("001050047405")], &path, &a)
            .await
            .unwrap();

        let cfg = BoardsConfig::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        cfg.validate().unwrap();
        let board = &cfg.boards[0];
        assert_eq!(board.id, "nrf52840-dk-1");
        assert_eq!(board.serial, "001050047405");
        assert_eq!(board.chip, "nRF52840_xxAA");
        assert_eq!(board.model.as_deref(), Some("nrf52840dk"));
        assert_eq!(board.tags, ["nrf52", "lab"]);
        assert!(board.exclusive, "exclusive defaults to true");
        assert_eq!(
            board.power,
            fleet_agent::config::PowerSpec::None,
            "power defaults to none; the template stays commented"
        );
    }

    /// **The regression that matters most.** `boards.toml` is a commented
    /// reference the operator owns; a round-trip through `toml::to_string`
    /// would delete every comment. Append-only makes the old contents a
    /// byte-for-byte prefix of the new ones.
    #[tokio::test]
    async fn comments_and_existing_entries_survive_the_write() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let original = "# probe-rs-fleet board inventory\n\
                        # ANNOTATION AND OVERRIDE, not admission control.\n\
                        \n\
                        [[board]]\n\
                        # the first one, hand-aligned\n\
                        id        = \"nrf52840-dk-3\"\n\
                        serial    = \"001050257890\"\n\
                        chip      = \"nRF52840_xxAA\"\n\
                        tags      = [\"nrf52\"]\n";
        std::fs::write(&path, original).unwrap();

        run_add(
            vec![probe("001050047405")],
            &path,
            &args("001050047405", "j-link-2"),
        )
        .await
        .unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.starts_with(original),
            "append-only: the previous contents must be a byte-for-byte prefix"
        );
        for line in original.lines().filter(|l| l.trim_start().starts_with('#')) {
            assert!(after.contains(line), "comment lost: {line}");
        }
        let cfg = BoardsConfig::from_str(&after).unwrap();
        assert_eq!(cfg.boards.len(), 2);
        assert_eq!(cfg.boards[0].id, "nrf52840-dk-3");
        assert_eq!(cfg.boards[1].id, "j-link-2");
    }

    /// The validator's message, and a file left byte-identical.
    #[tokio::test]
    async fn duplicate_id_is_refused_and_the_file_is_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let original = "[[board]]\nid = \"taken\"\nserial = \"AAA\"\nchip = \"\"\n";
        std::fs::write(&path, original).unwrap();

        let err = run_add(vec![probe("BBB")], &path, &args("BBB", "taken"))
            .await
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("duplicate board id"), "{text}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[tokio::test]
    async fn duplicate_serial_is_refused_and_the_file_is_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let original = "[[board]]\nid = \"first\"\nserial = \"AAA\"\nchip = \"\"\n";
        std::fs::write(&path, original).unwrap();

        let err = run_add(vec![probe("AAA")], &path, &args("AAA", "second"))
            .await
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("duplicate probe serial"), "{text}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    /// Declaring the first board on a machine that was never scaffolded must
    /// work, and must create the parent directory too.
    #[tokio::test]
    async fn adding_to_a_missing_file_creates_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("node").join("boards.toml");
        run_add(vec![probe("AAA")], &path, &args("AAA", "b1"))
            .await
            .unwrap();
        let cfg = BoardsConfig::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg.boards.len(), 1);
    }

    #[tokio::test]
    async fn adding_to_an_empty_file_works() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        std::fs::write(&path, "").unwrap();
        run_add(vec![probe("AAA")], &path, &args("AAA", "b1"))
            .await
            .unwrap();
        assert_eq!(
            BoardsConfig::from_str(&std::fs::read_to_string(&path).unwrap())
                .unwrap()
                .boards
                .len(),
            1
        );
    }

    /// An unattached serial is almost always a typo, so it is refused rather
    /// than declared blind — and the error says what *is* attached.
    #[tokio::test]
    async fn a_serial_that_is_not_attached_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let err = run_add(vec![probe("AAA")], &path, &args("BBB", "b1"))
            .await
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("BBB"), "{text}");
        assert!(
            text.contains("AAA"),
            "the error must name what is attached: {text}"
        );
        assert!(!path.exists());
    }

    /// An inaccessible probe can be declared — but the operator is told, in
    /// advance, exactly what they will see, because "declared board stuck
    /// Offline" is the confusion this helper exists to pre-empt.
    #[tokio::test]
    async fn an_inaccessible_probe_can_be_declared_but_the_picker_warns() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let mut p = probe("AAA");
        p.inaccessible = true;
        run_add(vec![p.clone()], &path, &args("AAA", "b1"))
            .await
            .unwrap();
        assert_eq!(
            BoardsConfig::from_str(&std::fs::read_to_string(&path).unwrap())
                .unwrap()
                .boards
                .len(),
            1
        );

        // The wording is the feature: the picker line has to say Offline and
        // permissions, or the operator declares it and then files a bug.
        let line = describe_probe(&p, &BoardsConfig { boards: Vec::new() });
        assert!(line.contains("inaccessible"), "{line}");
        assert!(line.contains("Offline"), "{line}");
        assert!(line.contains("permissions"), "{line}");
    }

    /// A quote or a backslash in an operator-supplied value must not be able to
    /// produce a file that does not parse.
    #[test]
    fn render_board_table_escapes_hostile_values() {
        let draft = BoardDraft {
            id: "we\"ird\\one".to_owned(),
            serial: "A\"B".to_owned(),
            chip: "chip\\x".to_owned(),
            model: Some("mo\"del".to_owned()),
            tags: vec!["t\"ag".to_owned()],
            exclusive: true,
        };
        let cfg = BoardsConfig::from_str(&render_board_table(&draft)).unwrap();
        assert_eq!(cfg.boards[0].id, "we\"ird\\one");
        assert_eq!(cfg.boards[0].serial, "A\"B");
        assert_eq!(cfg.boards[0].chip, "chip\\x");
        assert_eq!(cfg.boards[0].model.as_deref(), Some("mo\"del"));
        assert_eq!(cfg.boards[0].tags, ["t\"ag"]);
    }

    /// `chip` has no serde default, so the key must be written even when the
    /// operator has no value for it. Omitting it is a "missing field" parse
    /// error; `model` is the opposite and must be omitted when empty.
    #[test]
    fn an_empty_chip_is_written_as_a_key_and_an_empty_model_is_omitted() {
        let draft = BoardDraft {
            id: "b1".to_owned(),
            serial: "AAA".to_owned(),
            chip: String::new(),
            model: None,
            tags: Vec::new(),
            exclusive: true,
        };
        let table = render_board_table(&draft);
        assert!(table.contains("chip      = \"\""), "{table}");
        assert!(
            !table.lines().any(|l| l.starts_with("model")),
            "an empty model must be omitted, not written: {table}"
        );
        let cfg = BoardsConfig::from_str(&table).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.boards[0].chip.is_empty());
        assert!(cfg.boards[0].model.is_none());
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let mut a = args("AAA", "b1");
        a.dry_run = true;
        run_add(vec![probe("AAA")], &path, &a).await.unwrap();
        assert!(!path.exists(), "--dry-run must not create the file");
    }

    /// A board that is declared but whose probe is unplugged is Offline, an
    /// attached probe nobody declared is in the second section, and the section
    /// header says what this node's policy does with it.
    #[test]
    fn list_separates_declared_from_undeclared() {
        let boards = BoardsConfig::from_str(
            "[[board]]\nid = \"declared-1\"\nserial = \"AAA\"\nchip = \"nRF52840_xxAA\"\n\
             [[board]]\nid = \"unplugged\"\nserial = \"ZZZ\"\nchip = \"\"\n",
        )
        .unwrap();
        let mut undeclared = probe("BBB");
        undeclared.inaccessible = true;
        let out = render_list(
            &boards,
            &[probe("AAA"), undeclared],
            AdoptPolicy::Declared,
            Path::new("/x/boards.toml"),
        );

        assert!(out.contains("declared-1"));
        assert!(out.contains("Online"));
        assert!(out.contains("unplugged"));
        assert!(out.contains("Offline"));
        assert!(out.contains("BBB"));
        assert!(out.contains("inaccessible"));
        assert!(
            out.contains("probe-rs-fleet node board add --serial BBB"),
            "the report must be actionable: {out}"
        );
        assert!(
            out.contains("NOT leasable"),
            "under `declared` the header must say what that means: {out}"
        );
    }

    /// Under `auto` the same probes are already usable, so the header must not
    /// read as an alarm.
    #[test]
    fn list_names_the_adopt_policy_so_auto_does_not_read_as_an_alarm() {
        let boards = BoardsConfig::from_str("").unwrap();
        let out = render_list(
            &boards,
            &[probe("BBB")],
            AdoptPolicy::Auto,
            Path::new("/x/boards.toml"),
        );
        assert!(out.contains("adopted automatically"), "{out}");
        assert!(!out.contains("NOT leasable"), "{out}");
    }

    /// `boards_path` in `node.toml` must beat the default, and an explicit
    /// `--boards-path` must beat both — the whole precedence in one place,
    /// through the same helper the agent uses.
    #[test]
    fn boards_path_from_node_toml_is_honoured() {
        let tmp = tempfile::tempdir().unwrap();
        let node_dir = tmp.path().join("node");
        std::fs::create_dir_all(&node_dir).unwrap();
        let elsewhere = tmp.path().join("elsewhere.toml");
        std::fs::write(
            node_dir.join("node.toml"),
            format!(
                "boards_path = {}\n",
                toml_string(elsewhere.to_str().unwrap())
            ),
        )
        .unwrap();

        assert_eq!(resolve_boards_path(&node_dir, None).unwrap(), elsewhere);
        let explicit = tmp.path().join("explicit.toml");
        assert_eq!(
            resolve_boards_path(&node_dir, Some(&explicit)).unwrap(),
            explicit
        );

        // And with no node.toml at all, the scaffolded default.
        let bare = tmp.path().join("bare");
        assert_eq!(
            resolve_boards_path(&bare, None).unwrap(),
            bare.join("boards.toml")
        );
    }

    /// End-to-end through the resolution helper: an add with only a config dir
    /// must grow the overridden file and never create the default one.
    #[tokio::test]
    async fn add_writes_to_the_overridden_path_not_the_default() {
        let tmp = tempfile::tempdir().unwrap();
        let node_dir = tmp.path().join("node");
        std::fs::create_dir_all(&node_dir).unwrap();
        let elsewhere = tmp.path().join("elsewhere.toml");
        std::fs::write(
            node_dir.join("node.toml"),
            format!(
                "boards_path = {}\n",
                toml_string(elsewhere.to_str().unwrap())
            ),
        )
        .unwrap();

        let path = resolve_boards_path(&node_dir, None).unwrap();
        run_add(vec![probe("AAA")], &path, &args("AAA", "b1"))
            .await
            .unwrap();

        assert!(elsewhere.exists(), "the override must be the file written");
        assert!(
            !node_dir.join("boards.toml").exists(),
            "the default path must not be created"
        );
    }

    /// A file that is already broken is reported as such, before anything is
    /// appended: otherwise the operator debugs an error about a board they did
    /// not just add.
    #[tokio::test]
    async fn an_already_invalid_file_is_reported_before_anything_is_appended() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let original = "[[board]]\nid = \"a\"\nserial = \"AAA\"\n";
        std::fs::write(&path, original).unwrap();
        let err = run_add(vec![probe("BBB")], &path, &args("BBB", "b1"))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("does not parse"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    /// Prompting must be unreachable without a terminal, and the refusal must
    /// name the flag that would have avoided it.
    #[tokio::test]
    async fn a_missing_id_without_a_terminal_names_the_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let mut a = args("AAA", "unused");
        a.id = None;
        let err = run_add(vec![probe("AAA")], &path, &a).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("--id is required"), "{text}");
        assert!(!path.exists());
    }

    /// Likewise for the probe itself.
    #[tokio::test]
    async fn a_missing_serial_without_a_terminal_names_the_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        let mut a = args("AAA", "b1");
        a.serial = None;
        let err = run_add(vec![probe("AAA")], &path, &a).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("--serial is required"), "{text}");
        assert!(text.contains("AAA"), "{text}");
    }

    /// The prompt default mirrors the auto-adoption id's shape, so an operator
    /// who flips from `auto` to `declared` is offered the name their boards
    /// already had.
    #[test]
    fn the_derived_id_is_a_slug_of_product_and_serial() {
        assert_eq!(derived_id(&probe("00105_0047")), "j-link-00105-0047");
        let mut anonymous = probe("AAA");
        anonymous.product = None;
        assert_eq!(derived_id(&anonymous), "probe-13660101-aaa");
    }

    /// Append-only, stated as an invariant: whatever the separator logic does,
    /// it may only add bytes.
    #[test]
    fn append_board_only_ever_adds_bytes() {
        for existing in ["", "x = 1", "x = 1\n", "x = 1\n\n", "x = 1\n\n\n"] {
            let out = append_board(existing, "[[board]]\n");
            assert!(out.starts_with(existing), "{existing:?} -> {out:?}");
            assert!(out.ends_with("[[board]]\n"));
        }
        assert_eq!(append_board("", "[[board]]\n"), "[[board]]\n");
        assert_eq!(append_board("x = 1\n", "t\n"), "x = 1\n\nt\n");
    }

    /// Two adds in a row must both land, which is the case the separator logic
    /// exists for.
    #[tokio::test]
    async fn two_adds_in_a_row_both_land() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        run_add(vec![probe("AAA"), probe("BBB")], &path, &args("AAA", "b1"))
            .await
            .unwrap();
        run_add(vec![probe("AAA"), probe("BBB")], &path, &args("BBB", "b2"))
            .await
            .unwrap();
        let cfg = BoardsConfig::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg.boards.len(), 2);
        assert_eq!(cfg.boards[1].id, "b2");
    }

    /// A fresh file is seeded with the commented reference, not left bare: the
    /// comments are how an operator learns what `chip` versus `model` versus
    /// `tags` mean, and this command is often the first thing to touch the
    /// file.
    #[tokio::test]
    async fn a_freshly_created_file_carries_the_reference_comments() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boards.toml");
        run_add(vec![probe("AAA")], &path, &args("AAA", "b1"))
            .await
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(&starter_boards_toml()));
        let cfg = BoardsConfig::from_str(&text).unwrap();
        assert_eq!(
            cfg.boards.len(),
            1,
            "the scaffold's example stays commented"
        );
    }
}
