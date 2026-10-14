//! Probe discovery and reconciliation against `boards.toml`.
//!
//! The agent enumerates locally attached probes and reconciles them against the
//! declared boards: matched serials become leasable boards, declared-but-absent
//! boards are reported offline, and probes that are present but undeclared are
//! reported as `unknown`.
//!
//! What happens to those `unknown` probes is the node's **adoption policy**
//! ([`AdoptPolicy`], architecture §4.2 / §8):
//!
//! * [`AdoptPolicy::Declared`] — nothing. They are reported (so the condition
//!   is diagnosable) and stay unleasable until `boards.toml` declares them.
//! * [`AdoptPolicy::Auto`] — [`adopt_unknown`] synthesises a board for each,
//!   with a stable derived id and inferred tags, so plugging in a probe makes
//!   it usable with no further steps.
//!
//! A `boards.toml` declaration always wins: [`adopt_unknown`] only ever sees
//! probes [`reconcile`] put in `unknown`, which is by definition the set no
//! declaration matched.

use std::collections::HashMap;

use async_trait::async_trait;

use probefleet_proto::{
    AdoptPolicy, BoardName, BoardPresence, BoardStatus, DiscoveredProbe, ProbeInventory,
};

use crate::config::{BoardSpec, BoardsConfig, PowerSpec};

/// Enumerates probes physically attached to the agent host.
///
/// Defined as a trait so the reconciliation logic is testable with synthetic
/// inputs and the real `probe-rs list` shell-out is swappable.
#[async_trait]
pub trait ProbeLister: Send + Sync {
    /// List all currently attached probes.
    ///
    /// # Errors
    ///
    /// Returns an error string if enumeration fails.
    async fn list_probes(&self) -> Result<Vec<DiscoveredProbe>, String>;
}

/// Reconcile declared boards against discovered probes.
///
/// Pure function (no I/O): given the agent's `boards.toml` and the set of
/// probes currently present, produce the inventory the agent reports upward.
#[must_use]
pub fn reconcile(boards: &BoardsConfig, discovered: &[DiscoveredProbe]) -> ProbeInventory {
    let mut board_statuses = Vec::with_capacity(boards.boards.len());
    let mut matched_serials: Vec<&str> = Vec::new();

    for board in &boards.boards {
        // An inaccessible probe (probe-rs 0.32 `" (inaccessible)"` marker) is
        // physically attached but cannot be opened, so it must NOT count as
        // present: advertising the board Online would only make every lease on
        // it fail at `probe-rs serve` spawn time.
        //
        // This cannot flap a *leased* board: `inaccessible` is
        // `Accessibility::PermissionDenied`, which probe-rs derives from an
        // `access(2)` R_OK|W_OK check on the probe's `/dev/bus/usb/...` node
        // (Linux-only; always accessible elsewhere). It is a pure permissions
        // check and explicitly not a busy check — a probe held open by our own
        // `probe-rs serve` still lists as accessible.
        //
        // Operational note: on a misconfigured host (agent user lacking usbfs
        // permissions) *every* board now reports Offline instead of going
        // Online and failing at serve time. That is the intent; the warn below
        // is what makes it diagnosable.
        let present = discovered
            .iter()
            .any(|p| p.serial == board.serial && !p.inaccessible);
        if !present
            && discovered
                .iter()
                .any(|p| p.serial == board.serial && p.inaccessible)
        {
            tracing::warn!(
                serial = %board.serial,
                board = %board.id,
                "probe present but inaccessible (USB device-node permissions?); \
                 board reported offline"
            );
        }
        if present {
            matched_serials.push(&board.serial);
        }
        board_statuses.push(BoardStatus {
            board: BoardName(board.id.clone()),
            serial: board.serial.clone(),
            presence: if present {
                BoardPresence::Online
            } else {
                BoardPresence::Offline
            },
            chip: board.chip.clone(),
            model: board.model.clone(),
            tags: board.tags.clone(),
            exclusive: board.exclusive,
            power: board.power.to_power_kind(),
            adopted: false,
            // Stamped by the agent's discovery pass, which owns the tty lister.
            serial_ports: Vec::new(),
        });
    }

    let unknown = discovered
        .iter()
        .filter(|p| !boards.boards.iter().any(|b| b.serial == p.serial))
        .cloned()
        .collect();

    let _ = matched_serials;

    ProbeInventory {
        boards: board_statuses,
        unknown,
    }
}

/// The [`BoardSpec`] an undeclared probe becomes under [`AdoptPolicy::Auto`].
///
/// `None` when the probe cannot be adopted:
///
/// * it is `inaccessible` — `probe-rs` cannot open it, so advertising it would
///   only produce leases that fail at `probe-rs serve` spawn time (the same
///   reasoning [`reconcile`] applies to declared boards);
/// * it reports **no serial** — without one the board can be neither stably
///   named across restarts nor fenced with `ProbeAccess::Allow`, and a lease
///   selector that stops working after a reboot is worse than no board.
///
/// # The derived id must be stable
///
/// A lease selector names this id, so it is derived purely from the probe's own
/// identity — never from enumeration order, which `probe-rs list` does not
/// promise to keep.
///
/// # What is deliberately absent
///
/// * `chip` is **empty**. `probe-rs list` reports the *probe*, not the target
///   attached to it, so the agent genuinely cannot know. `chip` is documented
///   as informational (the caller passes `--chip` in-band), so an empty string
///   is honest. The visible consequence: `ctl lease --select 'chip=…'` will not
///   match an auto-adopted board until `boards.toml` annotates it. That is the
///   `boards.toml`-as-annotation story (§8), not a defect.
/// * `model` is **`None`**, for exactly the same reason: `probe-rs list`
///   reports the probe (a J-Link), never the board it is wired to, so the
///   agent cannot know that this is an `nrf52840dk`. The visible consequence:
///   `--select 'board=<model>'` never matches an adopted board until
///   `boards.toml` declares its `model`.
/// * `power` is [`PowerSpec::None`] — nobody declared this board, so nothing is
///   wired up to cut its power.
/// * `vid`/`pid` stay `0`. [`ProcessBackend::serve_spec`] re-enumerates at
///   spawn time and matches **by serial**, so a synthesised spec is enriched by
///   exactly the same path as a declared one (and already refuses to emit an
///   unmatchable `0000:0000:<serial>`). Nothing needs plumbing through the
///   wire.
///
/// [`ProcessBackend::serve_spec`]: crate::probers::ProcessBackend::serve_spec
#[must_use]
pub fn adopted_board_spec(probe: &DiscoveredProbe) -> Option<BoardSpec> {
    if probe.inaccessible || probe.serial.trim().is_empty() {
        return None;
    }
    Some(BoardSpec {
        id: adopted_board_id(probe),
        serial: probe.serial.clone(),
        vid: 0,
        pid: 0,
        chip: String::new(),
        model: None,
        tags: inferred_tags(probe),
        exclusive: true,
        power: PowerSpec::None,
        uart: Vec::new(),
        uart_discover: true,
    })
}

/// A stable, node-local, filesystem-safe board id for an undeclared probe.
///
/// `{product-slug}-{serial}` where the probe reports a product string,
/// `probe-{vid:04x}{pid:04x}-{serial}` where it does not. Both are functions of
/// the probe alone, so two discovery passes over the same hardware — in any
/// order, across a restart — produce the same id.
fn adopted_board_id(probe: &DiscoveredProbe) -> String {
    let serial = slugify(&probe.serial);
    match probe.product.as_deref().map(slugify) {
        Some(product) if !product.is_empty() => format!("{product}-{serial}"),
        _ => format!("probe-{:04x}{:04x}-{serial}", probe.vid, probe.pid),
    }
}

/// Selection tags inferred for an adopted board.
///
/// The probe-type slug plus a literal `auto`, so `ctl list` shows at a glance
/// which boards were adopted rather than declared. The spec asks for "tags
/// inferred from probe/chip"; the chip is unknowable here (see
/// [`adopted_board_spec`]), so the probe is all there is.
fn inferred_tags(probe: &DiscoveredProbe) -> Vec<String> {
    let mut tags = vec!["auto".to_owned()];
    if let Some(product) = probe.product.as_deref().map(slugify) {
        if !product.is_empty() && product != "auto" {
            tags.push(product);
        }
    }
    tags
}

/// Lowercase a string and collapse everything that is not `[a-z0-9]` into a
/// single `-`, trimming leading/trailing separators.
///
/// Board ids end up in file paths (the agent's per-board runtime directory) and
/// in selectors, so a probe reporting `"J-Link (v1.0)"` must not produce
/// something that needs quoting.
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

/// The [`BoardStatus`] an adopted board is reported as.
///
/// Derived *from* the [`BoardSpec`], never in parallel with it: if the id in
/// the report and the id [`Agent::board_spec`] resolves could drift apart, the
/// coordinator would happily lease a board the agent then fails to find, with
/// no error anywhere until the last hop.
///
/// `presence` is a parameter because an adopted board has to be reportable as
/// **`Offline`** too — see [`adopt_unknown`] for why that is not optional.
///
/// [`Agent::board_spec`]: crate::agent::Agent
#[must_use]
pub fn adopted_board_status(spec: &BoardSpec, presence: BoardPresence) -> BoardStatus {
    BoardStatus {
        board: spec.board_id(),
        serial: spec.serial.clone(),
        presence,
        chip: spec.chip.clone(),
        model: spec.model.clone(),
        tags: spec.tags.clone(),
        exclusive: spec.exclusive,
        power: spec.power.to_power_kind(),
        adopted: true,
        serial_ports: Vec::new(),
    }
}

/// Apply [`AdoptPolicy::Auto`] to a reconciled inventory: turn every adoptable
/// `unknown` probe into an online board, and report every board adopted by the
/// *previous* pass that has since gone away as **offline**.
///
/// Returns the synthesised specs by board name, for
/// [`Agent::set_adopted`](crate::agent::Agent::set_adopted) — the *same*
/// derivation that produced the reported statuses, which is what keeps the two
/// from drifting.
///
/// # Why departed boards are reported, not merely dropped
///
/// [`reconcile`] emits a status for every *declared* board, `Offline` when its
/// probe is absent. An adopted board has no declaration to emit a status from,
/// so simply not synthesising it would make it **vanish from the report**.
///
/// That used to be fatal on its own: nothing on the coordinator pruned a board
/// a report failed to mention, so the board sat in the scheduler as `Idle`
/// forever — `ctl list` showed it, a lease against it was granted, a capability
/// token minted, and the agent finally answered `UnknownBoard` at the last
/// possible hop. That hole is closed: the coordinator's `reconcile_inventory`
/// now treats each report as a **set**, so a board absent from it is retired
/// from the scheduler *and* from the coordinator's `board` table.
///
/// The tombstone is not thereby redundant, because the two removals do not mean
/// the same thing. Absence is an *inference* — the coordinator can only read it
/// as "this node no longer declares that board", which is the right reading for
/// a rename or a `boards.toml` deletion. An adopted board's `Offline` status is
/// a *declaration*: "this probe is gone". The coordinator acts on the
/// difference — `adopted && Offline` is a tombstone, not a declared-but-
/// unplugged board, so it clears the DB row as well, where a declared board
/// reported `Offline` keeps its row and stays visible in the UI. Emitting the
/// tombstone is also what makes the removal *prompt* and *legible*: it names
/// the board in the report the operator can see, instead of leaving the
/// coordinator to notice a gap.
///
/// A laptop is precisely the machine where probes get unplugged several times
/// a day, so this is the common case, not an edge one.
///
/// The tombstones are emitted **whatever the policy**, so that a node whose
/// policy flips `auto` → `declared` also cleans up after itself rather than
/// stranding whatever it adopted while it was `auto`.
///
/// The adopted probes stay in `inventory.unknown` as well: they are still
/// probes nobody declared, and an operator writing `boards.toml` wants to see
/// them there.
pub fn adopt_unknown<S: std::hash::BuildHasher>(
    inventory: &mut ProbeInventory,
    policy: AdoptPolicy,
    previously_adopted: &HashMap<BoardName, BoardSpec, S>,
) -> HashMap<BoardName, BoardSpec> {
    let mut adopted = HashMap::new();
    if policy == AdoptPolicy::Auto {
        for probe in &inventory.unknown {
            let Some(spec) = adopted_board_spec(probe) else {
                if !probe.inaccessible {
                    tracing::warn!(
                        vid = probe.vid,
                        pid = probe.pid,
                        "a probe reporting no serial cannot be adopted (it can be neither \
                         stably named nor fenced to one probe); declare it in boards.toml \
                         if you need it"
                    );
                }
                continue;
            };
            let name = spec.board_id();
            // A declaration always wins, and here that has to be enforced by
            // *name*, not only by serial: `boards.toml` may bind the name a
            // probe would derive to a different serial entirely. Two statuses
            // sharing one `BoardName` would have the coordinator upsert both
            // (last write wins) while `board_spec` resolves the declared one —
            // so a lease taken out for the adopted probe would attach to the
            // declared board's hardware. Skipping makes "declared wins" total
            // rather than dependent on iteration order.
            if inventory.boards.iter().any(|b| b.board == name) {
                tracing::warn!(
                    board = %name,
                    serial = %spec.serial,
                    "not adopting a probe whose derived board id is already declared \
                     in boards.toml; declare this serial explicitly to use it"
                );
                continue;
            }
            inventory
                .boards
                .push(adopted_board_status(&spec, BoardPresence::Online));
            adopted.insert(name, spec);
        }
    }

    // Tombstones for boards the previous pass adopted and this one did not:
    // the probe was unplugged, went inaccessible, or has just been declared.
    for (name, spec) in previously_adopted {
        if adopted.contains_key(name) || inventory.boards.iter().any(|b| &b.board == name) {
            continue;
        }
        tracing::info!(board = %name, serial = %spec.serial, "adopted board is gone; reporting offline");
        inventory
            .boards
            .push(adopted_board_status(spec, BoardPresence::Offline));
    }

    adopted
}

/// Stamp each declared board with the USB `vid`/`pid` of its physically present
/// probe, matched by serial against live discovery.
///
/// `boards.toml` keys boards by serial only; the canonical probe selector
/// probe-rs 0.32 requires (`vid:pid:serial`, see
/// [`crate::probers::ServeSpec::render_server_config`]) needs the USB ids, which
/// are only known at runtime from enumeration.
///
/// [`ProcessBackend`](crate::probers::ProcessBackend) calls this at
/// session-open time (against a fresh `probe-rs list`) so that the
/// [`BoardSpec`](crate::config::BoardSpec) handed to `probe-rs serve` carries
/// the real vid/pid and the rendered allow entry actually matches the attached
/// probe. It can equally be called after a periodic discovery pass.
///
/// Boards whose probe is absent are left untouched (their vid/pid stay at their
/// previous value); they cannot be served anyway.
///
/// Probes flagged `inaccessible` are deliberately *not* filtered here: stamping
/// the real vid/pid off an unopenable probe is harmless and keeps diagnostics
/// truthful. The serve path refuses inaccessible probes explicitly (see
/// [`ProcessBackend::serve_spec`](crate::probers::ProcessBackend::serve_spec)).
pub fn enrich_boards_with_discovery(boards: &mut BoardsConfig, discovered: &[DiscoveredProbe]) {
    for board in &mut boards.boards {
        if let Some(probe) = discovered.iter().find(|p| p.serial == board.serial) {
            board.vid = probe.vid;
            board.pid = probe.pid;
        }
    }
}

/// Parse one line of `probe-rs list` human-readable output into a
/// [`DiscoveredProbe`], or `None` if the line is not a probe entry.
///
/// probe-rs 0.32 prints each probe as (see `cmd/list.rs`, which formats
/// `DebugProbeEntry` from `rpc/functions/probe.rs` — character-for-character
/// the same shape as `impl Display for DebugProbeInfo`, unchanged since 0.31):
///
/// ```text
/// [0]: J-Link -- 1366:0101:000776543210 (J-Link)
/// [1]: J-Link -- 1366:0101:000776543211 (J-Link) (inaccessible)
/// ```
///
/// The token after `" -- "` is `{vid:04x}:{pid:04x}[-{interface}]:{serial} (…)`.
/// We extract `vid`/`pid`/`serial` from it; the interface suffix (`-N` on the
/// pid) and a missing serial (empty between the last `:` and ` (`) are both
/// tolerated. Header / "No debug probes" lines and anything without the
/// `" -- "` / hex-vid:pid shape return `None`.
///
/// New in 0.32: the trailing `" (inaccessible)"` marker, appended *after* the
/// `" (<probe type>)"` descriptor when probe-rs cannot open the probe. It is
/// captured into [`DiscoveredProbe::inaccessible`]; because the id parse stops
/// at the *first* `" ("`, the marker does not disturb vid/pid/serial.
#[must_use]
pub fn parse_probe_list_line(line: &str) -> Option<DiscoveredProbe> {
    // 0.32 marker, appended after the probe-type descriptor. Match the leading
    // space too, so a probe type ending in that token cannot false-positive.
    let inaccessible = line.trim_end().ends_with(" (inaccessible)");
    // Everything after the first " -- " is the `vid:pid[-iface]:serial (type)` tail.
    let tail = line.split_once(" -- ")?.1;
    // Strip the trailing " (type)" descriptor, if present.
    let ids = tail.split_once(" (").map_or(tail, |(ids, _)| ids).trim();
    // ids is now `vid:pid[-iface]:serial` (serial may be empty).
    let mut parts = ids.splitn(3, ':');
    let vid_hex = parts.next()?.trim();
    let pid_field = parts.next()?.trim();
    // serial is the remainder; absent => empty string.
    let serial = parts.next().unwrap_or("").trim().to_owned();
    // The pid field may carry an interface suffix `-N`; drop it.
    let pid_hex = pid_field.split('-').next().unwrap_or(pid_field);
    let vid = u16::from_str_radix(vid_hex, 16).ok()?;
    let pid = u16::from_str_radix(pid_hex, 16).ok()?;
    Some(DiscoveredProbe {
        serial,
        vid,
        pid,
        product: None,
        inaccessible,
    })
}

/// A [`ProbeLister`] that shells out to `probe-rs list` and parses its
/// human-readable output.
///
/// probefleet-agent deliberately carries **no** probe-rs library / USB dependency
/// (see the module-level doc): enumeration is a swappable shell-out to the same
/// `probe-rs` binary the agent already spawns `serve` with.
#[derive(Debug, Clone)]
pub struct ProbeRsListLister {
    /// The `probe-rs` binary to invoke (matches [`crate::probers::ProcessBackend`]).
    program: String,
}

impl ProbeRsListLister {
    /// Build a lister invoking `program list`.
    #[must_use]
    pub fn new(program: String) -> Self {
        Self { program }
    }
}

impl Default for ProbeRsListLister {
    fn default() -> Self {
        Self::new("probe-rs".to_owned())
    }
}

#[async_trait]
impl ProbeLister for ProbeRsListLister {
    async fn list_probes(&self) -> Result<Vec<DiscoveredProbe>, String> {
        let output = tokio::process::Command::new(&self.program)
            .arg("list")
            // probe-rs 0.32 prints multi-line USB-permission setup hints
            // whenever a probe is inaccessible or none are found. They go to
            // stderr (we only parse stdout), but the agent shells out on every
            // discovery pass, so silence the noise. The gate is a bare
            // `env::var(..).is_ok()`, so any value suppresses.
            .env("PROBE_RS_DISABLE_SETUP_HINTS", "1")
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| format!("running `{} list`: {e}", self.program))?;
        if !output.status.success() {
            return Err(format!(
                "`{} list` failed ({}): {}",
                self.program,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.lines().filter_map(parse_probe_list_line).collect())
    }
}

/// Whether `board` is leasable given an inventory snapshot (present + declared).
///
/// Keys off `inventory.boards`, so an **adopted** board is leasable here for
/// free once [`adopt_unknown`] has put it there — there is nothing extra to do.
#[must_use]
pub fn is_leasable(inventory: &ProbeInventory, board: &BoardName) -> bool {
    inventory
        .boards
        .iter()
        .any(|b| &b.board == board && b.presence == BoardPresence::Online)
}

/// A stub [`ProbeLister`] returning a fixed probe set: no hardware and no
/// `probe-rs` binary needed.
///
/// Lives here beside the trait it implements (rather than in one test module)
/// because three test modules need it — `discovery`, `probers` (the spawn-time
/// vid/pid resolution path) and `connection` (the discovery tick).
#[cfg(test)]
pub(crate) struct StubLister(pub Vec<DiscoveredProbe>);

#[cfg(test)]
#[async_trait]
impl ProbeLister for StubLister {
    async fn list_probes(&self) -> Result<Vec<DiscoveredProbe>, String> {
        Ok(self.0.clone())
    }
}

/// A [`ProbeLister`] whose probe set can be swapped between calls, for tests
/// that exercise a *transition* — a probe being plugged in or unplugged —
/// rather than a single snapshot.
#[cfg(test)]
pub(crate) struct SwappableLister(std::sync::Mutex<Vec<DiscoveredProbe>>);

#[cfg(test)]
impl SwappableLister {
    /// A lister starting with `probes` attached.
    pub fn new(probes: Vec<DiscoveredProbe>) -> Self {
        Self(std::sync::Mutex::new(probes))
    }

    /// Replace what the next `list_probes` will report (plug/unplug).
    pub fn set(&self, probes: Vec<DiscoveredProbe>) {
        *self.0.lock().unwrap() = probes;
    }
}

#[cfg(test)]
#[async_trait]
impl ProbeLister for SwappableLister {
    async fn list_probes(&self) -> Result<Vec<DiscoveredProbe>, String> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// A [`ProbeLister`] that always fails, for the "an enumeration hiccup must not
/// drop the connection or the inventory" path.
#[cfg(test)]
pub(crate) struct FailingLister;

#[cfg(test)]
#[async_trait]
impl ProbeLister for FailingLister {
    async fn list_probes(&self) -> Result<Vec<DiscoveredProbe>, String> {
        Err("usb is having a moment".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(serial: &str) -> DiscoveredProbe {
        DiscoveredProbe {
            serial: serial.to_owned(),
            vid: 0x1366,
            pid: 0x1015,
            product: Some("probe".to_owned()),
            inaccessible: false,
        }
    }

    fn inaccessible_probe(serial: &str) -> DiscoveredProbe {
        DiscoveredProbe {
            inaccessible: true,
            ..probe(serial)
        }
    }

    fn boards() -> BoardsConfig {
        BoardsConfig::from_str(
            r#"
[[board]]
id = "b1"
serial = "AAA"
chip = "c1"
[[board]]
id = "b2"
serial = "BBB"
chip = "c2"
"#,
        )
        .unwrap()
    }

    #[test]
    fn matched_board_is_online_absent_is_offline() {
        let inv = reconcile(&boards(), &[probe("AAA")]);
        assert_eq!(inv.boards.len(), 2);
        let b1 = inv.boards.iter().find(|b| b.board.0 == "b1").unwrap();
        let b2 = inv.boards.iter().find(|b| b.board.0 == "b2").unwrap();
        assert_eq!(b1.presence, BoardPresence::Online);
        assert_eq!(b2.presence, BoardPresence::Offline);
    }

    #[test]
    fn undeclared_probe_is_reported_as_unknown() {
        let inv = reconcile(&boards(), &[probe("AAA"), probe("ZZZ")]);
        assert_eq!(inv.unknown.len(), 1);
        assert_eq!(inv.unknown[0].serial, "ZZZ");
    }

    #[test]
    fn no_probes_means_all_offline_and_no_unknown() {
        let inv = reconcile(&boards(), &[]);
        assert!(inv
            .boards
            .iter()
            .all(|b| b.presence == BoardPresence::Offline));
        assert!(inv.unknown.is_empty());
    }

    #[test]
    fn is_leasable_requires_online() {
        let inv = reconcile(&boards(), &[probe("AAA")]);
        assert!(is_leasable(&inv, &BoardName("b1".into())));
        assert!(!is_leasable(&inv, &BoardName("b2".into())));
        assert!(!is_leasable(&inv, &BoardName("nope".into())));
    }

    fn probe_ids(serial: &str, vid: u16, pid: u16) -> DiscoveredProbe {
        DiscoveredProbe {
            serial: serial.to_owned(),
            vid,
            pid,
            product: Some("probe".to_owned()),
            inaccessible: false,
        }
    }

    #[test]
    fn inaccessible_probe_does_not_make_board_online() {
        // probe-rs 0.32 reports a present-but-unopenable probe; the board must
        // stay Offline rather than being leased and failing at serve time.
        let inv = reconcile(&boards(), &[inaccessible_probe("AAA")]);
        let b1 = inv.boards.iter().find(|b| b.board.0 == "b1").unwrap();
        assert_eq!(b1.presence, BoardPresence::Offline);
        assert!(!is_leasable(&inv, &BoardName("b1".into())));
    }

    #[test]
    fn accessible_duplicate_still_brings_board_online() {
        // Same serial listed twice (e.g. two interfaces), one openable: Online.
        let inv = reconcile(&boards(), &[inaccessible_probe("AAA"), probe("AAA")]);
        let b1 = inv.boards.iter().find(|b| b.board.0 == "b1").unwrap();
        assert_eq!(b1.presence, BoardPresence::Online);
    }

    #[test]
    fn inaccessible_undeclared_probe_is_reported_as_unknown_with_flag() {
        let inv = reconcile(&boards(), &[probe("AAA"), inaccessible_probe("ZZZ")]);
        assert_eq!(inv.unknown.len(), 1);
        assert_eq!(inv.unknown[0].serial, "ZZZ");
        assert!(inv.unknown[0].inaccessible);
    }

    #[test]
    fn enrich_stamps_vid_pid_onto_matched_boards() {
        let mut boards = boards();
        enrich_boards_with_discovery(
            &mut boards,
            &[
                probe_ids("AAA", 0x1366, 0x1015),
                probe_ids("ZZZ", 0xdead, 0xbeef),
            ],
        );
        let b1 = boards.boards.iter().find(|b| b.id == "b1").unwrap();
        assert_eq!((b1.vid, b1.pid), (0x1366, 0x1015));
        // b2's probe ("BBB") is absent from discovery: left at default 0/0.
        let b2 = boards.boards.iter().find(|b| b.id == "b2").unwrap();
        assert_eq!((b2.vid, b2.pid), (0, 0));
    }

    #[test]
    fn parses_real_probe_list_lines() {
        // J-Link with serial (the nRF52840-DK's onboard J-Link OB).
        let p = parse_probe_list_line("[0]: J-Link -- 1366:0101:000776543210 (J-Link)").unwrap();
        assert_eq!(
            (p.vid, p.pid, p.serial.as_str()),
            (0x1366, 0x0101, "000776543210")
        );
        assert!(!p.inaccessible);

        // CMSIS-DAP with serial.
        let p =
            parse_probe_list_line("[1]: Foo CMSIS-DAP -- 0d28:0204:0123ABCD (CMSIS-DAP)").unwrap();
        assert_eq!(
            (p.vid, p.pid, p.serial.as_str()),
            (0x0d28, 0x0204, "0123ABCD")
        );
        assert!(!p.inaccessible);
    }

    #[test]
    fn parses_inaccessible_probe_line() {
        // probe-rs 0.32 appends the marker *after* the " (<type>)" descriptor.
        let p =
            parse_probe_list_line("[0]: J-Link -- 1366:0101:000776543210 (J-Link) (inaccessible)")
                .unwrap();
        assert_eq!(
            (p.vid, p.pid, p.serial.as_str()),
            (0x1366, 0x0101, "000776543210")
        );
        assert!(p.inaccessible);

        // Same, with the interface-index suffix on the pid.
        let p = parse_probe_list_line(
            "[0]: HID Probe -- 1366:0101-0:001050257890 (J-Link) (inaccessible)",
        )
        .unwrap();
        assert_eq!(
            (p.vid, p.pid, p.serial.as_str()),
            (0x1366, 0x0101, "001050257890")
        );
        assert!(p.inaccessible);
    }

    #[test]
    fn parser_tolerates_interface_suffix_and_missing_serial() {
        // Interface index suffix on the pid (`-N`).
        let p =
            parse_probe_list_line("[0]: HID Probe -- 1366:0101-0:001050257890 (J-Link)").unwrap();
        assert_eq!(
            (p.vid, p.pid, p.serial.as_str()),
            (0x1366, 0x0101, "001050257890")
        );
        assert!(!p.inaccessible);

        // No serial reported: empty between the last `:` and ` (`.
        let p = parse_probe_list_line("[0]: Nameless -- 1366:0101: (J-Link)").unwrap();
        assert_eq!((p.vid, p.pid, p.serial.as_str()), (0x1366, 0x0101, ""));
    }

    #[test]
    fn parser_rejects_non_probe_lines() {
        assert!(parse_probe_list_line("The following debug probes were found:").is_none());
        assert!(parse_probe_list_line("No debug probes were found.").is_none());
        assert!(parse_probe_list_line("").is_none());
        // Has " -- " but no hex vid:pid.
        assert!(parse_probe_list_line("weird -- not:hex:stuff").is_none());
    }

    // ---- adoption ----------------------------------------------------------

    /// [`adopt_unknown`] on a node that has adopted nothing yet.
    ///
    /// Most adoption tests are about the *arrival* of a probe, where there is
    /// no previous set; the departure cases pass one explicitly.
    fn adopt_fresh(
        inventory: &mut ProbeInventory,
        policy: AdoptPolicy,
    ) -> HashMap<BoardName, BoardSpec> {
        adopt_unknown(inventory, policy, &HashMap::new())
    }

    fn named_probe(serial: &str, product: Option<&str>) -> DiscoveredProbe {
        DiscoveredProbe {
            serial: serial.to_owned(),
            vid: 0x1366,
            pid: 0x1015,
            product: product.map(ToOwned::to_owned),
            inaccessible: false,
        }
    }

    /// The derived id is what a lease selector names, so it must survive a
    /// restart and a reordered `probe-rs list`. Deriving it from enumeration
    /// order would look fine in one pass and break silently on the next.
    #[test]
    fn adopted_ids_are_stable_across_passes_and_ordering() {
        let a = named_probe("XXX", Some("J-Link"));
        let b = named_probe("YYY", Some("CMSIS-DAP"));

        let mut first = reconcile(&boards(), &[a.clone(), b.clone()]);
        let mut second = reconcile(&boards(), &[b, a]);
        let ids_a = adopt_fresh(&mut first, AdoptPolicy::Auto);
        let ids_b = adopt_fresh(&mut second, AdoptPolicy::Auto);

        let mut names_a: Vec<_> = ids_a.keys().map(|n| n.0.clone()).collect();
        let mut names_b: Vec<_> = ids_b.keys().map(|n| n.0.clone()).collect();
        names_a.sort();
        names_b.sort();
        assert_eq!(names_a, names_b);
        assert_eq!(
            names_a,
            vec!["cmsis-dap-yyy".to_owned(), "j-link-xxx".to_owned()]
        );
    }

    /// A probe with no serial can be neither stably named nor fenced with
    /// `ProbeAccess::Allow`, so adopting it would produce a board whose leases
    /// silently attach to the wrong hardware.
    #[test]
    fn a_serial_less_probe_is_not_adopted() {
        let mut probe = named_probe("", Some("J-Link"));
        probe.serial = String::new();
        assert!(adopted_board_spec(&probe).is_none());

        let mut inv = reconcile(&boards(), &[probe]);
        assert!(adopt_fresh(&mut inv, AdoptPolicy::Auto).is_empty());
        assert!(inv.boards.iter().all(|b| !b.adopted));
    }

    /// An unopenable probe must never become a board under either policy: the
    /// lease would fail at `probe-rs serve` spawn time, which is the same
    /// reasoning `reconcile` applies to declared boards.
    #[test]
    fn an_inaccessible_probe_is_never_adopted() {
        assert!(adopted_board_spec(&inaccessible_probe("ZZZ")).is_none());
        for policy in [AdoptPolicy::Auto, AdoptPolicy::Declared] {
            let mut inv = reconcile(&boards(), &[inaccessible_probe("ZZZ")]);
            assert!(adopt_fresh(&mut inv, policy).is_empty());
            assert!(inv.boards.iter().all(|b| !b.adopted));
        }
    }

    /// `declared` is unchanged behaviour: reported, not leasable.
    #[test]
    fn declared_policy_adopts_nothing() {
        let mut inv = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        assert!(adopt_fresh(&mut inv, AdoptPolicy::Declared).is_empty());
        assert_eq!(inv.unknown.len(), 1);
        assert!(!is_leasable(&inv, &BoardName("j-link-zzz".into())));
    }

    /// The adopted board is leasable, tagged `auto`, and carries no chip — the
    /// documented consequence being that `--select 'chip=…'` will not match it
    /// until `boards.toml` annotates it.
    #[test]
    fn an_adopted_board_is_leasable_tagged_auto_and_has_no_chip() {
        let mut inv = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        let specs = adopt_fresh(&mut inv, AdoptPolicy::Auto);
        assert_eq!(specs.len(), 1);

        let name = BoardName("j-link-zzz".into());
        assert!(is_leasable(&inv, &name));
        let status = inv.boards.iter().find(|b| b.board == name).unwrap();
        assert!(status.adopted);
        assert!(status.tags.contains(&"auto".to_owned()));
        assert!(status.tags.contains(&"j-link".to_owned()));
        assert!(
            status.chip.is_empty(),
            "the agent cannot know the target chip"
        );
        assert_eq!(status.serial, "ZZZ");
    }

    /// A probe with no product string still gets a stable id, from its USB ids.
    #[test]
    fn a_product_less_probe_falls_back_to_its_usb_ids() {
        let spec = adopted_board_spec(&named_probe("ZZZ", None)).unwrap();
        assert_eq!(spec.id, "probe-13661015-zzz");
        assert_eq!(spec.tags, vec!["auto".to_owned()]);
    }

    /// Precedence: a declared board and its probe must produce exactly one
    /// board, the declared one. `adopt_unknown` only ever sees probes
    /// `reconcile` put in `unknown`, so this is structural — but it is the
    /// property §2.4 is about, so it is asserted rather than assumed.
    #[test]
    fn a_declared_probe_is_never_also_adopted() {
        let mut inv = reconcile(&boards(), &[probe("AAA")]);
        let specs = adopt_fresh(&mut inv, AdoptPolicy::Auto);
        assert!(specs.is_empty());
        assert_eq!(inv.boards.iter().filter(|b| b.serial == "AAA").count(), 1);
        let b1 = inv.boards.iter().find(|b| b.board.0 == "b1").unwrap();
        assert!(!b1.adopted);
        assert_eq!(b1.chip, "c1", "the declaration's metadata must survive");
    }

    /// The status and the spec come from one derivation, so the id the
    /// coordinator schedules is exactly the id the agent can resolve. Drift
    /// here presents as a board that leases and then fails to open, with no
    /// error anywhere in between.
    #[test]
    fn the_reported_id_and_the_resolvable_id_are_the_same() {
        let mut inv = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        let specs = adopt_fresh(&mut inv, AdoptPolicy::Auto);
        for status in inv.boards.iter().filter(|b| b.adopted) {
            assert!(
                specs.contains_key(&status.board),
                "reported {} with no resolvable spec",
                status.board
            );
        }
    }

    /// Board ids reach file paths and selectors, so a chatty product string
    /// must not produce something that needs quoting.
    #[test]
    fn ids_are_slugified() {
        let spec = adopted_board_spec(&named_probe("00:11", Some("J-Link (v1.0)"))).unwrap();
        assert_eq!(spec.id, "j-link-v1-0-00-11");
        assert!(spec
            .id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }

    // ---- departure ---------------------------------------------------------

    /// **Unplugging an adopted probe must report it `Offline`, not omit it.**
    ///
    /// A laptop is the machine where boards come and go several times a day.
    /// If a departed board simply vanished from the report, nothing on the
    /// coordinator would prune it: it would sit in the scheduler as `Idle`,
    /// `ctl list` would show it, a lease would be *granted*, and the agent
    /// would answer `UnknownBoard` at the last possible hop.
    #[test]
    fn an_unplugged_adopted_board_is_reported_offline() {
        let mut first = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        let adopted = adopt_fresh(&mut first, AdoptPolicy::Auto);
        let name = BoardName("j-link-zzz".into());
        assert!(is_leasable(&first, &name));

        // The probe is unplugged: discovery returns nothing.
        let mut second = reconcile(&boards(), &[]);
        let still = adopt_unknown(&mut second, AdoptPolicy::Auto, &adopted);

        assert!(still.is_empty(), "the spec is dropped");
        let status = second
            .boards
            .iter()
            .find(|b| b.board == name)
            .expect("a departed adopted board must still be reported, as Offline");
        assert_eq!(status.presence, BoardPresence::Offline);
        assert!(status.adopted);
        assert!(!is_leasable(&second, &name));
    }

    /// A probe that goes `inaccessible` is as good as unplugged: it cannot be
    /// opened, so the board must go offline rather than linger as leasable.
    #[test]
    fn an_adopted_board_that_goes_inaccessible_is_reported_offline() {
        let mut first = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        let adopted = adopt_fresh(&mut first, AdoptPolicy::Auto);

        let mut second = reconcile(&boards(), &[inaccessible_probe("ZZZ")]);
        adopt_unknown(&mut second, AdoptPolicy::Auto, &adopted);

        let name = BoardName("j-link-zzz".into());
        assert_eq!(
            second
                .boards
                .iter()
                .find(|b| b.board == name)
                .map(|b| b.presence),
            Some(BoardPresence::Offline)
        );
    }

    /// A tombstone is emitted whatever the policy, so a node whose policy is
    /// flipped `auto` → `declared` cleans up after itself rather than stranding
    /// everything it adopted while it was `auto`.
    #[test]
    fn flipping_to_declared_still_retires_what_auto_adopted() {
        let mut first = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        let adopted = adopt_fresh(&mut first, AdoptPolicy::Auto);

        // Same hardware, but the policy is now `declared`.
        let mut second = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        let still = adopt_unknown(&mut second, AdoptPolicy::Declared, &adopted);

        assert!(still.is_empty());
        let name = BoardName("j-link-zzz".into());
        assert_eq!(
            second
                .boards
                .iter()
                .find(|b| b.board == name)
                .map(|b| b.presence),
            Some(BoardPresence::Offline),
            "the board must be retired, not silently left in the scheduler"
        );
    }

    /// A board that is *still* present must not be tombstoned: the previous set
    /// is a departure check, not a one-shot.
    #[test]
    fn a_still_present_adopted_board_is_not_tombstoned() {
        let mut first = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        let adopted = adopt_fresh(&mut first, AdoptPolicy::Auto);

        let mut second = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        let still = adopt_unknown(&mut second, AdoptPolicy::Auto, &adopted);

        let name = BoardName("j-link-zzz".into());
        assert!(still.contains_key(&name));
        assert_eq!(
            second.boards.iter().filter(|b| b.board == name).count(),
            1,
            "exactly one status, and not a tombstone"
        );
        assert!(is_leasable(&second, &name));
    }

    /// Declaring a previously adopted probe is a *handover*, not a duplicate:
    /// the declared status stands and no tombstone is emitted for it, because
    /// `reconcile` already produced a status under that name.
    #[test]
    fn declaring_a_previously_adopted_probe_does_not_double_report_it() {
        let mut first = reconcile(&boards(), &[named_probe("ZZZ", Some("J-Link"))]);
        let adopted = adopt_fresh(&mut first, AdoptPolicy::Auto);
        let name = BoardName("j-link-zzz".into());

        // The operator has since declared that serial under the same id.
        let declared = BoardsConfig::from_str(
            r#"
[[board]]
id = "j-link-zzz"
serial = "ZZZ"
chip = "nRF52840_xxAA"
"#,
        )
        .unwrap();
        let mut second = reconcile(&declared, &[named_probe("ZZZ", Some("J-Link"))]);
        adopt_unknown(&mut second, AdoptPolicy::Auto, &adopted);

        let statuses: Vec<_> = second.boards.iter().filter(|b| b.board == name).collect();
        assert_eq!(statuses.len(), 1, "one board, one status");
        assert!(!statuses[0].adopted, "the declaration takes over");
        assert_eq!(statuses[0].presence, BoardPresence::Online);
        assert_eq!(statuses[0].chip, "nRF52840_xxAA");
    }

    /// A derived id colliding with a *declared* id bound to a different serial
    /// must not produce two statuses under one name: the coordinator would
    /// upsert both (last wins) while `board_spec` resolves the declared one, so
    /// a lease taken out for the adopted probe would drive the declared board's
    /// hardware. Skipping makes "declared wins" total rather than dependent on
    /// iteration order.
    #[test]
    fn a_derived_id_colliding_with_a_declared_id_is_not_adopted() {
        // `j-link-zzz` is declared, but bound to serial AAA — while a probe
        // with serial ZZZ (which derives that exact name) is plugged in.
        let declared = BoardsConfig::from_str(
            r#"
[[board]]
id = "j-link-zzz"
serial = "AAA"
chip = "c1"
"#,
        )
        .unwrap();
        let mut inv = reconcile(
            &declared,
            &[named_probe("AAA", None), named_probe("ZZZ", Some("J-Link"))],
        );
        let specs = adopt_fresh(&mut inv, AdoptPolicy::Auto);

        let name = BoardName("j-link-zzz".into());
        assert!(
            !specs.contains_key(&name),
            "the colliding probe must not be adopted"
        );
        let statuses: Vec<_> = inv.boards.iter().filter(|b| b.board == name).collect();
        assert_eq!(
            statuses.len(),
            1,
            "exactly one board may carry a given name"
        );
        assert!(!statuses[0].adopted);
        assert_eq!(
            statuses[0].serial, "AAA",
            "the declared serial owns the name"
        );
    }
}
