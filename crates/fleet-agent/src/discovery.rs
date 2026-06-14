//! Probe discovery and reconciliation against `boards.toml`.
//!
//! The agent enumerates locally attached probes and reconciles them against the
//! declared boards: matched serials become leasable boards, declared-but-absent
//! boards are reported offline, and probes that are present but undeclared are
//! reported as `unknown` (not leasable) — see architecture §8.

use async_trait::async_trait;

use fleet_proto::{BoardId, BoardPresence, BoardStatus, DiscoveredProbe, ProbeInventory};

use crate::config::BoardsConfig;

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
        let present = discovered.iter().any(|p| p.serial == board.serial);
        if present {
            matched_serials.push(&board.serial);
        }
        board_statuses.push(BoardStatus {
            board: BoardId(board.id.clone()),
            serial: board.serial.clone(),
            presence: if present {
                BoardPresence::Online
            } else {
                BoardPresence::Offline
            },
            chip: board.chip.clone(),
            tags: board.tags.clone(),
            exclusive: board.exclusive,
            power: board.power.to_power_kind(),
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

/// Stamp each declared board with the USB `vid`/`pid` of its physically present
/// probe, matched by serial against live discovery.
///
/// `boards.toml` keys boards by serial only; the canonical probe selector
/// probe-rs 0.31 requires (`vid:pid:serial`, see
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
/// probe-rs 0.31 prints each probe as (see `cmd/list.rs` +
/// `impl Display for DebugProbeInfo`, probe-rs 0.31.0):
///
/// ```text
/// [0]: J-Link -- 1366:0101:000776543210 (J-Link)
/// ```
///
/// The token after `" -- "` is `{vid:04x}:{pid:04x}[-{interface}]:{serial} (…)`.
/// We extract `vid`/`pid`/`serial` from it; the interface suffix (`-N` on the
/// pid) and a missing serial (empty between the last `:` and ` (`) are both
/// tolerated. Header / "No debug probes" lines and anything without the
/// `" -- "` / hex-vid:pid shape return `None`.
#[must_use]
pub fn parse_probe_list_line(line: &str) -> Option<DiscoveredProbe> {
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
    })
}

/// A [`ProbeLister`] that shells out to `probe-rs list` and parses its
/// human-readable output.
///
/// fleet-agent deliberately carries **no** probe-rs library / USB dependency
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
#[must_use]
pub fn is_leasable(inventory: &ProbeInventory, board: &BoardId) -> bool {
    inventory
        .boards
        .iter()
        .any(|b| &b.board == board && b.presence == BoardPresence::Online)
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
        assert!(inv.boards.iter().all(|b| b.presence == BoardPresence::Offline));
        assert!(inv.unknown.is_empty());
    }

    #[test]
    fn is_leasable_requires_online() {
        let inv = reconcile(&boards(), &[probe("AAA")]);
        assert!(is_leasable(&inv, &BoardId("b1".into())));
        assert!(!is_leasable(&inv, &BoardId("b2".into())));
        assert!(!is_leasable(&inv, &BoardId("nope".into())));
    }

    fn probe_ids(serial: &str, vid: u16, pid: u16) -> DiscoveredProbe {
        DiscoveredProbe {
            serial: serial.to_owned(),
            vid,
            pid,
            product: Some("probe".to_owned()),
        }
    }

    #[test]
    fn enrich_stamps_vid_pid_onto_matched_boards() {
        let mut boards = boards();
        enrich_boards_with_discovery(
            &mut boards,
            &[probe_ids("AAA", 0x1366, 0x1015), probe_ids("ZZZ", 0xdead, 0xbeef)],
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
        assert_eq!((p.vid, p.pid, p.serial.as_str()), (0x1366, 0x0101, "000776543210"));

        // CMSIS-DAP with serial.
        let p = parse_probe_list_line("[1]: Foo CMSIS-DAP -- 0d28:0204:0123ABCD (CMSIS-DAP)")
            .unwrap();
        assert_eq!((p.vid, p.pid, p.serial.as_str()), (0x0d28, 0x0204, "0123ABCD"));
    }

    #[test]
    fn parser_tolerates_interface_suffix_and_missing_serial() {
        // Interface index suffix on the pid (`-N`).
        let p = parse_probe_list_line("[0]: HID Probe -- 1366:0101-0:001050257890 (J-Link)")
            .unwrap();
        assert_eq!((p.vid, p.pid, p.serial.as_str()), (0x1366, 0x0101, "001050257890"));

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
}
