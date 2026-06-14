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
/// are only known at runtime from enumeration. Call this after each discovery
/// pass so that the [`BoardSpec`](crate::config::BoardSpec) handed to
/// `probe-rs serve` carries the real vid/pid and the rendered allow entry
/// actually matches the attached probe.
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

}
