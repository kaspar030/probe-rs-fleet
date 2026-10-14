//! Who may use which board, and for what — the pure half of authorization.
//!
//! Architecture §6.5 gives two ways a subject reaches a board:
//!
//! * the **ownership path** — the board is in the subject's org and the subject
//!   is a member of it; or
//! * a **grant** — a live, unexpired [`GrantScope`] issued by the board's org
//!   whose selector matches the board.
//!
//! [`Access`] is the value object holding both, resolved once per request from
//! the authenticated subject and never from anything the caller says. It is
//! deliberately pure: no I/O, no clock (`now` is always a parameter), so the
//! whole (subject, object, op) → allow/deny matrix is a table-driven unit test.
//!
//! # Deny by default, and the org fence
//!
//! An [`Access`] built from nothing allows nothing. More importantly, **a grant
//! only ever admits boards in the granting org**: `GrantScope::org` is compared
//! to `board.id.org` as a conjunct of every check. This matters because the
//! selector language is org-blind — a grant issued in org A saying `tag=nrf52`
//! must not reach org C's identically tagged board. With the scheduler's board
//! matching no longer carrying an org argument of its own, this comparison *is*
//! the tenancy boundary.

use probefleet_proto::board::Board;
use probefleet_proto::ids::OrgId;
use probefleet_proto::lease::Constraint;
use probefleet_proto::token::AllowedOp;

/// One live grant, as the evaluator sees it.
///
/// Built from a stored `grant` row: the selector is re-parsed from its
/// canonical rendering and the ops from their labels. A row that fails to
/// re-parse is dropped **closed** by the builder — never widened into a
/// match-anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantScope {
    /// The grant's opaque id, so an audit line can name what allowed a request.
    pub id: String,
    /// The org that issued the grant. A grant may only admit boards belonging
    /// to this org — see the module docs.
    pub org: OrgId,
    /// Which boards the grant covers.
    pub selector: Constraint,
    /// Which operations it confers.
    pub ops: Vec<AllowedOp>,
    /// Expiry as epoch seconds; `None` means no expiry.
    pub expires: Option<u64>,
}

impl GrantScope {
    /// Whether the grant is still live at `now`.
    ///
    /// Exclusive at the boundary, matching
    /// [`probefleet_proto::token::CapabilityToken::is_valid_at`]: `now == expires`
    /// is expired.
    #[must_use]
    pub fn is_live_at(&self, now: u64) -> bool {
        self.expires.is_none_or(|e| now < e)
    }

    /// Whether the grant covers `board`: same org **and** selector match.
    #[must_use]
    pub fn covers(&self, board: &Board) -> bool {
        board.id.org == self.org && selector_matches(board, &self.selector)
    }
}

/// Everything one authenticated subject may reach.
///
/// Construct with [`Access::none`] (deny-all), [`Access::own_org`], or by
/// filling both fields; the coordinator's `authz::board_access` is the only
/// production builder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Access {
    /// Every org the subject is a **member** of, which is what the ownership
    /// path requires. Membership, not merely the org a request names: a
    /// request's target org is a claim, so trusting it here would let a
    /// non-member through. Empty for nodes-as-callers and workloads, which
    /// reach boards only through grants.
    pub member_of: Vec<OrgId>,
    /// Live grants issued *to* this subject, from any org.
    pub grants: Vec<GrantScope>,
}

impl Access {
    /// The deny-everything access. Distinct from `Default` only in name.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Membership of exactly one org and no grants.
    #[must_use]
    pub fn own_org(org: OrgId) -> Self {
        Self {
            member_of: vec![org],
            grants: Vec::new(),
        }
    }

    /// Whether this access confers nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.member_of.is_empty() && self.grants.is_empty()
    }

    /// Whether the subject owns `board` by membership.
    #[must_use]
    pub fn owns(&self, board: &Board) -> bool {
        self.member_of.contains(&board.id.org)
    }

    /// Whether the subject may use `board` at all (for any operation).
    ///
    /// This is the lease-time question: a lease is granted on "may use", and
    /// the *token* it mints is then attenuated to [`Access::effective_ops`].
    #[must_use]
    pub fn may_use(&self, board: &Board, now: u64) -> bool {
        self.owns(board) || self.matching_grant(board, now).is_some()
    }

    /// The first live grant covering `board`, if any.
    ///
    /// Returned so an audit line can record *which* grant admitted a request —
    /// "allowed by ownership" and "allowed by grant abc123" are different
    /// facts, and only the second one can be revoked.
    #[must_use]
    pub fn matching_grant(&self, board: &Board, now: u64) -> Option<&GrantScope> {
        self.grants
            .iter()
            .find(|g| g.is_live_at(now) && g.covers(board))
    }

    /// The union of operations the subject may perform on `board`.
    ///
    /// Ownership confers the full set; grants confer theirs, unioned across
    /// every live grant that covers the board. Empty means "no access", and
    /// callers must treat it that way rather than as "an unrestricted token".
    #[must_use]
    pub fn effective_ops(&self, board: &Board, now: u64) -> Vec<AllowedOp> {
        if self.owns(board) {
            return AllowedOp::all();
        }
        let mut ops: Vec<AllowedOp> = self
            .grants
            .iter()
            .filter(|g| g.is_live_at(now) && g.covers(board))
            .flat_map(|g| g.ops.iter().copied())
            .collect();
        ops.sort_unstable();
        ops.dedup();
        ops
    }

    /// Whether the subject may perform `op` on `board` at `now`.
    #[must_use]
    pub fn allows(&self, board: &Board, op: AllowedOp, now: u64) -> bool {
        self.owns(board) || self.effective_ops(board, now).contains(&op)
    }
}

/// Does `board` satisfy `constraint`, ignoring tenancy?
///
/// Tenancy is **not** checked here: this is the selector language alone. Every
/// caller must pair it with an org comparison — [`GrantScope::covers`] does,
/// and so does `Scheduler::is_candidate` via [`Access`].
#[must_use]
pub fn selector_matches(board: &Board, constraint: &Constraint) -> bool {
    match constraint {
        // The request side carries a node-local name (the caller does not know
        // the node), so only the name half is compared.
        Constraint::Id(name) => board.id.name == name.0,
        Constraint::Model(model) => board.model.as_deref() == Some(model.as_str()),
        Constraint::Tags(tags) => tags.iter().all(|t| board.tags.contains(t)),
        Constraint::Chip(chip) => &board.chip == chip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probefleet_proto::board::{BoardState, PowerKind};
    use probefleet_proto::ids::{BoardName, BoardRef, NodeId};

    fn org(name: &str) -> OrgId {
        OrgId(name.to_owned())
    }

    fn board(org_name: &str, name: &str, chip: &str, tags: &[&str]) -> Board {
        Board {
            id: BoardRef::new(org(org_name), NodeId("node-1".to_owned()), name),
            node: NodeId("node-1".to_owned()),
            chip: chip.to_owned(),
            model: None,
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
            serial_ports: Vec::new(),
        }
    }

    /// The same board, plus a declared board model.
    fn modelled_board(org_name: &str, name: &str, model: &str) -> Board {
        Board {
            model: Some(model.to_owned()),
            ..board(org_name, name, "nRF52840_xxAA", &[])
        }
    }

    fn grant(
        org_name: &str,
        selector: Constraint,
        ops: &[AllowedOp],
        expires: Option<u64>,
    ) -> GrantScope {
        GrantScope {
            id: format!("g-{org_name}"),
            org: org(org_name),
            selector,
            ops: ops.to_vec(),
            expires,
        }
    }

    fn tags(v: &[&str]) -> Constraint {
        Constraint::Tags(v.iter().map(|s| (*s).to_owned()).collect())
    }

    const NOW: u64 = 1_000;

    /// The (subject, object, op) → allow/deny matrix the spec asks for, as one
    /// table. Each row names the property it pins down.
    // A table-driven test: the length is the point, and splitting it would
    // scatter the matrix across functions. Tipped over the 100-line pedantic
    // limit by the whole-tree rustfmt pass, which only rewrapped rows.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn access_matrix() {
        let a_board = board("a", "b1", "nRF52840_xxAA", &["nrf52", "lab"]);
        let c_board = board("c", "b1", "nRF52840_xxAA", &["nrf52"]);
        // Two boards of the same model in org `a`, one in org `c`, and one
        // that declares no model at all (the adopted-board shape).
        let a_dk_1 = modelled_board("a", "dk-1", "nrf52840dk");
        let a_dk_2 = modelled_board("a", "dk-2", "nrf52840dk");
        let a_other_model = modelled_board("a", "pico-1", "rpi-pico");
        let c_dk = modelled_board("c", "dk-9", "nrf52840dk");
        let a_no_model = board("a", "adopted-1", "", &[]);

        let member_of_a = Access::own_org(org("a"));
        let granted_flash = Access {
            member_of: vec![org("b")],
            grants: vec![grant(
                "a",
                tags(&["nrf52"]),
                &[AllowedOp::Flash, AllowedOp::Attach],
                Some(2_000),
            )],
        };
        let expired = Access {
            member_of: vec![org("b")],
            grants: vec![grant(
                "a",
                tags(&["nrf52"]),
                &[AllowedOp::Attach],
                Some(NOW),
            )],
        };
        let selector_miss = Access {
            member_of: vec![org("b")],
            grants: vec![grant("a", tags(&["stm32"]), &[AllowedOp::Attach], None)],
        };
        let by_board_name = Access {
            member_of: vec![org("b")],
            grants: vec![grant(
                "a",
                Constraint::Id(BoardName("b1".to_owned())),
                &[AllowedOp::Attach],
                None,
            )],
        };
        let by_chip = Access {
            member_of: vec![org("b")],
            grants: vec![grant(
                "a",
                Constraint::Chip("nRF52840_xxAA".to_owned()),
                &[AllowedOp::Gdb],
                None,
            )],
        };
        let outsider = Access::own_org(org("b"));
        // A grant written against a board *model*: the requirement this whole
        // selector exists for (`grant bob --select 'board=nrf52840dk'`).
        let by_model = Access {
            member_of: vec![org("b")],
            grants: vec![grant(
                "a",
                Constraint::Model("nrf52840dk".to_owned()),
                &[AllowedOp::Attach],
                None,
            )],
        };

        #[allow(clippy::type_complexity)]
        let cases: &[(&str, &Access, &Board, AllowedOp, bool)] = &[
            // Ownership confers everything, including ops no grant listed.
            (
                "member of the board's org may attach",
                &member_of_a,
                &a_board,
                AllowedOp::Attach,
                true,
            ),
            (
                "member of the board's org may power-cycle",
                &member_of_a,
                &a_board,
                AllowedOp::PowerCycle,
                true,
            ),
            // A member of another org is not admitted by membership.
            (
                "non-member, no grant, is denied",
                &outsider,
                &a_board,
                AllowedOp::Attach,
                false,
            ),
            // A grant confers exactly its ops, and no more.
            (
                "grantee may use a granted op",
                &granted_flash,
                &a_board,
                AllowedOp::Flash,
                true,
            ),
            (
                "grantee may not use an ungranted op",
                &granted_flash,
                &a_board,
                AllowedOp::Gdb,
                false,
            ),
            (
                "grantee may not power-cycle without the op",
                &granted_flash,
                &a_board,
                AllowedOp::PowerCycle,
                false,
            ),
            // Time and selector.
            (
                "an expired grant confers nothing",
                &expired,
                &a_board,
                AllowedOp::Attach,
                false,
            ),
            (
                "a grant whose selector misses confers nothing",
                &selector_miss,
                &a_board,
                AllowedOp::Attach,
                false,
            ),
            // The degenerate individual-board grant.
            (
                "id= is a normal selector",
                &by_board_name,
                &a_board,
                AllowedOp::Attach,
                true,
            ),
            (
                "chip= is a normal selector",
                &by_chip,
                &a_board,
                AllowedOp::Gdb,
                true,
            ),
            // board= is the MODEL selector: it covers EVERY board of that
            // model in the granting org, and nothing else.
            (
                "board= covers one board of the model",
                &by_model,
                &a_dk_1,
                AllowedOp::Attach,
                true,
            ),
            (
                "board= covers every board of the model",
                &by_model,
                &a_dk_2,
                AllowedOp::Attach,
                true,
            ),
            (
                "board= does not cover another model",
                &by_model,
                &a_other_model,
                AllowedOp::Attach,
                false,
            ),
            (
                "board= never matches a board with no model",
                &by_model,
                &a_no_model,
                AllowedOp::Attach,
                false,
            ),
            (
                "board= confers only its ops",
                &by_model,
                &a_dk_1,
                AllowedOp::Flash,
                false,
            ),
            // THE ORG FENCE: a grant issued by org A must not reach org C's
            // identically tagged board, even though the selector matches it.
            (
                "a grant never crosses into a third org",
                &granted_flash,
                &c_board,
                AllowedOp::Flash,
                false,
            ),
            (
                "an id= grant never crosses either",
                &by_board_name,
                &c_board,
                AllowedOp::Attach,
                false,
            ),
            (
                "a model grant never crosses either",
                &by_model,
                &c_dk,
                AllowedOp::Attach,
                false,
            ),
            // Deny by default.
            (
                "empty access allows nothing",
                &Access::none(),
                &a_board,
                AllowedOp::Attach,
                false,
            ),
        ];

        for (why, access, board, op, expected) in cases {
            assert_eq!(access.allows(board, *op, NOW), *expected, "{why}");
        }
    }

    #[test]
    fn empty_access_is_empty_and_uses_nothing() {
        let a_board = board("a", "b1", "chip", &[]);
        let none = Access::none();
        assert!(none.is_empty());
        assert!(!none.may_use(&a_board, NOW));
        assert!(none.effective_ops(&a_board, NOW).is_empty());
        assert!(none.matching_grant(&a_board, NOW).is_none());
    }

    /// `may_use` (can I lease it?) is coarser than `allows` (can I do X?): a
    /// grantee with only `attach` may take the lease, and gets a token that
    /// says only `attach`.
    #[test]
    fn may_use_is_lease_time_and_effective_ops_is_op_time() {
        let a_board = board("a", "b1", "chip", &["nrf52"]);
        let access = Access {
            member_of: vec![org("b")],
            grants: vec![grant("a", tags(&["nrf52"]), &[AllowedOp::Attach], None)],
        };
        assert!(access.may_use(&a_board, NOW));
        assert_eq!(access.effective_ops(&a_board, NOW), vec![AllowedOp::Attach]);
        assert!(!access.allows(&a_board, AllowedOp::Flash, NOW));
    }

    #[test]
    fn ownership_confers_the_full_op_set() {
        let a_board = board("a", "b1", "chip", &[]);
        assert_eq!(
            Access::own_org(org("a")).effective_ops(&a_board, NOW),
            AllowedOp::all()
        );
    }

    /// Several grants on the same board union their ops.
    #[test]
    fn overlapping_grants_union_their_ops() {
        let a_board = board("a", "b1", "chip", &["nrf52", "lab"]);
        let access = Access {
            member_of: Vec::new(),
            grants: vec![
                grant("a", tags(&["nrf52"]), &[AllowedOp::Attach], None),
                grant("a", tags(&["lab"]), &[AllowedOp::Gdb], None),
            ],
        };
        assert_eq!(
            access.effective_ops(&a_board, NOW),
            vec![AllowedOp::Attach, AllowedOp::Gdb]
        );
    }

    /// Expiry is exclusive at the boundary, exactly like the capability token's.
    #[test]
    fn expiry_boundary_matches_the_capability_token() {
        let g = grant("a", tags(&[]), &[AllowedOp::Attach], Some(NOW));
        assert!(g.is_live_at(NOW - 1));
        assert!(!g.is_live_at(NOW));
        assert!(grant("a", tags(&[]), &[], None).is_live_at(u64::MAX));
    }

    /// A subject with no membership but a live grant is a first-class case: CI
    /// workloads have no `member` row at all.
    #[test]
    fn a_grant_works_without_any_membership() {
        let a_board = board("a", "b1", "chip", &["nrf52"]);
        let access = Access {
            member_of: Vec::new(),
            grants: vec![grant("a", tags(&["nrf52"]), &[AllowedOp::Attach], None)],
        };
        assert!(!access.is_empty());
        assert!(access.may_use(&a_board, NOW));
        assert_eq!(
            access.matching_grant(&a_board, NOW).map(|g| g.id.as_str()),
            Some("g-a")
        );
    }
}
