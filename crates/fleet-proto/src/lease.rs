//! Lease request/grant types and selection constraints.
//!
//! A lease is *not* tied to a single `probe-rs run`: a subject claims a board
//! and holds it (with an extendable timeout) across many probe-rs invocations,
//! so remote DX feels local. See `docs/architecture.md` §6.

use serde::{Deserialize, Serialize};

use crate::ids::{AgentId, BoardName, BoardRef, LeaseId, Subject};

/// A request to lease a board, by id or by constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub select: Constraint,
    /// Requested hold duration in seconds; the coordinator may cap it by
    /// policy. The lease is extendable via heartbeat/activity.
    pub duration_secs: u64,
    /// Priority class; higher wins when boards are scarce.
    pub priority: Priority,
}

/// How a caller picks a board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Constraint {
    /// Exactly this board, by its node-local name.
    ///
    /// A bare name is only unique within one node of one org, so the
    /// coordinator resolves it to a [`BoardRef`] **within the caller's org**
    /// (erroring on ambiguity). Keeping the request side node-local is what
    /// lets `PROBE_RS_FLEET_BOARD=nrf52840-dk-3` keep working unchanged.
    Board(BoardName),
    /// Any idle board matching all of these tags.
    Tags(Vec<String>),
    /// Any idle board with this probe-rs chip name.
    Chip(String),
}

/// What a bare (unprefixed) term in a selector expression means.
///
/// Two callers disagree, and the disagreement is real rather than accidental,
/// so it is a parameter instead of being silently unified:
///
/// * `PROBE_RS_FLEET_SELECT=nrf52 && bluetooth` is a *tag* conjunction — the
///   sidecar's selector is a fleet-wide "any board like this";
/// * `ctl lease nrf52840-dk-3` names a *board* — the operator verb takes an id.
///
/// Grants use [`BareTerm::Tag`]: a grant's whole point is to describe a set,
/// and an individual-board grant is spelled `board=<name>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareTerm {
    /// A bare word is a tag.
    Tag,
    /// A bare word is a node-local board name.
    Board,
}

/// Why a selector expression could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConstraintParseError {
    /// The expression had no terms at all.
    ///
    /// Refused rather than defaulted: an empty [`Constraint::Tags`] matches
    /// **every** board, which is the last thing a grant should silently mean.
    #[error("selector expression is empty")]
    Empty,
    /// A `board=`/`chip=`/`tag=` term had an empty value.
    #[error("empty value for `{term}`")]
    EmptyValue {
        /// The offending term key (`board`, `chip` or `tag`).
        term: &'static str,
    },
    /// `board=`/`chip=` cannot be conjoined — the wire [`Constraint`] has no
    /// representation for it.
    #[error("`{term}=` selects exactly one board and cannot be combined with other terms")]
    NotConjoinable {
        /// The offending term key.
        term: &'static str,
    },
    /// A term used an unknown `key=value` form.
    #[error("unsupported term `{0}`")]
    UnsupportedTerm(String),
}

/// Parse a selector expression into a [`Constraint`].
///
/// This is the fleet's **one** selector grammar (architecture §6.5); the
/// sidecar's `PROBE_RS_FLEET_SELECT`, `ctl lease`, `grant --select` and
/// `ctl delegate --select` all funnel through it, differing only in `bare`.
///
/// Grammar:
///
/// * `board=<name>` — exactly one board by node-local name. This is the
///   "individual board" case: a degenerate selector, not a special case.
/// * `chip=<name>` — any board with that probe-rs chip name.
/// * `tag=<t>`, or a bare word under [`BareTerm::Tag`] — one required tag.
/// * `a && b && …` — a conjunction, of tags only.
///
/// `board=`/`chip=` are not conjoinable: the wire [`Constraint`] enum cannot
/// express it, and quietly dropping the extra terms would widen a grant.
///
/// # Errors
///
/// Returns a [`ConstraintParseError`] for an empty expression, an empty term
/// value, a non-conjoinable term in a conjunction, or an unknown `key=value`.
pub fn parse_constraint(expr: &str, bare: BareTerm) -> Result<Constraint, ConstraintParseError> {
    let terms: Vec<&str> = expr
        .split("&&")
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();

    if terms.is_empty() {
        return Err(ConstraintParseError::Empty);
    }

    // Single-term forms that are not tags.
    if terms.len() == 1 {
        if let Some(name) = terms[0].strip_prefix("board=") {
            let name = name.trim();
            if name.is_empty() {
                return Err(ConstraintParseError::EmptyValue { term: "board" });
            }
            return Ok(Constraint::Board(BoardName(name.to_owned())));
        }
        if let Some(chip) = terms[0].strip_prefix("chip=") {
            let chip = chip.trim();
            if chip.is_empty() {
                return Err(ConstraintParseError::EmptyValue { term: "chip" });
            }
            return Ok(Constraint::Chip(chip.to_owned()));
        }
        if bare == BareTerm::Board && !terms[0].contains('=') {
            return Ok(Constraint::Board(BoardName(terms[0].to_owned())));
        }
    }

    let mut tags = Vec::with_capacity(terms.len());
    for term in terms {
        for key in ["board", "chip"] {
            if term.starts_with(&format!("{key}=")) {
                return Err(ConstraintParseError::NotConjoinable { term: key });
            }
        }
        let is_bare = !term.contains('=');
        if is_bare && bare == BareTerm::Board {
            // A conjunction of board names is meaningless.
            return Err(ConstraintParseError::NotConjoinable { term: "board" });
        }
        let tag = term.strip_prefix("tag=").unwrap_or(term).trim();
        if tag.is_empty() {
            return Err(ConstraintParseError::EmptyValue { term: "tag" });
        }
        if tag.contains('=') {
            return Err(ConstraintParseError::UnsupportedTerm(term.to_owned()));
        }
        tags.push(tag.to_owned());
    }
    Ok(Constraint::Tags(tags))
}

/// The canonical, round-trippable rendering of a [`Constraint`].
///
/// `parse_constraint(&c.to_string(), BareTerm::Tag) == Ok(c)` for every
/// constraint this grammar can produce. Grants store *this* form, so what a
/// grant means never depends on which CLI wrote it.
///
/// Note this is deliberately **not** the sidecar's `lease_cache::fingerprint`,
/// which sorts and dedups tags for set-equality as a cache key. Two different
/// jobs; unifying them would make one of them wrong.
impl std::fmt::Display for Constraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Constraint::Board(BoardName(name)) => write!(f, "board={name}"),
            Constraint::Chip(chip) => write!(f, "chip={chip}"),
            Constraint::Tags(tags) => {
                for (i, tag) in tags.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" && ")?;
                    }
                    write!(f, "tag={tag}")?;
                }
                Ok(())
            }
        }
    }
}

/// Priority classes for fairness when boards are contended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Soak = 0,
    Ci = 1,
    Interactive = 2,
}

/// Outcome of a [`LeaseRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseOutcome {
    Granted(LeaseGrant),
    /// No board free; position in the queue (0-based).
    Queued { position: u32 },
}

/// A granted lease. The capability `token` is verified locally by the agent;
/// it does not require a coordinator round-trip per operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub lease: LeaseId,
    pub board: BoardRef,
    pub agent: AgentId,
    pub holder: Subject,
    /// Expiry as epoch seconds; extend via heartbeat before this.
    pub expires: u64,
    /// Opaque signed capability token (see `fleet-coordinator` auth).
    ///
    /// **This is not the data-plane credential.** It is the *delegation*
    /// artefact (`ctl delegate` hands exactly these bytes to a sandbox) and
    /// the lease cache's identity. The bytes a probe-rs client must present to
    /// `probe-rs serve` are the ones the coordinator sent the agent, returned
    /// per channel in `CoordToSidecar::ChannelOpened { token }` — they differ
    /// as soon as the lease is extended or a grant attenuates `allowed_ops`.
    pub token: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(v: &[&str]) -> Constraint {
        Constraint::Tags(v.iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn bare_term_means_tag_or_board_depending_on_the_caller() {
        assert_eq!(
            parse_constraint("nrf52", BareTerm::Tag).unwrap(),
            tags(&["nrf52"])
        );
        assert_eq!(
            parse_constraint("nrf52840-dk-3", BareTerm::Board).unwrap(),
            Constraint::Board(BoardName("nrf52840-dk-3".to_owned()))
        );
    }

    #[test]
    fn explicit_terms_are_unambiguous_under_either_bare_rule() {
        for bare in [BareTerm::Tag, BareTerm::Board] {
            assert_eq!(
                parse_constraint("board=b1", bare).unwrap(),
                Constraint::Board(BoardName("b1".to_owned()))
            );
            assert_eq!(
                parse_constraint("chip=nRF52840_xxAA", bare).unwrap(),
                Constraint::Chip("nRF52840_xxAA".to_owned())
            );
            assert_eq!(parse_constraint("tag=lab", bare).unwrap(), tags(&["lab"]));
        }
    }

    #[test]
    fn tags_conjoin_in_order() {
        assert_eq!(
            parse_constraint("tag=nrf52 && bluetooth", BareTerm::Tag).unwrap(),
            tags(&["nrf52", "bluetooth"])
        );
    }

    /// An empty expression must never become `Tags([])`, which matches every
    /// board — the difference between "no grant" and "grant everything".
    #[test]
    fn an_empty_expression_is_refused_not_defaulted() {
        assert_eq!(
            parse_constraint("", BareTerm::Tag),
            Err(ConstraintParseError::Empty)
        );
        assert_eq!(
            parse_constraint("  &&  ", BareTerm::Tag),
            Err(ConstraintParseError::Empty)
        );
    }

    #[test]
    fn non_conjoinable_terms_are_rejected_rather_than_truncated() {
        assert_eq!(
            parse_constraint("board=b1 && tag=lab", BareTerm::Tag),
            Err(ConstraintParseError::NotConjoinable { term: "board" })
        );
        assert_eq!(
            parse_constraint("chip=x && tag=lab", BareTerm::Tag),
            Err(ConstraintParseError::NotConjoinable { term: "chip" })
        );
        assert_eq!(
            parse_constraint("b1 && b2", BareTerm::Board),
            Err(ConstraintParseError::NotConjoinable { term: "board" })
        );
    }

    #[test]
    fn empty_values_and_unknown_keys_are_errors() {
        assert_eq!(
            parse_constraint("board=", BareTerm::Tag),
            Err(ConstraintParseError::EmptyValue { term: "board" })
        );
        assert_eq!(
            parse_constraint("chip=", BareTerm::Tag),
            Err(ConstraintParseError::EmptyValue { term: "chip" })
        );
        assert_eq!(
            parse_constraint("tag=", BareTerm::Tag),
            Err(ConstraintParseError::EmptyValue { term: "tag" })
        );
        assert_eq!(
            parse_constraint("colour=red", BareTerm::Tag),
            Err(ConstraintParseError::UnsupportedTerm("colour=red".to_owned()))
        );
    }

    /// The stored form of a grant is `Display`; evaluation re-parses it. If the
    /// round trip did not hold, a grant would silently change meaning.
    #[test]
    fn display_round_trips_through_the_parser() {
        for c in [
            Constraint::Board(BoardName("nrf52840-dk-3".to_owned())),
            Constraint::Chip("nRF52840_xxAA".to_owned()),
            tags(&["nrf52"]),
            tags(&["nrf52", "bluetooth", "lab"]),
        ] {
            let rendered = c.to_string();
            assert_eq!(
                parse_constraint(&rendered, BareTerm::Tag),
                Ok(c.clone()),
                "round trip failed for {rendered}"
            );
        }
    }

    #[test]
    fn display_is_canonical() {
        assert_eq!(
            parse_constraint("nrf52 && tag=lab", BareTerm::Tag)
                .unwrap()
                .to_string(),
            "tag=nrf52 && tag=lab"
        );
    }
}
