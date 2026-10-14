//! Lease request/grant types and selection constraints.
//!
//! A lease is *not* tied to a single `probe-rs run`: a subject claims a board
//! and holds it (with an extendable timeout) across many probe-rs invocations,
//! so remote DX feels local. See `docs/architecture.md` §6.

use serde::{Deserialize, Serialize};

use crate::ids::{BoardName, BoardRef, LeaseId, NodeId, SubjectKey};

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
    /// (erroring on ambiguity). This is the instance selector: `id=<name>`,
    /// `--id`, `PROBE_RS_FLEET_ID`.
    Id(BoardName),
    /// Any idle board of this board *model* (board type), e.g. `nrf52840dk`.
    ///
    /// The model is declared by the operator in `boards.toml`; the node
    /// cannot infer it (`probe-rs list` reports the probe, never the board it
    /// is wired to), so an auto-adopted board has no model and is never
    /// matched by `board=`.
    Model(String),
    /// Any idle board matching all of these tags.
    Tags(Vec<String>),
    /// Any idle board with this probe-rs chip name.
    Chip(String),
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
    /// An `id=`/`board=`/`chip=`/`tag=` term had an empty value.
    #[error("empty value for `{term}`")]
    EmptyValue {
        /// The offending term key (`id`, `board`, `chip` or `tag`).
        term: &'static str,
    },
    /// `id=`/`board=`/`chip=` cannot be conjoined — the wire [`Constraint`]
    /// has no representation for it.
    #[error("`{term}=` cannot be combined with other terms")]
    NotConjoinable {
        /// The offending term key.
        term: &'static str,
    },
    /// A term used an unknown `key=value` form.
    #[error("unsupported term `{0}`")]
    UnsupportedTerm(String),
    /// A term value made *only* of glob/regex metacharacters — `*`, `?`, `%`,
    /// `.*` and friends.
    ///
    /// There is deliberately no match-everything selector (see
    /// [`parse_constraint`]), so such a term is not "unsupported syntax" but a
    /// user reaching for a feature that does not and will not exist; the
    /// message therefore names the real answer instead of the grammar.
    #[error(
        "there is no wildcard selector. To reach a set of boards, tag them and \
         select the tag (`--select lab`); `probe-rs-fleet ctl list` shows what \
         you can reach."
    )]
    NoWildcard,
}

/// Whether a term value is made *only* of glob/regex metacharacters — `*`,
/// `?`, `%`, `.*`, `**`, `.+` and other such shapes.
///
/// "Every character is a metacharacter" is the whole rule, which is what keeps
/// it from touching legitimate tags: `nrf52840-dk-3`, `v1.2` and `lab.eu` all
/// contain ordinary characters and parse unchanged. A value of only `.` is
/// refused too — it could never name a board either.
fn looks_like_a_wildcard(value: &str) -> bool {
    value.chars().all(|c| "*?%.[]{}()|\\^$+".contains(c))
}

/// Parse a selector expression into a [`Constraint`].
///
/// This is the fleet's **one** selector grammar (architecture §6.5); the
/// sidecar's `PROBE_RS_FLEET_SELECT`, `ctl lease`, `grant --select` and
/// `ctl delegate --select` all funnel through it, with no per-caller dialect.
///
/// Grammar:
///
/// * `id=<name>` — exactly one board by node-local name. This is the
///   "individual board" case: a degenerate selector, not a special case.
/// * `board=<model>` — any board of that *model* (board type), e.g.
///   `board=nrf52840dk`. This is the word devs use, so it means the generic
///   thing; the instance selector is `id=`.
/// * `chip=<name>` — any board with that probe-rs chip name.
/// * `tag=<t>`, or a bare word — one required tag. **A bare word is always a
///   tag**, in every caller; `ctl lease nrf52840-dk-3` is therefore a tag
///   selector and the operator writes `ctl lease id=nrf52840-dk-3`.
/// * `a && b && …` — a conjunction, of tags only.
///
/// `id=`/`board=`/`chip=` are not conjoinable: the wire [`Constraint`] enum
/// cannot express it, and quietly dropping the extra terms would widen a
/// grant.
///
/// # There is no wildcard, by design
///
/// [`Constraint`] has no any-board variant, an empty tag set (which *would*
/// match every board) is refused at every entry point, and a delegation's
/// `CapabilityToken` binds one `BoardRef` — so "the whole fleet" is not
/// expressible, deliberately. A term whose value is made entirely of
/// glob/regex metacharacters is therefore refused with
/// [`ConstraintParseError::NoWildcard`], whose message names the actual answer
/// (tag the boards, select the tag). Without that check `--select '*'` parses
/// into a tag nothing carries and the user gets a message about board
/// contention — a diagnostic about the fleet, for a typo.
///
/// Tag values are *not* charset-validated in general, and that is a decision,
/// not an omission: board tags come from `boards.toml`, which the node never
/// charset-validates, so an alnum/`.`/`_`/`-` rule would reject tags that work
/// today, and would do it at selection time, far from the file. An unmatchable
/// tag is not dangerous either — it fails closed. Only the syntactically
/// wildcard-shaped case is refused, because only there is the diagnostic
/// actively misleading. `all` is left alone: it is a plausible literal tag,
/// and unlike `*` it is not syntactically a wildcard.
///
/// # Errors
///
/// Returns a [`ConstraintParseError`] for an empty expression, an empty term
/// value, a non-conjoinable term in a conjunction, an unknown `key=value`, or
/// a wildcard-looking term value.
pub fn parse_constraint(expr: &str) -> Result<Constraint, ConstraintParseError> {
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
        if let Some(name) = terms[0].strip_prefix("id=") {
            let name = name.trim();
            if name.is_empty() {
                return Err(ConstraintParseError::EmptyValue { term: "id" });
            }
            if looks_like_a_wildcard(name) {
                return Err(ConstraintParseError::NoWildcard);
            }
            return Ok(Constraint::Id(BoardName(name.to_owned())));
        }
        if let Some(model) = terms[0].strip_prefix("board=") {
            let model = model.trim();
            if model.is_empty() {
                return Err(ConstraintParseError::EmptyValue { term: "board" });
            }
            if looks_like_a_wildcard(model) {
                return Err(ConstraintParseError::NoWildcard);
            }
            return Ok(Constraint::Model(model.to_owned()));
        }
        if let Some(chip) = terms[0].strip_prefix("chip=") {
            let chip = chip.trim();
            if chip.is_empty() {
                return Err(ConstraintParseError::EmptyValue { term: "chip" });
            }
            if looks_like_a_wildcard(chip) {
                return Err(ConstraintParseError::NoWildcard);
            }
            return Ok(Constraint::Chip(chip.to_owned()));
        }
    }

    let mut tags = Vec::with_capacity(terms.len());
    for term in terms {
        for key in ["id", "board", "chip"] {
            if term.starts_with(&format!("{key}=")) {
                return Err(ConstraintParseError::NotConjoinable { term: key });
            }
        }
        let tag = term.strip_prefix("tag=").unwrap_or(term).trim();
        if tag.is_empty() {
            return Err(ConstraintParseError::EmptyValue { term: "tag" });
        }
        if tag.contains('=') {
            return Err(ConstraintParseError::UnsupportedTerm(term.to_owned()));
        }
        // *After* the `=` check: `*=*` is an unknown-key typo, and
        // `unsupported term` is the better message for it. `tag=*` and a bare
        // `*` both still reach here — the `tag=` prefix is stripped above, so
        // what is left carries no `=`.
        if looks_like_a_wildcard(tag) {
            return Err(ConstraintParseError::NoWildcard);
        }
        tags.push(tag.to_owned());
    }
    Ok(Constraint::Tags(tags))
}

/// The canonical, round-trippable rendering of a [`Constraint`].
///
/// `parse_constraint(&c.to_string()) == Ok(c)` for every constraint this
/// grammar can produce. Grants store *this* form, so what a
/// grant means never depends on which CLI wrote it.
///
/// Note this is deliberately **not** the sidecar's `lease_cache::fingerprint`,
/// which sorts and dedups tags for set-equality as a cache key. Two different
/// jobs; unifying them would make one of them wrong.
impl std::fmt::Display for Constraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Constraint::Id(BoardName(name)) => write!(f, "id={name}"),
            Constraint::Model(model) => write!(f, "board={model}"),
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
    Queued {
        position: u32,
    },
}

/// A granted lease. The capability `token` is verified locally by the node;
/// it does not require a coordinator round-trip per operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub lease: LeaseId,
    pub board: BoardRef,
    pub node: NodeId,
    pub holder: SubjectKey,
    /// Expiry as epoch seconds; extend via heartbeat before this.
    pub expires: u64,
    /// Opaque signed capability token (see `fleet-coordinator` auth).
    ///
    /// **This is not a data-plane credential.** It is the *delegation*
    /// artefact (`ctl delegate` hands exactly these bytes to a sandbox) and
    /// the lease cache's identity. Two other credentials do the data-plane
    /// jobs, both arriving per channel in `CoordToSidecar::ChannelOpened`:
    /// its `token` is the per-channel capability the **node** verifies, and
    /// its `serve_token` is the lease-scoped secret **`probe-rs serve`**
    /// accepts. All three differ as soon as the lease is extended or a grant
    /// attenuates `allowed_ops`.
    pub token: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(v: &[&str]) -> Constraint {
        Constraint::Tags(v.iter().map(|s| (*s).to_owned()).collect())
    }

    /// One reading of a bare word, everywhere: it is a tag. `ctl lease foo`
    /// used to mean the board named `foo`; it now means `tag=foo`, and the
    /// instance form is `ctl lease id=foo`.
    #[test]
    fn a_bare_word_is_always_a_tag() {
        assert_eq!(parse_constraint("nrf52").unwrap(), tags(&["nrf52"]));
        assert_eq!(
            parse_constraint("nrf52840-dk-3").unwrap(),
            tags(&["nrf52840-dk-3"])
        );
    }

    /// `board=` is the *model* (board type); `id=` is the one instance.
    #[test]
    fn board_is_the_model_and_id_is_the_instance() {
        assert_eq!(
            parse_constraint("board=nrf52840dk").unwrap(),
            Constraint::Model("nrf52840dk".to_owned())
        );
        assert_eq!(
            parse_constraint("id=nrf52840-dk-3").unwrap(),
            Constraint::Id(BoardName("nrf52840-dk-3".to_owned()))
        );
    }

    #[test]
    fn explicit_terms_are_unambiguous() {
        assert_eq!(
            parse_constraint("id=b1").unwrap(),
            Constraint::Id(BoardName("b1".to_owned()))
        );
        assert_eq!(
            parse_constraint("chip=nRF52840_xxAA").unwrap(),
            Constraint::Chip("nRF52840_xxAA".to_owned())
        );
        assert_eq!(parse_constraint("tag=lab").unwrap(), tags(&["lab"]));
    }

    #[test]
    fn tags_conjoin_in_order() {
        assert_eq!(
            parse_constraint("tag=nrf52 && bluetooth").unwrap(),
            tags(&["nrf52", "bluetooth"])
        );
    }

    /// An empty expression must never become `Tags([])`, which matches every
    /// board — the difference between "no grant" and "grant everything".
    #[test]
    fn an_empty_expression_is_refused_not_defaulted() {
        assert_eq!(parse_constraint(""), Err(ConstraintParseError::Empty));
        assert_eq!(parse_constraint("  &&  "), Err(ConstraintParseError::Empty));
    }

    #[test]
    fn non_conjoinable_terms_are_rejected_rather_than_truncated() {
        assert_eq!(
            parse_constraint("id=b1 && tag=lab"),
            Err(ConstraintParseError::NotConjoinable { term: "id" })
        );
        assert_eq!(
            parse_constraint("board=nrf52840dk && tag=lab"),
            Err(ConstraintParseError::NotConjoinable { term: "board" })
        );
        assert_eq!(
            parse_constraint("chip=x && tag=lab"),
            Err(ConstraintParseError::NotConjoinable { term: "chip" })
        );
    }

    #[test]
    fn empty_values_and_unknown_keys_are_errors() {
        assert_eq!(
            parse_constraint("id="),
            Err(ConstraintParseError::EmptyValue { term: "id" })
        );
        assert_eq!(
            parse_constraint("board="),
            Err(ConstraintParseError::EmptyValue { term: "board" })
        );
        assert_eq!(
            parse_constraint("chip="),
            Err(ConstraintParseError::EmptyValue { term: "chip" })
        );
        assert_eq!(
            parse_constraint("tag="),
            Err(ConstraintParseError::EmptyValue { term: "tag" })
        );
        assert_eq!(
            parse_constraint("colour=red"),
            Err(ConstraintParseError::UnsupportedTerm(
                "colour=red".to_owned()
            ))
        );
    }

    /// `--select '*'` is the obvious first guess for "everything", and before
    /// this check it parsed into a tag no board carries: the user then got a
    /// message about board contention, i.e. a diagnostic about the fleet for
    /// what is a typo. The message must name the real answer.
    #[test]
    fn a_wildcard_looking_term_is_refused_with_the_real_answer() {
        for expr in [
            "*", "?", "%", ".*", "**", ".+", ".", "tag=*", "lab && *", "board=*", "id=*", "chip=.*",
        ] {
            assert_eq!(
                parse_constraint(expr),
                Err(ConstraintParseError::NoWildcard),
                "{expr} should be refused as a wildcard"
            );
        }
        let msg = ConstraintParseError::NoWildcard.to_string();
        assert!(msg.contains("no wildcard selector"), "{msg}");
        assert!(msg.contains("ctl list"), "{msg}");
    }

    /// The check is "every character is a metacharacter", so ordinary tags with
    /// dots and dashes are untouched — general charset validation was declined
    /// deliberately (see `parse_constraint`'s doc comment).
    #[test]
    fn tags_with_dots_and_dashes_still_parse() {
        for expr in ["nrf52840-dk-3", "v1.2", "lab.eu", "tag=a.b-c_d"] {
            assert!(parse_constraint(expr).is_ok(), "{expr} should parse");
        }
        // Deliberately *not* rejected: a literal `all` tag is plausible, and
        // `all` is not syntactically a wildcard.
        assert_eq!(parse_constraint("all"), Ok(tags(&["all"])));
    }

    /// `*=*` is an unknown-key typo, not a wildcard, and the unsupported-term
    /// message is the better one for it: the wildcard check runs *after* the
    /// `=` check for exactly this reason.
    #[test]
    fn a_metacharacter_key_keeps_the_unsupported_term_message() {
        assert_eq!(
            parse_constraint("*=*"),
            Err(ConstraintParseError::UnsupportedTerm("*=*".to_owned()))
        );
    }

    /// The stored form of a grant is `Display`; evaluation re-parses it. If the
    /// round trip did not hold, a grant would silently change meaning.
    #[test]
    fn display_round_trips_through_the_parser() {
        for c in [
            Constraint::Id(BoardName("nrf52840-dk-3".to_owned())),
            Constraint::Model("nrf52840dk".to_owned()),
            Constraint::Chip("nRF52840_xxAA".to_owned()),
            tags(&["nrf52"]),
            tags(&["nrf52", "bluetooth", "lab"]),
        ] {
            let rendered = c.to_string();
            assert_eq!(
                parse_constraint(&rendered),
                Ok(c.clone()),
                "round trip failed for {rendered}"
            );
        }
    }

    #[test]
    fn display_is_canonical() {
        assert_eq!(
            parse_constraint("nrf52 && tag=lab").unwrap().to_string(),
            "tag=nrf52 && tag=lab"
        );
        assert_eq!(parse_constraint("id=b1").unwrap().to_string(), "id=b1");
        assert_eq!(
            parse_constraint("board=nrf52840dk").unwrap().to_string(),
            "board=nrf52840dk"
        );
    }
}
