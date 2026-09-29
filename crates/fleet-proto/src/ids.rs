//! Identifier newtypes and the wire form of a caller's identity
//! ([`SubjectKey`]) used across the fleet protocol.
//!
//! Identity, orgs and membership are owned by **forgs** (the coordinator's
//! identity layer); this crate only mirrors the shapes that cross the wire, so
//! the node, sidecar and CLI never link an identity store:
//!
//! * [`OrgId`] carries a forgs namespace-node id (a 26-character ULID
//!   rendering) — fleet's only namespace kind is `org`.
//! * [`SubjectKey`] is the wire mirror of `forgs::SubjectKey`, with identical
//!   rendering and parse rules. The coordinator converts between the two by
//!   rendering and re-parsing.
//! * A board is keyed `(org, node, name)` ([`BoardRef`]), not by a globally
//!   unique string. The node-local half of that key is a [`BoardName`], which
//!   is all a node knows about itself.

use serde::{Deserialize, Serialize};

/// An org id: the rendering of a forgs namespace-node id (`NsNodeId`, a
/// 26-character ULID such as `01J0000000000000000000ORG1`).
///
/// Every object in the fleet belongs to exactly one org; a personal org (an
/// org of one) exists for every user. The id is immutable — an org's *path*
/// (its display name) can be renamed, its id cannot — so it is what boards,
/// nodes and grants are keyed by.
///
/// There is deliberately **no** user-owned/org-owned branch: one scoping rule
/// everywhere, so no code path can forget the org check (architecture §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrgId(pub String);

/// A node id — a machine offering probes to the fleet.
///
/// Namespaced by org (`<org id>/rpi-1`, see `state.rs::node_id_for`), so the
/// same machine name in two tenants is two nodes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeId(pub String);

/// Identifies an active lease. Allocated by the coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LeaseId(pub u64);

/// A board's node-local name, as declared in that node's `boards.toml`.
///
/// **Not fleet-unique**: two orgs may each plug in an `nrf52840-dk`. Only a
/// [`BoardRef`] identifies a board across the fleet. The node genuinely does
/// not know its own org, so this is the only board identifier it can mint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BoardName(pub String);

/// A board's fleet-unique key: `(org, node, name)` (architecture §6.1).
///
/// A `BoardRef` can only be built where the org is known — in practice only the
/// coordinator, from an authenticated node connection. That is what makes
/// cross-org board injection unrepresentable rather than merely discouraged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BoardRef {
    /// The owning org.
    pub org: OrgId,
    /// The node hosting the board.
    pub node: NodeId,
    /// The node-local board name.
    pub name: String,
}

impl BoardRef {
    /// Build a board reference from its three parts.
    #[must_use]
    pub fn new(org: OrgId, node: NodeId, name: impl Into<String>) -> Self {
        Self {
            org,
            node,
            name: name.into(),
        }
    }

    /// The node-local name half of this key.
    #[must_use]
    pub fn board_name(&self) -> BoardName {
        BoardName(self.name.clone())
    }

    /// Does this board answer to what a user typed?
    ///
    /// A board is normally named by its bare node-local name, but once boards
    /// can be **shared** across orgs (§6.5) two boards can answer to
    /// `nrf52840-dk-3`, so a caller needs a way to say which. This is that
    /// grammar, and it lives here rather than in either caller because the
    /// coordinator's resolver and `ctl release`'s board lookup must agree
    /// exactly — two copies of it drifted once already.
    ///
    /// The board name is always the **last** slash-separated segment; anything
    /// before it is a qualifier, matched against:
    ///
    /// * nothing — a bare `dk-3`;
    /// * the node's short name — `rpi-1/dk-3`;
    /// * the full node id — `<org id>/rpi-1/dk-3`;
    /// * org + node id — `<org id>/<org id>/rpi-1/dk-3`, which is this type's own
    ///   [`std::fmt::Display`], so a key copied out of `ctl list` works verbatim.
    ///
    /// # Why counting segments does not work
    ///
    /// A production [`NodeId`] is **already org-prefixed** (`<org id>/rpi-1`):
    /// node ids are namespaced by org so the same machine name in two tenants
    /// is two nodes. So a `BoardRef` has a variable number of segments, and the
    /// obvious `split('/')` into `[org, node, name]` cannot address a real
    /// board at all. Peel the name off the end instead, and compare the
    /// remainder as a whole.
    ///
    /// See [`BoardRef::answers_to_in`] for the additional org-path spelling
    /// the coordinator can offer when it knows the org's display name.
    #[must_use]
    pub fn answers_to(&self, typed: &str) -> bool {
        self.answers_to_in(typed, None)
    }

    /// [`BoardRef::answers_to`], additionally accepting the org's **path**
    /// (its human display name, e.g. `ariel-os`) in front of the node's short
    /// name: `ariel-os/rpi-1/dk-3`.
    ///
    /// An [`OrgId`] is an opaque ULID nobody types, so this is the spelling a
    /// human actually uses to disambiguate two same-named boards. Only the
    /// coordinator knows the path (it lives in forgs), so it is a parameter
    /// rather than part of the key; `None` behaves exactly like
    /// [`BoardRef::answers_to`].
    #[must_use]
    pub fn answers_to_in(&self, typed: &str, org_path: Option<&str>) -> bool {
        let (qualifier, name) = match typed.rsplit_once('/') {
            Some((qualifier, name)) => (Some(qualifier), name),
            None => (None, typed),
        };
        if self.name != name {
            return false;
        }
        let Some(qualifier) = qualifier else {
            return true;
        };
        // The node's short name: the trailing segment of its id, which is what
        // the machine calls itself and what `share` / `node up` were given.
        let node_short = self.node.0.rsplit('/').next().unwrap_or(&self.node.0);
        qualifier == self.node.0
            || qualifier == node_short
            || qualifier == format!("{}/{}", self.org.0, self.node.0)
            || org_path
                .is_some_and(|path| !path.is_empty() && qualifier == format!("{path}/{node_short}"))
    }
}

/// Which authentication path produced a caller's identity.
///
/// The wire mirror of `forgs::SubjectKind`, with fleet's one app kind (`node`)
/// spelled out as a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SubjectKind {
    /// A human, authenticated by a user session.
    User,
    /// A node (the machine hosting probes), authenticated by its node
    /// credential. forgs sees this as the app kind `node`.
    Node,
    /// A CI workload, authenticated by an exchanged workload token.
    Workload,
}

impl SubjectKind {
    /// The label this kind renders as (`user` | `node` | `workload`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectKind::User => "user",
            SubjectKind::Node => "node",
            SubjectKind::Workload => "workload",
        }
    }

    fn from_label(s: &str) -> Option<Self> {
        match s {
            "user" => Some(SubjectKind::User),
            "node" => Some(SubjectKind::Node),
            "workload" => Some(SubjectKind::Workload),
            _ => None,
        }
    }
}

impl std::fmt::Display for SubjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The stable identity of an authenticated caller, as it crosses the wire:
/// the lease holder, a grant's subject, an audit row's actor.
///
/// The wire mirror of `forgs::SubjectKey`, rendering identically as
/// `[<ns>/]<kind>:<id>`:
///
/// * `user:01J…` — a user, by immutable forgs user id (no namespace: a user is
///   not addressed "in" an org);
/// * `01J…/node:01J…/rpi-1` — a node, scoped by its org's namespace id;
/// * `gha/workload:owner/repo` — a GitHub Actions workload (`gha` is a
///   reserved namespace slot, not an org);
/// * `01J…/workload:agent:builder` / `01J…/workload:key:<hash8>` — an
///   API-key identity, scoped by the org that minted it.
///
/// [`SubjectKey::parse`] splits at the first `/` **only when it comes before
/// the first `:`**, then at the first `:`, so ids may contain `/` and `:` and
/// still round-trip while a namespace can contain neither. The fields are
/// private so a key cannot be assembled in a shape that would not round-trip;
/// build one with [`SubjectKey::new`] or [`SubjectKey::parse`].
///
/// Deserialisation does **not** re-validate: the struct form only ever comes
/// from a peer that built it through these constructors, and every consumer
/// compares keys by equality, never by re-rendering into another key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubjectKey {
    ns: Option<String>,
    kind: SubjectKind,
    id: String,
}

impl SubjectKey {
    /// A key from parts.
    ///
    /// Returns `None` if the parts would not round-trip through
    /// [`SubjectKey::parse`]: an empty namespace or id, a namespace containing
    /// `/`, `:` or a control character, or an id containing a control
    /// character. Same rules as `forgs::SubjectKey::new`.
    #[must_use]
    pub fn new(ns: Option<&str>, kind: SubjectKind, id: &str) -> Option<Self> {
        if let Some(ns) = ns {
            if ns.is_empty() || ns.contains(['/', ':']) || has_control(ns) {
                return None;
            }
        }
        if id.is_empty() || has_control(id) {
            return None;
        }
        Some(Self {
            ns: ns.map(str::to_owned),
            kind,
            id: id.to_owned(),
        })
    }

    /// The namespace slot, if any (`gha`, or an org's namespace id).
    #[must_use]
    pub fn ns(&self) -> Option<&str> {
        self.ns.as_deref()
    }

    /// How the subject authenticated.
    #[must_use]
    pub fn kind(&self) -> SubjectKind {
        self.kind
    }

    /// The id, unique within `(ns, kind)`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Parse a rendered subject key (`[<ns>/]<kind>:<id>`).
    ///
    /// The inverse of [`std::fmt::Display`], and equivalent to
    /// `forgs::SubjectKey::parse_with(s, &["node"])`. Returns `None` on any
    /// shape or kind it does not recognise — a grant whose subject will not
    /// parse must be dropped closed, never widened into a match-anything.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let colon = s.find(':')?;
        let (ns, rest) = match s.find('/') {
            Some(slash) if slash < colon => (Some(&s[..slash]), &s[slash + 1..]),
            _ => (None, s),
        };
        let (kind, id) = rest.split_once(':')?;
        Self::new(ns, SubjectKind::from_label(kind)?, id)
    }
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

impl std::fmt::Display for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for BoardName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for BoardRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.org.0, self.node.0, self.name)
    }
}

impl std::fmt::Display for SubjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ns) = &self.ns {
            write!(f, "{ns}/")?;
        }
        write!(f, "{}:{}", self.kind, self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG_A: &str = "01J0000000000000000000ORG1";
    const ORG_B: &str = "01J0000000000000000000ORG2";
    const USER: &str = "01J00000000000000000USER01";

    fn org(id: &str) -> OrgId {
        OrgId(id.to_owned())
    }

    #[test]
    fn a_user_key_renders_without_a_namespace() {
        let key = SubjectKey::new(None, SubjectKind::User, USER).unwrap();
        assert_eq!(key.to_string(), format!("user:{USER}"));
        assert_eq!(key.ns(), None);
        assert_eq!(key.kind(), SubjectKind::User);
        assert_eq!(key.id(), USER);
    }

    #[test]
    fn same_id_in_different_namespaces_is_a_different_subject() {
        let a = SubjectKey::new(Some(ORG_A), SubjectKind::Node, "rpi-1").unwrap();
        let b = SubjectKey::new(Some(ORG_B), SubjectKind::Node, "rpi-1").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn subject_keys_parse_back_from_their_rendering() {
        for key in [
            SubjectKey::new(None, SubjectKind::User, USER).unwrap(),
            SubjectKey::new(Some(ORG_A), SubjectKind::Node, &format!("{ORG_A}/rpi-1")).unwrap(),
            SubjectKey::new(Some("gha"), SubjectKind::Workload, "ariel-os/ariel-os").unwrap(),
            SubjectKey::new(Some(ORG_A), SubjectKind::Workload, "agent:builder").unwrap(),
            SubjectKey::new(Some(ORG_A), SubjectKind::Workload, "key:deadbeef").unwrap(),
        ] {
            assert_eq!(SubjectKey::parse(&key.to_string()), Some(key));
        }
    }

    /// The renderings forgs produces, verbatim: the coordinator converts
    /// between the two types by rendering one and parsing the other.
    #[test]
    fn forgs_renderings_parse_to_the_expected_parts() {
        let k = SubjectKey::parse("gha/workload:ariel-os/ariel-os").unwrap();
        assert_eq!(
            (k.ns(), k.kind(), k.id()),
            (Some("gha"), SubjectKind::Workload, "ariel-os/ariel-os")
        );
        let k = SubjectKey::parse(&format!("{ORG_A}/node:{ORG_A}/rpi-1")).unwrap();
        assert_eq!(k.ns(), Some(ORG_A));
        assert_eq!(k.kind(), SubjectKind::Node);
        assert_eq!(k.id(), format!("{ORG_A}/rpi-1"));
    }

    /// An id containing `:` still parses, and a `/` after the first `:`
    /// belongs to the id, not the namespace.
    #[test]
    fn parse_splits_at_the_first_separators() {
        let k = SubjectKey::parse("acme/user:x:2").unwrap();
        assert_eq!(k.id(), "x:2");
        assert_eq!(k.ns(), Some("acme"));
        let k = SubjectKey::parse("workload:a/b").unwrap();
        assert_eq!(k.ns(), None);
        assert_eq!(k.id(), "a/b");
    }

    #[test]
    fn malformed_subject_keys_are_rejected_not_guessed() {
        for bad in [
            "acme/user",
            "acme/root:alice",
            "/user:alice",
            "acme/user:",
            "user:",
            "alice",
            "",
            "a/b/user:x",
            "user:a\nb",
            "Node:x",
        ] {
            assert_eq!(SubjectKey::parse(bad), None, "{bad:?} should not parse");
        }
    }

    #[test]
    fn new_rejects_shapes_that_would_not_round_trip() {
        assert!(SubjectKey::new(Some("a/b"), SubjectKind::User, "x").is_none());
        assert!(SubjectKey::new(Some("a:b"), SubjectKind::User, "x").is_none());
        assert!(SubjectKey::new(Some(""), SubjectKind::User, "x").is_none());
        assert!(SubjectKey::new(Some("a\tb"), SubjectKind::User, "x").is_none());
        assert!(SubjectKey::new(None, SubjectKind::User, "").is_none());
        assert!(SubjectKey::new(None, SubjectKind::User, "a\nb").is_none());
    }

    #[test]
    fn board_ref_renders_all_three_parts() {
        let r = BoardRef::new(org(ORG_A), NodeId("rpi-1".to_owned()), "nrf52840-dk-3");
        assert_eq!(r.to_string(), format!("{ORG_A}/rpi-1/nrf52840-dk-3"));
        assert_eq!(r.board_name(), BoardName("nrf52840-dk-3".to_owned()));
    }

    fn prefixed_board(org_id: &str, node: &str, name: &str) -> BoardRef {
        BoardRef::new(org(org_id), NodeId(format!("{org_id}/{node}")), name)
    }

    /// A production node id is org-prefixed (`state.rs::node_id_for`), so a
    /// `BoardRef` has **four** slash-separated segments, not three. Every
    /// spelling below must work against that shape — the bug this pins is that
    /// counting segments cannot address a real board at all.
    #[test]
    fn a_board_answers_to_every_qualified_spelling() {
        let board = prefixed_board(ORG_A, "rpi-1", "dk-3");
        for spelling in [
            "dk-3".to_owned(),                     // bare node-local name
            "rpi-1/dk-3".to_owned(),               // the node's short name
            format!("{ORG_A}/rpi-1/dk-3"),         // the full node id
            format!("{ORG_A}/{ORG_A}/rpi-1/dk-3"), // org + node id: Display
        ] {
            assert!(
                board.answers_to(&spelling),
                "{spelling} should reach the board"
            );
        }
        // And the Display rendering round-trips by construction.
        assert!(board.answers_to(&board.to_string()));
    }

    #[test]
    fn a_board_refuses_a_qualifier_that_is_not_its_own() {
        let board = prefixed_board(ORG_A, "rpi-1", "dk-3");
        for spelling in [
            "dk-4".to_owned(),                     // wrong board
            "rpi-2/dk-3".to_owned(),               // wrong node
            format!("{ORG_B}/rpi-1/dk-3"),         // right node name, wrong org prefix
            format!("{ORG_B}/{ORG_A}/rpi-1/dk-3"), // wrong org
            format!("{ORG_A}/dk-3"),               // an org alone does not qualify a board
            "/dk-3".to_owned(),                    // empty qualifier
            "dk-3/".to_owned(),                    // empty name
            String::new(),
        ] {
            assert!(
                !board.answers_to(&spelling),
                "{spelling} must not reach the board"
            );
        }
    }

    /// The org **path** spelling (`ariel-os/rpi-1/dk-3`) works only when the
    /// caller supplies the path, and only that path.
    #[test]
    fn a_board_answers_to_its_org_path_when_given_one() {
        let board = prefixed_board(ORG_A, "rpi-1", "dk-3");
        assert!(board.answers_to_in("ariel-os/rpi-1/dk-3", Some("ariel-os")));
        assert!(!board.answers_to("ariel-os/rpi-1/dk-3"));
        assert!(!board.answers_to_in("other/rpi-1/dk-3", Some("ariel-os")));
        assert!(!board.answers_to_in("ariel-os/rpi-2/dk-3", Some("ariel-os")));
        assert!(!board.answers_to_in("ariel-os/dk-3", Some("ariel-os")));
        assert!(!board.answers_to_in("/rpi-1/dk-3", Some("")));
        // The other spellings keep working alongside it.
        assert!(board.answers_to_in("rpi-1/dk-3", Some("ariel-os")));
    }

    /// The whole reason the qualified form exists: two boards of the same name
    /// in different orgs must be separable.
    #[test]
    fn qualified_names_separate_same_named_boards_in_two_orgs() {
        let mine = prefixed_board(ORG_A, "rpi-1", "dk-3");
        let shared = prefixed_board(ORG_B, "lab-pi", "dk-3");
        // The bare name is ambiguous: both answer to it, which is why the
        // coordinator tiers own-org first.
        assert!(mine.answers_to("dk-3") && shared.answers_to("dk-3"));
        // The qualified forms are not.
        assert!(shared.answers_to("lab-pi/dk-3"));
        assert!(!mine.answers_to("lab-pi/dk-3"));
        assert!(mine.answers_to("rpi-1/dk-3"));
        assert!(!shared.answers_to("rpi-1/dk-3"));
    }

    /// A node id with no org prefix (as `boards.toml` fixtures can have) still
    /// works, so the grammar is not coupled to the prefix.
    #[test]
    fn an_unprefixed_node_id_still_resolves() {
        let board = BoardRef::new(org("acme"), NodeId("rpi-1".to_owned()), "dk-3");
        for spelling in ["dk-3", "rpi-1/dk-3", "acme/rpi-1/dk-3"] {
            assert!(board.answers_to(spelling), "{spelling} should resolve");
        }
    }
}
