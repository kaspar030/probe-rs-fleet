//! Identifier newtypes and the authenticated [`Subject`] used across the fleet
//! wire protocol.
//!
//! Revision 2 of the architecture (`docs/architecture.md` §6.1) makes the fleet
//! **multi-tenant**: every object belongs to exactly one org, and every caller
//! acts within one. That has two consequences visible in this module:
//!
//! * `Principal(String)` — a bare certificate CN with no org, no kind and no
//!   groups — is gone, replaced by [`Subject`].
//! * A board is keyed `(org, node, name)` ([`BoardRef`]), not by a globally
//!   unique string. The node-local half of that key is a [`BoardName`], which
//!   is all an agent knows about itself.

use serde::{Deserialize, Serialize};

/// An org id. Every object in the fleet belongs to exactly one org; a personal
/// org (an org of one) is created on first login.
///
/// There is deliberately **no** user-owned/org-owned branch: one scoping rule
/// everywhere, so no code path can forget the org check (architecture §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrgId(pub String);

/// A user id. Stable across GitHub login renames (the `user` row carries the
/// immutable numeric GitHub id separately).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserId(pub String);

/// A node id — a machine offering probes to the fleet.
///
/// Architecture revision 2 calls these "nodes"; the Rust type [`AgentId`] is
/// the historical spelling and is still what the wire and the scheduler use
/// (renaming it fleet-wide is tracked separately). `NodeId` exists so new code
/// and the DB layer can speak the revision-2 vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeId(pub String);

/// Identifies an agent (the machine hosting probes). Synonym of [`NodeId`] in
/// architecture revision-2 terms.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AgentId(pub String);

/// A group a subject belongs to. Groups are carried for future grant
/// evaluation; they are deliberately **not** part of a subject's identity (see
/// [`SubjectKey`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Group(pub String);

/// Identifies an active lease. Allocated by the coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LeaseId(pub u64);

/// A board's node-local name, as declared in that node's `boards.toml`.
///
/// **Not fleet-unique**: two orgs may each plug in an `nrf52840-dk`. Only a
/// [`BoardRef`] identifies a board across the fleet. The agent genuinely does
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
    pub node: AgentId,
    /// The node-local board name.
    pub name: String,
}

impl BoardRef {
    /// Build a board reference from its three parts.
    #[must_use]
    pub fn new(org: OrgId, node: AgentId, name: impl Into<String>) -> Self {
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
    /// * the full node id — `gh-1/rpi-1/dk-3`;
    /// * org + node id — `gh-1/gh-1/rpi-1/dk-3`, which is this type's own
    ///   [`std::fmt::Display`], so a key copied out of `ctl list` works verbatim.
    ///
    /// # Why counting segments does not work
    ///
    /// A production [`AgentId`] is **already org-prefixed** (`gh-1/rpi-1`):
    /// node ids are namespaced by org so the same machine name in two tenants
    /// is two nodes. So a `BoardRef` has a variable number of segments, and the
    /// obvious `split('/')` into `[org, node, name]` cannot address a real
    /// board at all. Peel the name off the end instead, and compare the
    /// remainder as a whole.
    #[must_use]
    pub fn answers_to(&self, typed: &str) -> bool {
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
        // the machine calls itself and what `share` / `agent up` were given.
        let node_short = self.node.0.rsplit('/').next().unwrap_or(&self.node.0);
        qualifier == self.node.0
            || qualifier == node_short
            || qualifier == format!("{}/{}", self.org.0, self.node.0)
    }
}

/// Which authentication path produced a [`Subject`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum SubjectKind {
    /// A human, authenticated by a user session.
    User,
    /// A node (agent machine), authenticated by its node credential.
    Node,
    /// A CI workload, authenticated by an exchanged workload token.
    Workload,
}

impl std::fmt::Display for SubjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SubjectKind::User => "user",
            SubjectKind::Node => "node",
            SubjectKind::Workload => "workload",
        })
    }
}

/// The org role a subject holds.
///
/// A `Member` may add a node and use the org's boards; an `Admin` additionally
/// acts on other members' leases and reads the audit log (architecture §6.5).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum Role {
    /// May use the org's boards and add nodes.
    Member,
    /// Everything a member may do, plus acting on others' leases and reading
    /// the audit log.
    Admin,
}

impl Role {
    /// Whether this role satisfies a `required` minimum. `Admin` implies
    /// `Member`.
    #[must_use]
    pub fn satisfies(self, required: Role) -> bool {
        self >= required
    }

    /// The DB/wire label for this role.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Member => "member",
            Role::Admin => "admin",
        }
    }

    /// Parse a role from its DB/wire label.
    #[must_use]
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "member" => Some(Role::Member),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An authenticated caller, resolved identically no matter how it proved
/// itself (architecture §6.1).
///
/// All three authentication paths — user session, node token, workload token —
/// resolve to this one shape, so authorization is a single mechanism. A
/// `Subject` is deliberately **not** constructible from a bare string (no
/// `Default`, no `From<String>`): it may only be minted where the org is known,
/// which in the coordinator is a single resolution seam.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Subject {
    /// The org this subject acts within.
    pub org: OrgId,
    /// How the subject authenticated.
    pub kind: SubjectKind,
    /// The subject's id, unique within `(org, kind)`.
    pub id: String,
    /// Groups the subject belongs to. Advisory: excluded from [`SubjectKey`].
    pub groups: Vec<Group>,
}

impl Subject {
    /// Build a subject with no groups.
    #[must_use]
    pub fn new(org: OrgId, kind: SubjectKind, id: impl Into<String>) -> Self {
        Self {
            org,
            kind,
            id: id.into(),
            groups: Vec::new(),
        }
    }

    /// This subject's **stable identity**: `(org, kind, id)`.
    ///
    /// `groups` is deliberately excluded, so adding or removing a group does
    /// not orphan a lease the subject holds.
    #[must_use]
    pub fn key(&self) -> SubjectKey {
        SubjectKey {
            org: self.org.clone(),
            kind: self.kind,
            id: self.id.clone(),
        }
    }

    /// Whether the subject belongs to `group`.
    #[must_use]
    pub fn in_group(&self, group: &Group) -> bool {
        self.groups.contains(group)
    }
}

/// The stable identity of a [`Subject`], used for equality wherever ownership
/// matters (lease holder checks, the per-subject concurrency cap, audit rows).
///
/// Excludes `groups` by construction: a group change must never transfer or
/// orphan a lease.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubjectKey {
    /// The org the subject acts within.
    pub org: OrgId,
    /// How the subject authenticated.
    pub kind: SubjectKind,
    /// The subject's id, unique within `(org, kind)`.
    pub id: String,
}

impl SubjectKey {
    /// Parse a rendered subject key (`<org>/<kind>:<id>`).
    ///
    /// The inverse of [`std::fmt::Display`], used to read back the `subject`
    /// column of a grant row. Returns `None` on any shape or kind it does not
    /// recognise — a grant whose subject will not parse must be dropped closed,
    /// never widened into a match-anything.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (org, rest) = s.split_once('/')?;
        let (kind, id) = rest.split_once(':')?;
        if org.is_empty() || id.is_empty() {
            return None;
        }
        let kind = match kind {
            "user" => SubjectKind::User,
            "node" => SubjectKind::Node,
            "workload" => SubjectKind::Workload,
            _ => return None,
        };
        Some(SubjectKey {
            org: OrgId(org.to_owned()),
            kind,
            id: id.to_owned(),
        })
    }
}

impl std::fmt::Display for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for Group {
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
        write!(f, "{}/{}:{}", self.org.0, self.kind, self.id)
    }
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.key(), f)
    }
}

/// The reserved namespace a GitHub Actions workload subject lives in
/// (architecture §6.7).
///
/// A workload token proves "a job in repo `owner/name`", and that fact is
/// **org-independent**: the same repo may be granted hardware by several orgs,
/// and belongs to none of them. So the subject key is
/// `gha/workload:<owner>/<repo>` — `gha` occupies the namespace slot a
/// [`SubjectKey`] would otherwise fill with an org id, and there is no `org`
/// row named `gha` that anything is scoped to.
///
/// Two properties make this safe rather than a collision waiting to happen:
///
/// * the namespace is **reserved at every org-creation path**
///   (`Db::ensure_org` refuses it, and `CoordinatorConfig::validate` refuses
///   `default_org = "gha"`), so no tenant can ever occupy it;
/// * a grant is matched on the **whole rendered key**, so even a hypothetical
///   `gha/user:x` could not be reached by a workload token, which always
///   renders `gha/workload:…`.
///
/// `repository_owner` is deliberately *not* part of the trust decision: a fork
/// or a newly created repo under a granted owner produces a different id here
/// and therefore matches no grant.
pub const WORKLOAD_NS_GHA: &str = "gha";

/// Validate and normalise a GitHub `owner/name` repository string.
///
/// Returns the **lowercased** repo, or `None` if it is not exactly one
/// `owner/name` pair over a conservative charset (`[A-Za-z0-9._-]`).
///
/// # Why lowercase, and why in one function
///
/// GitHub repository names are case-*preserving* but case-*insensitive*, so
/// `Ariel-OS/ariel-os` and `ariel-os/ariel-os` are the same repo. A grant
/// stores this id and a workload token's claim is matched against it by exact
/// string equality, so a case difference between the two spellings would
/// become a silent denial that looks like a coordinator bug. Both sides call
/// **this** function — `grant --repo` on the way in and the OIDC claim on the
/// way in — so they cannot disagree.
///
/// The charset is enforced because the result becomes a subject id that is
/// rendered into `<ns>/<kind>:<id>`: a `/` or `:` in the wrong place would let
/// a repo name impersonate another subject shape. One slash is allowed (the
/// separator itself), and [`SubjectKey::parse`] splits at the *first* `/` and
/// the *first* `:`, so the result round-trips.
#[must_use]
pub fn normalise_repo(repo: &str) -> Option<String> {
    let repo = repo.trim();
    let (owner, name) = repo.split_once('/')?;
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    // 39 is GitHub's owner limit and 100 its repo-name limit; the cap is here
    // to bound what a claim can write into a subject id, not to mirror GitHub
    // exactly.
    if owner.len() > 64 || name.len() > 128 {
        return None;
    }
    let ok = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    };
    if !ok(owner) || !ok(name) {
        return None;
    }
    Some(format!("{}/{}", owner.to_ascii_lowercase(), name.to_ascii_lowercase()))
}

/// The [`SubjectKey`] a GitHub Actions job in `repo` authenticates as.
///
/// `repo` must already have passed [`normalise_repo`]. The single constructor,
/// so the grant-creation path (`grant --repo`) and the token-exchange path
/// cannot produce two different spellings of the same identity.
#[must_use]
pub fn workload_subject_key(repo: &str) -> SubjectKey {
    SubjectKey {
        org: OrgId(WORKLOAD_NS_GHA.to_owned()),
        kind: SubjectKind::Workload,
        id: repo.to_owned(),
    }
}

/// Length cap on an auth-key identity name (`auth-key create --as <name>`).
///
/// Bounds what an operator-chosen string can write into a subject id, in the
/// same spirit as [`normalise_repo`]'s owner/name caps. 64 characters is far
/// more than a readable agent name needs and far less than anything that could
/// make a rendered key unwieldy in a terminal, a log line or an audit row.
pub const MAX_AGENT_NAME_LEN: usize = 64;

/// Validate and normalise an auth-key identity name.
///
/// Returns the **lowercased** name, or `None` if it is not a non-empty string
/// of at most [`MAX_AGENT_NAME_LEN`] characters over `[a-z0-9._-]` starting
/// with `[a-z0-9]`. Never repairs: a name that does not pass is refused at mint
/// time, with the rule named, rather than silently becoming a different
/// identity.
///
/// # Why each rule exists
///
/// * **Lowercasing.** An identity is a name an operator retypes months later
///   when rotating the credential. `Builder` and `builder` producing two
///   subjects would silently fork the audit trail and the concurrency budget —
///   which is exactly the bug named identities exist to remove. Same reasoning
///   as [`normalise_repo`]'s lowercasing, and normalising in one function is
///   what stops the mint path and the redemption path from disagreeing.
/// * **The charset.** The name is rendered into `<org>/workload:agent:<name>`.
///   Excluding `:` makes it structurally impossible to spell the unnamed
///   `key:<hash8>` form (`--as key:deadbeef` is refused, not accepted as a
///   look-alike) or to introduce a second separator into the rendered key.
///   Excluding `/` makes it impossible to be mistaken for a
///   `gha/workload:owner/repo` repo subject.
/// * **The first character.** A leading `-` reads as a flag in every message,
///   shell recipe and CLI example that quotes the name, and a leading `.`
///   invites `.` or `..`, which look like paths.
///
/// The name is **org-scoped**: the subject carries the org, so two tenants may
/// each have a `builder` without collision.
#[must_use]
pub fn normalise_agent_name(name: &str) -> Option<String> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() || name.len() > MAX_AGENT_NAME_LEN {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return None;
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(name)
}

/// The [`SubjectKey`] an auth key minted with `--as <name>` speaks as.
///
/// `name` must already have passed [`normalise_agent_name`]. The **only** place
/// the `agent:` prefix is spelled, for the reason [`workload_subject_key`]'s
/// doc comment gives: two spellings of one identity is the failure mode, and
/// here it would fork precisely the audit trail and concurrency budget the
/// named identity exists to keep whole.
///
/// Org-scoped, so it can never collide with a `gha/workload:owner/repo` repo
/// subject, and — because the charset excludes `:` — never with the unnamed
/// `key:<hash8>` spelling either.
#[must_use]
pub fn agent_subject_key(org: &OrgId, name: &str) -> SubjectKey {
    SubjectKey {
        org: org.clone(),
        kind: SubjectKind::Workload,
        id: format!("agent:{name}"),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn subject(org: &str, id: &str) -> Subject {
        Subject::new(OrgId(org.to_owned()), SubjectKind::User, id)
    }

    #[test]
    fn key_excludes_groups() {
        let mut a = subject("acme", "alice");
        let b = a.clone();
        a.groups.push(Group("firmware".to_owned()));
        assert_ne!(a, b);
        assert_eq!(a.key(), b.key());
    }

    #[test]
    fn same_id_in_different_orgs_is_a_different_subject() {
        assert_ne!(subject("a", "alice").key(), subject("b", "alice").key());
    }

    #[test]
    fn subject_key_renders_org_kind_id() {
        assert_eq!(subject("acme", "alice").key().to_string(), "acme/user:alice");
    }

    #[test]
    fn subject_key_parses_back_from_its_rendering() {
        for s in [
            subject("acme", "alice").key(),
            Subject::new(OrgId("gh-42".to_owned()), SubjectKind::Node, "rpi-1").key(),
            Subject::new(OrgId("gh-42".to_owned()), SubjectKind::Workload, "ci").key(),
        ] {
            assert_eq!(SubjectKey::parse(&s.to_string()), Some(s));
        }
    }

    /// An id containing `:` still parses: the split is at the *first* colon
    /// after the first slash, and ids are opaque.
    #[test]
    fn subject_key_parse_splits_at_the_first_separators() {
        let k = SubjectKey::parse("acme/user:gh-1:2").unwrap();
        assert_eq!(k.id, "gh-1:2");
        assert_eq!(k.org, OrgId("acme".to_owned()));
    }

    #[test]
    fn malformed_subject_keys_are_rejected_not_guessed() {
        for bad in [
            "acme/user",
            "acme:user:alice",
            "acme/root:alice",
            "/user:alice",
            "acme/user:",
            "alice",
        ] {
            assert_eq!(SubjectKey::parse(bad), None, "{bad} should not parse");
        }
    }

    /// The workload subject shape, and the property that makes it work with no
    /// schema change: an id containing a slash round-trips through
    /// `SubjectKey::parse`, because the parse splits at the *first* separators.
    #[test]
    fn a_workload_subject_key_round_trips_through_parse() {
        let key = workload_subject_key(&normalise_repo("ariel-os/ariel-os").unwrap());
        assert_eq!(key.to_string(), "gha/workload:ariel-os/ariel-os");
        assert_eq!(SubjectKey::parse(&key.to_string()), Some(key.clone()));
        assert_eq!(key.org, OrgId(WORKLOAD_NS_GHA.to_owned()));
        assert_eq!(key.kind, SubjectKind::Workload);
    }

    /// Case-insensitivity is normalised on **both** sides (grant creation and
    /// claim ingestion) by this one function, so a repo whose GitHub spelling
    /// is mixed-case cannot become a silent denial.
    #[test]
    fn repo_normalisation_lowercases_and_validates() {
        assert_eq!(
            normalise_repo("Ariel-OS/Ariel-OS").as_deref(),
            Some("ariel-os/ariel-os")
        );
        assert_eq!(normalise_repo("  a/b ").as_deref(), Some("a/b"));
        assert_eq!(normalise_repo("a_b.c/d-e.f").as_deref(), Some("a_b.c/d-e.f"));

        for bad in [
            "",
            "owner",
            "owner/",
            "/name",
            // A second slash, or a colon, would let a repo name impersonate
            // another subject shape once it is rendered into a subject key.
            "owner/name/extra",
            "own:er/name",
            "owner/na:me",
            "owner/na me",
            "owner/na\nme",
        ] {
            assert_eq!(normalise_repo(bad), None, "{bad:?} should not normalise");
        }
        assert_eq!(normalise_repo(&format!("{}/b", "x".repeat(65))), None);
        assert_eq!(normalise_repo(&format!("a/{}", "x".repeat(129))), None);
    }

    /// The rule set that makes a chosen name safe to render into a subject id,
    /// and the lowercasing that keeps a rotation from forking the identity.
    #[test]
    fn agent_name_normalisation_lowercases_and_validates() {
        assert_eq!(normalise_agent_name("Builder").as_deref(), Some("builder"));
        assert_eq!(normalise_agent_name("  ci-2 ").as_deref(), Some("ci-2"));
        assert_eq!(
            normalise_agent_name("a_b.c-9").as_deref(),
            Some("a_b.c-9")
        );

        for bad in [
            "",
            " ",
            "a b",
            // A `/` would make the name look like a `gha/workload:owner/repo`
            // repo subject once rendered.
            "a/b",
            // A `:` would let a name spell the unnamed `key:<hash>` form.
            "key:deadbeef",
            "a:b",
            // A leading `-` reads as a flag; a leading `.` invites `..`.
            "-x",
            "..",
            ".hidden",
            "naïve",
            "a\nb",
        ] {
            assert_eq!(
                normalise_agent_name(bad),
                None,
                "{bad:?} should not normalise"
            );
        }
        assert_eq!(
            normalise_agent_name(&"x".repeat(MAX_AGENT_NAME_LEN))
                .as_deref(),
            Some("x".repeat(MAX_AGENT_NAME_LEN).as_str())
        );
        assert_eq!(normalise_agent_name(&"x".repeat(MAX_AGENT_NAME_LEN + 1)), None);
    }

    /// The named identity's shape, and that it round-trips through
    /// `SubjectKey::parse` — which is what lets a grant row store it as text
    /// and read it back as the same subject.
    #[test]
    fn an_agent_subject_key_round_trips_through_parse() {
        let key = agent_subject_key(&OrgId("acme".to_owned()), "builder");
        assert_eq!(key.to_string(), "acme/workload:agent:builder");
        assert_eq!(SubjectKey::parse(&key.to_string()), Some(key.clone()));
        assert_eq!(key.kind, SubjectKind::Workload);
        // Org-scoped: the same name in two orgs is two subjects.
        assert_ne!(key, agent_subject_key(&OrgId("other".to_owned()), "builder"));
        // And it cannot collide with the unnamed spelling, whose id starts
        // `key:` and which the charset rule makes unrepresentable as a name.
        assert_ne!(key.id, "key:deadbeef");
    }

    #[test]
    fn board_ref_renders_all_three_parts() {
        let r = BoardRef::new(
            OrgId("acme".to_owned()),
            AgentId("rpi-1".to_owned()),
            "nrf52840-dk-3",
        );
        assert_eq!(r.to_string(), "acme/rpi-1/nrf52840-dk-3");
        assert_eq!(r.board_name(), BoardName("nrf52840-dk-3".to_owned()));
    }

    #[test]
    fn admin_implies_member() {
        assert!(Role::Admin.satisfies(Role::Member));
        assert!(Role::Admin.satisfies(Role::Admin));
        assert!(Role::Member.satisfies(Role::Member));
        assert!(!Role::Member.satisfies(Role::Admin));
    }

    #[test]
    fn role_label_roundtrip() {
        for role in [Role::Member, Role::Admin] {
            assert_eq!(Role::from_label(role.as_str()), Some(role));
        }
        assert_eq!(Role::from_label("root"), None);
    }

    /// A production node id is org-prefixed (`state.rs::node_id_for`), so a
    /// `BoardRef` has **four** slash-separated segments, not three. Every
    /// spelling below must work against that shape — the bug this pins is that
    /// counting segments cannot address a real board at all.
    #[test]
    fn a_board_answers_to_every_qualified_spelling() {
        let board = BoardRef::new(
            OrgId("gh-1".to_owned()),
            AgentId("gh-1/rpi-1".to_owned()),
            "dk-3",
        );
        for spelling in [
            "dk-3",                 // bare node-local name
            "rpi-1/dk-3",           // the node's short name
            "gh-1/rpi-1/dk-3",      // the full node id
            "gh-1/gh-1/rpi-1/dk-3", // org + node id: this type's own Display
        ] {
            assert!(
                board.answers_to(spelling),
                "{spelling} should reach the board"
            );
        }
        // And the Display rendering round-trips by construction.
        assert!(board.answers_to(&board.to_string()));
    }

    #[test]
    fn a_board_refuses_a_qualifier_that_is_not_its_own() {
        let board = BoardRef::new(
            OrgId("gh-1".to_owned()),
            AgentId("gh-1/rpi-1".to_owned()),
            "dk-3",
        );
        for spelling in [
            "dk-4",                 // wrong board
            "rpi-2/dk-3",           // wrong node
            "gh-2/rpi-1/dk-3",      // right node name, wrong org prefix
            "gh-2/gh-1/rpi-1/dk-3", // wrong org
            "gh-1/dk-3",            // an org alone does not qualify a board
            "/dk-3",                // empty qualifier
            "dk-3/",                // empty name
            "",
        ] {
            assert!(
                !board.answers_to(spelling),
                "{spelling} must not reach the board"
            );
        }
    }

    /// The whole reason the qualified form exists: two boards of the same name
    /// in different orgs must be separable.
    #[test]
    fn qualified_names_separate_same_named_boards_in_two_orgs() {
        let mine = BoardRef::new(
            OrgId("gh-1".to_owned()),
            AgentId("gh-1/rpi-1".to_owned()),
            "dk-3",
        );
        let shared = BoardRef::new(
            OrgId("gh-2".to_owned()),
            AgentId("gh-2/lab-pi".to_owned()),
            "dk-3",
        );
        // The bare name is ambiguous: both answer to it, which is why the
        // coordinator tiers own-org first.
        assert!(mine.answers_to("dk-3") && shared.answers_to("dk-3"));
        // The qualified forms are not.
        assert!(shared.answers_to("lab-pi/dk-3"));
        assert!(!mine.answers_to("lab-pi/dk-3"));
        assert!(mine.answers_to("rpi-1/dk-3"));
        assert!(!shared.answers_to("rpi-1/dk-3"));
    }

    /// A node id with no org prefix (as `boards.toml` fixtures and older rows
    /// can have) still works, so the grammar is not coupled to the prefix.
    #[test]
    fn an_unprefixed_node_id_still_resolves() {
        let board = BoardRef::new(
            OrgId("acme".to_owned()),
            AgentId("rpi-1".to_owned()),
            "dk-3",
        );
        for spelling in ["dk-3", "rpi-1/dk-3", "acme/rpi-1/dk-3"] {
            assert!(board.answers_to(spelling), "{spelling} should resolve");
        }
    }
}
