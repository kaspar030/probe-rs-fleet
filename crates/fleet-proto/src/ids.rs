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
}
