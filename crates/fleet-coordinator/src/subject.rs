//! The coordinator's view of an authenticated caller, and the conversions
//! between fleet's wire identity types and forgs'.
//!
//! forgs authenticates (`forgs_http::authenticate_request` is the only place
//! a credential becomes a [`forgs::Subject`]). What the coordinator adds is
//! the **acting org**: a user session is not bound to an org any more, so a
//! request names one (`?org=`, default the user's personal org) and the
//! handler attaches it to a [`Subject`] only after checking membership there
//! (`crate::http::acting_subject`). A node acts in its own node's org; a
//! workload acts in none and reaches boards only through grants.
//!
//! [`fleet_proto::ids::SubjectKey`] is the wire mirror of
//! [`forgs::SubjectKey`] and renders identically, so the conversions here are
//! a render + parse; a key that does not survive the round trip is dropped
//! closed (`None`).

use std::fmt;

use fleet_proto::ids::{NodeId, OrgId, SubjectKey, SubjectKind};
use forgs::{NsNodeId, Role, RoleLadder, UserId};

/// fleet's one app subject kind, and the label of the node token kind.
pub const NODE_KIND: &str = "node";

/// The org namespace kind in fleet's forgs schema.
pub const ORG_KIND: &str = "org";

/// The namespace id an [`OrgId`] names, if it is well-formed.
#[must_use]
pub fn ns_of(org: &OrgId) -> Option<NsNodeId> {
    NsNodeId::parse(&org.0).ok()
}

/// The [`OrgId`] of a forgs namespace node.
#[must_use]
pub fn org_of(ns: NsNodeId) -> OrgId {
    OrgId(ns.to_string())
}

/// forgs key → wire key.
#[must_use]
pub fn to_proto(key: &forgs::SubjectKey) -> Option<SubjectKey> {
    SubjectKey::parse(&key.to_string())
}

/// Wire key → forgs key (knowing fleet's `node` app kind).
#[must_use]
pub fn to_forgs(key: &SubjectKey) -> Option<forgs::SubjectKey> {
    forgs::SubjectKey::parse_with(&key.to_string(), &[NODE_KIND])
}

/// The wire key of user `user` (`user:<ulid>`).
///
/// # Panics
///
/// Never: a ULID is always a valid subject id.
#[must_use]
pub fn user_key(user: UserId) -> SubjectKey {
    SubjectKey::new(None, SubjectKind::User, &user.to_string())
        .expect("a ULID is a valid subject id")
}

/// The user id a wire key names, for a user key.
#[must_use]
pub fn user_of(key: &SubjectKey) -> Option<UserId> {
    (key.kind() == SubjectKind::User && key.ns().is_none())
        .then(|| UserId::parse(key.id()).ok())
        .flatten()
}

/// The wire key of node `node` in `org` (`<org>/node:<node id>`).
#[must_use]
pub fn node_key(org: &OrgId, node: &NodeId) -> Option<SubjectKey> {
    SubjectKey::new(Some(&org.0), SubjectKind::Node, &node.0)
}

/// fleet's two roles, mapped onto the forgs ladder `member < admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FleetRole {
    /// Uses the org's boards, adds nodes.
    Member,
    /// Also acts on other members' leases, reads the audit log, grants.
    Admin,
}

impl FleetRole {
    /// The ladder labels, lowest first.
    pub const LADDER: [&'static str; 2] = ["member", "admin"];

    /// The ladder label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FleetRole::Member => "member",
            FleetRole::Admin => "admin",
        }
    }

    /// Parse a ladder label.
    #[must_use]
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "member" => Some(FleetRole::Member),
            "admin" => Some(FleetRole::Admin),
            _ => None,
        }
    }

    /// This role on `ladder`.
    ///
    /// # Panics
    ///
    /// If `ladder` lacks the role (fleet's ladder, [`FleetRole::LADDER`],
    /// has both).
    #[must_use]
    pub fn on(self, ladder: &RoleLadder) -> Role {
        ladder
            .parse(self.as_str())
            .expect("fleet's ladder has both roles")
    }

    /// The fleet role a forgs role is, on `ladder`. An unknown label is
    /// `None` (fail closed).
    #[must_use]
    pub fn of(role: Role, ladder: &RoleLadder) -> Option<Self> {
        ladder.label(role).and_then(Self::from_label)
    }
}

impl fmt::Display for FleetRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An authenticated caller plus the org it acts in.
///
/// Built by the HTTP layer from a forgs `Caller` **after** membership in the
/// acting org was checked (or, for a node, from its token's own namespace).
/// Everything in `core`/`authz` consumes this and re-checks membership where
/// it matters, so a stale acting org (a membership revoked mid-connection)
/// still stops working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    key: SubjectKey,
    org: Option<OrgId>,
}

impl Subject {
    /// A subject from its key and acting org.
    #[must_use]
    pub fn new(key: SubjectKey, org: Option<OrgId>) -> Self {
        Self { key, org }
    }

    /// User `user`, acting in `org`.
    #[must_use]
    pub fn user(user: UserId, org: OrgId) -> Self {
        Self::new(user_key(user), Some(org))
    }

    /// Node `node` of `org`, acting in `org`.
    #[must_use]
    pub fn node(org: OrgId, node: &NodeId) -> Option<Self> {
        Some(Self::new(node_key(&org, node)?, Some(org)))
    }

    /// The stable identity.
    #[must_use]
    pub fn key(&self) -> &SubjectKey {
        &self.key
    }

    /// How it authenticated.
    #[must_use]
    pub fn kind(&self) -> SubjectKind {
        self.key.kind()
    }

    /// The acting org, if any (never for a workload).
    #[must_use]
    pub fn org(&self) -> Option<&OrgId> {
        self.org.as_ref()
    }

    /// The user id, for a user.
    #[must_use]
    pub fn user_id(&self) -> Option<UserId> {
        user_of(&self.key)
    }

    /// The forgs rendering of the key.
    #[must_use]
    pub fn forgs_key(&self) -> Option<forgs::SubjectKey> {
        to_forgs(&self.key)
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.key, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_between_wire_and_forgs() {
        let org = org_of(NsNodeId::generate(1_000));
        let node = crate::state::node_id_for(&org, "rpi-1");
        let k = node_key(&org, &node).unwrap();
        let f = to_forgs(&k).unwrap();
        assert_eq!(f.kind(), forgs::SubjectKind::App(NODE_KIND));
        assert_eq!(to_proto(&f).unwrap(), k);

        let u = UserId::generate(5);
        let k = user_key(u);
        assert_eq!(to_forgs(&k).unwrap(), forgs::SubjectKey::user(u));
        assert_eq!(user_of(&k), Some(u));
        assert_eq!(user_of(&node_key(&org, &node).unwrap()), None);
    }

    #[test]
    fn roles_map_onto_the_ladder() {
        let ladder = RoleLadder::new(&FleetRole::LADDER).unwrap();
        let admin = FleetRole::Admin.on(&ladder);
        assert!(admin.satisfies(FleetRole::Member.on(&ladder)));
        assert!(!FleetRole::Member.on(&ladder).satisfies(admin));
        assert_eq!(FleetRole::of(admin, &ladder), Some(FleetRole::Admin));
    }
}

/// Fixtures for the in-crate unit tests, built through the production
/// constructors (`create_local_user`, `create_node`) so no test hand-rolls an
/// id shape production cannot produce.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use crate::state::Db;

    /// A migrated in-memory database.
    pub async fn db() -> Db {
        Db::connect_in_memory().await.unwrap()
    }

    /// The team org named `name` (created if absent).
    pub async fn org(db: &Db, name: &str) -> OrgId {
        db.ensure_org_named(name, 1).await.unwrap()
    }

    /// The user named `name` (created, with its personal org, if absent).
    pub async fn user(db: &Db, name: &str) -> UserId {
        if let Some(u) = db.forgs().user_by_username(name).await.unwrap() {
            return u.id;
        }
        db.forgs().create_local_user(name, None, 1).await.unwrap().0
    }

    /// `name` as a member of org `org_name` with `role`, acting there.
    pub async fn member(db: &Db, org_name: &str, name: &str, role: FleetRole) -> Subject {
        let o = org(db, org_name).await;
        let u = user(db, name).await;
        db.set_member(&o, u, role, 1).await.unwrap();
        Subject::user(u, o)
    }

    /// FNV-1a, for deterministic fixture ids.
    fn fnv(name: &str) -> u128 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in name.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        u128::from(h)
    }

    /// The deterministic id of fixture org `name` (see [`seed_org`]). Lets
    /// synchronous fixtures (board refs, node ids) name an org before the
    /// database exists.
    pub fn org_id(name: &str) -> OrgId {
        org_of(NsNodeId::from_parts(1, fnv(name)))
    }

    /// The deterministic id of fixture user `name` (see [`seed_user`]).
    pub fn user_id(name: &str) -> UserId {
        UserId::from_parts(2, fnv(name))
    }

    /// Insert root org `name` with id [`org_id`] if absent. Fixed ids need a
    /// direct insert (production mints random ULIDs); the row is otherwise
    /// what `create_node(None, "org", …)` writes.
    pub async fn seed_org(db: &Db, name: &str) -> OrgId {
        let id = org_id(name);
        sqlx::query(
            "INSERT OR IGNORE INTO forgs_ns_node (id, parent_id, kind, name, name_canonical, created_at)
             VALUES (?1, NULL, 'org', ?2, ?2, 1)",
        )
        .bind(&id.0)
        .bind(name)
        .execute(db.pool_for_test())
        .await
        .unwrap();
        id
    }

    /// Insert active user `name` with id [`user_id`] if absent (no personal
    /// org).
    pub async fn seed_user(db: &Db, name: &str) -> UserId {
        let id = user_id(name);
        sqlx::query(
            "INSERT OR IGNORE INTO forgs_user (id, username, state, created_at)
             VALUES (?1, ?2, 'active', 1)",
        )
        .bind(id.to_string())
        .bind(name)
        .execute(db.pool_for_test())
        .await
        .unwrap();
        id
    }

    /// Seeded user `name` as a member of seeded org `org_name`.
    pub async fn seed_member(db: &Db, org_name: &str, name: &str, role: FleetRole) -> Subject {
        let o = seed_org(db, org_name).await;
        let u = seed_user(db, name).await;
        db.set_member(&o, u, role, 1).await.unwrap();
        Subject::user(u, o)
    }
}
