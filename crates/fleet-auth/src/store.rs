//! The storage seam token verification sits on.
//!
//! [`TokenStore`] is implemented by the coordinator over its `SQLite` handle
//! (`fleet_coordinator::tokens`). Keeping it a trait means [`crate::verify`] is
//! unit-testable against an in-memory fake, and — more importantly — that this
//! crate never learns how the coordinator stores anything.
//!
//! Every lookup is keyed by [`TokenHash`], never by the token: the secret is not
//! persisted anywhere.

use async_trait::async_trait;

use crate::token::TokenHash;

/// A node row, as verification needs to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    /// The node's id (its `AgentId` on the wire).
    pub node_id: String,
    /// The org the node belongs to.
    ///
    /// **This is where `/agent`'s org comes from** — never a configured
    /// default. A node's org is a property of its row, so a token cannot be
    /// replayed into another tenant.
    pub org_id: String,
    /// When the current token was issued (epoch seconds), for the rotation
    /// policy.
    pub token_issued_at: u64,
}

/// A user session row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// The subject id of the user this session belongs to.
    pub user_id: String,
    /// The org the session is scoped to.
    pub org_id: String,
    /// Expiry, epoch seconds.
    pub expires: u64,
}

/// A node-enrollment auth key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKeyRecord {
    /// The org nodes enrolled with this key join.
    pub org_id: String,
    /// Selection tags to stamp onto the enrolled node.
    pub tags: Vec<String>,
    /// Whether redeeming the key consumes it.
    pub single_use: bool,
    /// Expiry, epoch seconds; `None` means no expiry.
    pub expires: Option<u64>,
}

/// A CI workload token row (architecture §6.7).
///
/// Deliberately **not** org-scoped: a workload belongs to no tenant. The
/// `subject` it renders as is `gha/workload:<owner>/<repo>` for the OIDC path
/// (a reserved namespace, not an org) or `<key org>/workload:key:<hash8>` for
/// the auth-key fallback, and it reaches boards only through grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRecord {
    /// The namespace half of the subject key, used as
    /// [`crate::Authenticated::org_id`].
    ///
    /// For the OIDC path this is the reserved `gha` namespace, which has no
    /// `org` row — every caller that writes an org-scoped row for a workload
    /// must therefore key it on the *granting* org, not on this.
    pub org_id: String,
    /// The id half of the subject key (`<owner>/<repo>`, or `key:<hash8>`).
    pub id: String,
    /// Expiry, epoch seconds. Always set: a workload token is per job.
    pub expires: u64,
}

/// Read/write access to the credential tables.
///
/// Errors are returned as `String` rather than a concrete error type so this
/// crate does not depend on the coordinator's error enum or on `sqlx`; the
/// caller maps them back.
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Look up a node by its token hash.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_node(&self, hash: &TokenHash) -> Result<Option<NodeRecord>, String>;

    /// Look up a session by its token hash.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_session(&self, hash: &TokenHash) -> Result<Option<SessionRecord>, String>;

    /// Look up an auth key by its hash **without** consuming it.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_auth_key(&self, hash: &TokenHash) -> Result<Option<AuthKeyRecord>, String>;

    /// Look up a CI workload token by its hash.
    ///
    /// # Errors
    ///
    /// Returns a storage error description.
    async fn lookup_workload(&self, hash: &TokenHash) -> Result<Option<WorkloadRecord>, String>;
}

#[cfg(test)]
pub(crate) mod fake {
    //! An in-memory [`TokenStore`] used by this crate's own tests.

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::{AuthKeyRecord, NodeRecord, SessionRecord, TokenStore, WorkloadRecord};
    use crate::token::TokenHash;
    use async_trait::async_trait;

    #[derive(Default)]
    pub(crate) struct FakeStore {
        pub(crate) nodes: Mutex<HashMap<String, NodeRecord>>,
        pub(crate) sessions: Mutex<HashMap<String, SessionRecord>>,
        pub(crate) auth_keys: Mutex<HashMap<String, AuthKeyRecord>>,
        pub(crate) workloads: Mutex<HashMap<String, WorkloadRecord>>,
    }

    impl FakeStore {
        pub(crate) fn with_node(self, hash: &TokenHash, record: NodeRecord) -> Self {
            self.nodes
                .lock()
                .unwrap()
                .insert(hash.as_str().to_owned(), record);
            self
        }

        pub(crate) fn with_session(self, hash: &TokenHash, record: SessionRecord) -> Self {
            self.sessions
                .lock()
                .unwrap()
                .insert(hash.as_str().to_owned(), record);
            self
        }

        pub(crate) fn with_auth_key(self, hash: &TokenHash, record: AuthKeyRecord) -> Self {
            self.auth_keys
                .lock()
                .unwrap()
                .insert(hash.as_str().to_owned(), record);
            self
        }

        pub(crate) fn with_workload(self, hash: &TokenHash, record: WorkloadRecord) -> Self {
            self.workloads
                .lock()
                .unwrap()
                .insert(hash.as_str().to_owned(), record);
            self
        }
    }

    #[async_trait]
    impl TokenStore for FakeStore {
        async fn lookup_node(&self, hash: &TokenHash) -> Result<Option<NodeRecord>, String> {
            Ok(self.nodes.lock().unwrap().get(hash.as_str()).cloned())
        }

        async fn lookup_session(&self, hash: &TokenHash) -> Result<Option<SessionRecord>, String> {
            Ok(self.sessions.lock().unwrap().get(hash.as_str()).cloned())
        }

        async fn lookup_auth_key(&self, hash: &TokenHash) -> Result<Option<AuthKeyRecord>, String> {
            Ok(self.auth_keys.lock().unwrap().get(hash.as_str()).cloned())
        }

        async fn lookup_workload(
            &self,
            hash: &TokenHash,
        ) -> Result<Option<WorkloadRecord>, String> {
            Ok(self.workloads.lock().unwrap().get(hash.as_str()).cloned())
        }
    }
}
