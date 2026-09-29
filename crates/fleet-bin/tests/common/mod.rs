//! Shared fixtures for the fleet-bin e2e tests.
//!
//! Users and orgs are built with the production constructors
//! (`create_local_user`, `ensure_org_named`, `set_member`, forgs'
//! `mint_session` / `mint_refresh`) — never hand-rolled ids.
#![allow(dead_code)]

use std::sync::Arc;

use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, GithubActionsConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_coordinator::FleetRole;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::OrgId;

/// The shared org every fixture coordinator has.
pub const DEFAULT_ORG: &str = "default";

/// A live coordinator serving its real router on loopback.
pub struct Fleet {
    pub coord: Arc<Coordinator>,
    pub base_url: String,
    pub server: tokio::task::JoinHandle<()>,
}

impl Drop for Fleet {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fleet {
    /// The default org's id.
    pub async fn default_org(&self) -> OrgId {
        self.org(DEFAULT_ORG).await
    }

    /// Resolve an org by name.
    pub async fn org(&self, name: &str) -> OrgId {
        self.coord
            .db()
            .resolve_org(name)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("no org {name}"))
    }

    /// Create a team org (root `org` node) named `name`.
    pub async fn create_org(&self, name: &str) -> OrgId {
        self.coord
            .db()
            .ensure_org_named(name, self.coord.now())
            .await
            .unwrap()
    }

    /// Create (or reuse) the local user `username`.
    pub async fn user(&self, username: &str) -> forgs::UserId {
        let store = self.coord.db().forgs();
        if let Some(u) = store.user_by_username(username).await.unwrap() {
            return u.id;
        }
        store
            .create_local_user(username, None, self.coord.now())
            .await
            .unwrap()
            .0
    }

    /// Make `username` a member of org `org_name` with `role`.
    pub async fn member(&self, username: &str, org_name: &str, role: FleetRole) -> forgs::UserId {
        let user = self.user(username).await;
        let org = self.org(org_name).await;
        self.coord
            .db()
            .set_member(&org, user, role, self.coord.now())
            .await
            .unwrap();
        user
    }

    /// A session token for `username` (created if needed) who is a member of
    /// the default org with `role` — what `coordinator user-token` does.
    pub async fn session(&self, username: &str, role: FleetRole) -> String {
        let user = self.member(username, DEFAULT_ORG, role).await;
        forgs_http::session::mint_session(self.coord.auth(), user, "test")
            .await
            .unwrap()
            .token
    }

    /// A refresh token for `username` (created if needed).
    pub async fn refresh(&self, username: &str) -> String {
        let user = self.user(username).await;
        forgs_http::session::mint_refresh(self.coord.auth(), user)
            .await
            .unwrap()
    }

    /// Mint an API key into org `org_name` the way `coordinator auth-key`
    /// does (shell-minted: no creator). `payload` is validated by fleet's
    /// purpose policy first.
    pub async fn api_key(
        &self,
        org_name: &str,
        purpose: &str,
        payload: serde_json::Value,
        single_use: bool,
        subject_name: Option<&str>,
    ) -> String {
        let org = self.org(org_name).await;
        let ns = fleet_coordinator::subject::ns_of(&org).unwrap();
        let ctx = self.coord.auth();
        let payload = ctx
            .purposes()
            .check_payload(purpose, Some(&payload))
            .unwrap();
        let token = ctx.format().mint(forgs::TokenKind::ApiKey);
        self.coord
            .db()
            .forgs()
            .scoped(ns)
            .insert_api_key(
                &forgs_store::NewApiKey {
                    hash: token.hash(),
                    purpose: purpose.to_owned(),
                    subject_name: subject_name.map(ToOwned::to_owned),
                    payload,
                    single_use,
                    expires: None,
                    created_by: None,
                },
                self.coord.now(),
            )
            .await
            .unwrap();
        token.to_secret_string()
    }

    /// A single-use `node` key with `tags`, in the default org.
    pub async fn node_key(&self, tags: &[&str]) -> String {
        self.api_key(
            DEFAULT_ORG,
            "node",
            serde_json::json!({ "tags": tags }),
            true,
            None,
        )
        .await
    }
}

/// Start a fleet with the default config (plus `github_actions`).
pub async fn start_fleet_with(seed: [u8; 32], github_actions: Option<GithubActionsConfig>) -> Fleet {
    let config = CoordinatorConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        sqlite_path: ":memory:".into(),
        signing_key: SigningKeySource::Seed(seed),
        github_actions,
        ..CoordinatorConfig::default()
    };
    let db = Db::connect_in_memory().await.unwrap();
    let clock = Arc::new(SystemClock);
    db.ensure_org_named(DEFAULT_ORG, fleet_coordinator::now_epoch_secs())
        .await
        .unwrap();
    let coord = Arc::new(Coordinator::new(
        config,
        Scheduler::new(Policy::default()),
        db,
        Ed25519Signer::from_seed(&seed),
        clock,
    ));
    // The auth hooks (revocation cascade, node approval) reach the
    // coordinator through this link.
    coord.attach();

    let router = fleet_coordinator::http::router(Arc::clone(&coord));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    Fleet {
        coord,
        base_url: format!("http://{addr}"),
        server,
    }
}

/// Start a fleet with the default config.
pub async fn start_fleet(seed: [u8; 32]) -> Fleet {
    start_fleet_with(seed, None).await
}

/// A forgs client for `fleet`.
pub fn client(fleet: &Fleet) -> forgs_client::ForgsClient {
    forgs_client::ForgsClient::new(&fleet.base_url, None).unwrap()
}
