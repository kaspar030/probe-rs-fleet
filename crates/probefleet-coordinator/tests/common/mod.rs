//! Shared scaffolding for the coordinator's integration tests.
//!
//! Every test here runs the **real** axum router (fleet's routes merged with
//! forgs' `/auth/*`) on a real loopback socket and dials it with a real
//! `tokio-tungstenite` / hyper client.
//!
//! Fixtures are built through **production constructors** only: users with
//! forgs' `create_local_user` (which also creates the personal org), team orgs
//! with [`Db::ensure_org_named`] (forgs' `create_node`), memberships with
//! [`Db::set_member`], sessions with `forgs_http::session::mint_session` on the
//! coordinator's own `AuthContext`, API keys with `NsScope::insert_api_key`
//! (payload canonicalised by fleet's own purpose hook), and node tokens through
//! the coordinator's registration path. No test hand-rolls an id or a token
//! shape production could not produce.
//!
//! # Acting org
//!
//! A user session is no longer bound to one org: it acts in its **personal**
//! org unless the request names another (`?org=<name-or-id>`). So
//! [`TestCoordinator::seed_session`] returns a token whose holder is a member
//! of `org`, and a test that wants to act *there* on `/client` uses
//! [`TestCoordinator::client_session_in`] (or appends `?org=` itself).

#![allow(dead_code)]

use std::sync::Arc;

use forgs::{TokenKind, UserId};
use probefleet_coordinator::auth::Ed25519Signer;
use probefleet_coordinator::clock::SystemClock;
use probefleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use probefleet_coordinator::core::Coordinator;
use probefleet_coordinator::state::Db;
use probefleet_coordinator::FleetRole;
use probefleet_core::policy::Policy;
use probefleet_core::scheduler::Scheduler;
use probefleet_proto::adopt::AdoptPolicy;
use probefleet_proto::ids::{BoardRef, NodeId, OrgId};

/// The signing seed every test coordinator uses.
pub const SEED: [u8; 32] = [7u8; 32];

/// The CSRF secret every test coordinator uses.
pub const CSRF_SECRET: [u8; 32] = [9u8; 32];

/// A coordinator serving its real router on a real loopback port.
pub struct TestCoordinator {
    pub coord: Arc<Coordinator>,
    /// `http://127.0.0.1:<port>` — what a client passes as `fleet_url`.
    pub base_url: String,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for TestCoordinator {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl TestCoordinator {
    /// Start a coordinator with the default configuration.
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Start a coordinator, letting the caller adjust the configuration first.
    pub async fn start_with(tweak: impl FnOnce(&mut CoordinatorConfig)) -> Self {
        let mut config = CoordinatorConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            sqlite_path: ":memory:".into(),
            signing_key: SigningKeySource::Seed(SEED),
            csrf_secret: Some(CSRF_SECRET.to_vec()),
            ..CoordinatorConfig::default()
        };
        tweak(&mut config);
        Self::start_config(config, Vec::new()).await
    }

    /// Start a coordinator from a finished config plus login providers.
    pub async fn start_config(
        config: CoordinatorConfig,
        providers: Vec<Arc<dyn forgs_idp::IdentityProvider>>,
    ) -> Self {
        let db = Db::connect_in_memory().await.unwrap();
        // What `probefleet_coordinator::build` does at startup.
        db.ensure_org_named(
            &config.default_org,
            probefleet_coordinator::now_epoch_secs(),
        )
        .await
        .unwrap();
        let coord = Arc::new(
            Coordinator::with_providers(
                config,
                Scheduler::new(Policy::default()),
                db,
                Ed25519Signer::from_seed(&SEED),
                Arc::new(SystemClock),
                providers,
            )
            .unwrap(),
        );

        let router = probefleet_coordinator::http::router(Arc::clone(&coord));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        });

        Self {
            coord,
            base_url: format!("http://{addr}"),
            server,
        }
    }

    /// The database handle.
    pub fn db(&self) -> &Db {
        self.coord.db()
    }

    /// forgs' auth context of this coordinator.
    pub fn auth(&self) -> &forgs_http::AuthContext {
        self.coord.auth()
    }

    /// The coordinator's clock, epoch seconds.
    pub fn now(&self) -> u64 {
        self.coord.now()
    }

    // -----------------------------------------------------------------------
    // Identity fixtures
    // -----------------------------------------------------------------------

    /// The team org named `name`, created if absent (forgs `create_node`).
    pub async fn org(&self, name: &str) -> OrgId {
        self.db().ensure_org_named(name, self.now()).await.unwrap()
    }

    /// The user named `name`, created (with its personal org, where they are
    /// admin) if absent — forgs' `create_local_user`.
    pub async fn user(&self, name: &str) -> UserId {
        if let Some(u) = self.db().forgs().user_by_username(name).await.unwrap() {
            return u.id;
        }
        self.db()
            .forgs()
            .create_local_user(name, None, self.now())
            .await
            .unwrap()
            .0
    }

    /// `name`'s personal org.
    pub async fn personal_org(&self, name: &str) -> OrgId {
        let user = self.user(name).await;
        self.db().personal_org(user).await.unwrap().unwrap()
    }

    /// Make `user` a member of team org `org` with `role`; returns both ids.
    pub async fn member(&self, org: &str, user: &str, role: FleetRole) -> (OrgId, UserId) {
        let o = self.org(org).await;
        let u = self.user(user).await;
        self.db().set_member(&o, u, role, self.now()).await.unwrap();
        (o, u)
    }

    /// A fresh session token for `user` (created if absent), minted by forgs'
    /// own `mint_session`.
    pub async fn session_for(&self, user: &str) -> String {
        let u = self.user(user).await;
        forgs_http::session::mint_session(self.auth(), u, "test")
            .await
            .unwrap()
            .token
    }

    /// `login` as a `role` member of team org `org`, plus a session token.
    ///
    /// The session acts in `login`'s **personal** org unless a request names
    /// `org` (`?org=`); see the module docs.
    pub async fn seed_session(&self, org: &str, login: &str, role: FleetRole) -> String {
        self.member(org, login, role).await;
        self.session_for(login).await
    }

    /// A user with only their personal org: `(session token, personal org,
    /// user id)`. What a fresh signup looks like.
    pub async fn seed_user(&self, login: &str) -> (String, OrgId, UserId) {
        let user = self.user(login).await;
        let org = self.db().personal_org(user).await.unwrap().unwrap();
        (self.session_for(login).await, org, user)
    }

    /// A refresh token for `login` (forgs' `mint_refresh`).
    pub async fn seed_refresh_token(&self, login: &str) -> String {
        let u = self.user(login).await;
        forgs_http::session::mint_refresh(self.auth(), u)
            .await
            .unwrap()
    }

    /// A session for `login` that has already expired.
    pub async fn seed_expired_session(&self, login: &str) -> String {
        let u = self.user(login).await;
        let token = self.auth().format().mint(TokenKind::Session);
        let now = self.now();
        self.db()
            .forgs()
            .insert_session(&token.hash(), u, now - 100, now - 1)
            .await
            .unwrap();
        token.to_secret_string()
    }

    /// The `Cookie` header and `X-Fleet-Csrf` value a browser holding session
    /// `token` would send. The CSRF value is derived by forgs' own helper on
    /// the coordinator's context, so a test cannot agree with itself about a
    /// value the server would never produce.
    pub fn browser_session(&self, token: &str) -> (String, String) {
        let hash = self.auth().format().parse(token).unwrap().hash();
        let csrf = forgs_http::cookies::csrf_token(self.auth(), hash.as_str());
        (format!("prfs_session={token}"), csrf)
    }

    // -----------------------------------------------------------------------
    // Node fixtures
    // -----------------------------------------------------------------------

    /// Enroll node `name` in team org `org` through the coordinator's
    /// registration path (as an API-key enrollment: no owner, `declared`).
    /// Returns the node token and id.
    pub async fn seed_node(&self, org: &str, name: &str) -> (String, NodeId) {
        let org = self.org(org).await;
        self.seed_node_in(&org, name).await
    }

    /// As [`TestCoordinator::seed_node`] for an already-resolved org.
    pub async fn seed_node_in(&self, org: &OrgId, name: &str) -> (String, NodeId) {
        let resp = self
            .coord
            .register_node_and_mint(
                org,
                name,
                &[],
                None,
                AdoptPolicy::Declared,
                "node.enroll",
                "test fixture",
            )
            .await
            .unwrap();
        (resp.token, NodeId(resp.node_id))
    }

    /// Seed a node **owned** by user `owner` (the `share` shape).
    pub async fn seed_owned_node(
        &self,
        org: &str,
        name: &str,
        owner: &str,
        adopt: AdoptPolicy,
    ) -> (String, NodeId) {
        let org = self.org(org).await;
        let owner = self.user(owner).await;
        let resp = self
            .coord
            .register_node_and_mint(
                &org,
                name,
                &[],
                Some(owner),
                adopt,
                "node.self_register",
                "test fixture",
            )
            .await
            .unwrap();
        (resp.token, NodeId(resp.node_id))
    }

    /// As [`TestCoordinator::seed_node`], with an explicit `token_issued_at`,
    /// so a test can present a token that is already due for rotation.
    pub async fn seed_node_at(&self, org: &str, name: &str, issued_at: u64) -> (String, NodeId) {
        let org = self.org(org).await;
        let format = self.auth().format();
        let token = format.mint(probefleet_coordinator::identity::node_token_kind(format));
        let node = self
            .db()
            .register_node(
                &org,
                name,
                token.hash().as_str(),
                &[],
                i64::try_from(issued_at).unwrap(),
            )
            .await
            .unwrap();
        (token.to_secret_string(), node)
    }

    // -----------------------------------------------------------------------
    // API keys, grants, workloads
    // -----------------------------------------------------------------------

    /// Insert an API key in `org` whose payload fleet's own purpose hook
    /// canonicalised; returns the secret.
    async fn insert_key(
        &self,
        org: &OrgId,
        purpose: &str,
        payload: &serde_json::Value,
        single_use: bool,
        expires: Option<u64>,
        subject_name: Option<&str>,
    ) -> String {
        let payload = self
            .auth()
            .purposes()
            .check_payload(purpose, Some(payload))
            .unwrap();
        let token = self.auth().format().mint(TokenKind::ApiKey);
        let ns = probefleet_coordinator::subject::ns_of(org).unwrap();
        self.db()
            .forgs()
            .scoped(ns)
            .insert_api_key(
                &forgs_store::NewApiKey {
                    hash: token.hash(),
                    purpose: purpose.to_owned(),
                    subject_name: subject_name.map(str::to_owned),
                    payload,
                    single_use,
                    expires,
                    created_by: None,
                },
                self.now(),
            )
            .await
            .unwrap();
        token.to_secret_string()
    }

    /// A `node`-purpose API key for team org `org` stamping `tags`.
    pub async fn seed_auth_key(
        &self,
        org: &str,
        tags: &[String],
        single_use: bool,
        expires: Option<u64>,
    ) -> String {
        let org = self.org(org).await;
        self.insert_key(
            &org,
            probefleet_coordinator::identity::PURPOSE_NODE,
            &serde_json::json!({ "tags": tags }),
            single_use,
            expires,
            None,
        )
        .await
    }

    /// A multi-use `ci`-purpose key for team org `org` over boards tagged
    /// `tags` (non-empty: an empty selector is refused by the hook).
    pub async fn seed_ci_auth_key(
        &self,
        org: &str,
        tags: &[String],
        expires: Option<u64>,
    ) -> String {
        self.seed_named_ci_auth_key(org, tags, expires, None).await
    }

    /// As [`TestCoordinator::seed_ci_auth_key`], with an identity name
    /// (`<org>/workload:agent:<name>` instead of `…:key:<hash8>`).
    pub async fn seed_named_ci_auth_key(
        &self,
        org: &str,
        tags: &[String],
        expires: Option<u64>,
        subject_name: Option<&str>,
    ) -> String {
        let org = self.org(org).await;
        self.insert_key(
            &org,
            probefleet_coordinator::identity::PURPOSE_CI,
            &serde_json::json!({ "tags": tags }),
            false,
            expires,
            subject_name,
        )
        .await
    }

    /// Grant `repo` (`owner/name`) access to `org`'s boards matching
    /// `selector`, returning the grant id. The subject is built by forgs'
    /// `workload_subject_key`, as the exchange path builds it.
    pub async fn seed_workload_grant(
        &self,
        org: &str,
        repo: &str,
        selector: &str,
        ops: &[probefleet_proto::token::AllowedOp],
        expires: Option<u64>,
    ) -> String {
        let org = self.org(org).await;
        let normalised = forgs::subject::normalise_repo(repo)
            .unwrap_or_else(|| panic!("{repo} is not a valid owner/name"));
        let subject = forgs::subject::workload_subject_key(&normalised);
        let selector = probefleet_proto::lease::parse_constraint(selector)
            .unwrap()
            .to_string();
        let now = self.now();
        let ns = probefleet_coordinator::subject::ns_of(&org).unwrap();
        self.db()
            .forgs()
            .scoped(ns)
            .insert_grant(
                &forgs_store::NewGrant {
                    subject,
                    selector,
                    ops: probefleet_coordinator::state::join_ops(ops),
                    expires: expires.or(Some(now + 86_400)),
                    created_by: None,
                },
                now,
            )
            .await
            .unwrap()
            .to_string()
    }

    /// A workload token for `repo`, inserted through forgs' store.
    ///
    /// For tests about what a workload token may *do* once it exists, which
    /// should not have to stand up a stub issuer to find out.
    pub async fn seed_workload_token(&self, repo: &str, expires: u64) -> String {
        let normalised = forgs::subject::normalise_repo(repo).unwrap();
        let subject = forgs::subject::workload_subject_key(&normalised);
        let token = self.auth().format().mint(TokenKind::Workload);
        self.db()
            .forgs()
            .insert_workload_token(
                &token.hash(),
                &subject,
                "github-actions",
                None,
                self.now(),
                expires,
            )
            .await
            .unwrap();
        token.to_secret_string()
    }

    // -----------------------------------------------------------------------
    // Boards
    // -----------------------------------------------------------------------

    /// Put a board into the scheduler directly, bypassing a node connection.
    pub async fn seed_board(&self, org: &OrgId, node: &str, name: &str, tags: &[&str]) -> BoardRef {
        self.seed_board_with_model(org, node, name, tags, None)
            .await
    }

    /// As [`seed_board`](Self::seed_board), but declaring a board **model**.
    pub async fn seed_board_with_model(
        &self,
        org: &OrgId,
        node: &str,
        name: &str,
        tags: &[&str],
        model: Option<&str>,
    ) -> BoardRef {
        use probefleet_proto::board::{Board, BoardState, PowerKind};

        let node = probefleet_coordinator::node_id_for(org, node);
        let now = i64::try_from(self.now()).unwrap();
        self.db()
            .scoped(org.clone())
            .ensure_node(&node, now)
            .await
            .unwrap();
        let board = Board {
            id: BoardRef::new(org.clone(), node.clone(), name),
            node,
            chip: "nRF52840_xxAA".to_owned(),
            model: model.map(str::to_owned),
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        };
        self.db()
            .scoped(org.clone())
            .record_board(
                &board,
                probefleet_proto::node_api::BoardPresence::Online,
                now,
            )
            .await
            .unwrap();
        let id = board.id.clone();
        self.coord.scheduler().lock().await.upsert_board(board);
        id
    }

    // -----------------------------------------------------------------------
    // Transport
    // -----------------------------------------------------------------------

    /// Dial a route with a bearer token, returning the connected wire halves.
    /// `path` may carry a query (`/client?org=acme`).
    pub async fn dial(
        &self,
        path: &str,
        bearer: &str,
    ) -> Result<
        (
            probefleet_wire::client::DialedTx,
            probefleet_wire::client::DialedRx,
        ),
        probefleet_wire::WireError,
    > {
        // `DialOpts::path` is `'static` for production's fixed routes; a test
        // leaks its few dynamic ones.
        let path: &'static str = Box::leak(path.to_owned().into_boxed_str());
        probefleet_wire::client::dial(probefleet_wire::client::DialOpts {
            url: self.base_url.clone(),
            path,
            bearer: bearer.to_owned(),
            pin: None,
        })
        .await
    }

    /// The HTTP status a `WebSocket` upgrade attempt was rejected with (101 on
    /// success).
    pub async fn upgrade_status(&self, path: &str, bearer: Option<&str>) -> u16 {
        self.upgrade_status_with(path, bearer, &[]).await
    }

    /// As [`TestCoordinator::upgrade_status`], with extra request headers (a
    /// `Cookie`, say).
    pub async fn upgrade_status_with(
        &self,
        path: &str,
        bearer: Option<&str>,
        headers: &[(&'static str, &str)],
    ) -> u16 {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

        let url = format!("{}{path}", self.base_url.replace("http://", "ws://"));
        let mut request = url.as_str().into_client_request().unwrap();
        if let Some(bearer) = bearer {
            request.headers_mut().insert(
                http::header::AUTHORIZATION,
                format!("Bearer {bearer}").parse().unwrap(),
            );
        }
        for (name, value) in headers {
            request.headers_mut().insert(*name, value.parse().unwrap());
        }
        match tokio_tungstenite::connect_async(request).await {
            Ok(_) => 101,
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => resp.status().as_u16(),
            Err(e) => panic!("unexpected dial failure: {e}"),
        }
    }

    /// A plain HTTP request, returning `(status, body)`.
    pub async fn http(&self, method: &str, path: &str, body: Option<String>) -> (u16, String) {
        self.http_auth(method, path, None, body).await
    }

    /// As [`TestCoordinator::http`], with an optional `Authorization: Bearer`.
    pub async fn http_auth(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<String>,
    ) -> (u16, String) {
        let auth = bearer.map(|b| format!("Bearer {b}"));
        let headers: Vec<(&str, &str)> = auth
            .as_deref()
            .map(|a| vec![("authorization", a)])
            .unwrap_or_default();
        let (status, _, body) = self.http_full(method, path, &headers, body).await;
        (status, body)
    }

    /// An HTTP request with arbitrary headers, returning `(status, response
    /// headers, body)`. Redirects are **not** followed.
    pub async fn http_full(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<String>,
    ) -> (u16, Vec<(String, String)>, String) {
        use http_body_util::BodyExt as _;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        let client: Client<_, http_body_util::Full<hyper::body::Bytes>> =
            Client::builder(TokioExecutor::new()).build_http();
        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base_url));
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            builder = builder.header(http::header::CONTENT_TYPE, "application/json");
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                body.unwrap_or_default(),
            )))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let status = resp.status().as_u16();
        let response_headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            response_headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    /// Open a `/client` session as the holder of `bearer`, acting in its
    /// default org (a user's personal org; a workload's none).
    pub async fn client_session(
        &self,
        bearer: &str,
    ) -> probefleet_sidecar::transport::CoordSession {
        self.client_session_at("/client", bearer).await
    }

    /// Open a `/client` session acting in `org` (a name or id).
    pub async fn client_session_in(
        &self,
        bearer: &str,
        org: &str,
    ) -> probefleet_sidecar::transport::CoordSession {
        self.client_session_at(&format!("/client?org={org}"), bearer)
            .await
    }

    async fn client_session_at(
        &self,
        path: &str,
        bearer: &str,
    ) -> probefleet_sidecar::transport::CoordSession {
        let (tx, rx) = self.dial(path, bearer).await.unwrap();
        probefleet_sidecar::transport::CoordSession::start(Box::new(tx), Box::new(rx))
            .await
            .unwrap()
    }

    /// Every fleet audit action recorded, as `(org id, subject, action)`.
    pub async fn audit_rows(&self) -> Vec<(String, Option<String>, String)> {
        sqlx::query_as("SELECT ns_node_id, subject, action FROM audit_log ORDER BY id")
            .fetch_all(self.db().pool_for_test())
            .await
            .unwrap()
    }

    /// Every forgs (identity) audit action recorded, oldest first.
    pub async fn forgs_audit_actions(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT action FROM forgs_audit ORDER BY id")
            .fetch_all(self.db().pool_for_test())
            .await
            .unwrap()
    }
}

/// A stand-in for a connected node, registered directly in the coordinator's
/// registry.
pub struct NodeStub {
    rx: tokio::sync::mpsc::Receiver<probefleet_coordinator::registry::NodeMessage>,
}

/// What a node was told to open, as observed by a [`NodeStub`].
pub struct OpenedSession {
    pub channel: probefleet_proto::ChannelId,
    pub token: Vec<u8>,
    pub serve_token: String,
}

impl NodeStub {
    /// Register a stub handle for `node`.
    pub async fn attach(fleet: &TestCoordinator, node: &NodeId) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        fleet
            .coord
            .nodes()
            .insert(
                node.clone(),
                probefleet_coordinator::registry::NodeHandle::new(tx),
            )
            .await;
        Self { rx }
    }

    /// Await the next `OpenSession` command.
    pub async fn expect_open_session(&mut self) -> OpenedSession {
        match self.rx.recv().await.expect("node connection closed") {
            probefleet_coordinator::registry::NodeMessage::Command(
                probefleet_proto::CoordinatorCommand::OpenSession {
                    channel,
                    token,
                    serve_token,
                    ..
                },
            ) => OpenedSession {
                channel,
                token,
                serve_token,
            },
            other => panic!("expected OpenSession, got {other:?}"),
        }
    }

    /// Await the next `PowerCycle` command, returning the board name.
    pub async fn expect_power_cycle(&mut self) -> probefleet_proto::ids::BoardName {
        match self.rx.recv().await.expect("node connection closed") {
            probefleet_coordinator::registry::NodeMessage::Command(
                probefleet_proto::CoordinatorCommand::PowerCycle { board },
            ) => board,
            other => panic!("expected PowerCycle, got {other:?}"),
        }
    }

    /// Await the next `KillSession` command, returning the channel.
    pub async fn expect_kill_session(&mut self) -> probefleet_proto::ChannelId {
        match self.rx.recv().await.expect("node connection closed") {
            probefleet_coordinator::registry::NodeMessage::Command(
                probefleet_proto::CoordinatorCommand::KillSession { channel },
            ) => channel,
            other => panic!("expected KillSession, got {other:?}"),
        }
    }

    /// Whether any command is queued for this stub, without waiting.
    pub fn is_idle(&mut self) -> bool {
        self.rx.try_recv().is_err()
    }
}
