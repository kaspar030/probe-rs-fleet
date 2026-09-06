//! Shared scaffolding for the `WebSocket` integration tests.
//!
//! Every test in `ws_e2e` / `ws_auth` / `auth_token` / `rotation` / `keepalive`
//! runs the **real** axum router on a real loopback socket and dials it with a
//! real `tokio-tungstenite` client. Nothing here stubs the transport: that is
//! the point, since the transport is what this task changed.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{AgentId, BoardRef, OrgId, Role};

/// The signing seed every test coordinator uses.
pub const SEED: [u8; 32] = [7u8; 32];

/// Counter behind [`TestCoordinator::seed_workload_grant`]'s ids.
static NEXT_GRANT_ID: AtomicU64 = AtomicU64::new(1);

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
            ..CoordinatorConfig::default()
        };
        tweak(&mut config);

        let db = Db::connect_in_memory().await.unwrap();
        let coord = Arc::new(Coordinator::new(
            config,
            Scheduler::new(Policy::default()),
            db,
            Ed25519Signer::from_seed(&SEED),
            Arc::new(SystemClock),
        ));

        let router = fleet_coordinator::http::router(Arc::clone(&coord));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
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

    /// Seed a node row with a fresh token; returns the token's string form.
    pub async fn seed_node(&self, org: &str, name: &str) -> (String, AgentId) {
        self.seed_node_at(org, name, self.coord.now()).await
    }

    /// As [`TestCoordinator::seed_node`], with an explicit `token_issued_at`,
    /// so a test can present a token that is already due for rotation.
    pub async fn seed_node_at(&self, org: &str, name: &str, issued_at: u64) -> (String, AgentId) {
        let org = OrgId(org.to_owned());
        self.db().ensure_org(&org, "personal").await.unwrap();
        let token = OpaqueToken::mint(TokenKind::Node);
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

    /// Seed a user + membership + session; returns the session token.
    pub async fn seed_session(&self, org: &str, login: &str, role: Role) -> String {
        let org = OrgId(org.to_owned());
        self.db().ensure_org(&org, "personal").await.unwrap();
        self.db()
            .ensure_user_member(&org, login, role)
            .await
            .unwrap();
        let token = OpaqueToken::mint(TokenKind::Session);
        let now = i64::try_from(self.coord.now()).unwrap();
        self.db()
            .insert_session(token.hash().as_str(), &org, login, now, now + 3_600)
            .await
            .unwrap();
        token.to_secret_string()
    }

    /// Seed a session that has already expired.
    pub async fn seed_expired_session(&self, org: &str, login: &str) -> String {
        let org = OrgId(org.to_owned());
        self.db().ensure_org(&org, "personal").await.unwrap();
        self.db()
            .ensure_user_member(&org, login, Role::Admin)
            .await
            .unwrap();
        let token = OpaqueToken::mint(TokenKind::Session);
        let now = i64::try_from(self.coord.now()).unwrap();
        self.db()
            .insert_session(token.hash().as_str(), &org, login, now - 100, now - 1)
            .await
            .unwrap();
        token.to_secret_string()
    }

    /// Seed an auth key; returns its string form.
    pub async fn seed_auth_key(
        &self,
        org: &str,
        tags: &[String],
        single_use: bool,
        expires: Option<i64>,
    ) -> String {
        let org = OrgId(org.to_owned());
        self.db().ensure_org(&org, "personal").await.unwrap();
        let token = OpaqueToken::mint(TokenKind::AuthKey);
        let now = i64::try_from(self.coord.now()).unwrap();
        self.db()
            .insert_auth_key(
                &org,
                token.hash().as_str(),
                tags,
                single_use,
                expires,
                None,
                now,
            )
            .await
            .unwrap();
        token.to_secret_string()
    }

    /// Seed a CI (`--purpose ci`) auth key; returns the key's string form.
    ///
    /// Separate from [`TestCoordinator::seed_auth_key`] because it is a
    /// different credential: a `node` key enrolls a machine that *offers*
    /// probes, a `ci` key redeems into a workload token that *leases* them
    /// (architecture §6.7). Nothing should be able to conflate the two by
    /// accident, in the tests least of all.
    pub async fn seed_ci_auth_key(
        &self,
        org: &str,
        tags: &[String],
        expires: Option<i64>,
    ) -> String {
        let org = OrgId(org.to_owned());
        self.db().ensure_org(&org, "personal").await.unwrap();
        let token = OpaqueToken::mint(TokenKind::AuthKey);
        let now = i64::try_from(self.coord.now()).unwrap();
        self.db()
            .insert_auth_key_with_purpose(
                &org,
                token.hash().as_str(),
                tags,
                false,
                expires,
                None,
                now,
                "ci",
                &[],
            )
            .await
            .unwrap();
        token.to_secret_string()
    }

    /// Grant `repo` (as `owner/name`) access to `org`'s boards matching
    /// `selector`, returning the grant id.
    ///
    /// The **per-repo** grant of architecture §6.7, built through the same
    /// `workload_subject_key` the exchange path uses, so a test cannot pass by
    /// agreeing with itself about a spelling the production code would not
    /// produce.
    pub async fn seed_workload_grant(
        &self,
        org: &str,
        repo: &str,
        selector: &str,
        ops: &[fleet_proto::token::AllowedOp],
        expires: Option<i64>,
    ) -> String {
        let org = OrgId(org.to_owned());
        self.db().ensure_org(&org, "personal").await.unwrap();
        let normalised = fleet_proto::ids::normalise_repo(repo)
            .unwrap_or_else(|| panic!("{repo} is not a valid owner/name"));
        let key = fleet_proto::ids::workload_subject_key(&normalised);
        let selector =
            fleet_proto::lease::parse_constraint(selector, fleet_proto::lease::BareTerm::Tag)
                .unwrap()
                .to_string();
        // Unique per call: the id is the revocation handle and two grants in one
        // test must not collide.
        let id = format!("{:032x}", NEXT_GRANT_ID.fetch_add(1, Ordering::Relaxed));
        let now = i64::try_from(self.coord.now()).unwrap();
        self.db()
            .scoped(org)
            .insert_grant(
                &id,
                &key,
                &selector,
                ops,
                expires.or(Some(now + 86_400)),
                None,
                now,
            )
            .await
            .unwrap();
        id
    }

    /// Seed a workload token row directly; returns the token's string form.
    ///
    /// For tests about what a workload token may *do* once it exists, which
    /// should not have to stand up a stub issuer to find out.
    pub async fn seed_workload_token(&self, repo: &str, expires: i64) -> String {
        let token = OpaqueToken::mint(TokenKind::Workload);
        let normalised = fleet_proto::ids::normalise_repo(repo).unwrap();
        let key = fleet_proto::ids::workload_subject_key(&normalised);
        let now = i64::try_from(self.coord.now()).unwrap();
        self.db()
            .insert_workload_token(
                token.hash().as_str(),
                &key,
                "github_oidc",
                &fleet_coordinator::state::WorkloadClaimColumns {
                    repository: Some(normalised),
                    repository_owner: Some("seeded".to_owned()),
                    ..fleet_coordinator::state::WorkloadClaimColumns::default()
                },
                now,
                expires,
            )
            .await
            .unwrap();
        token.to_secret_string()
    }

    /// Dial a route with a bearer token, returning the connected wire halves.
    pub async fn dial(
        &self,
        path: &'static str,
        bearer: &str,
    ) -> Result<(fleet_wire::client::DialedTx, fleet_wire::client::DialedRx), fleet_wire::WireError>
    {
        fleet_wire::client::dial(fleet_wire::client::DialOpts {
            url: self.base_url.clone(),
            path,
            bearer: bearer.to_owned(),
            pin: None,
        })
        .await
    }

    /// The HTTP status a `WebSocket` upgrade attempt was rejected with.
    ///
    /// The dial helper collapses tungstenite's error into a `Protocol` string,
    /// which is right for production (the client should not branch on the
    /// status) but not enough for a test asserting 401 vs. 403 — hence the raw
    /// dial here.
    pub async fn upgrade_status(&self, path: &str, bearer: Option<&str>) -> u16 {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

        let url = format!("{}{path}", self.base_url.replace("http://", "ws://"));
        let mut request = url.as_str().into_client_request().unwrap();
        if let Some(bearer) = bearer {
            request.headers_mut().insert(
                http::header::AUTHORIZATION,
                format!("Bearer {bearer}").parse().unwrap(),
            );
        }
        match tokio_tungstenite::connect_async(request).await {
            Ok(_) => 101,
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => resp.status().as_u16(),
            Err(e) => panic!("unexpected dial failure: {e}"),
        }
    }

    /// Issue a plain HTTP request against the coordinator, returning
    /// `(status, body)`.
    pub async fn http(&self, method: &str, path: &str, body: Option<String>) -> (u16, String) {
        self.http_auth(method, path, None, body).await
    }

    /// As [`TestCoordinator::http`], with an optional `Authorization: Bearer`.
    ///
    /// `/auth/keys` authenticates with a header rather than a body field, and
    /// the only other bearer-capable helper here ([`TestCoordinator::upgrade_status`])
    /// is `WebSocket`-only.
    pub async fn http_auth(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<String>,
    ) -> (u16, String) {
        use http_body_util::BodyExt as _;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        let client: Client<_, http_body_util::Full<hyper::body::Bytes>> =
            Client::builder(TokioExecutor::new()).build_http();
        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base_url))
            .header(http::header::CONTENT_TYPE, "application/json");
        if let Some(bearer) = bearer {
            builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let req = builder
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                body.unwrap_or_default(),
            )))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }


    /// As [`TestCoordinator::http_auth`], but with arbitrary request headers
    /// and the **response** headers returned.
    ///
    /// The browser surface is defined by its headers as much as by its bodies:
    /// a test that cannot see `Set-Cookie` cannot check that a session cookie
    /// is `HttpOnly`, `Secure`, `SameSite=Lax` and no longer-lived than the
    /// `session` row — which is most of what `docs/web-ui.md` D1 promises.
    /// Returns `(status, response headers, body)`.
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
            .uri(format!("{}{path}", self.base_url))
            .header(http::header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                body.unwrap_or_default(),
            )))
            .unwrap();
        // The browser flows answer with 302s that a following client would
        // chase; this one deliberately does not, because the redirect target
        // and the cookies riding with it are the thing under test.
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

    /// The `Cookie` header and `X-Fleet-Csrf` value a browser holding `token`
    /// would send.
    ///
    /// The CSRF value is derived **the way the server derives it** — from
    /// [`SEED`], through the production code's own helper — so a test cannot
    /// pass by agreeing with itself about a value the coordinator would never
    /// produce.
    pub fn browser_session(&self, token: &str) -> (String, String) {
        let hash = OpaqueToken::parse(token).unwrap().hash();
        let csrf = fleet_coordinator::browser_auth::csrf_token_for_test(&self.coord, hash.as_str());
        (format!("prfs_session={token}"), csrf)
    }

    /// Seed a GitHub-shaped user (so `grant <login>` can resolve it) plus a
    /// session, and return the session token.
    ///
    /// The grant path resolves a login to the immutable `user.id`, so a test
    /// that grants by name needs a real `user` row rather than the bare
    /// membership `seed_session` creates.
    pub async fn seed_github_user(
        &self,
        gh_id: i64,
        login: &str,
        role: Role,
    ) -> (String, OrgId, String) {
        let now = i64::try_from(self.coord.now()).unwrap();
        let (user_id, org, _created) = self
            .db()
            .upsert_github_user(gh_id, login, None, now)
            .await
            .unwrap();
        self.db()
            .ensure_user_member(&org, &user_id, role)
            .await
            .unwrap();
        let token = OpaqueToken::mint(TokenKind::Session);
        self.db()
            .insert_session(token.hash().as_str(), &org, &user_id, now, now + 3_600)
            .await
            .unwrap();
        (token.to_secret_string(), org, user_id)
    }

    /// Put a board into the scheduler directly, bypassing an agent connection.
    ///
    /// Authorization tests care about who may reach a board, not about how it
    /// got there; standing up a real agent for each one would drown the
    /// property being tested.
    pub async fn seed_board(&self, org: &OrgId, node: &str, name: &str, tags: &[&str]) -> BoardRef {
        use fleet_proto::board::{Board, BoardState, PowerKind};

        self.db().ensure_org(org, "personal").await.unwrap();
        let agent = AgentId(format!("{}/{node}", org.0));
        let now = i64::try_from(self.coord.now()).unwrap();
        self.db()
            .scoped(org.clone())
            .ensure_node(&agent, now)
            .await
            .unwrap();
        let board = Board {
            id: BoardRef::new(org.clone(), agent.clone(), name),
            agent,
            chip: "nRF52840_xxAA".to_owned(),
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        };
        self.db()
            .scoped(org.clone())
            .record_board(&board, now)
            .await
            .unwrap();
        let id = board.id.clone();
        self.coord.scheduler().lock().await.upsert_board(board);
        id
    }

    /// Open a `/client` session as the holder of `bearer`.
    pub async fn client_session(&self, bearer: &str) -> fleet_sidecar::transport::CoordSession {
        let (tx, rx) = self.dial("/client", bearer).await.unwrap();
        fleet_sidecar::transport::CoordSession::start(Box::new(tx), Box::new(rx))
            .await
            .unwrap()
    }
}

/// A stand-in for a connected agent, registered directly in the coordinator's
/// registry.
///
/// The delegation tests care about which capability token the coordinator hands
/// the node, not about running a real `probe-rs serve`; standing up a full
/// agent for that would bury the property under scaffolding. `ws_e2e.rs`
/// already covers the real agent end to end.
pub struct AgentStub {
    rx: tokio::sync::mpsc::Receiver<fleet_coordinator::registry::AgentMessage>,
}

impl AgentStub {
    /// Register a stub handle for `node`.
    pub async fn attach(fleet: &TestCoordinator, node: &AgentId) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        fleet
            .coord
            .agents()
            .insert(
                node.clone(),
                fleet_coordinator::registry::AgentHandle::new(tx),
            )
            .await;
        Self { rx }
    }

    /// Await the next `OpenSession` command, returning `(channel, token)`.
    ///
    /// The token is what makes this helper worth having: it is the byte string
    /// the node will check, and therefore the one the client must present.
    pub async fn expect_open_session(&mut self) -> (fleet_proto::ChannelId, Vec<u8>) {
        match self.rx.recv().await.expect("agent connection closed") {
            fleet_coordinator::registry::AgentMessage::Command(
                fleet_proto::CoordinatorCommand::OpenSession { channel, token, .. },
            ) => (channel, token),
            other => panic!("expected OpenSession, got {other:?}"),
        }
    }
}
