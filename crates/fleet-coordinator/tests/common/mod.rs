//! Shared scaffolding for the `WebSocket` integration tests.
//!
//! Every test in `ws_e2e` / `ws_auth` / `auth_token` / `rotation` / `keepalive`
//! runs the **real** axum router on a real loopback socket and dials it with a
//! real `tokio-tungstenite` client. Nothing here stubs the transport: that is
//! the point, since the transport is what this task changed.

#![allow(dead_code)]

use std::sync::Arc;

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{AgentId, OrgId, Role};

/// The signing seed every test coordinator uses.
pub const SEED: [u8; 32] = [7u8; 32];

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
        self.db().ensure_user_member(&org, login, role).await.unwrap();
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
        use http_body_util::BodyExt as _;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        let client: Client<_, http_body_util::Full<hyper::body::Bytes>> =
            Client::builder(TokioExecutor::new()).build_http();
        let req = http::Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base_url))
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                body.unwrap_or_default(),
            )))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }
}
