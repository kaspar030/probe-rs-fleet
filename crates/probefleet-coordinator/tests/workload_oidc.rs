//! Workload identity, end to end: GitHub Actions OIDC against a **stub
//! issuer** on loopback, and the CI auth-key fallback (architecture §6.7).
//!
//! The exchange itself is forgs' (`POST /auth/token` with `grant_type`
//! `github_oidc` or `api_key`); the issuer is configured from the
//! coordinator's `[github_actions]` table (`identity::gha_issuer`), and the
//! real issuer needs a GitHub Actions runner, which no test has. So the JWKS
//! URL is configurable — that is the only reason it is — and these tests
//! point it at an axum stub serving a JWK set they hold the private key for.
//!
//! # What is genuinely exercised
//!
//! Signature verification against a fixture key, the rejection taxonomy
//! (expiry, audience, issuer, unknown `kid`, algorithm confusion, tampering,
//! missing claims — all one indistinguishable `401`), key rotation, the JWKS
//! fetch rate limit, and — the point of the whole path — that the token which
//! comes out **authenticates a real `/client` upgrade and leases a real
//! board**, and only the boards its grant selects. An exchange that mints a
//! token nothing can use would pass a weaker test suite and be worthless.
//!
//! The fleet-facing properties: a workload acts in **no org** (asking for one
//! is a `403`), reaches boards only through grants, is refused on `/agent`,
//! on forgs' key surface and on the delegate/admin verbs, and is clamped to
//! CI priority. A `ci` API key's redemption synthesises one deterministic
//! grant per identity (named `…/workload:agent:<name>` or
//! `…/workload:key:<hash8>`), and revoking the key cascades: the grant goes
//! and the live leases are torn down.
//!
//! The headline test is [`a_repo_not_listed_under_a_listed_owner_is_denied`]:
//! the per-repo trust rule is the security-relevant decision, and it is
//! asserted with a *sibling* grant proving the owner is otherwise reachable —
//! otherwise the test would pass equally well against a coordinator that had
//! simply failed to configure anything.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use serde_json::{json, Value};

use common::TestCoordinator;
use probefleet_coordinator::config::GithubActionsConfig;
use probefleet_coordinator::FleetRole;
use probefleet_proto::ids::OrgId;
use probefleet_proto::lease::{Constraint, LeaseRequest, Priority};
use probefleet_proto::token::AllowedOp;
use probefleet_wire::{CoordToSidecar, SidecarToCoord};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
//
// Two committed RSA-2048 keys, PKCS#1 DER, base64. Committed rather than
// generated at test time because RSA keygen in a debug build is slow and its
// timing varies enough to make a test flaky for reasons unrelated to the code
// under test. They exist only here and sign only fixtures.

/// The issuer's ordinary signing key.
const KEY_A_DER_B64: &str = concat!(
    "MIIEpAIBAAKCAQEArsL3i977OYrPnKq6SjRYRIYuzkEAd+rd3hvupoNtMt/w7kG6qX2apWgw",
    "tqbMvX06fmswpnBqQuF99lOvBZYQ1AfsV6igmRp9WET0X+kO0ptI0bYs1UGWYc2LMHQWEUJA",
    "tFjH5YzOteoEsw1RwceJ9kDn1WMkotIq/uvx+LlptN98PtnpL3vjIvo+QyYD8ulcEmIygjnE",
    "Vf/Dpx76agi4gRTG9miu7NkU3VgZXnMfQdjh7Exz04Qg3ItN/kTkoxx6Yjn1wuo77fZxj7Sp",
    "AiZbSRix3sRxij/Wt4VfMT2MBwWNb1KjOVxQygPfl9KsxTxD6njiXWtQez89r5RVfoUH0QID",
    "AQABAoIBAAv/eqXxqGcU7pf06KvmLWvW7SkKhru04N06JweWMk2x2NqioewM9tcFm4KOr7O6",
    "qzoOpd0SDq7fcu8RuQxgdxtMx/RksVHm4wAdC8yh4CX5XzshOga8uqmlm463XuR5xfNxEkLi",
    "MzbYsCXoHjAi64fVK5VszxEWmLkTqHMeV5wr4SMQA4JmmMO8Yr/TcmkIQxCwzTlOy+Mm9XBq",
    "3WnKKhiAeDX1V2S+DzXucbiXRNpyHx2o/FDtDpsWe2ZGiiZTrUBM9HgU3lS3FXGwNkhAHKAn",
    "VxVMpiAk0xFoJQ1+ZevTy+SJHf9SeTalhxZENjPmX6FY5095UFNSdHWb2nZKVSECgYEA7OFb",
    "CaoIB3ELnlnwbu3CUiASd8JpxDhViBiKpykwAnO/shrc/meeuzbqn+LGOHW/WicuVJBQwdF8",
    "3LOGHWxqmOnBZbRgdw0His27xQ3BSKm0p90qb3kKqoLTg0gY/sZ9lWsSci4f+OxdqamzNHDV",
    "vof2KiQjCcrZ9CIS8VSB550CgYEAvN4OVeuFM9Q7j2YRnAxSPMIvE0Z35LG9UQYVmwU9/rDm",
    "IQwV6TkrGrjhytz9Ra4neeZDmY8PvgP6KMyzwPtEF8ozop9I4fU40iel+UioAo/+FacctwgM",
    "0geGcG7rsA92udPxwbpNCmJA8tdKRJ9lcp/kNEbAHQEIGhjFs7LJPMUCgYEA5SYj0TeAyOIc",
    "oTTUGBs8jgGkm+GgO0dbxmonRwna/aRHXt4JxrkqnmTDl6PiqR+O2oFomjl5ReWHamDobnJA",
    "tGf8xIw3fTNHhoj7CecCgW5Z6sFSmb94B/bC8g6+z0fomLCZiYcBOuY8vTICv8ofm08fXSjU",
    "FFb9fOOxe2+KsykCgYEAkirIrXY5AIOgFLrJphtjCeK+zAwdfcCQ48PxtKe58wK1F55i1ryH",
    "v4aWOIoO+X5uzsiGSLGPXV92m1zRQOk1KbQzgggEP9uovfwxV1wDqvgFjHxonL5+LY3lXd56",
    "SSeumuKMl4G3XfHskgRMVg+GU8+qrUqUI95IhunlF82mMIECgYAxvXnRxgjI/p/5ERXYvvaL",
    "QfnJ0jFfcGr6hlx3INsMq9JcpI1C2FiWkPuU/folOSKYHQ7bNNxtMh6lkBW2+m4Zm1CAzlRB",
    "DM8oAR00QMf12agzXuXXBqpaDIeq011IJmtUIPwSJAxSBOnrT1lZvff7EIqg8CRj5uUPNLfx",
    "hKhlIA==",
);

/// Base64url modulus of [`KEY_A_DER_B64`].
const KEY_A_N: &str = concat!(
    "rsL3i977OYrPnKq6SjRYRIYuzkEAd-rd3hvupoNtMt_w7kG6qX2apWgwtqbMvX06fmswpnBq",
    "QuF99lOvBZYQ1AfsV6igmRp9WET0X-kO0ptI0bYs1UGWYc2LMHQWEUJAtFjH5YzOteoEsw1R",
    "wceJ9kDn1WMkotIq_uvx-LlptN98PtnpL3vjIvo-QyYD8ulcEmIygjnEVf_Dpx76agi4gRTG",
    "9miu7NkU3VgZXnMfQdjh7Exz04Qg3ItN_kTkoxx6Yjn1wuo77fZxj7SpAiZbSRix3sRxij_W",
    "t4VfMT2MBwWNb1KjOVxQygPfl9KsxTxD6njiXWtQez89r5RVfoUH0Q",
);

/// The key the issuer rotates *to*.
const KEY_B_DER_B64: &str = concat!(
    "MIIEowIBAAKCAQEApesnGL/IibSnxbbALzq9yErXD9Hklbk6gpMTvfEOnPmNDw7w/MiHgTSb",
    "3JC9zyZ5Qb9zS8HK3SCMDd/VysZIe2rQ1MvETvkL3ryX3g6qHTtXy8yqLvOIDMrS7abrglWr",
    "EHrYziVHxaB6nxO6X8gVMThi+yAuUoZjm4pirkwohD8Gf/tpYgIP7A/zGOSluQj8vodb1M9q",
    "kfWllxMSTjg0Y2hgxz3/PKTKRoeRmJY1vVQC75VuA716KRGlepi7u0bex49jB3R1gvJRper0",
    "rN+Oidt/bOn3+oIolxCHUmulJrWASpwkwVMnew1AcI9VT8HF4R99TB6LdRUVfjbA1JgJjwID",
    "AQABAoIBAE99V5/N0h/XQ0HAClcWR3I8GMjlgCQTN+ry19R6NswR6vi56c7Rq8nFEJ8dYTJr",
    "dlB/jpdO4wgJ3c+P23dog7VNOXuZnBVRz9QIeqHSWMHkem2TQj14Q0gNq/xbqh0pOemNUW2C",
    "At61wcmQxAu7ahvIrfMuOcMjy3jrVde3ePnSChWoj+bSWKV+XH3cRnPhez6NispbpTb0y35E",
    "z93bixH5bb5CzzH+59DtPF8+9tQ9q3jUQRtsGKm+jgcXNYbr2ENCC5I2LzyfAtzHP6wzUSxv",
    "FeeiOroZ/ChNTOptm3ECH8BJGfBw6LnlGxBcUFIC69ixmLMECSlgWhHYRUmr+uECgYEA3oo/",
    "KYsSsO66bZW5xJTCdsu2vAA21ATRKJptLAghQ1FImLMQYoM9rfW4OWD+Uf4SJ2OqN45B1GtC",
    "Ff8wa1w3dG17gRio1PBw0ctALxm0vbOFiGT2qGBfOJ3IAS0uUw4mSesdiUKpEzzSz+e5Hq3O",
    "Z72UidgmBuarmVLacOupAUcCgYEAvt1/ivhL8u0JDyfw8F72znsRYkXw3DFRq65KoSCrnoek",
    "mj42Z+7B+TVjwhwB9u4q8u0ohtZu6UC2LDWWjg8MSotvjW3TwKQhpwZV8LX1NEcpBU9XI1fD",
    "GbNQu5GT1ESTL1/Dy5Ik4DfJ2Y3yJC/f6jeWnYLm2yqWAc1AXpH1mXkCgYAP/XT+YizMo8qn",
    "dxurAVlbudV+erF12IbC2R3BDTB+qseBmVQzD+UNq9s53DtJ3uylAedIKKOYRMCx3e03uZ+O",
    "cRNvujrfWgtxN558A+fVvaF5pG+It6v/4G5vjzSF6T1dEFTF+RE2/abUI31MtAZhs+CJawuI",
    "cWihEq/5byVsnwKBgGsbT1yEE9LB88h+iHXLRMMASvQT/aMDRiqKhzS+abBvvA4WhV9zm4Sm",
    "0lF2eB/C7XUfYxOvt9PLTa+nbtJPXX1jm/kIvcCoGn5pTsbixTRODpX9PRAHSuPcPZzUh9mh",
    "ldsK6YwOegUdKXedcVmfSA9enHXNpJEu57khHlMzo1g5AoGBANQcvcBfnMDuGPYKSqGsrCn9",
    "G3UZDtJ+mCvXyTdnTif/tP8Xvsi9+h4CYQl/zG8CHNo9aNqdnIoIVS9ZfTVmSF1n9IQTVByr",
    "Y4o97s7rIAqpEVzY0H2fHA5MgO4hmSAAOdWiG0d5ScstfWofmcj/8tYWHv8VZthbkqxtJtW/",
    "bqP0",
);

/// Base64url modulus of [`KEY_B_DER_B64`].
const KEY_B_N: &str = concat!(
    "pesnGL_IibSnxbbALzq9yErXD9Hklbk6gpMTvfEOnPmNDw7w_MiHgTSb3JC9zyZ5Qb9zS8HK",
    "3SCMDd_VysZIe2rQ1MvETvkL3ryX3g6qHTtXy8yqLvOIDMrS7abrglWrEHrYziVHxaB6nxO6",
    "X8gVMThi-yAuUoZjm4pirkwohD8Gf_tpYgIP7A_zGOSluQj8vodb1M9qkfWllxMSTjg0Y2hg",
    "xz3_PKTKRoeRmJY1vVQC75VuA716KRGlepi7u0bex49jB3R1gvJRper0rN-Oidt_bOn3-oIo",
    "lxCHUmulJrWASpwkwVMnew1AcI9VT8HF4R99TB6LdRUVfjbA1JgJjw",
);

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const AUDIENCE: &str = "https://fleet.test";

/// The one body every refused exchange answers with (forgs' shape).
const INVALID_GRANT: &str = r#"{"error":"invalid_grant"}"#;

fn der(b64: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap()
}

// ---------------------------------------------------------------------------
// The stub issuer
// ---------------------------------------------------------------------------

struct StubState {
    /// The JWK set currently served. Swappable, so a test can rotate keys.
    keys: std::sync::Mutex<Value>,
    /// How many times the JWKS was fetched. The rotation and rate-limit tests
    /// are *about* this number.
    fetches: AtomicUsize,
    /// When set, the endpoint answers `500`. An issuer outage is the case the
    /// rate limit exists for, and it cannot be staged by simply not starting
    /// the stub: a refused connection and a failing endpoint take different
    /// paths, and it is the endpoint that must still be counted.
    down: std::sync::atomic::AtomicBool,
}

/// A stub `token.actions.githubusercontent.com` JWKS endpoint on loopback.
struct StubIssuer {
    base_url: String,
    state: Arc<StubState>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for StubIssuer {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl StubIssuer {
    async fn start() -> Self {
        let state = Arc::new(StubState {
            keys: std::sync::Mutex::new(jwks(&[("k1", KEY_A_N)])),
            fetches: AtomicUsize::new(0),
            down: std::sync::atomic::AtomicBool::new(false),
        });
        let router = Router::new()
            .route("/.well-known/jwks", get(serve_jwks))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Self {
            base_url: format!("http://{addr}"),
            state,
            server,
        }
    }

    /// The `[github_actions]` config pointing a coordinator at this stub.
    fn config(&self) -> GithubActionsConfig {
        GithubActionsConfig {
            issuer: ISSUER.to_owned(),
            jwks_url: format!("{}/.well-known/jwks", self.base_url),
            audience: AUDIENCE.to_owned(),
            // Long enough that nothing refetches on a staleness timer during a
            // test: every refetch these tests count is a *forced* one.
            jwks_refresh_secs: 3_600,
            // Zero, so the rotation test is not fighting the rate limit; the
            // rate limit gets its own tests with a real floor.
            jwks_min_refetch_secs: 0,
            workload_token_ttl_secs: 3_600,
        }
    }

    fn fetches(&self) -> usize {
        self.state.fetches.load(Ordering::Relaxed)
    }

    /// Publish a new key set, as a rotation would.
    fn rotate_to(&self, entries: &[(&str, &str)]) {
        *self.state.keys.lock().unwrap() = jwks(entries);
    }

    /// Start answering `500`, as an issuer having a bad day would.
    fn take_down(&self) {
        self.state.down.store(true, Ordering::Relaxed);
    }
}

async fn serve_jwks(
    State(state): State<Arc<StubState>>,
) -> Result<Json<Value>, axum::http::StatusCode> {
    state.fetches.fetch_add(1, Ordering::Relaxed);
    if state.down.load(Ordering::Relaxed) {
        return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(Json(state.keys.lock().unwrap().clone()))
}

fn jwks(entries: &[(&str, &str)]) -> Value {
    let keys: Vec<Value> = entries
        .iter()
        .map(|(kid, n)| {
            json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": "AQAB" })
        })
        .collect();
    json!({ "keys": keys })
}

// ---------------------------------------------------------------------------
// Token construction and exchange
// ---------------------------------------------------------------------------

/// The claim set a real GitHub Actions job's token carries.
fn claims(fleet: &TestCoordinator, repo: &str) -> Value {
    let now = fleet.now();
    let (owner, _) = repo.split_once('/').unwrap();
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": format!("repo:{repo}:ref:refs/heads/main"),
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 600,
        "repository": repo,
        "repository_owner": owner,
        "ref": "refs/heads/main",
        "workflow": "hil",
        "job_workflow_ref": format!("{repo}/.github/workflows/hil.yml@refs/heads/main"),
        "run_id": "998877",
    })
}

fn sign(kid: &str, key_der_b64: &str, claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(&der(key_der_b64)),
    )
    .unwrap()
}

/// POST a `github_oidc` exchange (forgs `TokenRequest::GithubOidc`); returns
/// `(status, body)`.
async fn exchange(fleet: &TestCoordinator, jwt: &str) -> (u16, String) {
    let body = json!({ "grant_type": "github_oidc", "oidc_token": jwt }).to_string();
    fleet.http("POST", "/auth/token", Some(body)).await
}

/// POST an `api_key` redemption (forgs `TokenRequest::ApiKey`); returns
/// `(status, body)`.
async fn redeem(fleet: &TestCoordinator, key: &str) -> (u16, String) {
    let body = json!({ "grant_type": "api_key", "api_key": key }).to_string();
    fleet.http("POST", "/auth/token", Some(body)).await
}

/// Redeem `key`, asserting success; returns the workload token.
async fn redeem_ok(fleet: &TestCoordinator, key: &str) -> String {
    let (status, body) = redeem(fleet, key).await;
    assert_eq!(status, 200, "{body}");
    token_of(&body)
}

fn token_of(body: &str) -> String {
    let parsed: Value = serde_json::from_str(body).unwrap();
    parsed["token"].as_str().unwrap().to_owned()
}

/// Start a coordinator wired to `issuer`.
async fn coordinator_for(issuer: &StubIssuer) -> TestCoordinator {
    let config = issuer.config();
    TestCoordinator::start_with(move |c| c.github_actions = Some(config)).await
}

/// Team org `acme` with admin `alice`: `(org, alice's session)`. Alice acts
/// in her personal org unless a request names `acme`.
async fn acme_with_admin(fleet: &TestCoordinator) -> (OrgId, String) {
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    (fleet.org("acme").await, alice)
}

/// Grant `ariel-os/ariel-os` access to `acme`'s `nrf52` boards.
async fn grant_ariel(fleet: &TestCoordinator, ops: &[AllowedOp]) -> String {
    fleet
        .seed_workload_grant("acme", "ariel-os/ariel-os", "tag=nrf52", ops, None)
        .await
}

/// `org`'s grants, straight from forgs' store.
async fn grants_of(fleet: &TestCoordinator, org: &OrgId) -> Vec<forgs_store::GrantRow> {
    let ns = probefleet_coordinator::subject::ns_of(org).unwrap();
    fleet.db().forgs().scoped(ns).list_grants().await.unwrap()
}

/// The lowercase-hex SHA-256 of an API key (the revocation handle).
fn key_hash(fleet: &TestCoordinator, key: &str) -> String {
    fleet
        .auth()
        .format()
        .parse(key)
        .unwrap()
        .hash()
        .as_str()
        .to_owned()
}

/// Revoke `key` through forgs' `POST /auth/keys` as `admin`.
async fn revoke_key(fleet: &TestCoordinator, admin: &str, org: &OrgId, key: &str) {
    let body = json!({
        "action": "revoke",
        "namespace": org.0,
        "prefix": &key_hash(fleet, key)[..16],
    })
    .to_string();
    let (status, body) = fleet
        .http_auth("POST", "/auth/keys", Some(admin), Some(body))
        .await;
    assert_eq!(status, 200, "{body}");
}

fn lease_by_tag(tag: &str, priority: Priority) -> SidecarToCoord {
    SidecarToCoord::Lease(LeaseRequest {
        select: Constraint::Tags(vec![tag.to_owned()]),
        duration_secs: 600,
        priority,
    })
}

async fn lease_nrf52(
    ci: &probefleet_sidecar::transport::CoordSession,
) -> probefleet_proto::lease::LeaseGrant {
    match ci
        .request(lease_by_tag("nrf52", Priority::Interactive))
        .await
        .unwrap()
    {
        CoordToSidecar::Lease(g) => g,
        other => panic!("expected a lease, got {other:?}"),
    }
}

async fn lease_is_gone(fleet: &TestCoordinator, lease: probefleet_proto::ids::LeaseId) -> bool {
    fleet
        .coord
        .scheduler()
        .lock()
        .await
        .lease_holder(lease)
        .is_none()
}

// ---------------------------------------------------------------------------
// 1. The happy path, all the way to a leased board
// ---------------------------------------------------------------------------

/// A signed token for a **granted** repo yields a `prfw1_` token, and that
/// token authenticates a real `/client` upgrade and leases the granted board
/// — and sees nothing the grant does not select.
///
/// The last clause is what makes the exchange meaningful rather than
/// decorative: a mint nothing can use would satisfy a weaker test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_granted_repo_exchanges_a_token_that_leases_its_board() {
    let issuer = StubIssuer::start().await;
    let fleet = coordinator_for(&issuer).await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    let board = fleet
        .seed_board(&org, "rpi-1", "nrf52840-dk-3", &["nrf52"])
        .await;
    // Same org, a board the grant's selector does not match.
    fleet.seed_board(&org, "rpi-1", "stm32-1", &["stm32"]).await;
    grant_ariel(&fleet, &[AllowedOp::Flash, AllowedOp::Attach]).await;

    let jwt = sign("k1", KEY_A_DER_B64, &claims(&fleet, "ariel-os/ariel-os"));
    let (status, body) = exchange(&fleet, &jwt).await;
    assert_eq!(status, 200, "{body}");

    let parsed: Value = serde_json::from_str(&body).unwrap();
    let token = parsed["token"].as_str().unwrap().to_owned();
    assert!(
        token.starts_with("prfw1_"),
        "a workload token has its own prefix: {token}"
    );
    assert!(parsed["expires"].as_u64().unwrap() > fleet.now());
    // A workload is nobody: no user, no refresh token, no node enrollment.
    assert!(parsed.get("user_id").is_none());
    assert!(parsed.get("refresh_token").is_none());
    assert!(parsed.get("node_id").is_none());

    // …and the token works, on a real upgrade, against the real board.
    let ci = fleet.client_session(&token).await;
    match ci.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => {
            assert_eq!(boards.len(), 1, "the granted board, and only it");
            assert_eq!(boards[0].board, board);
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
    assert_eq!(lease_nrf52(&ci).await.board, board);
    // The ungranted board is not reachable by asking for it directly.
    if let CoordToSidecar::Lease(g) = ci
        .request(lease_by_tag("stm32", Priority::Interactive))
        .await
        .unwrap()
    {
        panic!("leased an ungranted board: {g:?}");
    }

    // The mint is audited under the repo's subject, and the claims that make
    // "who used what" answerable are recorded with the token (§6.6).
    let subjects: Vec<Option<String>> =
        sqlx::query_scalar("SELECT subject FROM forgs_audit WHERE action = 'workload.token.mint'")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert_eq!(
        subjects,
        vec![Some("gha/workload:ariel-os/ariel-os".to_owned())]
    );
    let claims: Option<String> = sqlx::query_scalar(
        "SELECT claims FROM forgs_workload_token WHERE subject = 'gha/workload:ariel-os/ariel-os'",
    )
    .fetch_one(fleet.db().pool_for_test())
    .await
    .unwrap();
    let claims: Value = serde_json::from_str(&claims.unwrap()).unwrap();
    assert_eq!(claims["repository"], json!("ariel-os/ariel-os"));
    assert_eq!(claims["repository_owner"], json!("ariel-os"));
    assert_eq!(claims["run_id"], json!("998877"));
    assert_eq!(claims["workflow"], json!("hil"));
}

// ---------------------------------------------------------------------------
// 2. THE HEADLINE TEST
// ---------------------------------------------------------------------------

/// A repo that is **not listed**, under an owner that **is**, gets no token.
///
/// The security-relevant decision of the whole path. The sibling grant is
/// load-bearing: without it the test would also pass against a coordinator
/// that had simply failed to load any grants at all, which is the failure
/// mode that makes a security test worthless. A grantless repo is refused
/// exactly like a bad credential (forgs mints nothing a workload could not
/// use, and gives no oracle for which repos are granted).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repo_not_listed_under_a_listed_owner_is_denied() {
    let issuer = StubIssuer::start().await;
    let fleet = coordinator_for(&issuer).await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet
        .seed_board(&org, "rpi-1", "nrf52840-dk-3", &["nrf52"])
        .await;

    // The owner IS reachable — through this one repo, and only this one.
    grant_ariel(&fleet, &[AllowedOp::Flash, AllowedOp::Attach]).await;
    let listed = sign("k1", KEY_A_DER_B64, &claims(&fleet, "ariel-os/ariel-os"));
    let (status, body) = exchange(&fleet, &listed).await;
    assert_eq!(status, 200, "the listed repo works: {body}");

    // A *different* repo under the same owner: a fork, a new repo, anything.
    // The token is perfectly valid and signed by the real issuer, and it gets
    // nothing — and a fork under a *different* owner is the same rule seen
    // from the other side.
    for sibling in [
        "ariel-os/ariel-os-fork",
        "ariel-os/some-new-repo",
        "ariel-os/ariel-os-docs",
        "attacker/ariel-os",
    ] {
        let jwt = sign("k1", KEY_A_DER_B64, &claims(&fleet, sibling));
        let (status, body) = exchange(&fleet, &jwt).await;
        assert_eq!(status, 401, "{sibling} must be denied, got {body}");
        assert_eq!(body, INVALID_GRANT, "{sibling}: no oracle");
    }
    // The operator's next action is named in the audit log, not the reply.
    let rejects = fleet
        .forgs_audit_actions()
        .await
        .into_iter()
        .filter(|a| a == "workload.reject.no_grant")
        .count();
    assert_eq!(rejects, 4);
}

/// Repo names are case-insensitive on GitHub, so a case difference between the
/// grant and the claim must not become a silent denial. Both sides go through
/// one normaliser; this pins that they agree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_matching_is_case_insensitive_on_both_sides() {
    let issuer = StubIssuer::start().await;
    let fleet = coordinator_for(&issuer).await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    // Granted in one spelling…
    fleet
        .seed_workload_grant(
            "acme",
            "Ariel-OS/Ariel-OS",
            "tag=nrf52",
            &[AllowedOp::Flash],
            None,
        )
        .await;

    // …claimed in another.
    let jwt = sign("k1", KEY_A_DER_B64, &claims(&fleet, "ariel-os/ARIEL-os"));
    let (status, body) = exchange(&fleet, &jwt).await;
    assert_eq!(status, 200, "{body}");
}

// ---------------------------------------------------------------------------
// 3. The rejection taxonomy
// ---------------------------------------------------------------------------

/// Every way a token can be wrong, and the one thing they all have in common:
/// the response is byte-identical. The audit log knows why; the caller does
/// not (no oracle).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_invalid_token_is_refused_with_one_indistinguishable_body() {
    let issuer = StubIssuer::start().await;
    let fleet = coordinator_for(&issuer).await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    grant_ariel(&fleet, &[AllowedOp::Flash]).await;
    let repo = "ariel-os/ariel-os";
    let now = fleet.now();

    // Expired: `exp` well in the past, beyond the 60s leeway.
    let mut expired = claims(&fleet, repo);
    expired["exp"] = json!(now - 3_600);
    expired["nbf"] = json!(now - 7_200);
    expired["iat"] = json!(now - 7_200);

    // Wrong audience: GitHub's own *default* audience, which is precisely why
    // the configured one has no default.
    let mut wrong_audience = claims(&fleet, repo);
    wrong_audience["aud"] = json!("https://github.com/ariel-os");

    // Wrong issuer.
    let mut wrong_issuer = claims(&fleet, repo);
    wrong_issuer["iss"] = json!("https://token.actions.evil.example");

    // Missing `repository`: the claim that becomes the subject id.
    let mut no_repo = claims(&fleet, repo);
    no_repo.as_object_mut().unwrap().remove("repository");

    // A token for a repo that IS granted, signed by a key the issuer does not
    // publish: an attacker bringing their own key.
    let wrong_key = sign("k1", KEY_B_DER_B64, &claims(&fleet, repo));

    // Algorithm confusion: HS256, with the RSA public modulus as the HMAC
    // secret. The `[RS256]` allowlist is what makes this unrepresentable.
    let mut hs_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    hs_header.kid = Some("k1".to_owned());
    let hs256 = jsonwebtoken::encode(
        &hs_header,
        &claims(&fleet, repo),
        &jsonwebtoken::EncodingKey::from_secret(KEY_A_N.as_bytes()),
    )
    .unwrap();

    // A tampered payload: valid signature over *different* claims.
    let good = sign("k1", KEY_A_DER_B64, &claims(&fleet, repo));
    let forged_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(claims(&fleet, "attacker/attacker").to_string());
    let mut parts: Vec<&str> = good.split('.').collect();
    parts[1] = &forged_payload;
    let tampered = parts.join(".");

    let cases: Vec<(&str, String)> = vec![
        ("expired", sign("k1", KEY_A_DER_B64, &expired)),
        ("wrong audience", sign("k1", KEY_A_DER_B64, &wrong_audience)),
        ("wrong issuer", sign("k1", KEY_A_DER_B64, &wrong_issuer)),
        ("missing repository", sign("k1", KEY_A_DER_B64, &no_repo)),
        // A `kid` the JWKS does not have and never will. The forced refetch
        // fires and finds the same set, so the token is still refused.
        (
            "unknown kid",
            sign("k9", KEY_A_DER_B64, &claims(&fleet, repo)),
        ),
        ("wrong signing key", wrong_key),
        ("algorithm confusion", hs256),
        ("tampered payload", tampered),
        ("not a jwt at all", "garbage".to_owned()),
        ("empty", String::new()),
    ];

    let mut bodies = std::collections::HashSet::new();
    for (label, jwt) in cases {
        let (status, body) = exchange(&fleet, &jwt).await;
        assert_eq!(status, 401, "{label} must be a 401, got {status} {body}");
        bodies.insert(body);
    }
    assert_eq!(
        bodies,
        std::collections::HashSet::from([INVALID_GRANT.to_owned()]),
        "every rejection body must be byte-identical: no oracle"
    );
    // Nothing was minted along the way.
    let minted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forgs_workload_token")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(minted, 0);
}

/// A fleet with no `[github_actions]` table answers a **named** 503 rather than
/// a 404 or silence, so the CLI can say why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconfigured_coordinator_says_so_by_name() {
    let fleet = TestCoordinator::start().await;
    let (status, body) = exchange(&fleet, "anything").await;
    assert_eq!(status, 503);
    assert_eq!(body, r#"{"error":"workload_unconfigured"}"#);
}

// ---------------------------------------------------------------------------
// 4. Key rotation and the fetch rate limit
// ---------------------------------------------------------------------------

/// A rotated JWKS is picked up by exactly **one** extra fetch.
///
/// That is what an unknown `kid` is for: waiting out the refresh interval
/// instead would break every CI job in the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rotated_signing_key_is_picked_up_after_one_refetch() {
    let issuer = StubIssuer::start().await;
    let fleet = coordinator_for(&issuer).await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    grant_ariel(&fleet, &[AllowedOp::Flash]).await;
    let repo = "ariel-os/ariel-os";

    // Warm the cache with the old key.
    let (status, _) = exchange(&fleet, &sign("k1", KEY_A_DER_B64, &claims(&fleet, repo))).await;
    assert_eq!(status, 200);
    let after_warm = issuer.fetches();
    assert_eq!(after_warm, 1, "one fetch to populate the cache");

    // A second token on the cached key costs no fetch at all.
    let (status, _) = exchange(&fleet, &sign("k1", KEY_A_DER_B64, &claims(&fleet, repo))).await;
    assert_eq!(status, 200);
    assert_eq!(issuer.fetches(), after_warm, "the cache is actually used");

    // The issuer rotates: `k2` replaces `k1`.
    issuer.rotate_to(&[("k2", KEY_B_N)]);
    let (status, body) = exchange(&fleet, &sign("k2", KEY_B_DER_B64, &claims(&fleet, repo))).await;
    assert_eq!(status, 200, "the rotation must be picked up: {body}");
    assert_eq!(
        issuer.fetches(),
        after_warm + 1,
        "exactly one extra fetch, triggered by the unknown kid"
    );
}

/// An attacker feeding invented `kid`s cannot turn `POST /auth/token` into a
/// fetch amplifier aimed at the issuer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_kids_cannot_amplify_fetches_at_the_issuer() {
    let issuer = StubIssuer::start().await;
    let mut config = issuer.config();
    // A real floor, unlike the other tests' zero.
    config.jwks_min_refetch_secs = 3_600;
    let fleet = TestCoordinator::start_with(move |c| c.github_actions = Some(config)).await;

    for i in 0..25 {
        let kid = format!("invented-{i}");
        let jwt = sign(&kid, KEY_A_DER_B64, &claims(&fleet, "ariel-os/ariel-os"));
        let (status, _) = exchange(&fleet, &jwt).await;
        assert_eq!(status, 401);
    }
    assert!(
        issuer.fetches() <= 2,
        "25 invented kids caused {} fetches; the rate limit is not holding",
        issuer.fetches()
    );
}

/// An issuer outage must not turn `POST /auth/token` into a 1:1 outbound
/// amplifier.
///
/// `/auth/token` is **unauthenticated**, so this needs no valid JWT and no
/// invented `kid` — the requests below carry outright garbage. Without a
/// floor on every fetch, a failed refresh leaves the cache permanently stale
/// and every subsequent POST performs a fresh fetch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_down_issuer_does_not_make_the_exchange_a_fetch_amplifier() {
    let issuer = StubIssuer::start().await;
    let mut config = issuer.config();
    config.jwks_min_refetch_secs = 3_600;
    let fleet = TestCoordinator::start_with(move |c| c.github_actions = Some(config)).await;

    // Cold cache *and* a failing issuer: the worst case, since there is not
    // even a stale set to fall back on.
    issuer.take_down();
    for _ in 0..25 {
        let (status, body) = exchange(&fleet, "not-even-a-jwt").await;
        assert_eq!(status, 401, "{body}");
        assert_eq!(body, INVALID_GRANT);
    }
    assert!(
        issuer.fetches() <= 2,
        "25 unauthenticated POSTs against a down issuer caused {} fetches",
        issuer.fetches()
    );

    // And a well-formed token inside the floor is refused rather than made to
    // dial the issuer again — still indistinguishable from a bad signature.
    let before = issuer.fetches();
    let jwt = sign("k1", KEY_A_DER_B64, &claims(&fleet, "ariel-os/ariel-os"));
    let (status, body) = exchange(&fleet, &jwt).await;
    assert_eq!(status, 401);
    assert_eq!(body, INVALID_GRANT);
    assert_eq!(issuer.fetches(), before, "still inside the refetch floor");
}

/// A *stale but present* key set is served through an outage rather than
/// refused: an issuer having a bad day must not take the fleet's CI with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_warm_cache_survives_an_issuer_outage() {
    let issuer = StubIssuer::start().await;
    let mut config = issuer.config();
    // Stale almost immediately, so every request takes the refresh branch —
    // and the floor is what stops that becoming a fetch each time.
    config.jwks_refresh_secs = 1;
    config.jwks_min_refetch_secs = 3_600;
    let fleet = TestCoordinator::start_with(move |c| c.github_actions = Some(config)).await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    grant_ariel(&fleet, &[AllowedOp::Flash]).await;

    // Warm the cache while the issuer is healthy.
    let jwt = sign("k1", KEY_A_DER_B64, &claims(&fleet, "ariel-os/ariel-os"));
    let (status, body) = exchange(&fleet, &jwt).await;
    assert_eq!(status, 200, "{body}");

    issuer.take_down();
    let warm = issuer.fetches();
    for _ in 0..5 {
        let jwt = sign("k1", KEY_A_DER_B64, &claims(&fleet, "ariel-os/ariel-os"));
        let (status, body) = exchange(&fleet, &jwt).await;
        assert_eq!(status, 200, "the cached keys must keep working: {body}");
    }
    assert_eq!(
        issuer.fetches(),
        warm,
        "a warm cache inside the floor must not dial a down issuer at all"
    );
}

// ---------------------------------------------------------------------------
// 5. Route fences
// ---------------------------------------------------------------------------

/// A workload token is the wrong **kind** for `/agent` and the key-minting
/// surfaces, and that is a 403 (the route is the problem) rather than a 401
/// (the credential is fine). A CI job must not be able to enroll a node or
/// mint credentials. On `/client` it is accepted — but a workload acts in
/// **no** org, so naming one is a 403 too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workload_token_is_refused_on_the_node_and_key_surfaces() {
    let fleet = TestCoordinator::start().await;
    let org = fleet.org("acme").await;
    let token = fleet
        .seed_workload_token("ariel-os/ariel-os", fleet.now() + 3_600)
        .await;

    assert_eq!(
        fleet.upgrade_status("/agent", Some(&token)).await,
        403,
        "the node plane is for nodes"
    );
    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&token),
            Some(json!({"action": "list", "namespace": org.0}).to_string()),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = fleet
        .http_auth(
            "POST",
            "/api/v1/auth-keys?org=acme",
            Some(&token),
            Some(json!({"tags": ["nrf52"], "ttl_secs": 3600, "purpose": "ci"}).to_string()),
        )
        .await;
    assert_eq!(status, 403, "{body}");

    // …but `/client` accepts it, which is the point of the allowlist…
    assert_eq!(fleet.upgrade_status("/client", Some(&token)).await, 101);
    // …in no org: a workload reaches boards through grants, never membership.
    for org_ref in ["acme".to_owned(), org.0.clone()] {
        assert_eq!(
            fleet
                .upgrade_status(&format!("/client?org={org_ref}"), Some(&token))
                .await,
            403,
            "a workload asking to act in {org_ref}"
        );
    }
}

/// An expired workload token stops working on `/client`, and the sweep reclaims
/// the row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_workload_token_is_refused_and_swept() {
    let fleet = TestCoordinator::start().await;
    let token = fleet
        .seed_workload_token("ariel-os/ariel-os", fleet.now() - 1)
        .await;
    assert_eq!(fleet.upgrade_status("/client", Some(&token)).await, 401);

    probefleet_coordinator::sweep::sweep_once(&fleet.coord).await;
    let hash = fleet.auth().format().parse(&token).unwrap().hash();
    let left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forgs_workload_token WHERE token_hash = ?1")
            .bind(hash.as_str())
            .fetch_one(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert_eq!(left, 0);
}

/// The verbs a workload may *not* reach behind `/client`. The route allowlist
/// is only a fence if the surface behind it has been walked (architecture
/// §6.7), and `Delegate` is the one that had to be refused explicitly rather
/// than by a role check it would fail anyway.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workload_may_lease_but_not_delegate_or_administer() {
    let fleet = TestCoordinator::start().await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    let board = fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    grant_ariel(&fleet, &[AllowedOp::Flash, AllowedOp::Attach]).await;
    let token = fleet
        .seed_workload_token("ariel-os/ariel-os", fleet.now() + 3_600)
        .await;
    let ci = fleet.client_session(&token).await;

    // Allowed: it can see and lease the granted board.
    assert_eq!(lease_nrf52(&ci).await.board, board);

    // Refused: delegation. A CI job handing a lab board to something else is a
    // decision nobody made, so it is refused rather than allowed by omission.
    match ci
        .request(SidecarToCoord::Delegate {
            select: Constraint::Tags(vec!["nrf52".to_owned()]),
            duration_secs: 300,
            ops: vec![AllowedOp::Attach],
        })
        .await
        .unwrap()
    {
        CoordToSidecar::Error { message } => {
            assert!(message.contains("workload"), "{message}");
        }
        other => panic!("a workload must not be able to delegate, got {other:?}"),
    }

    // Refused: the admin and grant verbs, which need a role a workload has
    // nowhere.
    for verb in [
        SidecarToCoord::GrantList,
        SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Flash],
            expires: Some(fleet.now() + 600),
        },
        SidecarToCoord::GrantRevoke {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned(),
        },
        SidecarToCoord::Logs {
            board: None,
            follow: false,
        },
    ] {
        match ci.request(verb).await.unwrap() {
            CoordToSidecar::Error { .. } => {}
            other => panic!("expected a denial, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Revocation, metering, priority
// ---------------------------------------------------------------------------

/// Revoking the repo's grant releases the live lease and denies the next
/// request. A regression fence over §6.5's cascade rather than new behaviour —
/// which is the point: the CI path gets revocation for free precisely because
/// it is an ordinary grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_repo_grant_releases_the_live_lease() {
    let fleet = TestCoordinator::start().await;
    let (org, alice_token) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let grant_id = grant_ariel(&fleet, &[AllowedOp::Flash, AllowedOp::Attach]).await;
    let token = fleet
        .seed_workload_token("ariel-os/ariel-os", fleet.now() + 3_600)
        .await;

    let ci = fleet.client_session(&token).await;
    let lease = lease_nrf52(&ci).await.lease;

    let alice = fleet.client_session_in(&alice_token, "acme").await;
    match alice
        .request(SidecarToCoord::GrantRevoke {
            id: grant_id[..8].to_owned(),
        })
        .await
        .unwrap()
    {
        CoordToSidecar::GrantRevoked { ids } => assert_eq!(ids, vec![grant_id.clone()]),
        other => panic!("expected GrantRevoked, got {other:?}"),
    }

    // The lease is gone from the scheduler, not merely marked.
    assert!(
        lease_is_gone(&fleet, lease).await,
        "revocation must release the lease, not wait out its TTL"
    );
    // And the next request from the same credential gets nothing.
    let ci = fleet.client_session(&token).await;
    if let CoordToSidecar::Lease(g) = ci
        .request(lease_by_tag("nrf52", Priority::Interactive))
        .await
        .unwrap()
    {
        panic!("leased after revocation: {g:?}");
    }
}

/// **Metering.** After the lease ends, its row survives with the workload as
/// `holder` and both timestamps set. §6.6 promises "who used what, for how
/// long" is recoverable by construction; this is that promise, tested.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_released_workload_lease_stays_in_the_ledger() {
    let fleet = TestCoordinator::start().await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    grant_ariel(&fleet, &[AllowedOp::Flash]).await;
    let token = fleet
        .seed_workload_token("ariel-os/ariel-os", fleet.now() + 3_600)
        .await;

    let ci = fleet.client_session(&token).await;
    let lease = lease_nrf52(&ci).await.lease;
    match ci.request(SidecarToCoord::Release { lease }).await.unwrap() {
        CoordToSidecar::Released { .. } => {}
        other => panic!("expected a release ack, got {other:?}"),
    }

    let row: (String, String, i64, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT holder, ns_node_id, granted_at, closed_at, close_reason FROM leases WHERE lease = ?1",
    )
    .bind(i64::try_from(lease.0).unwrap())
    .fetch_one(fleet.db().pool_for_test())
    .await
    .unwrap();
    assert_eq!(
        row.0, "gha/workload:ariel-os/ariel-os",
        "the holder is the repo, so a bill can be addressed to it"
    );
    assert_eq!(row.1, org.0, "the lease is on the granting org's board");
    assert!(row.2 > 0, "granted_at is set");
    assert!(
        row.3.is_some(),
        "closed_at is set: the row is never deleted"
    );
    assert!(row.4.is_some());
}

/// **Priority clamp.** A workload asking for `Interactive` is recorded as `Ci`.
///
/// Not an edge case: the sidecar sends `Priority::Interactive` unconditionally,
/// so this fires on every CI lease. §6.6's fairness ordering puts a human at a
/// desk above nightly CI, and priority is a plain wire field — without the
/// clamp a CI job could simply outbid the human by setting it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workloads_lease_is_clamped_to_ci_priority() {
    let fleet = TestCoordinator::start().await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    grant_ariel(&fleet, &[AllowedOp::Flash]).await;
    let token = fleet
        .seed_workload_token("ariel-os/ariel-os", fleet.now() + 3_600)
        .await;

    let ci = fleet.client_session(&token).await;
    // Ask for the *longest* interactive duration; the CI cap is shorter, so the
    // granted expiry is the observable proof the clamp fired.
    let granted = match ci
        .request(SidecarToCoord::Lease(LeaseRequest {
            select: Constraint::Tags(vec!["nrf52".to_owned()]),
            duration_secs: 4 * 3_600,
            priority: Priority::Interactive,
        }))
        .await
        .unwrap()
    {
        CoordToSidecar::Lease(g) => g,
        other => panic!("expected a lease, got {other:?}"),
    };
    let held = granted.expires.saturating_sub(fleet.now());
    assert!(
        held <= 3_600,
        "a workload asking for 4h of Interactive got {held}s; \
         Policy::max_duration_ci is 3600 and the clamp should bind it"
    );
    assert!(
        held > 3_000,
        "…but it should still get the CI maximum: {held}s"
    );
}

// ---------------------------------------------------------------------------
// 7. The CI auth-key fallback
// ---------------------------------------------------------------------------

/// A self-hosted runner with no workload identity authenticates with a `ci`
/// API key, and the resulting token leases a board.
///
/// Everything that bounds the weak path is asserted alongside: a `node` key is
/// refused on this grant type, the synthesised grant is org-scoped and
/// selector-scoped, a multi-use key converges on one grant, and revoking the
/// key takes the grant (and the live lease) with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_self_hosted_runner_can_authenticate_with_a_ci_auth_key() {
    let fleet = TestCoordinator::start().await;
    let (org, alice_token) = acme_with_admin(&fleet).await;
    let board = fleet
        .seed_board(&org, "rpi-1", "nrf52840-dk-3", &["nrf52"])
        .await;
    // A board the key's tags do NOT select, to prove the selector is real.
    fleet.seed_board(&org, "rpi-1", "stm32-1", &["stm32"]).await;

    let expires = fleet.now() + 86_400;
    let key = fleet
        .seed_ci_auth_key("acme", &["nrf52".to_owned()], Some(expires))
        .await;

    // A `node` key is not a board-access credential — the whole reason
    // `purpose` exists — and a mis-aimed redemption must not mint.
    let node_key = fleet.seed_auth_key("acme", &[], false, Some(expires)).await;
    let (status, body) = redeem(&fleet, &node_key).await;
    assert_eq!(
        status, 403,
        "a node key must not mint a workload token: {body}"
    );
    assert!(grants_of(&fleet, &org).await.is_empty());

    let token = redeem_ok(&fleet, &key).await;
    assert!(token.starts_with("prfw1_"), "{token}");

    // The token leases the *tagged* board, and only it.
    let ci = fleet.client_session(&token).await;
    match ci.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => {
            assert_eq!(
                boards.len(),
                1,
                "the selector is real: only the tagged board"
            );
            assert_eq!(boards[0].board, board);
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
    let lease = lease_nrf52(&ci).await;
    assert_eq!(lease.board, board);
    let lease = lease.lease;

    // A second runner redeeming the same multi-use key converges on one grant
    // row rather than accumulating one per runner.
    let second = redeem_ok(&fleet, &key).await;
    assert_ne!(second, token, "each runner gets its own workload token");
    let grants = grants_of(&fleet, &org).await;
    assert_eq!(grants.len(), 1, "one key, one grant however many runners");

    // Revoking the key revokes the grant, and therefore the live lease: §6.5's
    // "revocation is real", inherited rather than reimplemented.
    revoke_key(&fleet, &alice_token, &org, &key).await;
    assert!(
        lease_is_gone(&fleet, lease).await,
        "revoking a CI key must release what it was holding, not wait out the TTL"
    );
    assert!(grants_of(&fleet, &org).await.is_empty());
    // The key itself is dead, and the workload tokens it minted reach nothing.
    let (status, body) = redeem(&fleet, &key).await;
    assert_eq!(status, 401, "{body}");
    let ci = fleet.client_session(&second).await;
    match ci.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => assert!(boards.is_empty(), "{boards:?}"),
        CoordToSidecar::Error { .. } => {}
        other => panic!("expected nothing reachable, got {other:?}"),
    }
    if let CoordToSidecar::Lease(g) = ci
        .request(lease_by_tag("nrf52", Priority::Interactive))
        .await
        .unwrap()
    {
        panic!("leased after the key was revoked: {g:?}");
    }
}

/// The workload token a key mints **never outlives the key**: a key expiring
/// before the configured workload TTL caps the token at the key's expiry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workload_token_never_outlives_its_key() {
    let fleet = TestCoordinator::start().await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    // The workload TTL is an hour; the key has ten minutes left.
    let key_expires = fleet.now() + 600;
    let key = fleet
        .seed_ci_auth_key("acme", &["nrf52".to_owned()], Some(key_expires))
        .await;

    let (status, body) = redeem(&fleet, &key).await;
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let expires = parsed["expires"].as_u64().unwrap();
    assert!(
        expires <= key_expires,
        "the token ({expires}) outlives its key ({key_expires})"
    );
    // The synthesised grant is bounded by the key too.
    let grants = grants_of(&fleet, &org).await;
    assert_eq!(grants[0].expires, Some(key_expires));
}

/// The grant a CI key synthesises is revocable **through `grant revoke`**, not
/// only as a side effect of revoking the key — by the id `grant list` prints
/// and by an 8-character prefix of it.
///
/// The two routes differ in what survives: revoking the grant leaves the key
/// valid (the next runner recreates the grant, with the same deterministic
/// id), revoking the key takes both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ci_keys_grant_is_revocable_through_grant_revoke() {
    let fleet = TestCoordinator::start().await;
    let (org, alice_token) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let key = fleet
        .seed_ci_auth_key("acme", &["nrf52".to_owned()], Some(fleet.now() + 86_400))
        .await;
    redeem_ok(&fleet, &key).await;

    let grants = grants_of(&fleet, &org).await;
    assert_eq!(grants.len(), 1);
    let id = grants[0].id.to_string();

    let alice = fleet.client_session_in(&alice_token, "acme").await;
    // `grant list` prints the id; it must be the one revoke accepts.
    match alice.request(SidecarToCoord::GrantList).await.unwrap() {
        CoordToSidecar::Grants(list) => {
            assert!(list.iter().any(|g| g.id == id), "{list:?}");
        }
        other => panic!("expected Grants, got {other:?}"),
    }
    for spelling in [id.clone(), id[..8].to_owned(), id[..8].to_ascii_lowercase()] {
        match alice
            .request(SidecarToCoord::GrantRevoke {
                id: spelling.clone(),
            })
            .await
            .unwrap()
        {
            CoordToSidecar::GrantRevoked { ids } => assert_eq!(ids, vec![id.clone()]),
            other => panic!("`grant revoke {spelling}` was refused: {other:?}"),
        }
        // Redeem again so the next spelling has a row to delete — and to show
        // the key itself survived and recreates the *same* grant.
        redeem_ok(&fleet, &key).await;
        let again = grants_of(&fleet, &org).await;
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].id.to_string(), id, "the grant id is deterministic");
    }

    // The prefix floor is untouched: too short or outside the id alphabet is
    // refused, and nothing is deleted.
    for bad in ["", "ABC", "ci-", "nothexbutlong"] {
        match alice
            .request(SidecarToCoord::GrantRevoke { id: bad.to_owned() })
            .await
            .unwrap()
        {
            CoordToSidecar::Error { message } => {
                assert!(message.contains("8 characters"), "{bad:?}: {message}");
            }
            other => panic!("{bad:?} should have been refused, got {other:?}"),
        }
    }
    assert_eq!(grants_of(&fleet, &org).await.len(), 1);
}

/// A CI key with no tags is refused at redemption: an empty tag set is an empty
/// selector, which would match every board in the org.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ci_key_with_no_tags_cannot_be_redeemed() {
    let fleet = TestCoordinator::start().await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    // Inserted raw, bypassing the purpose hook's mint-time check — this is the
    // second belt, for a key that reached the table some other way (a shell
    // insert, a hand-edited row).
    let token = fleet.auth().format().mint(forgs::TokenKind::ApiKey);
    let ns = probefleet_coordinator::subject::ns_of(&org).unwrap();
    fleet
        .db()
        .forgs()
        .scoped(ns)
        .insert_api_key(
            &forgs_store::NewApiKey {
                hash: token.hash(),
                purpose: probefleet_coordinator::identity::PURPOSE_CI.to_owned(),
                subject_name: None,
                payload: Some(r#"{"tags":[]}"#.to_owned()),
                single_use: false,
                expires: Some(fleet.now() + 86_400),
                created_by: None,
            },
            fleet.now(),
        )
        .await
        .unwrap();

    let (status, body) = redeem(&fleet, &token.to_secret_string()).await;
    assert_eq!(status, 403, "{body}");
    assert!(
        grants_of(&fleet, &org).await.is_empty(),
        "no grant may be synthesised for a tagless key"
    );
    let minted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forgs_workload_token")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(minted, 0, "and no workload token minted");
}

/// The key surface refuses to *mint* a tagless CI key in the first place —
/// on forgs' `POST /auth/keys` and on fleet's `POST /api/v1/auth-keys`, which
/// share one validation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_api_refuses_to_mint_a_tagless_ci_key() {
    let fleet = TestCoordinator::start().await;
    let (org, alice_token) = acme_with_admin(&fleet).await;
    let create = |purpose: &str, payload: Value| {
        json!({"action": "create", "namespace": org.0, "ttl_secs": 3600,
               "multi_use": true, "purpose": purpose, "payload": payload})
        .to_string()
    };

    for (label, request) in [
        ("no tags", create("ci", json!({"tags": []}))),
        ("no payload", create("ci", Value::Null)),
        ("unknown purpose", create("wat", json!({"tags": ["nrf52"]}))),
        (
            "unknown op",
            create("ci", json!({"tags": ["nrf52"], "ops": ["teleport"]})),
        ),
    ] {
        let (status, body) = fleet
            .http_auth("POST", "/auth/keys", Some(&alice_token), Some(request))
            .await;
        assert_eq!(status, 400, "/auth/keys {label}: {body}");
    }
    for (label, request) in [
        (
            "no tags",
            json!({"tags": [], "ttl_secs": 3600, "purpose": "ci"}),
        ),
        (
            "unknown op",
            json!({"tags": ["nrf52"], "ttl_secs": 3600, "purpose": "ci", "ops": ["teleport"]}),
        ),
    ] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/api/v1/auth-keys?org=acme",
                Some(&alice_token),
                Some(request.to_string()),
            )
            .await;
        assert_eq!(status, 400, "/api/v1/auth-keys {label}: {body}");
    }

    // …and a tagged one mints fine, echoing its purpose and canonical payload.
    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&alice_token),
            Some(create("ci", json!({"tags": ["nrf52"], "ops": ["flash"]}))),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["purpose"], json!("ci"));
    assert_eq!(parsed["namespace"], json!(org.0));
    assert_eq!(parsed["payload"]["tags"], json!(["nrf52"]));
    let key = parsed["key"].as_str().unwrap();
    assert!(key.starts_with("prfk1_"), "{key}");
    // And it is a working CI credential.
    redeem_ok(&fleet, key).await;
}

// ---------------------------------------------------------------------------
// 8. Named identities (`auth-key create --name <name>`), architecture §6.7
// ---------------------------------------------------------------------------

/// The headline: **rotating a named key does not move the identity.**
///
/// Mint key A `--name builder`, redeem it, lease a board. Mint key B with the
/// same name and a different secret, redeem that. Both redemptions must produce
/// the *same* subject and re-upsert the *same* grant row — which is what keeps
/// the audit trail, the per-subject concurrency budget and the revocation
/// handle whole across a rotation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_keys_identity_survives_rotating_the_key() {
    let fleet = TestCoordinator::start().await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    let board = fleet
        .seed_board(&org, "rpi-1", "nrf52840-dk-3", &["nrf52"])
        .await;
    let expires = fleet.now() + 86_400;
    let tags = ["nrf52".to_owned()];

    let key_a = fleet
        .seed_named_ci_auth_key("acme", &tags, Some(expires), Some("builder"))
        .await;
    let token_a = redeem_ok(&fleet, &key_a).await;

    let grants = grants_of(&fleet, &org).await;
    assert_eq!(grants.len(), 1);
    let grant_id = grants[0].id;
    let subject = grants[0].subject.clone();
    assert_eq!(
        subject,
        format!("{}/workload:agent:builder", org.0),
        "the identity is the name, not the credential"
    );

    // The token works: it is a real board-access credential, not just a row,
    // and the lease is held by the named identity.
    let ci_a = fleet.client_session(&token_a).await;
    let lease_a = lease_nrf52(&ci_a).await;
    assert_eq!(lease_a.board, board);
    assert_eq!(
        fleet
            .coord
            .scheduler()
            .lock()
            .await
            .lease_holder(lease_a.lease)
            .map(ToString::to_string),
        Some(subject.clone())
    );
    ci_a.request(SidecarToCoord::Release {
        lease: lease_a.lease,
    })
    .await
    .unwrap();

    // The rotation: a *different secret*, the same `--name` — and then the same
    // name spelled differently, which normalises to the same identity.
    for name in ["builder", "BUILDER"] {
        let key = fleet
            .seed_named_ci_auth_key("acme", &tags, Some(expires), Some(name))
            .await;
        assert_ne!(key, key_a, "a rotation is a new secret");
        redeem_ok(&fleet, &key).await;

        let grants = grants_of(&fleet, &org).await;
        assert_eq!(
            grants.len(),
            1,
            "`{name}` re-upserts the identity's row rather than adding one"
        );
        assert_eq!(grants[0].id, grant_id, "same grant id across the rotation");
        assert_eq!(
            grants[0].subject, subject,
            "same subject across the rotation"
        );
    }

    // And the identity is on the token rows too, so the audit trail does not
    // fork: every workload token speaks as the same subject.
    let subjects: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT subject FROM forgs_workload_token")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert_eq!(subjects, vec![subject]);
}

/// The accepted trade, asserted so it cannot be "fixed" by accident.
///
/// Two live keys sharing an `--name` are **one identity**, and the grant belongs
/// to the identity, not to the key. So revoking key A tears down the shared
/// grant and key B's runner's live lease — a disruption, not a revocation:
/// key B redeeming again re-creates the grant with the same id and subject.
///
/// The alternative (suppressing the cascade when a sibling key shares the name)
/// was rejected because the "does a sibling share this name" query's answer is
/// stale the instant it returns — a concurrent mint between the check and the
/// delete flips it — so it would cascade or not by coin-flip. See §6.7.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_one_key_of_a_shared_identity_is_a_disruption_not_a_revocation() {
    let fleet = TestCoordinator::start().await;
    let (org, alice_token) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let expires = fleet.now() + 86_400;
    let tags = ["nrf52".to_owned()];

    let key_a = fleet
        .seed_named_ci_auth_key("acme", &tags, Some(expires), Some("builder"))
        .await;
    let key_b = fleet
        .seed_named_ci_auth_key("acme", &tags, Some(expires), Some("builder"))
        .await;
    redeem_ok(&fleet, &key_a).await;
    let token_b = redeem_ok(&fleet, &key_b).await;

    let grants = grants_of(&fleet, &org).await;
    assert_eq!(grants.len(), 1, "two keys, one identity, one grant");
    let grant_id = grants[0].id;
    let subject = grants[0].subject.clone();

    // B's runner takes a lease under the shared identity.
    let ci_b = fleet.client_session(&token_b).await;
    let lease_b = lease_nrf52(&ci_b).await.lease;

    // Revoke key A only — through fleet's browser API this time, which calls
    // the same forgs revocation (and so the same cascade).
    let prefix = &key_hash(&fleet, &key_a)[..16];
    let (status, body) = fleet
        .http_auth(
            "DELETE",
            &format!("/api/v1/auth-keys/{prefix}?org=acme"),
            Some(&alice_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // The accepted trade, both halves. The grant belonged to the identity, so
    // it is gone — along with *another key's* live lease.
    assert!(
        lease_is_gone(&fleet, lease_b).await,
        "revoking one key of a shared identity tears down the identity's leases"
    );
    assert!(
        !grants_of(&fleet, &org)
            .await
            .iter()
            .any(|g| g.id == grant_id),
        "the shared grant is gone, not merely orphaned"
    );

    // …and it is a disruption, not a revocation: key B still redeems, and the
    // identity comes back with the same id and the same subject. Key A does not.
    assert_eq!(redeem(&fleet, &key_a).await.0, 401);
    redeem_ok(&fleet, &key_b).await;
    let back = grants_of(&fleet, &org).await;
    let restored = back
        .iter()
        .find(|g| g.id == grant_id)
        .expect("a surviving key re-creates the identity's grant on its next redemption");
    assert_eq!(restored.subject, subject);
}

/// An **unnamed** CI key's identity is derived from the key itself: the
/// subject is `<org>/workload:key:<hash8>`, and the grant id is the
/// deterministic `ci_grant_id(org, subject)` both redemption and the
/// revocation cascade compute. Asserted as literal strings: the cascade finds
/// the grant only if they agree byte for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unnamed_ci_key_has_a_hash_derived_identity() {
    let fleet = TestCoordinator::start().await;
    let (org, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let key = fleet
        .seed_ci_auth_key("acme", &["nrf52".to_owned()], Some(fleet.now() + 86_400))
        .await;
    redeem_ok(&fleet, &key).await;

    let hash = key_hash(&fleet, &key);
    let grants = grants_of(&fleet, &org).await;
    assert_eq!(grants.len(), 1);
    let subject = format!("{}/workload:key:{}", org.0, &hash[..8]);
    assert_eq!(grants[0].subject, subject);
    let ns = probefleet_coordinator::subject::ns_of(&org).unwrap();
    assert_eq!(
        grants[0].id,
        probefleet_coordinator::identity::ci_grant_id(
            ns,
            &forgs::SubjectKey::parse(&subject).unwrap()
        )
    );
    assert_eq!(grants[0].selector, "tag=nrf52");
}

/// The cross-tenant trap the org-in-the-digest rule exists to close: a grant
/// id spelled from the name alone would let one org's redemption collide with
/// another org's row. Two orgs using the same identity name get two grants,
/// and neither redemption touches the other's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_identity_name_in_two_orgs_is_two_grants() {
    let fleet = TestCoordinator::start().await;
    let (org_a, _alice) = acme_with_admin(&fleet).await;
    fleet.seed_session("globex", "bob", FleetRole::Admin).await;
    let org_b = fleet.org("globex").await;
    assert_ne!(org_a, org_b);
    fleet.seed_board(&org_a, "rpi-1", "dk-3", &["nrf52"]).await;
    fleet.seed_board(&org_b, "rpi-2", "dk-4", &["stm32"]).await;
    let expires = fleet.now() + 86_400;

    let key_a = fleet
        .seed_named_ci_auth_key(
            "acme",
            &["nrf52".to_owned()],
            Some(expires),
            Some("builder"),
        )
        .await;
    let key_b = fleet
        .seed_named_ci_auth_key(
            "globex",
            &["stm32".to_owned()],
            Some(expires),
            Some("builder"),
        )
        .await;
    let token_a = redeem_ok(&fleet, &key_a).await;
    redeem_ok(&fleet, &key_b).await;

    let grants_a = grants_of(&fleet, &org_a).await;
    let grants_b = grants_of(&fleet, &org_b).await;
    assert_eq!(grants_a.len(), 1);
    assert_eq!(grants_b.len(), 1);
    assert_ne!(grants_a[0].id, grants_b[0].id, "two orgs, two grant rows");
    assert_eq!(
        grants_a[0].subject,
        format!("{}/workload:agent:builder", org_a.0)
    );
    assert_eq!(
        grants_b[0].subject,
        format!("{}/workload:agent:builder", org_b.0)
    );
    // Neither redemption rewrote the other's selector.
    assert_eq!(grants_a[0].selector, "tag=nrf52");
    assert_eq!(grants_b[0].selector, "tag=stm32");

    // Redeeming A again must still not touch B.
    redeem_ok(&fleet, &key_a).await;
    assert_eq!(
        grants_of(&fleet, &org_b).await,
        grants_b,
        "org B's row is untouched"
    );

    // And A's workload sees only A's board: the two `builder`s are different
    // subjects, not one identity spanning orgs.
    let ci = fleet.client_session(&token_a).await;
    match ci.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => {
            assert_eq!(boards.len(), 1);
            assert_eq!(boards[0].board.org, org_a);
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
}

/// A named key's revocation cascade must recompute the *name*-derived grant id,
/// not the hash-derived one: otherwise it would silently find nothing and
/// leave the identity's grant and its live lease standing while reporting
/// success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_named_key_cascades_to_the_name_derived_grant() {
    let fleet = TestCoordinator::start().await;
    let (org, alice_token) = acme_with_admin(&fleet).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let key = fleet
        .seed_named_ci_auth_key(
            "acme",
            &["nrf52".to_owned()],
            Some(fleet.now() + 86_400),
            Some("builder"),
        )
        .await;

    let token = redeem_ok(&fleet, &key).await;
    let ci = fleet.client_session(&token).await;
    let lease = lease_nrf52(&ci).await.lease;

    revoke_key(&fleet, &alice_token, &org, &key).await;
    assert!(
        lease_is_gone(&fleet, lease).await,
        "the cascade must find the name-derived grant"
    );
    assert!(grants_of(&fleet, &org).await.is_empty());
}
