//! `probe-rs-fleet ci login` end to end, through the CLI's own code paths.
//!
//! The story-1 assertion this task exists for, at the CLI seam: a CI job that
//! holds **no secret** exchanges its runner-provided workload identity for a
//! fleet token, and that token lands in `$GITHUB_ENV` under exactly the two
//! variable names the sidecar reads.
//!
//! Modelled on `auth_key_e2e.rs`. Two stubs stand in for things no test can
//! have: the GitHub Actions **token service** (which only exists inside a real
//! runner) and the issuer's **JWKS endpoint**. Everything else — the
//! coordinator, its verification, the grant lookup, the token mint — is real.
//!
//! # These tests mutate process-global environment
//!
//! `ci login` reads `ACTIONS_ID_TOKEN_REQUEST_*` and `GITHUB_ENV` from the
//! environment, because that is how a runner hands them over. Every test here
//! therefore takes the crate's process-wide `ENV_LOCK` (see
//! `fleet_bin::test_support`) — but that lock is `pub(crate)`, so an
//! integration test cannot reach it and declares its own. The two do not
//! mutually exclude, which is why nothing in the *unit* tests touches these
//! particular variables.
//!
//! The guard is deliberately held across `await` points: what it protects is
//! the *process environment* for the whole duration of a test body, and an
//! async-aware mutex would not change that requirement. Each test is a
//! separate `#[tokio::test]` runtime, so there is no task to starve.
#![allow(clippy::await_holding_lock)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use serde_json::{json, Value};

use fleet_bin::cli::CiLoginArgs;
use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, GithubActionsConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::OrgId;
use fleet_proto::token::AllowedOp;

/// Serialises the tests in this file, which all mutate the same env vars.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Take [`ENV_LOCK`], ignoring poisoning.
///
/// A panicking test poisons the lock; the *next* test would then fail for a
/// reason that has nothing to do with it, which turns one failure into a
/// cascade and hides the real one.
fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

const SEED: [u8; 32] = [31u8; 32];
const ISSUER: &str = "https://token.actions.githubusercontent.com";
const AUDIENCE: &str = "https://fleet.test";
const REPO: &str = "ariel-os/ariel-os";

/// The same committed RSA-2048 fixture the coordinator's tests use: PKCS#1 DER,
/// base64. Committed rather than generated, because RSA keygen in a debug build
/// is slow enough to make a test flaky for reasons unrelated to the code.
const KEY_DER_B64: &str = concat!(
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

/// Base64url modulus of [`KEY_DER_B64`].
const KEY_N: &str = concat!(
    "rsL3i977OYrPnKq6SjRYRIYuzkEAd-rd3hvupoNtMt_w7kG6qX2apWgwtqbMvX06fmswpnBq",
    "QuF99lOvBZYQ1AfsV6igmRp9WET0X-kO0ptI0bYs1UGWYc2LMHQWEUJAtFjH5YzOteoEsw1R",
    "wceJ9kDn1WMkotIq_uvx-LlptN98PtnpL3vjIvo-QyYD8ulcEmIygjnEVf_Dpx76agi4gRTG",
    "9miu7NkU3VgZXnMfQdjh7Exz04Qg3ItN_kTkoxx6Yjn1wuo77fZxj7SpAiZbSRix3sRxij_W",
    "t4VfMT2MBwWNb1KjOVxQygPfl9KsxTxD6njiXWtQez89r5RVfoUH0Q",
);

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

struct StubState {
    /// The bearer the token service demands, exactly as a runner's would be.
    request_token: String,
    /// Every `audience` the token service was asked for, so a test can prove
    /// the CLI forwards what it was told rather than something invented.
    seen_audiences: Mutex<Vec<String>>,
    calls: AtomicUsize,
    now: u64,
}

/// A stub GitHub Actions token service **and** JWKS endpoint on one listener.
struct StubGithub {
    base_url: String,
    state: Arc<StubState>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for StubGithub {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl StubGithub {
    async fn start() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let state = Arc::new(StubState {
            request_token: "runner-injected-request-token".to_owned(),
            seen_audiences: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            now,
        });
        let router = Router::new()
            .route("/token", get(id_token))
            .route("/.well-known/jwks", get(jwks))
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

    fn config(&self) -> GithubActionsConfig {
        GithubActionsConfig {
            issuer: ISSUER.to_owned(),
            jwks_url: format!("{}/.well-known/jwks", self.base_url),
            audience: AUDIENCE.to_owned(),
            jwks_refresh_secs: 3_600,
            jwks_min_refetch_secs: 0,
            workload_token_ttl_secs: 3_600,
        }
    }
}

/// The runner's token service: authenticated with the injected request token,
/// answers `{"value": "<jwt>"}`.
async fn id_token(
    State(state): State<Arc<StubState>>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<Value>, axum::http::StatusCode> {
    state.calls.fetch_add(1, Ordering::Relaxed);
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if bearer != state.request_token {
        // A runner's token service is authenticated; a test that did not send
        // the injected token would otherwise pass for the wrong reason.
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    let audience = query
        .unwrap_or_default()
        .split('&')
        .find_map(|kv| kv.strip_prefix("audience=").map(percent_decode))
        .unwrap_or_default();
    state.seen_audiences.lock().unwrap().push(audience.clone());

    let claims = json!({
        "iss": ISSUER,
        "aud": audience,
        "sub": format!("repo:{REPO}:ref:refs/heads/main"),
        "iat": state.now - 10,
        "nbf": state.now - 10,
        "exp": state.now + 600,
        "repository": REPO,
        "repository_owner": "ariel-os",
        "ref": "refs/heads/main",
        "workflow": "hil",
        "run_id": "424242",
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("k1".to_owned());
    let der = base64::engine::general_purpose::STANDARD
        .decode(KEY_DER_B64)
        .unwrap();
    let jwt = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(&der),
    )
    .unwrap();
    Ok(Json(json!({ "value": jwt })))
}

async fn jwks() -> Json<Value> {
    Json(json!({
        "keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256",
            "kid": "k1", "n": KEY_N, "e": "AQAB",
        }]
    }))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// The coordinator
// ---------------------------------------------------------------------------

struct Fleet {
    coord: Arc<Coordinator>,
    base_url: String,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fleet {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn start_fleet(github_actions: Option<GithubActionsConfig>) -> Fleet {
    let config = CoordinatorConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        sqlite_path: ":memory:".into(),
        signing_key: SigningKeySource::Seed(SEED),
        github_actions,
        ..CoordinatorConfig::default()
    };
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
    Fleet {
        coord,
        base_url: format!("http://{addr}"),
        server,
    }
}

/// Grant `REPO` access to the default org's `nrf52`-tagged boards.
async fn grant_repo(fleet: &Fleet) -> OrgId {
    let org = OrgId("default".to_owned());
    let now = i64::try_from(fleet.coord.now()).unwrap();
    let key = fleet_proto::ids::workload_subject_key(REPO);
    fleet
        .coord
        .db()
        .scoped(org.clone())
        .insert_grant(
            &"a".repeat(32),
            &key,
            "tag=nrf52",
            &[AllowedOp::Flash, AllowedOp::Attach],
            Some(now + 86_400),
            None,
            now,
        )
        .await
        .unwrap();
    org
}

fn args(fleet: &Fleet, config_dir: &std::path::Path) -> CiLoginArgs {
    CiLoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        audience: Some(AUDIENCE.to_owned()),
        auth_key: None,
        export: false,
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    }
}

/// Set the variables a runner injects, run `f`, restore.
///
/// The caller holds `ENV_LOCK`.
struct RunnerEnv {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl RunnerEnv {
    fn set(vars: &[(&'static str, String)]) -> Self {
        let mut saved = Vec::new();
        for (key, value) in vars {
            saved.push((*key, std::env::var_os(key)));
            std::env::set_var(key, value);
        }
        Self { saved }
    }

    fn unset(keys: &[&'static str]) -> Self {
        let mut saved = Vec::new();
        for key in keys {
            saved.push((*key, std::env::var_os(key)));
            std::env::remove_var(key);
        }
        Self { saved }
    }
}

impl Drop for RunnerEnv {
    fn drop(&mut self) {
        for (key, value) in &self.saved {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The whole zero-secrets path: a job holding nothing but the runner's injected
/// endpoint gets a fleet token into `$GITHUB_ENV`, under the exact names the
/// sidecar reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ci_job_with_no_secret_exchanges_its_workload_identity() {
    let _guard = lock_env();
    let github = StubGithub::start().await;
    let fleet = start_fleet(Some(github.config())).await;
    grant_repo(&fleet).await;

    let dir = tempfile::tempdir().unwrap();
    let github_env = dir.path().join("github.env");
    std::fs::write(&github_env, "").unwrap();

    let _env = RunnerEnv::set(&[
        (
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/token", github.base_url),
        ),
        (
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            github.state.request_token.clone(),
        ),
        ("GITHUB_ENV", github_env.to_string_lossy().into_owned()),
    ]);

    fleet_bin::roles::ci::run(args(&fleet, dir.path()))
        .await
        .expect("ci login");

    let written = std::fs::read_to_string(&github_env).unwrap();
    let token_line = written
        .lines()
        .find_map(|l| l.strip_prefix("PROBE_RS_FLEET_TOKEN="))
        .expect("PROBE_RS_FLEET_TOKEN in $GITHUB_ENV");
    assert!(
        token_line.starts_with("prfw1_"),
        "a workload token, not something else: {token_line}"
    );
    assert!(written.contains(&format!("PROBE_RS_FLEET_COORDINATOR={}\n", fleet.base_url)));

    // The CLI forwarded the audience it was given, rather than inventing one.
    assert_eq!(
        github.state.seen_audiences.lock().unwrap().as_slice(),
        &[AUDIENCE.to_owned()]
    );

    // **No fleet file is written.** A CI runner's credential lives in the
    // environment for one job; persisting it on a shared runner is the durable
    // artefact this whole design exists to avoid.
    assert!(
        !dir.path().join("default.toml").exists(),
        "ci login must write no fleet file"
    );

    // The token really works: a real `/client` upgrade against the real
    // coordinator, seeing the granted org.
    let (tx, rx) = fleet_wire::client::dial(fleet_wire::client::DialOpts {
        url: fleet.base_url.clone(),
        path: "/client",
        bearer: token_line.to_owned(),
        pin: None,
    })
    .await
    .expect("the exchanged token must authenticate /client");
    drop((tx, rx));
}

/// A runner with no workload identity is told exactly what to add, and reaches
/// no network at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_runner_without_id_token_permission_gets_actionable_advice() {
    let _guard = lock_env();
    let github = StubGithub::start().await;
    let fleet = start_fleet(Some(github.config())).await;
    let dir = tempfile::tempdir().unwrap();

    let _env = RunnerEnv::unset(&[
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "GITHUB_ENV",
    ]);

    let err = fleet_bin::roles::ci::run(args(&fleet, dir.path()))
        .await
        .expect_err("a runner with no identity must fail");
    let text = format!("{err:#}");
    assert!(text.contains("id-token: write"), "{text}");
    assert!(text.contains("--auth-key"), "{text}");
    assert_eq!(
        github.state.calls.load(Ordering::Relaxed),
        0,
        "nothing should have been requested"
    );
}

/// A repo with no grant is refused, and the CLI's message names the per-repo
/// rule and the admin command that fixes it — not a generic 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ungranted_repo_is_told_about_the_per_repo_rule() {
    let _guard = lock_env();
    let github = StubGithub::start().await;
    // No grant seeded at all.
    let fleet = start_fleet(Some(github.config())).await;
    let dir = tempfile::tempdir().unwrap();

    let _env = RunnerEnv::set(&[
        (
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/token", github.base_url),
        ),
        (
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            github.state.request_token.clone(),
        ),
    ]);
    let _no_github_env = RunnerEnv::unset(&["GITHUB_ENV"]);

    let err = fleet_bin::roles::ci::run(args(&fleet, dir.path()))
        .await
        .expect_err("an ungranted repo must fail");
    let text = format!("{err:#}");
    assert!(text.contains("PER REPO"), "{text}");
    assert!(text.contains("grant --repo"), "{text}");
}

/// The auth-key fallback: a runner with no workload identity at all, holding
/// only a pre-minted CI key, still authenticates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_self_hosted_runner_can_use_a_ci_auth_key() {
    let _guard = lock_env();
    // No `[github_actions]` table: the auth-key path involves no issuer, and
    // must work on a coordinator that has never heard of GitHub Actions.
    let fleet = start_fleet(None).await;
    let org = OrgId("default".to_owned());
    let now = i64::try_from(fleet.coord.now()).unwrap();
    let key = fleet_auth::OpaqueToken::mint(fleet_auth::TokenKind::AuthKey);
    fleet
        .coord
        .db()
        .insert_auth_key_with_purpose(
            &org,
            key.hash().as_str(),
            &["nrf52".to_owned()],
            false,
            Some(now + 86_400),
            None,
            now,
            "ci",
            &[],
            None,
        )
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let github_env = dir.path().join("github.env");
    std::fs::write(&github_env, "").unwrap();
    let _env = RunnerEnv::set(&[("GITHUB_ENV", github_env.to_string_lossy().into_owned())]);
    // Deliberately no runner identity: this is the whole point of the path.
    let _no_identity = RunnerEnv::unset(&["ACTIONS_ID_TOKEN_REQUEST_URL"]);

    let mut a = args(&fleet, dir.path());
    a.auth_key = Some(key.to_secret_string());
    fleet_bin::roles::ci::run(a)
        .await
        .expect("ci login --auth-key");

    let written = std::fs::read_to_string(&github_env).unwrap();
    let token = written
        .lines()
        .find_map(|l| l.strip_prefix("PROBE_RS_FLEET_TOKEN="))
        .expect("PROBE_RS_FLEET_TOKEN in $GITHUB_ENV");
    assert!(token.starts_with("prfw1_"), "{token}");

    // Redemption synthesised an ordinary grant, which is what makes the key
    // revocable through the normal path rather than a special case.
    let grants = fleet.coord.db().scoped(org).list_grants().await.unwrap();
    assert_eq!(grants.len(), 1);
    assert!(grants[0].id.starts_with("ci-"));
    assert_eq!(grants[0].selector, "tag=nrf52");
}

/// The same fallback with a **named** key (`auth-key create --as builder`):
/// `ci login` is unchanged, but the subject the runner speaks as is the
/// identity rather than the credential — so re-minting the key would keep it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_ci_auth_key_authenticates_as_its_identity() {
    let _guard = lock_env();
    let fleet = start_fleet(None).await;
    let org = OrgId("default".to_owned());
    let now = i64::try_from(fleet.coord.now()).unwrap();
    let key = fleet_auth::OpaqueToken::mint(fleet_auth::TokenKind::AuthKey);
    fleet
        .coord
        .db()
        .insert_auth_key_with_purpose(
            &org,
            key.hash().as_str(),
            &["nrf52".to_owned()],
            false,
            Some(now + 86_400),
            None,
            now,
            "ci",
            &[],
            Some("builder"),
        )
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let github_env = dir.path().join("github.env");
    std::fs::write(&github_env, "").unwrap();
    let _env = RunnerEnv::set(&[("GITHUB_ENV", github_env.to_string_lossy().into_owned())]);
    let _no_identity = RunnerEnv::unset(&["ACTIONS_ID_TOKEN_REQUEST_URL"]);

    let mut a = args(&fleet, dir.path());
    a.auth_key = Some(key.to_secret_string());
    fleet_bin::roles::ci::run(a)
        .await
        .expect("ci login --auth-key");

    let written = std::fs::read_to_string(&github_env).unwrap();
    assert!(written.contains("PROBE_RS_FLEET_TOKEN=prfw1_"), "{written}");

    let grants = fleet.coord.db().scoped(org).list_grants().await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0].subject, "default/workload:agent:builder",
        "the runner speaks as the identity, not as the key hash"
    );
    assert_eq!(grants[0].selector, "tag=nrf52");
}
