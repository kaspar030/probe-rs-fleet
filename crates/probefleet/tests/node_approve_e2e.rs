//! `node up --interactive` + `probe-rs-fleet node approve` end to end, through
//! the CLI's own code paths (architecture §4.2 rung 3, §6.4).
//!
//! The story this asserts: a headless Pi with **no credential of any kind**
//! runs `node up`, a colleague on a logged-in laptop approves it, and the Pi
//! ends up with a `[node]` credential that works against the live coordinator.
//! Nothing long-lived is copy-pasted anywhere — which is the property the rung
//! exists for, given that `auth-key create` (task 3454) already covers "a
//! hosted customer can enroll a Pi at all".
//!
//! Modelled on `share_e2e.rs`. As there, `login --token` stands in for the
//! device flow (covered against a stub GitHub in
//! `fleet-coordinator/tests/device_flow.rs`), and the sessions are minted far
//! from expiry so `ensure_fresh_session` never writes to the real XDG path.
//!
//! **How the approver learns the code.** `node up` prints it, and a sibling
//! task cannot read another task's stdout. So the laptop side polls
//! the pending-registration table (`Fleet::live_pending_codes`) — the same query a `node list-pending` verb would
//! use — which is the seam that lets this test cover the interesting half
//! rather than being weakened into asserting the boring one.

mod common;

use std::time::Duration;

use common::{start_fleet, Fleet};
use fleet_bin::cli::{LoginArgs, NodeApproveArgs, NodeUpFlags};
use fleet_coordinator::FleetRole;
use fleet_proto::auth_api::NodeRegisterStartRequest;
use fleet_proto::ids::NodeId;

const SEED: [u8; 32] = [31u8; 32];

/// Mint a session token with its membership, as `coordinator user-token` does.
async fn mint_user_token(fleet: &Fleet, login: &str) -> String {
    fleet.session(login, FleetRole::Member).await
}

/// Run `login --token` into `config_dir`.
async fn login(fleet: &Fleet, config_dir: &std::path::Path, login_name: &str) {
    let token = mint_user_token(fleet, login_name).await;
    fleet_bin::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(token),
        refresh_token: None,
        no_browser: true,
        org: Some(common::DEFAULT_ORG.to_owned()),
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    })
    .await
    .expect("login --token");
}

fn up_args(fleet: &Fleet, node_name: &str) -> NodeUpFlags {
    NodeUpFlags {
        fleet_url: Some(fleet.base_url.clone()),
        auth_key: None,
        node_name: Some(node_name.to_owned()),
        tag: vec!["lab".to_owned()],
        adopt: None,
        server_cert_sha256: None,
        force: false,
        // Forced on: there is no terminal under a test runner, and this rung is
        // exactly what the test is about.
        interactive: true,
        no_interactive: false,
    }
}

fn approve_args(config_dir: &std::path::Path, code: &str) -> NodeApproveArgs {
    NodeApproveArgs {
        code: code.to_owned(),
        deny: false,
        // Non-interactive by necessity: stdin is not a terminal here, and the
        // verb refuses to proceed without this rather than defaulting either
        // way. That refusal has its own unit test in `node_approve`.
        yes: true,
        replace: false,
        // The approver's personal org is the default target; these tests
        // enroll into the shared org.
        org: Some(common::DEFAULT_ORG.to_owned()),
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    }
}

/// Wait for the enrolling machine's pending registration to appear, and return
/// its code — what the human would read off the Pi's terminal.
async fn await_pending_code(fleet: &Fleet, node_name: &str) -> String {
    for _ in 0..100 {
        let live = fleet.live_pending_codes().await;
        if let Some((code, _)) = live.into_iter().find(|(_, name)| name == node_name) {
            return code;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no pending registration for {node_name} appeared");
}

/// The payoff: a headless machine with nothing, approved from a laptop, ends up
/// a working node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_headless_machine_is_approved_from_a_logged_in_laptop() {
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    let pi = tmp.path().join("pi");
    login(&fleet, &laptop, "alice").await;

    // The Pi: no `[node]`, no `[user]`, no key. Rungs 1-3 cannot serve it.
    let args = up_args(&fleet, "rpi-lab-3");
    let pi_dir = pi.clone();
    let bootstrap = tokio::spawn(async move {
        fleet_bin::roles::node_up::bootstrap(&args, "default", Some(&pi_dir)).await
    });

    // The laptop: read the code (as a human would off the Pi's screen) and
    // approve.
    let code = await_pending_code(&fleet, "rpi-lab-3").await;
    fleet_bin::roles::node_approve::run(&approve_args(&laptop, &code))
        .await
        .expect("node approve");

    bootstrap
        .await
        .unwrap()
        .expect("node up must finish once the registration is approved");

    let node = fleet_bin::fleet_config::load(&pi.join("default.toml"))
        .unwrap()
        .node
        .expect("[node] was written");
    let default_org = fleet.default_org().await;
    assert_eq!(node.node_id, format!("{}/rpi-lab-3", default_org.0));

    // The credential works against the live coordinator: a real token, not a
    // plausible-looking string.
    let (tx, rx) = fleet_wire::client::dial(fleet_wire::client::DialOpts {
        url: fleet.base_url.clone(),
        path: "/agent",
        bearer: node.node_token.clone(),
        pin: None,
    })
    .await
    .expect("the approved node's token must authenticate on /agent");
    drop((tx, rx));

    // Owned by the approver, in her org, with the policy the rung asked for —
    // identical to what `share` would have produced.
    let node_id = NodeId(node.node_id.clone());
    let (org, adopt) = fleet
        .coord
        .db()
        .node_org_and_policy(&node_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(org, default_org);
    assert_eq!(adopt, fleet_proto::AdoptPolicy::Auto);
    assert_eq!(
        fleet
            .coord
            .db()
            .node_owner(&node_id)
            .await
            .unwrap()
            .as_deref(),
        Some(fleet.user("alice").await.to_string().as_str()),
        "the node is owned by the human who approved it"
    );

    // The pending row is spent: the same code cannot enroll a second machine.
    assert!(fleet.live_pending_codes().await.is_empty());
}

/// Denial is a first-class outcome: `node up` stops with a clear message
/// rather than spinning until the code expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_denied_machine_is_told_and_gives_up() {
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    let pi = tmp.path().join("pi");
    login(&fleet, &laptop, "alice").await;

    let args = up_args(&fleet, "rpi-lab-4");
    let pi_dir = pi.clone();
    let bootstrap = tokio::spawn(async move {
        fleet_bin::roles::node_up::bootstrap(&args, "default", Some(&pi_dir)).await
    });

    let code = await_pending_code(&fleet, "rpi-lab-4").await;
    let mut deny = approve_args(&laptop, &code);
    deny.deny = true;
    fleet_bin::roles::node_approve::run(&deny)
        .await
        .expect("node approve --deny");

    let err = bootstrap
        .await
        .unwrap()
        .expect_err("a denied registration must not enroll anything");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("denied"), "got: {rendered}");
    assert!(
        !pi.join("default.toml").exists(),
        "nothing may be written on a denial"
    );
}

/// A machine can be approved into the org of whoever approves it — and only
/// that org. A member of another org cannot take it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approving_requires_membership_of_the_org_the_node_would_join() {
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let stranger_dir = tmp.path().join("stranger");

    // A session for a user who is *not* a member of the org it names: mallory
    // belongs to another org (and her personal one), never to `default`.
    fleet.create_org("elsewhere").await;
    fleet
        .member("mallory", "elsewhere", FleetRole::Member)
        .await;
    let mallory = fleet.user("mallory").await;
    let token = forgs_http::session::mint_session(fleet.coord.auth(), mallory, "test")
        .await
        .unwrap()
        .token;
    fleet_bin::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(token),
        refresh_token: None,
        no_browser: true,
        org: Some(common::DEFAULT_ORG.to_owned()),
        fleet: "default".to_owned(),
        config_dir: Some(stranger_dir.clone()),
    })
    .await
    .expect("login --token");

    // Start a registration directly: no `node up` task to leave running.
    let client = fleet_bin::node_client::client(&fleet.base_url, None).unwrap();
    let grant = fleet_bin::node_client::register_start(
        &client,
        &NodeRegisterStartRequest {
            node_name: "rpi-lab-5".to_owned(),
            tags: vec![],
            adopt: None,
        },
    )
    .await
    .expect("node register start");

    let err = fleet_bin::roles::node_approve::run(&approve_args(&stranger_dir, &grant.user_code))
        .await
        .expect_err("a non-member must not approve");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("not a member"), "got: {rendered}");
}

/// A mistyped code fails locally, before any request: the user typed it, so the
/// error should be about what they typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mistyped_code_is_refused_with_the_shape_it_should_have() {
    let tmp = tempfile::tempdir().unwrap();
    let err = fleet_bin::roles::node_approve::run(&approve_args(tmp.path(), "nope"))
        .await
        .expect_err("a malformed code");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("ABCD-1234"), "got: {rendered}");
    // Note it did not even need a fleet file: the check is local.
    assert!(!rendered.contains("login"), "got: {rendered}");
}
