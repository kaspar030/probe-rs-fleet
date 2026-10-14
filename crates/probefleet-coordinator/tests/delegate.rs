//! `ctl delegate` and `GET /delegate` end to end: a sandboxed node can flash a
//! board with a delegated token, and can do nothing else with it
//! (architecture §6.5).
//!
//! The positives here are cheap; the **negatives** are the point, and each has
//! its own test:
//!
//! * every non-relay verb is refused on the delegated route — the sandbox
//!   cannot enumerate the fleet, lease another board, extend or release;
//! * a token for another lease does not open a channel;
//! * an expired token, and a token whose lease has been released, are refused
//!   at the door;
//! * the two credential types do not cross: a capability token is not a session
//!   token and vice versa.

mod common;

use common::TestCoordinator;

use fleet_proto::ids::BoardName;
use fleet_proto::token::{AllowedOp, SignedToken};
use fleet_wire::{CoordToSidecar, SidecarToCoord};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Delegate a board as `bearer` and return the capability token's wire bytes.
async fn delegate(
    fleet: &TestCoordinator,
    bearer: &str,
    select: fleet_proto::lease::Constraint,
    ops: Vec<AllowedOp>,
) -> fleet_proto::lease::LeaseGrant {
    let session = fleet.client_session(bearer).await;
    match session
        .request(SidecarToCoord::Delegate {
            select,
            duration_secs: 600,
            ops,
        })
        .await
        .unwrap()
    {
        CoordToSidecar::Lease(g) => g,
        other => panic!("expected a delegated lease, got {other:?}"),
    }
}

fn by_board(name: &str) -> fleet_proto::lease::Constraint {
    fleet_proto::lease::Constraint::Id(BoardName(name.to_owned()))
}

/// Open a `/delegate` session with a capability token.
async fn delegated_session(
    fleet: &TestCoordinator,
    token: &[u8],
) -> fleet_sidecar::transport::CoordSession {
    let (tx, rx) = fleet.dial("/delegate", &hex(token)).await.unwrap();
    fleet_sidecar::transport::CoordSession::start(Box::new(tx), Box::new(rx))
        .await
        .unwrap()
}

/// A sandbox with a delegated token can open a data channel on its board.
///
/// It does *not* need a `/client` session, a fleet file, or any identity: the
/// token is the whole credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegated_token_opens_a_channel_and_nothing_else_is_needed() {
    use crate::common::NodeStub;

    let fleet = TestCoordinator::start().await;
    let (alice_token, org, _) = fleet.seed_user("alice").await;
    let board = fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let mut node = NodeStub::attach(&fleet, &board.node).await;

    let grant = delegate(
        &fleet,
        &alice_token,
        by_board("dk-3"),
        vec![AllowedOp::Flash, AllowedOp::Attach],
    )
    .await;
    assert_eq!(grant.board, board);
    // The handed-out token says exactly what was delegated.
    let handed = SignedToken::from_wire(&grant.token)
        .unwrap()
        .decode_token()
        .unwrap();
    assert_eq!(
        handed.allowed_ops,
        vec![AllowedOp::Flash, AllowedOp::Attach]
    );
    assert_eq!(handed.lease, grant.lease);
    assert_eq!(handed.board, board);

    // The sandbox connects with nothing but that token.
    let sandbox = delegated_session(&fleet, &grant.token).await;
    let opened = sandbox
        .open_channel(grant.lease, fleet_proto::ChannelKind::Data)
        .await
        .unwrap();

    // The node got a capability token, and it is byte-identical to the one the
    // sandbox was handed. This is the property `ChannelOpened { token }` exists
    // for.
    let session = node.expect_open_session().await;
    assert_eq!(session.channel, opened.channel);
    assert_eq!(
        opened.token, session.token,
        "the sandbox's channel credential must be the node's"
    );
    // And the **serve** token likewise: this is the new end-to-end property.
    // The sandbox exports it as `PROBE_RS_REMOTE_TOKEN`, the node wrote it into
    // `.probe-rs.toml`, so the two must be the same string or the loopback
    // splice is refused. Being lease-scoped, it is also what lands the sandbox
    // on the delegator's *existing* `probe-rs serve` rather than a second one.
    assert_eq!(
        opened.serve_token, session.serve_token,
        "the sandbox's serve credential must be the node's"
    );
    assert!(!opened.serve_token.is_empty());
    // Note the channel token may or may not equal the capability the sandbox
    // presented — here it happens to, because nothing has narrowed the ops or
    // moved the expiry. That coincidence is exactly what `ChannelOpened
    // { token }` stops us depending on: the sandbox uses what it was *given*,
    // so it keeps working when the two diverge (after an extend, or under an
    // attenuating grant). Asserting inequality here would pin the coincidence
    // rather than the property.
}

/// The allowlist: everything that is not relay traffic is refused, so the
/// sandbox cannot enumerate the fleet, take another board, or touch the lease's
/// lifecycle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_non_relay_verb_is_refused_on_the_delegated_route() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, org, _) = fleet.seed_user("alice").await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    let grant = delegate(
        &fleet,
        &alice_token,
        by_board("dk-3"),
        vec![AllowedOp::Attach],
    )
    .await;
    let sandbox = delegated_session(&fleet, &grant.token).await;

    let refused: Vec<(&str, SidecarToCoord)> = vec![
        (
            "leasing another board",
            SidecarToCoord::Lease(fleet_proto::lease::LeaseRequest {
                select: by_board("dk-3"),
                duration_secs: 600,
                priority: fleet_proto::lease::Priority::Interactive,
            }),
        ),
        ("enumerating the fleet", SidecarToCoord::ListBoards),
        ("listing the fleet's machines", SidecarToCoord::ListNodes),
        ("seeing who holds what", SidecarToCoord::Who),
        (
            "reading the audit log",
            SidecarToCoord::Logs {
                board: None,
                follow: false,
            },
        ),
        (
            "power-cycling",
            SidecarToCoord::PowerCycle {
                board: BoardName("dk-3".to_owned()),
            },
        ),
        (
            "extending the lease it was lent",
            SidecarToCoord::Extend { lease: grant.lease },
        ),
        (
            "releasing the lease it was lent",
            SidecarToCoord::Release { lease: grant.lease },
        ),
        ("listing the org's grants", SidecarToCoord::GrantList),
        (
            "granting itself more",
            SidecarToCoord::GrantCreate {
                subject: "mallory".to_owned(),
                selector: "tag=nrf52".to_owned(),
                ops: vec![AllowedOp::Flash],
                expires: Some(fleet.coord.now() + 3_600),
            },
        ),
        (
            "delegating onward",
            SidecarToCoord::Delegate {
                select: by_board("dk-3"),
                duration_secs: 600,
                ops: vec![AllowedOp::Attach],
            },
        ),
    ];

    for (why, request) in refused {
        match sandbox.request(request).await.unwrap() {
            CoordToSidecar::Error { message } => {
                assert_eq!(
                    message, "not permitted on a delegated connection",
                    "{why} must be refused by the allowlist, not by a handler"
                );
            }
            other => panic!("{why} must be refused, got {other:?}"),
        }
    }

    // And the lease survived all of it.
    let sched = fleet.coord.scheduler().lock().await;
    assert!(
        sched.lease_holder(grant.lease).is_some(),
        "none of the refused verbs may have had an effect"
    );
}

/// A token authorises one lease. Asking for another is refused even if that
/// lease exists and is the sandbox's own delegator's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_cannot_open_a_channel_on_another_lease() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, org, _) = fleet.seed_user("alice").await;
    fleet.seed_board(&org, "rpi-1", "dk-a", &["nrf52"]).await;
    fleet.seed_board(&org, "rpi-1", "dk-b", &["nrf52"]).await;

    let first = delegate(
        &fleet,
        &alice_token,
        by_board("dk-a"),
        vec![AllowedOp::Attach],
    )
    .await;
    let second = delegate(
        &fleet,
        &alice_token,
        by_board("dk-b"),
        vec![AllowedOp::Attach],
    )
    .await;
    assert_ne!(first.lease, second.lease);

    let sandbox = delegated_session(&fleet, &first.token).await;
    match sandbox
        .request(SidecarToCoord::OpenChannel {
            lease: second.lease,
            kind: fleet_proto::ChannelKind::Data,
        })
        .await
        .unwrap()
    {
        CoordToSidecar::Error { message } => {
            assert_eq!(message, "this token does not authorise that lease");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Revocation of a delegation *is* releasing the lease, so a token whose lease
/// has been released must stop working immediately — not when it expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_stops_working_the_moment_its_lease_is_released() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, org, _) = fleet.seed_user("alice").await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    let grant = delegate(
        &fleet,
        &alice_token,
        by_board("dk-3"),
        vec![AllowedOp::Attach],
    )
    .await;
    // It works before the release.
    assert_eq!(
        fleet
            .upgrade_status("/delegate", Some(&hex(&grant.token)))
            .await,
        101
    );

    // Alice, the delegator, takes the board back.
    let alice = fleet.client_session(&alice_token).await;
    match alice
        .request(SidecarToCoord::Release { lease: grant.lease })
        .await
        .unwrap()
    {
        CoordToSidecar::Released { .. } => {}
        other => panic!("expected Released, got {other:?}"),
    }

    // The token is cryptographically valid and unexpired — and useless.
    assert_eq!(
        fleet
            .upgrade_status("/delegate", Some(&hex(&grant.token)))
            .await,
        401,
        "releasing the lease is how a delegation is revoked"
    );
}

/// Every way of failing at the door looks the same, and none of them is a
/// signature the caller can learn from.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_credentials_are_refused_uniformly() {
    use fleet_proto::ids::BoardRef;
    use fleet_proto::token::{CapabilityToken, TokenSigner as _};

    let fleet = TestCoordinator::start().await;
    let (session_token, org, _) = fleet.seed_user("alice").await;

    // A board key of the shape the coordinator mints. Nothing here resolves it
    // — both tokens below are refused before the board is ever looked up — but
    // a fixture that spells an unreachable shape teaches the next reader the
    // wrong one.
    let board = {
        let node = fleet_coordinator::node_id_for(&org, "rpi-1");
        BoardRef::new(org, node, "dk-3")
    };

    // A well-formed token, signed by *another* coordinator's key.
    let impostor = fleet_coordinator::auth::Ed25519Signer::from_seed(&[9u8; 32]);
    let forged = impostor
        .sign(&CapabilityToken {
            lease: fleet_proto::LeaseId(1),
            board: board.clone(),
            allowed_ops: vec![AllowedOp::Flash],
            expires: fleet.coord.now() + 3_600,
        })
        .unwrap()
        .to_wire();

    // One signed by us, but already expired.
    let expired = fleet
        .coord
        .signer()
        .sign(&CapabilityToken {
            lease: fleet_proto::LeaseId(1),
            board,
            allowed_ops: vec![AllowedOp::Flash],
            expires: 1,
        })
        .unwrap()
        .to_wire();

    let cases: &[(&str, Option<String>)] = &[
        ("no credential at all", None),
        ("not hex", Some("hello, world".to_owned())),
        (
            "hex but too short to be a token",
            Some("deadbeef".to_owned()),
        ),
        ("a token signed by another key", Some(hex(&forged))),
        ("a token that has expired", Some(hex(&expired))),
        // The two credential types must not cross.
        ("a session token", Some(session_token.clone())),
    ];
    for (why, bearer) in cases {
        assert_eq!(
            fleet.upgrade_status("/delegate", bearer.as_deref()).await,
            401,
            "{why} must be a flat 401"
        );
    }
}

/// The mirror image: a capability token is not a session token either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_capability_token_is_not_accepted_on_the_client_route() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, org, _) = fleet.seed_user("alice").await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    let grant = delegate(
        &fleet,
        &alice_token,
        by_board("dk-3"),
        vec![AllowedOp::Attach],
    )
    .await;
    assert_eq!(
        fleet
            .upgrade_status("/client", Some(&hex(&grant.token)))
            .await,
        401,
        "a capability token confers no fleet identity"
    );
}

/// You cannot delegate more than you hold: the handed-out token is the
/// intersection of what was asked for and what the delegator may actually do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegation_cannot_exceed_the_delegators_own_access() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _) = fleet.seed_user("alice").await;
    let (bob_token, _, _) = fleet.seed_user("bob").await;
    fleet
        .seed_board(&alice_org, "rpi-1", "dk-3", &["nrf52"])
        .await;

    // Bob may only attach.
    let alice = fleet.client_session(&alice_token).await;
    let _ = alice
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Attach],
            expires: Some(fleet.coord.now() + 3_600),
        })
        .await
        .unwrap();

    // He asks to delegate gdb as well as attach; only attach comes back.
    let grant = delegate(
        &fleet,
        &bob_token,
        by_board("dk-3"),
        vec![AllowedOp::Attach, AllowedOp::Gdb],
    )
    .await;
    let handed = SignedToken::from_wire(&grant.token)
        .unwrap()
        .decode_token()
        .unwrap();
    assert_eq!(
        handed.allowed_ops,
        vec![AllowedOp::Attach],
        "the intersection, not the request"
    );

    // Asking for *only* ops he lacks is refused outright, and leaves no lease
    // behind. A second board, since the first is now held by the delegation
    // above and would merely queue.
    fleet
        .seed_board(&alice_org, "rpi-1", "dk-4", &["nrf52"])
        .await;
    let bob = fleet.client_session(&bob_token).await;
    match bob
        .request(SidecarToCoord::Delegate {
            select: by_board("dk-4"),
            duration_secs: 600,
            ops: vec![AllowedOp::Gdb],
        })
        .await
        .unwrap()
    {
        CoordToSidecar::Error { .. } => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
    // The refused delegation left the board free, rather than parking a lease
    // on it that nobody can use.
    let sched = fleet.coord.scheduler().lock().await;
    let dk4 = fleet_proto::ids::BoardRef::new(
        alice_org.clone(),
        fleet_coordinator::node_id_for(&alice_org, "rpi-1"),
        "dk-4",
    );
    assert_eq!(
        sched.board(&dk4).unwrap().state,
        fleet_proto::board::BoardState::Idle,
        "a refused delegation must not strand the board"
    );
}

// ---------------------------------------------------------------------------
// Connection-scoped channel teardown (task 3670, issue #512)
// ---------------------------------------------------------------------------

/// A dropped sidecar connection closes **its** channels, and tells the node.
///
/// The backstop for a sidecar that is `SIGKILL`ed rather than returning: the
/// invocation closes its own channel on the way out, but a crashed one cannot.
/// Nothing else would ever do it — the node reports `SessionClosed` only in
/// reply to a `KillSession`, so waiting for the node here waits forever — and a
/// surviving channel keeps the node's reused `probe-rs serve` holding the
/// probe, so the next invocation's attach is refused.
///
/// The **lease** deliberately survives: it outlives one connection, which is
/// the whole premise of the sidecar's lease cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_sidecar_connection_closes_its_channels() {
    use crate::common::NodeStub;

    let fleet = TestCoordinator::start().await;
    let (alice_token, org, _) = fleet.seed_user("alice").await;
    let board = fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let mut node = NodeStub::attach(&fleet, &board.node).await;

    let session = fleet.client_session(&alice_token).await;
    let lease = match session
        .request(SidecarToCoord::Lease(fleet_proto::lease::LeaseRequest {
            select: by_board("dk-3"),
            duration_secs: 600,
            priority: fleet_proto::lease::Priority::Interactive,
        }))
        .await
        .unwrap()
    {
        CoordToSidecar::Lease(g) => g.lease,
        other => panic!("expected a lease, got {other:?}"),
    };
    let opened = session
        .open_channel(lease, fleet_proto::ChannelKind::Data)
        .await
        .unwrap();
    let _ = node.expect_open_session().await;
    assert!(fleet.coord.channels().get(opened.channel).await.is_some());

    // The client goes away without closing anything.
    drop(session);

    assert_eq!(
        node.expect_kill_session().await,
        opened.channel,
        "the node must be told to drop its side"
    );
    assert!(
        fleet.coord.channels().get(opened.channel).await.is_none(),
        "the route must be gone too"
    );
    // But the lease is untouched: it is not the connection's to lose.
    let sched = fleet.coord.scheduler().lock().await;
    assert!(
        sched.lease_target(lease).is_some(),
        "a disconnect drops channels, not leases"
    );
}

/// The same for a **delegated** connection, which mints no `RequesterId` at all
/// and so is found by its own handle rather than by a registry lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_delegated_connection_closes_its_channels() {
    use crate::common::NodeStub;

    let fleet = TestCoordinator::start().await;
    let (alice_token, org, _) = fleet.seed_user("alice").await;
    let board = fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let mut node = NodeStub::attach(&fleet, &board.node).await;

    let grant = delegate(
        &fleet,
        &alice_token,
        by_board("dk-3"),
        vec![AllowedOp::Flash, AllowedOp::Attach],
    )
    .await;
    let sandbox = delegated_session(&fleet, &grant.token).await;
    let opened = sandbox
        .open_channel(grant.lease, fleet_proto::ChannelKind::Data)
        .await
        .unwrap();
    let _ = node.expect_open_session().await;

    drop(sandbox);

    assert_eq!(node.expect_kill_session().await, opened.channel);
    assert!(fleet.coord.channels().get(opened.channel).await.is_none());
    // The delegator's lease is untouched: the sandbox never owned it.
    let sched = fleet.coord.scheduler().lock().await;
    assert!(sched.lease_target(grant.lease).is_some());
}

/// Teardown is keyed on the **connection**, not the lease: two connections may
/// legitimately hold channels on one lease (the delegator's own `probe-rs run`
/// and a `ctl delegate` sandbox landing on the same `probe-rs serve`), and
/// dropping one must leave the other's channel alone.
///
/// A lease-keyed implementation passes every other test in this file and fails
/// exactly here, by killing a live sandbox's channel when its delegator exits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_connection_dropping_leaves_another_connections_channel_alone() {
    use crate::common::NodeStub;

    let fleet = TestCoordinator::start().await;
    let (alice_token, org, _) = fleet.seed_user("alice").await;
    let board = fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let mut node = NodeStub::attach(&fleet, &board.node).await;

    let grant = delegate(
        &fleet,
        &alice_token,
        by_board("dk-3"),
        vec![AllowedOp::Flash, AllowedOp::Attach],
    )
    .await;

    // Two connections, one lease.
    let first = delegated_session(&fleet, &grant.token).await;
    let second = delegated_session(&fleet, &grant.token).await;
    let a = first
        .open_channel(grant.lease, fleet_proto::ChannelKind::Data)
        .await
        .unwrap();
    let _ = node.expect_open_session().await;
    let b = second
        .open_channel(grant.lease, fleet_proto::ChannelKind::Data)
        .await
        .unwrap();
    let _ = node.expect_open_session().await;
    assert_ne!(a.channel, b.channel);
    // Same lease, so both channels carry the same serve token and the node
    // reuses one `probe-rs serve` for them.
    assert_eq!(a.serve_token, b.serve_token);

    drop(first);

    assert_eq!(node.expect_kill_session().await, a.channel);
    assert!(fleet.coord.channels().get(a.channel).await.is_none());
    assert!(
        fleet.coord.channels().get(b.channel).await.is_some(),
        "the surviving connection's channel must be untouched"
    );
}
