//! Grants end to end: alice shares a board with bob, bob uses it, alice takes
//! it back (architecture §6.5).
//!
//! Everything runs through the real router on a real socket with real bearer
//! tokens — two users in two orgs, exactly the "a second GitHub user can be
//! granted access to a subset of boards, use them, and be revoked" story the
//! feature exists for.
//!
//! Note what is *not* stubbed: the selector is parsed and re-parsed, the grant
//! goes through the database, and bob's access is recomputed from scratch on
//! every request. The negatives (cross-org, expired, revoked) matter more than
//! the positive here, so each has its own test rather than being an assertion
//! tacked onto the happy path.

mod common;

use common::TestCoordinator;

use fleet_proto::ids::{BoardName, Role};
use fleet_proto::lease::{Constraint, LeaseRequest, Priority};
use fleet_proto::token::{AllowedOp, SignedToken};
use fleet_wire::{CoordToSidecar, SidecarToCoord};

/// One hour from now, as a grant deadline.
fn soon(fleet: &TestCoordinator) -> u64 {
    fleet.coord.now() + 3_600
}

fn lease_by_tag(tag: &str) -> SidecarToCoord {
    SidecarToCoord::Lease(LeaseRequest {
        select: Constraint::Tags(vec![tag.to_owned()]),
        duration_secs: 600,
        priority: Priority::Interactive,
    })
}

/// The ops carried by a minted capability token, decoded.
fn token_ops(wire: &[u8]) -> Vec<AllowedOp> {
    SignedToken::from_wire(wire)
        .unwrap()
        .decode_token()
        .unwrap()
        .allowed_ops
}

/// The whole story-6 flow: grant → use → revoke → denied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_user_can_be_granted_a_board_use_it_and_be_revoked() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _alice) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _bob_org, _bob) = fleet.seed_github_user(2, "bob", Role::Member).await;
    let board = fleet
        .seed_board(&alice_org, "rpi-1", "nrf52840-dk-3", &["nrf52"])
        .await;

    // Before the grant: bob cannot see or lease alice's board.
    let bob = fleet.client_session(&bob_token).await;
    match bob.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => {
            assert!(boards.is_empty(), "bob sees nothing before the grant");
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
    assert!(
        matches!(
            bob.request(lease_by_tag("nrf52")).await.unwrap(),
            CoordToSidecar::NoCandidate { reachable: 0, .. }
        ),
        "with no access the request is refused outright rather than granting"
    );

    // Alice grants.
    let alice = fleet.client_session(&alice_token).await;
    let grant_id = match alice
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Flash, AllowedOp::Attach],
            expires: Some(soon(&fleet)),
        })
        .await
        .unwrap()
    {
        CoordToSidecar::GrantCreated(g) => {
            assert_eq!(g.selector, "tag=nrf52", "stored in canonical form");
            assert_eq!(g.org, alice_org);
            // Resolved to the immutable id, never the login.
            assert_eq!(g.subject.id, "gh-2");
            g.id
        }
        other => panic!("expected GrantCreated, got {other:?}"),
    };

    // Bob now sees the board and can lease it — on a fresh connection, so the
    // access really is recomputed rather than cached.
    let bob = fleet.client_session(&bob_token).await;
    match bob.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => {
            assert_eq!(boards.len(), 1);
            assert_eq!(boards[0].board, board);
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
    let lease = match bob.request(lease_by_tag("nrf52")).await.unwrap() {
        CoordToSidecar::Lease(g) => {
            assert_eq!(g.board, board);
            // The token says exactly what the grant said, and no more.
            assert_eq!(
                token_ops(&g.token),
                vec![AllowedOp::Flash, AllowedOp::Attach],
                "the capability token is attenuated to the grant's ops"
            );
            g.lease
        }
        other => panic!("expected Lease, got {other:?}"),
    };

    // The lease is recorded in *alice's* org — it is her hardware.
    assert_eq!(
        fleet
            .db()
            .scoped(alice_org.clone())
            .open_lease_count()
            .await
            .unwrap(),
        1,
        "a cross-org lease belongs to the board's tenant"
    );

    // Alice revokes.
    match alice
        .request(SidecarToCoord::GrantRevoke {
            id: grant_id[..8].to_owned(),
        })
        .await
        .unwrap()
    {
        CoordToSidecar::GrantRevoked { ids } => assert_eq!(ids.len(), 1),
        other => panic!("expected GrantRevoked, got {other:?}"),
    }

    // The cascade released bob's lease, rather than leaving him holding the
    // board until its TTL ran out.
    {
        let sched = fleet.coord.scheduler().lock().await;
        assert!(
            sched.lease_holder(lease).is_none(),
            "revocation must release the lease it was holding open"
        );
    }
    assert_eq!(
        fleet
            .db()
            .scoped(alice_org)
            .open_lease_count()
            .await
            .unwrap(),
        0,
        "and close it in the database, not just in memory"
    );

    // And bob is back to seeing nothing.
    let bob = fleet.client_session(&bob_token).await;
    match bob.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => assert!(boards.is_empty()),
        other => panic!("expected BoardList, got {other:?}"),
    }
}

/// A grant confers its ops and nothing else. Power-cycle is the one op the
/// coordinator enforces itself, so it is the one that can be tested at this
/// level.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grantee_without_the_op_is_refused() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _, _) = fleet.seed_github_user(2, "bob", Role::Member).await;
    fleet
        .seed_board(&alice_org, "rpi-1", "dk-3", &["nrf52"])
        .await;

    let alice = fleet.client_session(&alice_token).await;
    let _ = alice
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Attach],
            expires: Some(soon(&fleet)),
        })
        .await
        .unwrap();

    let bob = fleet.client_session(&bob_token).await;
    // He can see it...
    match bob.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => assert_eq!(boards.len(), 1),
        other => panic!("expected BoardList, got {other:?}"),
    }
    // ...but not cut its power.
    match bob
        .request(SidecarToCoord::PowerCycle {
            board: BoardName("dk-3".to_owned()),
        })
        .await
        .unwrap()
    {
        CoordToSidecar::Error { message } => assert_eq!(message, "not authorized"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// An expired grant confers nothing, and the check is at evaluation time rather
/// than at creation time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_grant_is_denied() {
    let fleet = TestCoordinator::start().await;
    let (_alice_token, alice_org, _) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _, bob_id) = fleet.seed_github_user(2, "bob", Role::Member).await;
    fleet
        .seed_board(&alice_org, "rpi-1", "dk-3", &["nrf52"])
        .await;

    // Seeded directly, because the API refuses to *create* an expired grant —
    // which is itself the point: this row could only come from a grant that has
    // since lapsed.
    let key = fleet_proto::ids::SubjectKey {
        org: fleet_proto::ids::OrgId("gh-2".to_owned()),
        kind: fleet_proto::ids::SubjectKind::User,
        id: bob_id,
    };
    let now = i64::try_from(fleet.coord.now()).unwrap();
    fleet
        .db()
        .scoped(alice_org)
        .insert_grant(
            &fleet_coordinator::state::new_grant_id(),
            &key,
            "tag=nrf52",
            &[AllowedOp::Attach],
            Some(now - 1),
            None,
            now - 100,
        )
        .await
        .unwrap();

    let bob = fleet.client_session(&bob_token).await;
    match bob.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => {
            assert!(boards.is_empty(), "an expired grant shows nothing");
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
    // An expired grant leaves bob reaching nothing, so the request is
    // `NoCandidate` rather than a queue slip that could never be satisfied.
    assert!(matches!(
        bob.request(lease_by_tag("nrf52")).await.unwrap(),
        CoordToSidecar::NoCandidate { reachable: 0, .. }
    ));
}

/// The org fence: a grant from org A must not admit an identically tagged board
/// in org C. The selector matches; the org does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grant_does_not_reach_a_third_orgs_same_tagged_board() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _, _) = fleet.seed_github_user(2, "bob", Role::Member).await;
    let (_carol_token, carol_org, _) = fleet.seed_github_user(3, "carol", Role::Admin).await;

    let alice_board = fleet
        .seed_board(&alice_org, "rpi-1", "dk-a", &["nrf52"])
        .await;
    // Carol's board carries the very same tag.
    fleet
        .seed_board(&carol_org, "rpi-9", "dk-c", &["nrf52"])
        .await;

    let alice = fleet.client_session(&alice_token).await;
    let _ = alice
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Attach],
            expires: Some(soon(&fleet)),
        })
        .await
        .unwrap();

    let bob = fleet.client_session(&bob_token).await;
    match bob.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => {
            assert_eq!(boards.len(), 1, "only the granting org's board");
            assert_eq!(boards[0].board, alice_board);
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
}

/// The requirement `board=<model>` exists for: a grant written against a board
/// **type** covers every board of that model in the granting org — and nothing
/// of another model, and nothing in another org.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_model_grant_covers_every_board_of_that_model_in_the_org() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _, _) = fleet.seed_github_user(2, "bob", Role::Member).await;
    let (_carol_token, carol_org, _) = fleet.seed_github_user(3, "carol", Role::Admin).await;

    let dk1 = fleet
        .seed_board_with_model(&alice_org, "rpi-1", "dk-1", &[], Some("nrf52840dk"))
        .await;
    let dk2 = fleet
        .seed_board_with_model(&alice_org, "rpi-1", "dk-2", &[], Some("nrf52840dk"))
        .await;
    // Another model in the same org, a board with no declared model at all
    // (the adopted-board shape), and the same model in another org.
    fleet
        .seed_board_with_model(&alice_org, "rpi-1", "pico-1", &[], Some("rpi-pico"))
        .await;
    fleet
        .seed_board_with_model(&alice_org, "rpi-1", "adopted-1", &[], None)
        .await;
    fleet
        .seed_board_with_model(&carol_org, "rpi-9", "dk-9", &[], Some("nrf52840dk"))
        .await;

    let alice = fleet.client_session(&alice_token).await;
    let _ = alice
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "board=nrf52840dk".to_owned(),
            ops: vec![AllowedOp::Attach],
            expires: Some(soon(&fleet)),
        })
        .await
        .unwrap();

    let bob = fleet.client_session(&bob_token).await;
    match bob.request(SidecarToCoord::ListBoards).await.unwrap() {
        CoordToSidecar::BoardList(boards) => {
            let mut visible: Vec<String> = boards.iter().map(|b| b.board.name.clone()).collect();
            visible.sort();
            let mut expected = vec![dk1.name.clone(), dk2.name.clone()];
            expected.sort();
            assert_eq!(
                visible, expected,
                "a model grant covers exactly the boards of that model in the granting org"
            );
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
}

/// Creating a grant is admin-only — deliberately stricter than minting an auth
/// key, because a grant points outward at a non-member.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_member_cannot_share_the_orgs_hardware() {
    let fleet = TestCoordinator::start().await;
    let (_admin_token, org, _) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (_bob_token, _, _) = fleet.seed_github_user(2, "bob", Role::Member).await;

    // A second member of alice's org, without admin.
    let now = i64::try_from(fleet.coord.now()).unwrap();
    let (member_id, _) = fleet
        .db()
        .upsert_github_user(4, "dave", None, now)
        .await
        .map(|(id, o, _)| (id, o))
        .unwrap();
    fleet
        .db()
        .ensure_user_member(&org, &member_id, Role::Member)
        .await
        .unwrap();
    let token = fleet_auth::OpaqueToken::mint(fleet_auth::TokenKind::Session);
    fleet
        .db()
        .insert_session(token.hash().as_str(), &org, &member_id, now, now + 3_600)
        .await
        .unwrap();

    let dave = fleet.client_session(&token.to_secret_string()).await;
    match dave
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Attach],
            expires: Some(soon(&fleet)),
        })
        .await
        .unwrap()
    {
        CoordToSidecar::Error { message } => assert_eq!(message, "not authorized"),
        other => panic!("a member must not be able to grant, got {other:?}"),
    }

    // But listing is fine: it names only this org's own outbound grants.
    match dave.request(SidecarToCoord::GrantList).await.unwrap() {
        CoordToSidecar::Grants(g) => assert!(g.is_empty()),
        other => panic!("expected Grants, got {other:?}"),
    }
}

/// Guards that must live below the CLI, so a hand-rolled client cannot bypass
/// them: no unbounded grant, no match-everything selector, no empty op set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dangerous_grant_shapes_are_refused_server_side() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (_bob_token, _, _) = fleet.seed_github_user(2, "bob", Role::Member).await;
    let alice = fleet.client_session(&alice_token).await;

    let cases: &[(&str, SidecarToCoord)] = &[
        (
            "a grant with no expiry",
            SidecarToCoord::GrantCreate {
                subject: "bob".to_owned(),
                selector: "tag=nrf52".to_owned(),
                ops: vec![AllowedOp::Attach],
                expires: None,
            },
        ),
        (
            "a grant that expired before it was created",
            SidecarToCoord::GrantCreate {
                subject: "bob".to_owned(),
                selector: "tag=nrf52".to_owned(),
                ops: vec![AllowedOp::Attach],
                expires: Some(1),
            },
        ),
        (
            "an empty selector, which would match every board",
            SidecarToCoord::GrantCreate {
                subject: "bob".to_owned(),
                selector: String::new(),
                ops: vec![AllowedOp::Attach],
                expires: Some(soon(&fleet)),
            },
        ),
        (
            "an empty op set",
            SidecarToCoord::GrantCreate {
                subject: "bob".to_owned(),
                selector: "tag=nrf52".to_owned(),
                ops: vec![],
                expires: Some(soon(&fleet)),
            },
        ),
        (
            "a grantee nobody has heard of",
            SidecarToCoord::GrantCreate {
                subject: "nobody-at-all".to_owned(),
                selector: "tag=nrf52".to_owned(),
                ops: vec![AllowedOp::Attach],
                expires: Some(soon(&fleet)),
            },
        ),
    ];

    for (why, request) in cases {
        match alice.request(request.clone()).await.unwrap() {
            CoordToSidecar::Error { .. } => {}
            other => panic!("{why} must be refused, got {other:?}"),
        }
    }

    // Nothing was written by any of them.
    assert!(fleet
        .db()
        .scoped(alice_org)
        .list_grants()
        .await
        .unwrap()
        .is_empty());
}

/// Revoking by a short or non-hex prefix would match every grant in the org
/// (`LIKE '%'`), so it is refused before the delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_by_a_dangerous_prefix_is_refused() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (_bob_token, _, _) = fleet.seed_github_user(2, "bob", Role::Member).await;
    let alice = fleet.client_session(&alice_token).await;
    let _ = alice
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Attach],
            expires: Some(soon(&fleet)),
        })
        .await
        .unwrap();

    for prefix in ["", "a", "abc", "not-hex-at-all"] {
        match alice
            .request(SidecarToCoord::GrantRevoke {
                id: prefix.to_owned(),
            })
            .await
            .unwrap()
        {
            CoordToSidecar::Error { .. } => {}
            other => panic!("prefix {prefix:?} must be refused, got {other:?}"),
        }
    }
    assert_eq!(
        fleet
            .db()
            .scoped(alice_org)
            .list_grants()
            .await
            .unwrap()
            .len(),
        1,
        "nothing was deleted"
    );
}

/// The board's org admin may reclaim hardware from a grantee holding it —
/// otherwise sharing a board would mean losing control of it until the lease
/// lapsed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_boards_owner_can_release_a_grantees_lease() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _, _) = fleet.seed_github_user(2, "bob", Role::Member).await;
    fleet
        .seed_board(&alice_org, "rpi-1", "dk-3", &["nrf52"])
        .await;

    let alice = fleet.client_session(&alice_token).await;
    let _ = alice
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Attach],
            expires: Some(soon(&fleet)),
        })
        .await
        .unwrap();

    let bob = fleet.client_session(&bob_token).await;
    let lease = match bob.request(lease_by_tag("nrf52")).await.unwrap() {
        CoordToSidecar::Lease(g) => g.lease,
        other => panic!("expected Lease, got {other:?}"),
    };

    match alice
        .request(SidecarToCoord::Release { lease })
        .await
        .unwrap()
    {
        CoordToSidecar::Released { lease: l } => assert_eq!(l, lease),
        other => panic!("the hardware's owner must be able to reclaim it, got {other:?}"),
    }
}

/// The qualified-name escape hatch, against **production-shaped** node ids.
///
/// `state.rs::node_id_for` namespaces node ids by org, so a real `BoardRef` is
/// `org=gh-1, node="gh-1/rpi-1", name="dk-3"` — four slash-separated segments,
/// not three. `seed_board` builds exactly that shape. Without a spelling that
/// works against it, a shared board is unreachable for `ctl release` /
/// `ctl power-cycle` the moment you own a same-named one, which is the failure
/// the own-org-wins tiering is only half a fix for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_qualified_name_reaches_a_shared_board_past_a_same_named_local_one() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, bob_org, _) = fleet.seed_github_user(2, "bob", Role::Member).await;

    // Both orgs have a board called `dk-3`. Bob owns one; alice shares hers.
    let alices = fleet
        .seed_board(&alice_org, "rpi-1", "dk-3", &["nrf52"])
        .await;
    let bobs = fleet
        .seed_board(&bob_org, "lab-pi", "dk-3", &["nrf52"])
        .await;
    // The shape this test exists to exercise.
    assert_eq!(alices.node.0, format!("{}/rpi-1", alice_org.0));

    let alice = fleet.client_session(&alice_token).await;
    let _ = alice
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Attach, AllowedOp::PowerCycle],
            expires: Some(soon(&fleet)),
        })
        .await
        .unwrap();

    let bob = fleet.client_session(&bob_token).await;

    // The bare name resolves to bob's *own* board: a shared board must never
    // shadow your own hardware.
    match bob
        .request(SidecarToCoord::PowerCycle {
            board: BoardName("dk-3".to_owned()),
        })
        .await
        .unwrap()
    {
        // No agent is connected, so this is as far as resolution gets — but the
        // message names the node, which is what proves *which* board won.
        CoordToSidecar::Error { message } => assert!(
            message.contains(&bobs.node.0),
            "the bare name must resolve to bob's own board, got {message:?}"
        ),
        other => panic!("expected the agent-not-connected error, got {other:?}"),
    }

    // Every qualified spelling reaches alice's board instead — including the
    // full `BoardRef` rendering a user copies out of `ctl list`.
    for spelling in [
        format!("rpi-1/{}", alices.name),             // node short name
        format!("{}/{}", alices.node.0, alices.name), // full node id
        format!("{}/{}/{}", alices.org.0, alices.node.0, alices.name), // Display
        alices.to_string(),
    ] {
        match bob
            .request(SidecarToCoord::PowerCycle {
                board: BoardName(spelling.clone()),
            })
            .await
            .unwrap()
        {
            CoordToSidecar::Error { message } => assert!(
                message.contains(&alices.node.0),
                "{spelling} should reach alice's board, got {message:?}"
            ),
            other => panic!("expected the agent-not-connected error, got {other:?}"),
        }
    }

    // A qualified name for a board bob may not reach is still just "not found".
    let (_carol, carol_org, _) = fleet.seed_github_user(3, "carol", Role::Admin).await;
    let carols = fleet.seed_board(&carol_org, "rpi-9", "dk-3", &[]).await;
    match bob
        .request(SidecarToCoord::PowerCycle {
            board: BoardName(carols.to_string()),
        })
        .await
        .unwrap()
    {
        CoordToSidecar::Error { message } => assert!(
            message.starts_with("no such board"),
            "an unreachable board must not be distinguishable, got {message:?}"
        ),
        other => panic!("expected no-such-board, got {other:?}"),
    }
}
