//! Moving a node (and its boards) to another org over `/api/v1`:
//! `POST /api/v1/nodes/{name}/move`.
//!
//! The route's status codes and CSRF gate, plus the property that makes the
//! move usable at all: the node's **existing token** still authenticates
//! after the move, the agent reconnects announcing its pre-move id, and its
//! inventory lands in the target org's scheduler.

mod common;

use common::TestCoordinator;

use probefleet_coordinator::FleetRole;
use probefleet_proto::adopt::AdoptPolicy;
use probefleet_proto::board::PowerKind;
use probefleet_proto::ids::BoardName;
use probefleet_proto::node_api::{BoardPresence, BoardStatus, NodeReport, ProbeInventory};
use probefleet_wire::{NodeToCoord, WireEvent, WireRx as _};

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
}

async fn as_browser(
    fleet: &TestCoordinator,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> (u16, String) {
    let (cookie, csrf) = fleet.browser_session(token);
    let (status, _, body) = fleet
        .http_full(
            "POST",
            path,
            &[("cookie", &cookie), ("x-fleet-csrf", &csrf)],
            Some(body.to_string()),
        )
        .await;
    (status, body)
}

fn inventory(board: &str) -> NodeReport {
    NodeReport::Inventory(ProbeInventory {
        boards: vec![BoardStatus {
            board: BoardName(board.to_owned()),
            serial: "0001".to_owned(),
            presence: BoardPresence::Online,
            chip: "nRF52840_xxAA".to_owned(),
            model: None,
            tags: vec!["nrf52".to_owned()],
            exclusive: true,
            power: PowerKind::None,
            adopted: false,
            serial_ports: Vec::new(),
        }],
        unknown: Vec::new(),
    })
}

/// Status codes: 200 with the new id and org names; 403 for a non-admin of
/// the source and for an unknown / foreign target (the same answer); 400 for
/// the same org; 404 for no such node; 409 `node_name_taken`; 409
/// `node_leased` without `force`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // one scenario, each refusal in turn
async fn the_move_route_answers_each_refusal_distinctly() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    fleet.member("beta", "alice", FleetRole::Member).await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;
    fleet.member("beta", "bob", FleetRole::Admin).await;
    fleet.org("gamma").await;
    let acme = fleet.org("acme").await;
    let beta = fleet.org("beta").await;
    fleet
        .seed_owned_node("acme", "rpi-1", "alice", AdoptPolicy::Declared)
        .await;
    fleet.seed_board(&acme, "rpi-1", "dk-3", &["nrf52"]).await;
    fleet.seed_node("acme", "dup").await;
    fleet.seed_node("beta", "dup").await;
    let path = "/api/v1/nodes/rpi-1/move?org=acme";

    // Unauthenticated, and a cookie with no CSRF header.
    let (status, _) = fleet
        .http("POST", path, Some(r#"{"to_org":"beta"}"#.into()))
        .await;
    assert_eq!(status, 401);
    let (cookie, _) = fleet.browser_session(&alice);
    let (status, _, _) = fleet
        .http_full(
            "POST",
            path,
            &[("cookie", &cookie)],
            Some(r#"{"to_org":"beta"}"#.into()),
        )
        .await;
    assert_eq!(status, 403, "CSRF required");

    let to = |org: &str| serde_json::json!({ "to_org": org });
    // bob is a member, not an admin, of the source.
    let (status, body) = as_browser(&fleet, path, &bob, &to("beta")).await;
    assert_eq!(status, 403, "{body}");
    assert!(fleet
        .audit_rows()
        .await
        .iter()
        .any(|(o, _, a)| o == &acme.0 && a == "node.move.denied"));
    // Unknown and foreign targets look the same.
    for target in ["gamma", "no-such-org"] {
        let (status, body) = as_browser(&fleet, path, &alice, &to(target)).await;
        assert_eq!(status, 403, "{target}: {body}");
        assert!(body.contains("forbidden"), "{body}");
    }
    let (status, _) = as_browser(&fleet, path, &alice, &to("acme")).await;
    assert_eq!(status, 400);
    let (status, _) = as_browser(
        &fleet,
        "/api/v1/nodes/ghost/move?org=acme",
        &alice,
        &to("beta"),
    )
    .await;
    assert_eq!(status, 404);
    let (status, body) = as_browser(
        &fleet,
        "/api/v1/nodes/dup/move?org=acme",
        &alice,
        &to("beta"),
    )
    .await;
    assert_eq!(status, 409);
    assert!(body.contains("node_name_taken"), "{body}");
    let (status, _) = as_browser(&fleet, path, &alice, &serde_json::json!({"x": 1})).await;
    assert_eq!(status, 400, "unknown fields are refused");

    // A leased board refuses the move unless forced.
    let session = fleet.client_session_in(&alice, "acme").await;
    let lease = match session
        .request(probefleet_wire::SidecarToCoord::Lease(
            probefleet_proto::lease::LeaseRequest {
                select: probefleet_proto::lease::Constraint::Id(BoardName("dk-3".to_owned())),
                duration_secs: 600,
                priority: probefleet_proto::lease::Priority::Interactive,
            },
        ))
        .await
        .unwrap()
    {
        probefleet_wire::CoordToSidecar::Lease(g) => g.lease,
        other => panic!("expected a lease, got {other:?}"),
    };
    let (status, body) = as_browser(&fleet, path, &alice, &to("beta")).await;
    assert_eq!(status, 409, "{body}");
    let v = parse(&body);
    assert_eq!(v["error"], "node_leased");
    assert_eq!(v["leased"], 1);

    let (status, body) = as_browser(
        &fleet,
        path,
        &alice,
        &serde_json::json!({ "to_org": beta.0, "force": true }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let v = parse(&body);
    assert_eq!(v["node"]["id"], format!("{}/rpi-1", beta.0));
    assert_eq!(v["node"]["boards"], serde_json::json!(["dk-3"]));
    assert_eq!(v["old_id"], format!("{}/rpi-1", acme.0));
    assert_eq!(v["from_org"]["name"], "acme");
    assert_eq!(v["to_org"]["name"], "beta");
    assert_eq!(v["revoked_leases"], 1);
    assert!(fleet
        .coord
        .scheduler()
        .lock()
        .await
        .lease_holder(lease)
        .is_none());

    let rows = fleet.audit_rows().await;
    assert!(rows
        .iter()
        .any(|(o, _, a)| o == &acme.0 && a == "node.move.out"));
    assert!(rows
        .iter()
        .any(|(o, _, a)| o == &beta.0 && a == "node.move.in"));
}

/// The node keeps working through a move: its connection is closed, it
/// reconnects with the **same token** while still announcing its old id,
/// and its re-reported inventory lands in the target org's scheduler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_moved_node_reconnects_with_its_token_and_lands_in_the_target_org() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    fleet.member("beta", "alice", FleetRole::Member).await;
    let beta = fleet.org("beta").await;
    let (token, old_id) = fleet
        .seed_owned_node("acme", "rpi-1", "alice", AdoptPolicy::Declared)
        .await;

    let (mut tx, mut rx) = fleet.dial("/agent", &token).await.unwrap();
    probefleet_wire::send(
        &mut tx,
        &NodeToCoord::Report(NodeReport::Register {
            node: old_id.clone(),
            protocol_version: probefleet_proto::PROTOCOL_VERSION,
        }),
    )
    .await
    .unwrap();
    probefleet_wire::send(&mut tx, &NodeToCoord::Report(inventory("dk-3")))
        .await
        .unwrap();
    // Wait until the inventory is in the scheduler under the old org.
    loop {
        if fleet
            .coord
            .scheduler()
            .lock()
            .await
            .boards()
            .any(|b| b.node == old_id)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let (status, body) = as_browser(
        &fleet,
        "/api/v1/nodes/rpi-1/move?org=acme",
        &alice,
        &serde_json::json!({ "to_org": "beta" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // The old connection is closed.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Ok(WireEvent::Closed) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the moved node's connection stayed open");
    drop(tx);

    // Reconnect with the same token, still announcing the pre-move id.
    let new_id = probefleet_coordinator::node_id_for(&beta, "rpi-1");
    let (mut tx, _rx) = fleet.dial("/agent", &token).await.unwrap();
    probefleet_wire::send(
        &mut tx,
        &NodeToCoord::Report(NodeReport::Register {
            node: old_id.clone(),
            protocol_version: probefleet_proto::PROTOCOL_VERSION,
        }),
    )
    .await
    .unwrap();
    probefleet_wire::send(&mut tx, &NodeToCoord::Report(inventory("dk-3")))
        .await
        .unwrap();
    let landed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let found = fleet
                .coord
                .scheduler()
                .lock()
                .await
                .boards()
                .any(|b| b.node == new_id && b.id.org == beta && b.id.name == "dk-3");
            if found {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(landed.is_ok(), "the re-reported board never reached beta");
    assert!(fleet.coord.nodes().get(&new_id).await.is_some());
    assert!(!fleet
        .coord
        .scheduler()
        .lock()
        .await
        .boards()
        .any(|b| b.node == old_id));
}
