//! Board tags edited from the web UI (`PATCH /api/v1/nodes/{name}/boards/{board}`,
//! `DELETE …/tags`; `docs/web-ui.md` §3).
//!
//! The override lives in the coordinator and **replaces** the node's reported
//! tags. What matters, and is asserted here over the browser's carrier
//! (cookie + CSRF): owner-or-admin only, cross-org is a `404`, input is
//! validated, the change is audited, `GET /api/v1/boards` reports the
//! effective tags with their provenance, and a `tag=` lease matches them.

mod common;

use common::TestCoordinator;

use probefleet_coordinator::FleetRole;
use probefleet_proto::adopt::AdoptPolicy;

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
}

/// Call a route the way the UI does: session cookie + CSRF header.
async fn as_browser(
    fleet: &TestCoordinator,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> (u16, String) {
    let (cookie, csrf) = fleet.browser_session(token);
    let (status, _, body) = fleet
        .http_full(
            method,
            path,
            &[("cookie", &cookie), ("x-fleet-csrf", &csrf)],
            body.map(str::to_owned),
        )
        .await;
    (status, body)
}

const PATH: &str = "/api/v1/nodes/rpi-1/boards/dk-3?org=acme";
const RESET: &str = "/api/v1/nodes/rpi-1/boards/dk-3/tags?org=acme";

/// `acme` with admin alice, member bob, member carol owning `rpi-1`, which
/// hosts `dk-3` reporting `nrf52`.
async fn fixture() -> (TestCoordinator, String, String, String) {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;
    let carol = fleet.seed_session("acme", "carol", FleetRole::Member).await;
    fleet
        .seed_owned_node("acme", "rpi-1", "carol", AdoptPolicy::Declared)
        .await;
    let org = fleet.org("acme").await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    (fleet, alice, bob, carol)
}

async fn board_view(fleet: &TestCoordinator, token: &str) -> serde_json::Value {
    let (status, body) = as_browser(fleet, "GET", "/api/v1/boards?org=acme", token, None).await;
    assert_eq!(status, 200, "{body}");
    parse(&body)
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["board"]["name"] == "dk-3")
        .cloned()
        .expect("dk-3 listed")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owner_retags_a_board_and_everything_sees_it() {
    let (fleet, _alice, bob, carol) = fixture().await;

    // Before: reported tags, editable by the owner only.
    let v = board_view(&fleet, &carol).await;
    assert_eq!(v["tags"], serde_json::json!(["nrf52"]));
    assert_eq!(v["tags_overridden"], false);
    assert_eq!(v["tags_editable"], true);
    assert!(v["reported_tags"].is_null());
    assert_eq!(board_view(&fleet, &bob).await["tags_editable"], false);

    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        PATH,
        &carol,
        Some(r#"{"tags":["lab","desk"]}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let out = parse(&body);
    assert_eq!(out["tags"], serde_json::json!(["lab", "desk"]));
    assert_eq!(out["reported_tags"], serde_json::json!(["nrf52"]));
    assert_eq!(out["overridden"], true);

    let v = board_view(&fleet, &bob).await;
    assert_eq!(v["tags"], serde_json::json!(["lab", "desk"]));
    assert_eq!(v["tags_overridden"], true);
    assert_eq!(v["reported_tags"], serde_json::json!(["nrf52"]));

    let rows = fleet.audit_rows().await;
    assert!(rows.iter().any(|(_, _, a)| a == "board.tags"), "{rows:?}");

    // A `tag=` lease over the wire matches the edited tag.
    let session = fleet.client_session_in(&bob, "acme").await;
    {
        use probefleet_proto::lease::{Constraint, LeaseRequest, Priority};
        use probefleet_wire::{CoordToSidecar, SidecarToCoord};
        let reply = session
            .request(SidecarToCoord::Lease(LeaseRequest {
                select: Constraint::Tags(vec!["desk".to_owned()]),
                duration_secs: 600,
                priority: Priority::Interactive,
            }))
            .await
            .unwrap();
        match reply {
            CoordToSidecar::Lease(g) => assert_eq!(g.board.name, "dk-3"),
            other => panic!("expected a lease, got {other:?}"),
        }
    }

    // Reset restores the reported tags.
    let (status, body) = as_browser(&fleet, "DELETE", RESET, &carol, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["tags"], serde_json::json!(["nrf52"]));
    let v = board_view(&fleet, &carol).await;
    assert_eq!(v["tags"], serde_json::json!(["nrf52"]));
    assert_eq!(v["tags_overridden"], false);
    let rows = fleet.audit_rows().await;
    assert!(
        rows.iter().any(|(_, _, a)| a == "board.tags.reset"),
        "{rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_owner_member_is_refused_and_an_admin_is_not() {
    let (fleet, alice, bob, _carol) = fixture().await;
    let (status, body) =
        as_browser(&fleet, "PATCH", PATH, &bob, Some(r#"{"tags":["mine"]}"#)).await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = as_browser(&fleet, "DELETE", RESET, &bob, None).await;
    assert_eq!(status, 403, "{body}");
    let rows = fleet.audit_rows().await;
    assert!(
        rows.iter().any(|(_, _, a)| a == "board.tags.denied"),
        "{rows:?}"
    );
    assert_eq!(
        board_view(&fleet, &bob).await["tags"],
        serde_json::json!(["nrf52"])
    );

    // The admin may, and sees the control.
    assert_eq!(board_view(&fleet, &alice).await["tags_editable"], true);
    let (status, body) = as_browser(&fleet, "PATCH", PATH, &alice, Some(r#"{"tags":["x"]}"#)).await;
    assert_eq!(status, 200, "{body}");
}

/// A node with no owner (auth-key enrolled) is admin-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ownerless_node_is_admin_only() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;
    fleet.seed_node("acme", "rpi-1").await;
    let org = fleet.org("acme").await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    let (status, body) = as_browser(&fleet, "PATCH", PATH, &bob, Some(r#"{"tags":["x"]}"#)).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(board_view(&fleet, &bob).await["tags_editable"], false);
    let (status, body) = as_browser(&fleet, "PATCH", PATH, &alice, Some(r#"{"tags":["x"]}"#)).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_and_cross_org_boards_are_404_and_bad_input_is_400() {
    let (fleet, alice, _bob, _carol) = fixture().await;
    let other = fleet.org("other").await;
    fleet.seed_board(&other, "rpi-9", "secret", &["x"]).await;

    for path in [
        "/api/v1/nodes/rpi-1/boards/nope?org=acme",
        "/api/v1/nodes/nope/boards/dk-3?org=acme",
        "/api/v1/nodes/rpi-9/boards/secret?org=acme",
    ] {
        let (status, body) =
            as_browser(&fleet, "PATCH", path, &alice, Some(r#"{"tags":["x"]}"#)).await;
        assert_eq!(status, 404, "{path}: {body}");
    }
    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        "/api/v1/nodes/rpi-1/boards/nope/tags?org=acme",
        &alice,
        None,
    )
    .await;
    assert_eq!(status, 404, "{body}");

    for bad in [
        r#"{"tags":["<img src=x>"]}"#,
        r#"{"tags":["ok"],"name":"x"}"#,
        r"{}",
        "not json",
    ] {
        let (status, body) = as_browser(&fleet, "PATCH", PATH, &alice, Some(bad)).await;
        assert_eq!(status, 400, "{bad}: {body}");
    }

    // No CSRF header: refused.
    let (cookie, _) = fleet.browser_session(&alice);
    let (status, _, body) = fleet
        .http_full(
            "PATCH",
            PATH,
            &[("cookie", &cookie)],
            Some(r#"{"tags":[]}"#.to_owned()),
        )
        .await;
    assert_eq!(status, 403, "{body}");
}
