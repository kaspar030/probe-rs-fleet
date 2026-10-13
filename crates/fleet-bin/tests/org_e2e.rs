//! `probe-rs-fleet org {create,list,members,rename,delete}` end to end, through the CLI's
//! own code paths.
//!
//! A user who has only run `probe-rs-fleet login` — no shell on the
//! coordinator host — creates a team org, adds a teammate, promotes them,
//! and removes them again. Modelled on `auth_key_e2e.rs`: `login --token`
//! stands in for the device flow, the role functions are driven directly,
//! and every session is minted fresh (far from the refresh window, so nothing
//! is written outside the tempdir).

mod common;

use common::{start_fleet, Fleet};
use fleet_bin::cli::{
    LoginArgs, OrgCliCreateArgs, OrgDeleteArgs, OrgMembersArgs, OrgRenameArgs, OrgSessionArgs,
    RoleArg,
};
use fleet_coordinator::FleetRole;

const SEED: [u8; 32] = [31u8; 32];

/// `login --token` into `config_dir` as `name`, acting in `org` by default.
async fn login(fleet: &Fleet, config_dir: &std::path::Path, name: &str, org: Option<&str>) {
    let user = fleet.user(name).await;
    let token = forgs_http::session::mint_session(fleet.coord.auth(), user, "test")
        .await
        .unwrap()
        .token;
    fleet_bin::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(token),
        refresh_token: None,
        no_browser: true,
        org: org.map(ToOwned::to_owned),
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    })
    .await
    .expect("login --token");
}

fn session(config_dir: &std::path::Path) -> OrgSessionArgs {
    OrgSessionArgs {
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    }
}

fn members_args(config_dir: &std::path::Path, org: Option<&str>) -> OrgMembersArgs {
    OrgMembersArgs {
        command: None,
        org: org.map(ToOwned::to_owned),
        session: session(config_dir),
    }
}

fn create_args(config_dir: &std::path::Path, name: &str) -> OrgCliCreateArgs {
    OrgCliCreateArgs {
        name: name.to_owned(),
        session: session(config_dir),
    }
}

async fn roster(config_dir: &std::path::Path, org: &str) -> Vec<(String, String)> {
    let list = fleet_bin::roles::org::members(&members_args(config_dir, Some(org)))
        .await
        .expect("org members");
    let mut out: Vec<_> = list
        .members
        .into_iter()
        .map(|m| (m.username.unwrap_or_default(), m.role))
        .collect();
    out.sort();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_logged_in_user_creates_an_org_and_manages_its_members() {
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    login(&fleet, &alice, "alice", None).await;
    login(&fleet, &bob, "bob", None).await;

    let created = fleet_bin::roles::org::create(&create_args(&alice, "acme"))
        .await
        .expect("org create");
    assert_eq!(created.name.as_deref(), Some("acme"));
    assert_eq!(created.role, "admin");
    assert_eq!(fleet.org("acme").await.0, created.id);

    // `org list` shows it, as admin, beside the personal org.
    let (orgs, acting) = fleet_bin::roles::org::list(&session(&alice))
        .await
        .expect("org list");
    assert!(
        orgs.iter()
            .any(|m| m.name.as_deref() == Some("acme") && m.role == "admin" && m.id == created.id),
        "{orgs:?}"
    );
    assert!(
        orgs.iter().any(|m| m.name.as_deref() == Some("alice")),
        "{orgs:?}"
    );
    // `login --token` records no username, so no default org is known.
    assert!(
        matches!(acting.as_deref(), None | Some("alice")),
        "{acting:?}"
    );

    // Add bob as a member (the default role).
    let alice_acme = members_args(&alice, Some("acme"));
    let org = fleet_bin::roles::org::add_member(&alice_acme, "bob", RoleArg::Member)
        .await
        .expect("members add");
    assert_eq!(org, "acme");
    assert_eq!(
        roster(&bob, "acme").await,
        vec![
            ("alice".into(), "admin".into()),
            ("bob".into(), "member".into())
        ]
    );

    // bob, a mere member, is refused with an explanation.
    let bob_acme = members_args(&bob, Some("acme"));
    let err = fleet_bin::roles::org::remove_member(&bob_acme, "alice")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not an admin"), "{err}");

    // The last admin cannot demote themselves …
    let err = fleet_bin::roles::org::set_role(&alice_acme, "alice", RoleArg::Member)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no admin"), "{err}");

    // … but can once bob is an admin too.
    fleet_bin::roles::org::set_role(&alice_acme, "bob", RoleArg::Admin)
        .await
        .expect("set-role admin");
    fleet_bin::roles::org::set_role(&alice_acme, "alice", RoleArg::Member)
        .await
        .expect("demote alice");
    assert_eq!(
        roster(&bob, "acme").await,
        vec![
            ("alice".into(), "member".into()),
            ("bob".into(), "admin".into())
        ]
    );

    // bob removes alice; she is no longer a member.
    fleet_bin::roles::org::remove_member(&bob_acme, "alice")
        .await
        .expect("members remove");
    assert_eq!(
        roster(&bob, "acme").await,
        vec![("bob".into(), "admin".into())]
    );
    let alice_id = fleet.user("alice").await;
    assert_eq!(
        fleet
            .coord
            .db()
            .role_of(&fleet.org("acme").await, alice_id)
            .await
            .unwrap(),
        None
    );
    assert!(fleet_bin::roles::org::members(&alice_acme).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn names_collide_and_unknown_users_are_named() {
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    login(&fleet, &alice, "alice", None).await;
    fleet.user("bob").await;

    // A username, and the default org, are taken.
    for taken in ["bob", common::DEFAULT_ORG] {
        let err = fleet_bin::roles::org::create(&create_args(&alice, taken))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("existing org or user"), "{taken}: {err}");
    }
    let err = fleet_bin::roles::org::create(&create_args(&alice, "Acme"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("lowercase"), "{err}");

    fleet_bin::roles::org::create(&create_args(&alice, "acme"))
        .await
        .unwrap();
    let err = fleet_bin::roles::org::add_member(
        &members_args(&alice, Some("acme")),
        "nobody",
        RoleArg::Member,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("log in"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn members_defaults_to_the_fleet_files_org() {
    let fleet = start_fleet(SEED).await;
    fleet
        .member("carol", common::DEFAULT_ORG, FleetRole::Member)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let carol = tmp.path().join("carol");
    login(&fleet, &carol, "carol", Some(common::DEFAULT_ORG)).await;
    let list = fleet_bin::roles::org::members(&members_args(&carol, None))
        .await
        .unwrap();
    assert_eq!(list.namespace, fleet.default_org().await.0);
    // A member of `default` but not its admin: no mutation.
    assert!(fleet_bin::roles::org::add_member(
        &members_args(&carol, None),
        "carol",
        RoleArg::Admin
    )
    .await
    .is_err());
}

fn rename_args(config_dir: &std::path::Path, org: Option<&str>, new_name: &str) -> OrgRenameArgs {
    OrgRenameArgs {
        new_name: new_name.to_owned(),
        org: org.map(ToOwned::to_owned),
        session: session(config_dir),
    }
}

fn delete_args(config_dir: &std::path::Path, org: Option<&str>) -> OrgDeleteArgs {
    OrgDeleteArgs {
        yes: true,
        org: org.map(ToOwned::to_owned),
        session: session(config_dir),
    }
}

/// The fleet file's `[user].org`.
fn default_org(config_dir: &std::path::Path) -> Option<String> {
    let path = config_dir.join("default.toml");
    let text = std::fs::read_to_string(path).unwrap();
    let value: toml::Value = toml::from_str(&text).unwrap();
    value
        .get("user")
        .and_then(|u| u.get("org"))
        .and_then(|o| o.as_str())
        .map(ToOwned::to_owned)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admins_rename_and_delete_team_orgs() {
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    login(&fleet, &alice, "alice", None).await;
    fleet_bin::roles::org::create(&create_args(&alice, "acme"))
        .await
        .expect("org create");
    // Re-login acting in acme, so the fleet file's default follows.
    login(&fleet, &alice, "alice", Some("acme")).await;
    login(&fleet, &bob, "bob", None).await;
    fleet_bin::roles::org::add_member(&members_args(&alice, Some("acme")), "bob", RoleArg::Member)
        .await
        .expect("members add");

    // A member may not rename.
    let err = fleet_bin::roles::org::rename(&rename_args(&bob, Some("acme"), "acme2"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not an admin"), "{err}");

    // The admin renames the default org; the fleet file follows.
    assert_eq!(default_org(&alice).as_deref(), Some("acme"));
    let (old, renamed) = fleet_bin::roles::org::rename(&rename_args(&alice, None, "acme2"))
        .await
        .expect("org rename");
    assert_eq!(old, "acme");
    assert_eq!(renamed.name.as_deref(), Some("acme2"));
    assert_eq!(default_org(&alice).as_deref(), Some("acme2"));
    assert_eq!(fleet.org("acme2").await.0, renamed.id);

    // A personal org is refused, with why.
    let err = fleet_bin::roles::org::delete(&delete_args(&alice, Some("alice")))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("personal org"), "{err}");

    // An org with a node is refused, with what to do.
    let org = fleet.org("acme2").await;
    fleet
        .coord
        .register_node_and_mint(
            &org,
            "rpi-1",
            &[],
            None,
            fleet_proto::AdoptPolicy::Declared,
            "node.enroll",
            "test fixture",
        )
        .await
        .unwrap();
    let err = fleet_bin::roles::org::delete(&delete_args(&alice, None))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Remove its nodes"), "{err}");
    assert!(fleet
        .coord
        .db()
        .scoped(org.clone())
        .delete_node("rpi-1")
        .await
        .unwrap());

    // Empty: deleted, and the fleet file's default cleared.
    let name = fleet_bin::roles::org::delete(&delete_args(&alice, None))
        .await
        .expect("org delete");
    assert_eq!(name, "acme2");
    assert!(fleet
        .coord
        .db()
        .resolve_org("acme2")
        .await
        .unwrap()
        .is_none());
    assert_eq!(default_org(&alice), None);
}
