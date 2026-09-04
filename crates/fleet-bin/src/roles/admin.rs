//! Interim admin verbs: `coordinator auth-key` and `coordinator user-token`.
//!
//! Both mint a credential directly from a shell on the coordinator host,
//! bypassing the login flow. Now that `probe-rs-fleet login` and
//! `probe-rs-fleet share` exist they are the **unattended / air-gapped escape
//! hatch**, not the front door.
//!
//! `auth-key` is joined here by `auth-keys` (list) and `auth-key-revoke`.
//! Those are not conveniences: auth keys are the weak link in the credential
//! model — long-lived bearer secrets that end up in strangers' CI config and
//! disk images — and "revocable" is only true in practice if an operator can
//! first find out which keys exist.
//!
//! # `user-token` and `login` mint different identities
//!
//! Worth knowing before mixing them. `login` keys a user off the immutable
//! GitHub numeric id (`user.id = "gh-<id>"`, see `Db::upsert_github_user`);
//! `user-token` has no GitHub identity to work from and keys off the login
//! string it was handed (`user.id = "alice"`). So `coordinator user-token alice`
//! and alice's own `login` are **two distinct subjects for one human**: a lease
//! held under one cannot be extended or released by the other, because
//! `authz::require_lease_control` keys off `SubjectKey`.
//!
//! That is tolerable for an interim admin verb — but it is the kind of thing
//! that gets filed as a bug by whoever hits it first, so it is written down
//! here rather than discovered.
//!
//! Both open the coordinator's database directly rather than talking to a
//! running coordinator: the operator running them already has a shell on the
//! host and therefore total authority, and requiring the daemon to be up to mint
//! the first credential would be a bootstrap cycle.

use anyhow::{Context, Result};
use tracing::warn;

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_coordinator::state::Db;
use fleet_proto::ids::{OrgId, Role};

use crate::cli::{AuthKeyArgs, UserTokenArgs};
use crate::paths;

/// Open the coordinator's database from its config file.
async fn open_db(config_dir: Option<std::path::PathBuf>) -> Result<(Db, OrgId, u64)> {
    let config_dir = match config_dir {
        Some(dir) => dir,
        None => paths::coordinator_config_dir()?,
    };
    let config_path = config_dir.join("coordinator.toml");
    let config = crate::config::load_coordinator_config(&config_path)
        .with_context(|| format!("loading coordinator config {}", config_path.display()))?;
    let sqlite = config
        .sqlite_path
        .to_str()
        .context("sqlite_path is not UTF-8")?
        .to_owned();
    let db = Db::connect(&sqlite)
        .await
        .with_context(|| format!("opening coordinator database {sqlite}"))?;
    Ok((db, config.default_org.clone(), config.session_ttl_secs))
}

/// Current time in epoch seconds.
fn now() -> i64 {
    i64::try_from(fleet_coordinator::now_epoch_secs()).unwrap_or(i64::MAX)
}

/// The `org.kind` to create an org with, given whether the operator named it.
///
/// A personal org is an org-of-one, created implicitly for a user. An org the
/// operator named on the command line is by definition not that, so creating it
/// as `personal` would be a lie the schema then carries forever — `kind` is only
/// consulted at creation (`ON CONFLICT DO NOTHING`), so nothing later corrects
/// it.
///
/// Personal orgs are now created by `login` (keyed off the GitHub numeric id),
/// so what these verbs create is normally a **team** org; the `personal`
/// fallback only applies to the unnamed default org, which is the bootstrap
/// org every deployment starts with. A team org still ought to be created by an
/// explicit `coordinator org create` rather than as a side effect of minting a
/// credential for it — that is a UX gap, not a correctness one.
fn org_kind(explicit: bool) -> &'static str {
    if explicit {
        "team"
    } else {
        "personal"
    }
}

/// Run `coordinator auth-key`: mint an org-scoped node-enrollment key.
///
/// # Errors
///
/// Returns an error if the config or database cannot be opened, or the write
/// fails.
pub async fn auth_key(args: AuthKeyArgs) -> Result<()> {
    warn!(
        "`coordinator auth-key` mints a node-enrollment credential from a shell \
         on this host. It is the unattended / air-gapped escape hatch, not the \
         normal path: a machine with a login uses `probe-rs-fleet share`."
    );

    let (db, default_org, _) = open_db(args.config_dir).await?;
    let explicit_org = args.org.is_some();
    let org = args.org.map_or(default_org, OrgId);
    db.ensure_org(&org, org_kind(explicit_org))
        .await
        .context("ensuring the org exists")?;

    let now = now();
    let expires = if args.ttl == 0 {
        None
    } else {
        Some(now.saturating_add(i64::try_from(args.ttl).unwrap_or(i64::MAX)))
    };
    let token = OpaqueToken::mint(TokenKind::AuthKey);
    db.insert_auth_key(
        &org,
        token.hash().as_str(),
        &args.tag,
        !args.multi_use,
        expires,
        None,
        now,
    )
    .await
    .context("recording the auth key")?;

    println!("Auth key for org '{org}':");
    println!();
    // The one place the secret is printed: it is not stored anywhere, only its
    // SHA-256, so this output is the only chance to capture it.
    println!("  {}", token.to_secret_string());
    println!();
    println!("  single use : {}", !args.multi_use);
    match expires {
        Some(e) => println!("  expires    : {e} (epoch seconds)"),
        None => println!("  expires    : never"),
    }
    if !args.tag.is_empty() {
        println!("  tags       : {}", args.tag.join(", "));
    }
    println!();
    println!("Enroll a node with it:");
    println!("  probe-rs-fleet agent up --fleet-url <url> --auth-key <key>");
    println!();
    println!("This key is a bearer credential and is not stored anywhere (only its");
    println!("hash). Copy it now; anyone holding it can enroll a node into this org.");
    Ok(())
}

/// Run `coordinator auth-keys`: list the org's outstanding auth keys.
///
/// The secret was never stored — only its SHA-256 — so a listing is safe to
/// print and pipe, and the hash prefix is the handle `auth-key-revoke` takes.
/// Without this an operator has no way to find out what keys exist, which is
/// what makes "revocable" true in practice rather than only in principle.
///
/// # Errors
///
/// Returns an error if the config or database cannot be opened.
pub async fn auth_keys(args: crate::cli::AuthKeysArgs) -> Result<()> {
    let (db, default_org, _) = open_db(args.config_dir).await?;
    let org = args.org.map_or(default_org, OrgId);
    let keys = db
        .list_auth_keys(&org)
        .await
        .context("listing the org's auth keys")?;

    if keys.is_empty() {
        println!("No auth keys for org '{org}'.");
        return Ok(());
    }

    let now = now();
    println!("Auth keys for org '{org}' ({} total):", keys.len());
    println!();
    println!(
        "  {:<16}  {:<10}  {:<12}  {:<12}  TAGS",
        "HASH PREFIX", "SINGLE-USE", "EXPIRES", "STATE"
    );
    for key in &keys {
        let prefix: String = key.key_hash.chars().take(16).collect();
        let expires = match key.expires {
            None => "never".to_owned(),
            Some(e) => e.to_string(),
        };
        let state = if key.consumed_at.is_some() {
            "consumed"
        } else if key.expires.is_some_and(|e| e <= now) {
            "expired"
        } else {
            "live"
        };
        println!(
            "  {prefix:<16}  {:<10}  {expires:<12}  {state:<12}  {}",
            key.single_use,
            key.tags.join(",")
        );
    }
    println!();
    println!("Revoke one with:");
    println!("  probe-rs-fleet coordinator auth-key-revoke <hash-prefix> --org {org}");
    Ok(())
}

/// Run `coordinator auth-key-revoke`: delete an auth key by hash prefix.
///
/// An **ambiguous** prefix is refused rather than resolved to the first match:
/// a rack provisioned from one image shares nothing, but a rack provisioned
/// from several might, and revoking the wrong one silently de-provisions
/// machines nobody is looking at.
///
/// # Errors
///
/// Returns an error if the config or database cannot be opened, the prefix
/// matches nothing, or it matches more than one key.
pub async fn auth_key_revoke(args: crate::cli::AuthKeyRevokeArgs) -> Result<()> {
    let (db, default_org, _) = open_db(args.config_dir).await?;
    let org = args.org.map_or(default_org, OrgId);
    let prefix = args.prefix.trim().to_ascii_lowercase();
    anyhow::ensure!(!prefix.is_empty(), "a hash prefix is required");

    // Resolve before deleting, so an ambiguous prefix can be refused with the
    // candidates named rather than after the fact.
    let keys = db
        .list_auth_keys(&org)
        .await
        .context("listing the org's auth keys")?;
    let matches: Vec<_> = keys
        .iter()
        .filter(|k| k.key_hash.starts_with(&prefix))
        .collect();
    match matches.len() {
        0 => anyhow::bail!("no auth key in org '{org}' has a hash starting with {prefix:?}"),
        1 => {}
        n => {
            let candidates: Vec<String> = matches
                .iter()
                .map(|k| k.key_hash.chars().take(16).collect())
                .collect();
            anyhow::bail!(
                "{prefix:?} matches {n} auth keys in org '{org}'; be more specific:\n  {}",
                candidates.join("\n  ")
            );
        }
    }

    let deleted = db
        .delete_auth_keys_by_prefix(&org, &prefix)
        .await
        .context("revoking the auth key")?;
    for hash in &deleted {
        println!("Revoked auth key {hash} (org '{org}').");
    }
    println!();
    println!("Nodes already enrolled with it keep working: their node tokens are");
    println!("separate credentials. Revoke a node by deleting its row.");
    Ok(())
}

/// Run `coordinator user-token`: provision a user and mint a session token.
///
/// The whole chain is provisioned in order — org, user, member, session —
/// because a session token without a `member` row authenticates fine and then
/// fails *every* authorization check: `authz::require_role` consults membership,
/// so `ctl list` would fail closed on a perfectly valid token. The foreign keys
/// (`user.personal_org_id`, `session.user_id`) make the order load-bearing
/// rather than merely tidy.
///
/// # Errors
///
/// Returns an error if the config or database cannot be opened, or a write
/// fails.
pub async fn user_token(args: UserTokenArgs) -> Result<()> {
    warn!(
        "`coordinator user-token` is an INTERIM verb: it mints a session token \
         from a shell on this host, bypassing any login flow. It should not \
         become the way people log in — `probe-rs-fleet login` (GitHub device \
         flow) is."
    );

    let (db, default_org, default_ttl) = open_db(args.config_dir).await?;
    let explicit_org = args.org.is_some();
    let org = args.org.map_or(default_org, OrgId);
    let role: Role = args.role.into();
    let ttl = args.ttl.unwrap_or(default_ttl);

    let now = now();
    let expires = now.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX));

    db.ensure_org(&org, org_kind(explicit_org))
        .await
        .context("ensuring the org exists")?;
    db.ensure_user_member(&org, &args.login, role)
        .await
        .context("provisioning the user and its membership")?;

    let token = OpaqueToken::mint(TokenKind::Session);
    db.insert_session(token.hash().as_str(), &org, &args.login, now, expires)
        .await
        .context("recording the session")?;

    println!("Session token for '{}' in org '{org}' ({role}):", args.login);
    println!();
    println!("  {}", token.to_secret_string());
    println!();
    println!("  expires: {expires} (epoch seconds)");
    println!();
    println!("Point `ctl` and the probe-rs shim at the fleet with it:");
    println!("  probe-rs-fleet login --fleet-url <url> --token <token>");
    println!();
    println!("This token is a bearer credential and is not stored anywhere (only its");
    println!("hash). Copy it now.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_coordinator::state::DEFAULT_ORG_ID;

    /// The membership provisioning that makes a session token *useful*: without
    /// the `member` row, `authz::require_role` denies everything and `ctl list`
    /// fails closed on a valid token.
    #[tokio::test]
    async fn user_token_provisions_org_user_member_and_session() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());

        db.ensure_user_member(&org, "alice", Role::Admin)
            .await
            .unwrap();
        let token = OpaqueToken::mint(TokenKind::Session);
        db.insert_session(token.hash().as_str(), &org, "alice", 1_000, 2_000)
            .await
            .unwrap();

        assert_eq!(db.role_of(&org, "alice").await.unwrap(), Some(Role::Admin));
        let session = db
            .session_by_token_hash(token.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.0, "alice");
        assert_eq!(session.1, org);
    }

    /// `--role member` is honoured, so the admin default is a choice rather
    /// than the only option.
    #[tokio::test]
    async fn member_role_is_expressible() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = OrgId("acme".to_owned());
        db.ensure_org(&org, "team").await.unwrap();
        db.ensure_user_member(&org, "bob", Role::Member)
            .await
            .unwrap();
        assert_eq!(db.role_of(&org, "bob").await.unwrap(), Some(Role::Member));
    }

    #[tokio::test]
    async fn auth_key_is_recorded_by_hash_and_consumable_once() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        let key = OpaqueToken::mint(TokenKind::AuthKey);
        db.insert_auth_key(
            &org,
            key.hash().as_str(),
            &["nrf52".to_owned()],
            true,
            Some(9_000),
            None,
            1_000,
        )
        .await
        .unwrap();

        assert_eq!(
            db.consume_auth_key(key.hash().as_str(), 1_500)
                .await
                .unwrap(),
            Some((org, vec!["nrf52".to_owned()]))
        );
        assert!(db
            .consume_auth_key(key.hash().as_str(), 1_600)
            .await
            .unwrap()
            .is_none());
    }

    /// An org the operator named is not an org-of-one. `kind` is only consulted
    /// at creation, so getting it wrong here is permanent.
    #[test]
    fn an_explicitly_named_org_is_created_as_a_team() {
        assert_eq!(org_kind(true), "team");
        assert_eq!(org_kind(false), "personal");
    }

    /// `ensure_org` is idempotent, so the kind chosen at creation is the one
    /// that sticks — which is exactly why the choice above matters.
    #[tokio::test]
    async fn ensure_org_does_not_revise_an_existing_kind() {
        let db = Db::connect_in_memory().await.unwrap();
        let acme = OrgId("acme".to_owned());

        db.ensure_org(&acme, org_kind(true)).await.unwrap();
        // A later call with a different kind must not silently reclassify it.
        db.ensure_org(&acme, "personal").await.unwrap();

        // Observable through the API surface this crate has: the org exists and
        // membership in it behaves normally.
        db.ensure_user_member(&acme, "alice", Role::Admin)
            .await
            .unwrap();
        assert_eq!(db.role_of(&acme, "alice").await.unwrap(), Some(Role::Admin));
    }
}
