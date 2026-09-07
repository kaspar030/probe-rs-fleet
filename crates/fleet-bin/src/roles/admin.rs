//! Interim admin verbs: `coordinator auth-key` and `coordinator user-token`.
//!
//! Both mint a credential directly from a shell on the coordinator host,
//! bypassing the login flow. Now that `probe-rs-fleet login` and
//! `probe-rs-fleet share` exist they are the **unattended / air-gapped escape
//! hatch**, not the front door.
//!
//! Since `probe-rs-fleet auth-key create` landed, that is true of the auth-key
//! verbs too: a member with a login mints over the authenticated API, needing
//! no shell here. These stay for the self-hosted operator, for the air-gapped
//! case, and for the one thing the API refuses — a key that never expires,
//! including a never-expiring `--purpose ci` key, which no other path can mint.
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
use fleet_coordinator::state::{Db, AUTH_KEY_PURPOSE_CI, AUTH_KEY_PURPOSE_NODE};
use fleet_proto::ids::{OrgId, Role};

use crate::cli::{AuthKeyArgs, UserTokenArgs};
use crate::paths;
use crate::roles::auth_key::{identity_epilogue, normalise_identity_name, PURPOSE_AGENT_ALIAS};

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
         on this host. It is the self-hosted / air-gapped escape hatch, not the \
         normal path: a member with a login runs `probe-rs-fleet auth-key \
         create`, and a machine with a login runs `probe-rs-fleet share`."
    );

    // Everything that can be judged from the arguments alone is judged *before*
    // `open_db`: `ensure_org` below has a permanent `kind` side effect, so a
    // rejected invocation must not have created an org on its way out (nor need
    // a reachable coordinator config to be told it was wrong).
    //
    // `--purpose agent` is normalised to `ci` here, at the parse boundary, so
    // the database still holds exactly two purposes and nothing downstream has
    // to learn a third. Only the epilogue branches on what the operator typed.
    let purpose = if args.purpose == AUTH_KEY_PURPOSE_CI || args.purpose == PURPOSE_AGENT_ALIAS {
        AUTH_KEY_PURPOSE_CI
    } else {
        AUTH_KEY_PURPOSE_NODE
    };
    // A CI key's tags become the *selector* of the grant its redemption
    // synthesises, so an empty set would share every board in the org. Refused
    // here as well as at the coordinator (`exchange_workload_key`), because a
    // key that could never redeem must not be mintable: the failure would
    // otherwise be a bare `403` at redemption, long after the mint.
    anyhow::ensure!(
        purpose != AUTH_KEY_PURPOSE_CI || !args.tag.is_empty(),
        "a `--purpose ci` key needs at least one `--tag`: the tags become the \
         selector of the grant it creates, and an empty selector matches every \
         board in the org"
    );
    // And the tags must survive the trip *through* the selector grammar, since
    // that is literally what redemption does with them (it synthesises
    // `tag=a && tag=b` and parses it). A tag like `*` is refused there — there
    // is no wildcard selector — so checking here turns what would be a bare
    // `403` at redemption into a message naming the mistake at mint time. The
    // shared parser is used rather than a second copy of the rule.
    if !args.tag.is_empty() {
        let selector = args
            .tag
            .iter()
            .map(|t| format!("tag={t}"))
            .collect::<Vec<_>>()
            .join(" && ");
        fleet_proto::lease::parse_constraint(&selector)
            .map_err(|e| anyhow::anyhow!("invalid `--tag`: {e}"))?;
    }
    let ops: Vec<String> = match &args.ops {
        // Validated locally so a typo names the unknown op rather than being
        // silently dropped and discovered at redemption. `normalize_ops`
        // matches what the API path stores, so the same `--ops` produces the
        // same row whichever verb minted it.
        Some(spec) => fleet_proto::token::normalize_ops(crate::roles::grant::parse_ops_arg(spec)?)
            .iter()
            .map(|o| o.as_str().to_owned())
            .collect(),
        None => Vec::new(),
    };
    if !ops.is_empty() && purpose != AUTH_KEY_PURPOSE_CI {
        // Stored either way (as the API path does), but a node key's redemption
        // never reads them — say so now rather than let the flag look effective.
        warn!(
            "`--ops` only takes effect for a `--purpose ci` key; a node key confers no operations"
        );
    }
    // The identity name, validated locally so a bad one names the rule rather
    // than being repaired into a *different* identity — the whole point is that
    // the operator can retype the same name on the next rotation.
    let subject_name: Option<String> = match &args.subject_name {
        None => None,
        Some(raw) => {
            // A node key confers no subject, so there is nothing for a name to
            // attach to. Refused rather than stored, so the flag cannot look
            // effective and be discovered inert months later.
            anyhow::ensure!(
                purpose == AUTH_KEY_PURPOSE_CI,
                "`--as` names the identity a `--purpose ci` (or `agent`) key speaks as; \
                 a node key enrolls a machine and confers no subject for a name to attach to"
            );
            Some(normalise_identity_name(raw)?)
        }
    };

    let (db, default_org, _) = open_db(args.config_dir.clone()).await?;
    let explicit_org = args.org.is_some();
    let org = args.org.clone().map_or(default_org, OrgId);
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
    db.insert_auth_key_with_purpose(
        &org,
        token.hash().as_str(),
        &args.tag,
        !args.multi_use,
        expires,
        None,
        now,
        purpose,
        &ops,
        subject_name.as_deref(),
    )
    .await
    .context("recording the auth key")?;

    print_auth_key(
        &org,
        &token.to_secret_string(),
        &args,
        purpose,
        subject_name.as_deref(),
        expires,
    );
    Ok(())
}

/// Print a freshly minted key. **The only place the secret is printed.**
///
/// Split out of [`auth_key`] the way `roles::auth_key` splits work from
/// printing: the epilogue now branches on purpose, and a `ci` key's is four
/// times the size of a node key's.
fn print_auth_key(
    org: &OrgId,
    secret: &str,
    args: &AuthKeyArgs,
    purpose: &str,
    subject_name: Option<&str>,
    expires: Option<i64>,
) {
    println!("Auth key for org '{org}':");
    println!();
    // The one place the secret is printed: it is not stored anywhere, only its
    // SHA-256, so this output is the only chance to capture it.
    println!("  {secret}");
    println!();
    println!("  single use : {}", !args.multi_use);
    println!("  purpose    : {purpose}");
    if let Some(name) = subject_name {
        println!("  identity   : agent:{name}");
        println!(
            "  subject    : {}",
            fleet_proto::ids::agent_subject_key(org, name)
        );
    }
    match expires {
        Some(e) => println!("  expires    : {e} (epoch seconds)"),
        None => println!("  expires    : never"),
    }
    if !args.tag.is_empty() {
        println!("  tags       : {}", args.tag.join(", "));
    }
    println!();
    if purpose == AUTH_KEY_PURPOSE_CI {
        println!("Use it on a CI runner with no workload identity of its own:");
        println!("  probe-rs-fleet ci login --fleet-url <url> --auth-key <key>");
        println!();
        println!("Redeeming it creates a GRANT in this org selecting the tagged boards,");
        println!("so revoking the key also tears down whatever it is holding — not just");
        println!("the credential. This is the weak CI path: prefer GitHub Actions");
        println!("workload identity (`grant --repo owner/name`), which stores no secret");
        println!("anywhere at all. See docs/ci-github-actions.md.");
        if expires.is_none() {
            println!();
            println!("This key never expires, but the grant it creates is capped at 30 days");
            println!("and renewed on each redemption — a rolling share, not a perpetual one.");
        }
        if let Some(name) = subject_name {
            println!();
            println!("{}", identity_epilogue(org.0.as_str(), name));
        }
        println!();
        println!("This key is a bearer credential and is not stored anywhere (only its");
        println!("hash). Copy it now; anyone holding it can use it.");
    } else {
        println!("Enroll a node with it:");
        println!("  probe-rs-fleet agent up --fleet-url <url> --auth-key <key>");
        println!();
        println!("This key is a bearer credential and is not stored anywhere (only its");
        println!("hash). Copy it now; anyone holding it can enroll a node into this org.");
    }
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
        "  {:<16}  {:<10}  {:<12}  {:<12}  {:<16}  {:<16}  TAGS",
        "HASH PREFIX", "SINGLE-USE", "EXPIRES", "STATE", "CREATED BY", "IDENTITY"
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
        // `(shell)` rather than blank: now that members can mint over the API,
        // an operator reading this wants to know which keys are theirs.
        let created_by = key.created_by.as_deref().unwrap_or("(shell)");
        // Load-bearing rather than decorative: keys sharing an identity share
        // one grant, so an operator must be able to see which before revoking.
        let identity = key.subject_name.as_deref().unwrap_or("-");
        println!(
            "  {prefix:<16}  {:<10}  {expires:<12}  {state:<12}  {created_by:<16}  {identity:<16}  {}",
            key.single_use,
            key.tags.join(",")
        );
    }
    println!();
    println!("Revoke one with:");
    println!("  probe-rs-fleet coordinator auth-key-revoke <hash-prefix> --org {org}");
    if keys.iter().any(|k| k.subject_name.is_some()) {
        println!();
        println!("Keys sharing an IDENTITY share ONE grant, so revoking any one of them takes");
        println!("that grant and every live lease under the name down with it — including");
        println!("another key's runner. A surviving key with the same identity re-creates the");
        println!("grant on its next redemption.");
    }
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

    println!(
        "Session token for '{}' in org '{org}' ({role}):",
        args.login
    );
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

    /// Build an `AuthKeyArgs` with the defaults clap would supply, so a test
    /// names only the field it is about.
    fn args_for(config_dir: Option<std::path::PathBuf>) -> AuthKeyArgs {
        AuthKeyArgs {
            org: None,
            tag: Vec::new(),
            ttl: 86_400,
            multi_use: false,
            purpose: AUTH_KEY_PURPOSE_NODE.to_owned(),
            subject_name: None,
            ops: None,
            config_dir,
        }
    }

    /// A coordinator config directory pointing at a fresh sqlite file inside
    /// it. The path must be absolute: `load_coordinator_config` does not
    /// resolve `sqlite_path` relative to the config file, so a bare name would
    /// land in the test process's cwd and make these tests order-dependent.
    fn coordinator_config_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let sqlite = dir.path().join("coord.sqlite");
        let seed = "ab".repeat(32);
        std::fs::write(
            dir.path().join("coordinator.toml"),
            format!(
                "listen_addr = \"127.0.0.1:7000\"\n\
                 public_url = \"https://fleet.example\"\n\
                 sqlite_path = \"{}\"\n\
                 signing_key_hex = \"{seed}\"\n",
                sqlite.display()
            ),
        )
        .unwrap();
        (dir, sqlite)
    }

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

    /// The point of the verb: a CI-purpose key that never expires, which the
    /// API path cannot mint (it caps the TTL) and this path could not express
    /// (it hardcoded `node`).
    #[tokio::test]
    async fn mints_a_never_expiring_ci_key_with_ops() {
        let (dir, sqlite) = coordinator_config_dir();
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            ttl: 0,
            purpose: AUTH_KEY_PURPOSE_CI.to_owned(),
            ops: Some("flash,attach".to_owned()),
            ..args_for(Some(dir.path().to_owned()))
        };
        auth_key(args).await.unwrap();

        let db = Db::connect(sqlite.to_str().unwrap()).await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        let keys = db.list_auth_keys(&org).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].purpose, AUTH_KEY_PURPOSE_CI);
        assert_eq!(keys[0].tags, vec!["desk".to_owned()]);
        assert_eq!(keys[0].expires, None, "--ttl 0 means no expiry");

        let meta = db
            .ci_auth_key_meta(&keys[0].key_hash)
            .await
            .unwrap()
            .expect("the key is redeemable at the CI path");
        assert_eq!(meta.purpose, AUTH_KEY_PURPOSE_CI);
        let mut ops = meta.ops.clone();
        ops.sort();
        assert_eq!(ops, vec!["attach".to_owned(), "flash".to_owned()]);
    }

    /// The default is still a node-enrollment key with no ops, so the
    /// coordinator's redemption behaviour for existing callers is unchanged.
    #[tokio::test]
    async fn defaults_to_a_node_key_with_no_ops() {
        let (dir, sqlite) = coordinator_config_dir();
        auth_key(args_for(Some(dir.path().to_owned())))
            .await
            .unwrap();

        let db = Db::connect(sqlite.to_str().unwrap()).await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        let keys = db.list_auth_keys(&org).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].purpose, AUTH_KEY_PURPOSE_NODE);
        let meta = db
            .ci_auth_key_meta(&keys[0].key_hash)
            .await
            .unwrap()
            .unwrap();
        assert!(
            meta.ops.is_empty(),
            "empty ops let DEFAULT_CI_KEY_OPS apply"
        );
    }

    /// A tagless CI key could never redeem — and its empty tag set would be an
    /// empty *selector*, i.e. every board in the org. Refused at mint time, and
    /// refused before any config or database work, so a bad invocation leaves
    /// no org behind.
    #[tokio::test]
    async fn a_tagless_ci_key_is_refused_before_touching_the_database() {
        let args = AuthKeyArgs {
            purpose: AUTH_KEY_PURPOSE_CI.to_owned(),
            ..args_for(Some(std::path::PathBuf::from(
                "/nonexistent/coordinator/config/dir",
            )))
        };
        let err = auth_key(args).await.unwrap_err().to_string();
        assert!(
            err.contains("empty selector"),
            "the refusal must say why, got: {err}"
        );
    }

    /// A wildcard `--tag` is refused at mint too: the tags become a selector at
    /// redemption, where there is deliberately no wildcard, so a key with tag
    /// `*` could never redeem.
    #[tokio::test]
    async fn a_wildcard_tag_is_refused_before_touching_the_database() {
        let args = AuthKeyArgs {
            purpose: AUTH_KEY_PURPOSE_CI.to_owned(),
            tag: vec!["*".to_owned()],
            ..args_for(Some(std::path::PathBuf::from(
                "/nonexistent/coordinator/config/dir",
            )))
        };
        let err = auth_key(args).await.unwrap_err().to_string();
        assert!(
            err.contains("no wildcard selector"),
            "the refusal must name the real answer, got: {err}"
        );
    }

    /// A typo in `--ops` names the unknown op, rather than being dropped and
    /// discovered as a missing capability at redemption — also before any
    /// database work.
    #[tokio::test]
    async fn an_unknown_op_is_named_before_touching_the_database() {
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            purpose: AUTH_KEY_PURPOSE_CI.to_owned(),
            ops: Some("flash,bogus".to_owned()),
            ..args_for(Some(std::path::PathBuf::from(
                "/nonexistent/coordinator/config/dir",
            )))
        };
        let err = auth_key(args).await.unwrap_err().to_string();
        assert!(err.contains("bogus"), "the refusal must name the op: {err}");
    }

    /// `--as` stores the **normalised** name, so a rotation typed with
    /// different capitalisation months later is the same identity.
    #[tokio::test]
    async fn an_identity_name_is_stored_normalised() {
        let (dir, sqlite) = coordinator_config_dir();
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            purpose: AUTH_KEY_PURPOSE_CI.to_owned(),
            subject_name: Some("  Builder-1 ".to_owned()),
            ..args_for(Some(dir.path().to_owned()))
        };
        auth_key(args).await.unwrap();

        let db = Db::connect(sqlite.to_str().unwrap()).await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        let keys = db.list_auth_keys(&org).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject_name.as_deref(), Some("builder-1"));
        assert_eq!(keys[0].purpose, AUTH_KEY_PURPOSE_CI);
    }

    /// `--purpose agent` is a *spelling* of `ci`: the row stores `ci`, so the
    /// database still holds exactly two purposes and the redemption check is
    /// untouched.
    #[tokio::test]
    async fn the_agent_purpose_alias_stores_ci() {
        let (dir, sqlite) = coordinator_config_dir();
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            purpose: PURPOSE_AGENT_ALIAS.to_owned(),
            subject_name: Some("builder".to_owned()),
            ..args_for(Some(dir.path().to_owned()))
        };
        auth_key(args).await.unwrap();

        let db = Db::connect(sqlite.to_str().unwrap()).await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        let keys = db.list_auth_keys(&org).await.unwrap();
        assert_eq!(keys[0].purpose, AUTH_KEY_PURPOSE_CI, "stored as `ci`");
        assert_eq!(keys[0].subject_name.as_deref(), Some("builder"));
        // And it really is redeemable at the CI path, which is the point of
        // normalising at the parse boundary rather than storing a third value.
        let meta = db
            .ci_auth_key_meta(&keys[0].key_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.purpose, AUTH_KEY_PURPOSE_CI);
        assert_eq!(meta.subject_name.as_deref(), Some("builder"));
    }

    /// A node key confers no subject, so `--as` on one is refused rather than
    /// stored as a flag that looks effective and is not — and refused before
    /// any database work, like the other argument-only judgements.
    #[tokio::test]
    async fn an_identity_name_on_a_node_key_is_refused() {
        let args = AuthKeyArgs {
            subject_name: Some("builder".to_owned()),
            ..args_for(Some(std::path::PathBuf::from(
                "/nonexistent/coordinator/config/dir",
            )))
        };
        let err = auth_key(args).await.unwrap_err().to_string();
        assert!(
            err.contains("confers no subject"),
            "the refusal must say why: {err}"
        );
    }

    /// A name that breaks the charset rule names the rule, rather than being
    /// repaired into a *different* identity.
    #[tokio::test]
    async fn an_invalid_identity_name_names_the_rule() {
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            purpose: AUTH_KEY_PURPOSE_CI.to_owned(),
            subject_name: Some("key:deadbeef".to_owned()),
            ..args_for(Some(std::path::PathBuf::from(
                "/nonexistent/coordinator/config/dir",
            )))
        };
        let err = auth_key(args).await.unwrap_err().to_string();
        assert!(err.contains("[a-z0-9._-]"), "got: {err}");
    }
}
