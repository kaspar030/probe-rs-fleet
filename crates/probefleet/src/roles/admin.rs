//! Shell-on-the-host admin verbs: `coordinator auth-key(s)`,
//! `auth-key-revoke`, `user-token` and `org create`.
//!
//! All of them work from a shell on the coordinator host, bypassing the login
//! flow. Now that `probefleet login`, `share` and `auth-key create` exist
//! they are the **unattended / air-gapped escape hatch**, not the front door.
//! They stay for the self-hosted operator, for the air-gapped case, and for
//! the one thing the API refuses — a key that never expires, including a
//! never-expiring `--purpose ci` key, which no other path can mint.
//!
//! `auth-key` is joined by `auth-keys` (list) and `auth-key-revoke`. Those are
//! not conveniences: auth keys are the weak link in the credential model —
//! long-lived bearer secrets that end up in strangers' CI config and disk
//! images — and "revocable" is only true in practice if an operator can first
//! find out which keys exist.
//!
//! # `user-token` makes an ordinary user
//!
//! `user-token --username alice` creates (or reuses) the forgs user `alice`
//! through the same constructor signup uses — personal org included — just
//! with no provider identity linked. If alice later logs in with a provider
//! she signs up as a *new* user unless the name is free; the two are not
//! merged. That is the escape hatch's trade, written down here rather than
//! discovered.
//!
//! Every verb opens the coordinator's database directly rather than talking to
//! a running coordinator: the operator running them already has a shell on the
//! host and therefore total authority, and requiring the daemon to be up to
//! mint the first credential would be a bootstrap cycle. They build an
//! in-process [`Coordinator`] (no login providers, so no network) so that
//! minting and revocation go through the same forgs `AuthContext` — and the
//! same revocation hooks — the server uses.

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::warn;

use forgs::TokenKind;
use probefleet_coordinator::identity::{PURPOSE_CI, PURPOSE_NODE};
use probefleet_coordinator::{Coordinator, Db, FleetRole};

use crate::cli::{AuthKeyArgs, OrgCreateArgs, UserTokenArgs};
use crate::paths;
use crate::roles::auth_key::{identity_epilogue, normalise_identity_name, PURPOSE_AGENT_ALIAS};

/// A coordinator over the on-disk database, for the admin verbs.
struct Admin {
    coord: Arc<Coordinator>,
    default_org: String,
}

impl Admin {
    fn db(&self) -> &Db {
        self.coord.db()
    }

    fn store(&self) -> &forgs_store::Store {
        self.coord.db().forgs()
    }

    fn now(&self) -> u64 {
        self.coord.now()
    }

    /// Resolve an org reference (path or id), defaulting to `default_org`.
    async fn org(&self, raw: Option<&str>) -> Result<forgs::NsNodeId> {
        let raw = raw.unwrap_or(&self.default_org);
        let org = self
            .db()
            .resolve_org(raw)
            .await
            .context("resolving the org")?
            .with_context(|| {
                format!(
                    "no org `{raw}`; create it with `probefleet coordinator org create \
                     {raw} --admin <username>`"
                )
            })?;
        probefleet_coordinator::subject::ns_of(&org).context("the org id is not a namespace id")
    }
}

/// Open the coordinator's database from its config file.
async fn open(config_dir: Option<std::path::PathBuf>) -> Result<Admin> {
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
    let clock: probefleet_coordinator::SharedClock = Arc::new(probefleet_coordinator::SystemClock);
    // The daemon ensures the default org at startup; so does every admin
    // verb, so the first one run before the daemon ever started works.
    db.ensure_org_named(&config.default_org, clock.now_secs())
        .await
        .context("ensuring the default org exists")?;
    let default_org = config.default_org.clone();
    let signer = match &config.signing_key {
        probefleet_coordinator::SigningKeySource::Seed(seed) => {
            probefleet_coordinator::Ed25519Signer::from_seed(seed)
        }
    };
    let scheduler = probefleet_core::scheduler::Scheduler::new(config.policy.clone());
    let coord = Arc::new(
        Coordinator::with_providers(config, scheduler, db, signer, clock, Vec::new())
            .context("building the coordinator's auth context")?,
    );
    coord.attach();
    Ok(Admin { coord, default_org })
}

/// Run `coordinator auth-key`: mint an org-scoped key.
///
/// # Errors
///
/// Returns an error if the arguments are invalid, the config or database
/// cannot be opened, or the write fails.
#[allow(clippy::too_many_lines)]
pub async fn auth_key(args: AuthKeyArgs) -> Result<()> {
    warn!(
        "`coordinator auth-key` mints a node-enrollment credential from a shell \
         on this host. It is the self-hosted / air-gapped escape hatch, not the \
         normal path: a member with a login runs `probefleet auth-key \
         create`, and a machine with a login runs `probefleet share`."
    );

    // Everything that can be judged from the arguments alone is judged *before*
    // opening the database, so a rejected invocation needs no reachable
    // coordinator config to be told it was wrong.
    //
    // `--purpose agent` is normalised to `ci` here, at the parse boundary, so
    // the database still holds exactly two purposes and nothing downstream has
    // to learn a third. Only the epilogue branches on what the operator typed.
    let purpose = if args.purpose == PURPOSE_CI || args.purpose == PURPOSE_AGENT_ALIAS {
        PURPOSE_CI
    } else {
        PURPOSE_NODE
    };
    // A CI key's tags become the *selector* of the grant its redemption
    // synthesises, so an empty set would share every board in the org.
    anyhow::ensure!(
        purpose != PURPOSE_CI || !args.tag.is_empty(),
        "a `--purpose ci` key needs at least one `--tag`: the tags become the \
         selector of the grant it creates, and an empty selector matches every \
         board in the org"
    );
    // And the tags must survive the trip *through* the selector grammar, since
    // that is literally what redemption does with them.
    if !args.tag.is_empty() {
        let selector = args
            .tag
            .iter()
            .map(|t| format!("tag={t}"))
            .collect::<Vec<_>>()
            .join(" && ");
        probefleet_proto::lease::parse_constraint(&selector)
            .map_err(|e| anyhow::anyhow!("invalid `--tag`: {e}"))?;
    }
    let ops: Vec<String> = match &args.ops {
        Some(spec) => {
            probefleet_proto::token::normalize_ops(crate::roles::grant::parse_ops_arg(spec)?)
                .iter()
                .map(|o| o.as_str().to_owned())
                .collect()
        }
        None => Vec::new(),
    };
    anyhow::ensure!(
        ops.is_empty() || purpose == PURPOSE_CI,
        "`--ops` only applies to a `--purpose ci` (or `agent`) key; a node key confers \
         no operations"
    );
    let subject_name: Option<String> = match &args.subject_name {
        None => None,
        Some(raw) => {
            anyhow::ensure!(
                purpose == PURPOSE_CI,
                "`--name` names the identity a `--purpose ci` (or `agent`) key speaks as; \
                 a node key enrolls a machine and confers no subject for a name to attach to"
            );
            Some(normalise_identity_name(raw)?)
        }
    };
    let payload = if purpose == PURPOSE_CI {
        serde_json::json!({ "tags": args.tag, "ops": ops })
    } else {
        serde_json::json!({ "tags": args.tag })
    };
    // The same purpose policy the API path runs: validates and canonicalises.
    let admin = open(args.config_dir.clone()).await?;
    let payload = admin
        .coord
        .auth()
        .purposes()
        .check_payload(purpose, Some(&payload))
        .map_err(|e| anyhow::anyhow!("the key's tags/ops were refused: {e}"))?;
    let ns = admin.org(args.org.as_deref()).await?;

    let now = admin.now();
    let expires = (args.ttl != 0).then(|| now.saturating_add(args.ttl));
    let token = admin.coord.auth().format().mint(TokenKind::ApiKey);
    admin
        .store()
        .scoped(ns)
        .insert_api_key(
            &forgs_store::NewApiKey {
                hash: token.hash(),
                purpose: purpose.to_owned(),
                subject_name: subject_name.clone(),
                payload,
                single_use: !args.multi_use,
                expires,
                created_by: None,
            },
            now,
        )
        .await
        .context("recording the auth key")?;

    let org_label = args
        .org
        .clone()
        .unwrap_or_else(|| admin.default_org.clone());
    print_auth_key(
        &org_label,
        &ns.to_string(),
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
    org: &str,
    ns: &str,
    secret: &str,
    args: &AuthKeyArgs,
    purpose: &str,
    subject_name: Option<&str>,
    expires: Option<u64>,
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
            forgs::NsNodeId::parse(ns).map_or_else(
                |_| format!("{ns}/workload:agent:{name}"),
                |id| forgs::subject::agent_subject_key(&id, name).to_string()
            )
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
    if purpose == PURPOSE_CI {
        println!("Use it on a CI runner with no workload identity of its own:");
        println!("  probefleet ci login --fleet-url <url> --auth-key <key>");
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
            println!("{}", identity_epilogue(ns, name));
        }
        println!();
        println!("This key is a bearer credential and is not stored anywhere (only its");
        println!("hash). Copy it now; anyone holding it can use it.");
    } else {
        println!("Enroll a node with it:");
        println!("  probefleet node up --fleet-url <url> --auth-key <key>");
        println!();
        println!("This key is a bearer credential and is not stored anywhere (only its");
        println!("hash). Copy it now; anyone holding it can enroll a node into this org.");
    }
}

/// Run `coordinator auth-keys`: list the org's outstanding auth keys.
///
/// The secret was never stored — only its SHA-256 — so a listing is safe to
/// print and pipe, and the hash prefix is the handle `auth-key-revoke` takes.
///
/// # Errors
///
/// Returns an error if the config or database cannot be opened.
pub async fn auth_keys(args: crate::cli::AuthKeysArgs) -> Result<()> {
    let admin = open(args.config_dir).await?;
    let org = args
        .org
        .clone()
        .unwrap_or_else(|| admin.default_org.clone());
    let ns = admin.org(Some(&org)).await?;
    let keys = admin
        .store()
        .scoped(ns)
        .list_api_keys()
        .await
        .context("listing the org's auth keys")?;

    if keys.is_empty() {
        println!("No auth keys for org '{org}'.");
        return Ok(());
    }

    let now = admin.now();
    println!("Auth keys for org '{org}' ({} total):", keys.len());
    println!();
    println!(
        "  {:<16}  {:<8}  {:<10}  {:<12}  {:<12}  {:<26}  {:<16}  PAYLOAD",
        "HASH PREFIX", "PURPOSE", "SINGLE-USE", "EXPIRES", "STATE", "CREATED BY", "IDENTITY"
    );
    for key in &keys {
        let prefix: String = key.key_hash.as_str().chars().take(16).collect();
        let expires = key
            .expires
            .map_or_else(|| "never".to_owned(), |e| e.to_string());
        let state = if key.consumed_at.is_some() {
            "consumed"
        } else if key.expires.is_some_and(|e| e <= now) {
            "expired"
        } else {
            "live"
        };
        // `(shell)` rather than blank: members can mint over the API, and an
        // operator reading this wants to know which keys are theirs.
        let created_by = key
            .created_by
            .map_or_else(|| "(shell)".to_owned(), |u| u.to_string());
        // Load-bearing rather than decorative: keys sharing an identity share
        // one grant, so an operator must be able to see which before revoking.
        let identity = key.subject_name.as_deref().unwrap_or("-");
        println!(
            "  {prefix:<16}  {:<8}  {:<10}  {expires:<12}  {state:<12}  {created_by:<26}  {identity:<16}  {}",
            key.purpose,
            key.single_use,
            key.payload.as_deref().unwrap_or("")
        );
    }
    println!();
    println!("Revoke one with:");
    println!("  probefleet coordinator auth-key-revoke <hash-prefix> --org {org}");
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
/// revoking the wrong key silently de-provisions machines nobody is looking
/// at. The revocation runs fleet's cascade (a `ci` key's grant and its live
/// leases), exactly as the API path does.
///
/// # Errors
///
/// Returns an error if the config or database cannot be opened, the prefix
/// matches nothing, or it matches more than one key.
pub async fn auth_key_revoke(args: crate::cli::AuthKeyRevokeArgs) -> Result<()> {
    let admin = open(args.config_dir).await?;
    let org = args
        .org
        .clone()
        .unwrap_or_else(|| admin.default_org.clone());
    let ns = admin.org(Some(&org)).await?;
    let prefix = args.prefix.trim().to_ascii_lowercase();
    anyhow::ensure!(!prefix.is_empty(), "a hash prefix is required");

    let scope = admin.store().scoped(ns);
    let keys = scope
        .list_api_keys()
        .await
        .context("listing the org's auth keys")?;
    let matches: Vec<_> = keys
        .iter()
        .filter(|k| k.key_hash.as_str().starts_with(&prefix))
        .collect();
    let target = match matches.as_slice() {
        [] => anyhow::bail!("no auth key in org '{org}' has a hash starting with {prefix:?}"),
        [one] => *one,
        many => {
            let candidates: Vec<String> = many
                .iter()
                .map(|k| k.key_hash.as_str().chars().take(16).collect())
                .collect();
            anyhow::bail!(
                "{prefix:?} matches {} auth keys in org '{org}'; be more specific:\n  {}",
                many.len(),
                candidates.join("\n  ")
            );
        }
    };
    let subject_name = target.subject_name.clone();
    let deleted: Vec<String> = scope
        .delete_api_key(target.id)
        .await
        .context("revoking the auth key")?
        .then(|| target.key_hash.as_str().to_owned())
        .into_iter()
        .collect();
    let ctx = admin.coord.auth();
    ctx.purposes()
        .on_revoked(ctx, ns, &deleted, subject_name.as_deref())
        .await;
    for hash in &deleted {
        println!("Revoked auth key {hash} (org '{org}').");
    }
    println!();
    println!("Nodes already enrolled with it keep working: their node tokens are");
    println!("separate credentials. Revoke a node by deleting its row.");
    Ok(())
}

/// Find the user `username`, or create it as a local user (no provider
/// identity) through forgs' signup path, personal org included.
async fn ensure_user(admin: &Admin, username: &str) -> Result<(forgs::UserId, String, bool)> {
    if let Some(u) = admin
        .store()
        .user_by_username(username)
        .await
        .context("looking up the user")?
    {
        return Ok((u.id, u.username, false));
    }
    let (id, _) = admin
        .store()
        .create_local_user(username, None, admin.now())
        .await
        .with_context(|| format!("creating the user `{username}`"))?;
    let user = admin
        .store()
        .user_by_id(id)
        .await?
        .context("the user just created is missing")?;
    Ok((id, user.username, true))
}

/// Run `coordinator user-token`: provision a user and mint a session and a
/// refresh token for it.
///
/// The membership matters as much as the token: a session whose user is in
/// no org but their personal one authenticates fine and then fails every
/// check in the org the operator meant.
///
/// # Errors
///
/// Returns an error if the config or database cannot be opened, the username
/// is invalid, or a write fails.
pub async fn user_token(args: UserTokenArgs) -> Result<()> {
    warn!(
        "`coordinator user-token` mints a session from a shell on this host, \
         bypassing any login flow. It is the air-gapped / bootstrap escape hatch; \
         `probefleet login` is the front door."
    );

    let admin = open(args.config_dir).await?;
    let org = args
        .org
        .clone()
        .unwrap_or_else(|| admin.default_org.clone());
    let ns = admin.org(Some(&org)).await?;
    let role: FleetRole = args.role.into();
    let (user, username, created) = ensure_user(&admin, &args.username).await?;
    admin
        .db()
        .set_member(
            &probefleet_coordinator::subject::org_of(ns),
            user,
            role,
            admin.now(),
        )
        .await
        .context("adding the user to the org")?;

    let ctx = admin.coord.auth();
    let mut session = forgs_http::session::mint_session(ctx, user, "coordinator user-token")
        .await
        .map_err(|e| anyhow::anyhow!("minting the session: {e}"))?;
    if let Some(ttl) = args.ttl {
        // A custom lifetime: re-mint through the store with the operator's TTL.
        let now = admin.now();
        let token = ctx.format().mint(TokenKind::Session);
        let expires = now.saturating_add(ttl);
        admin
            .store()
            .insert_session(&token.hash(), user, now, expires)
            .await
            .context("recording the session")?;
        session = forgs_http::session::MintedSession {
            token: token.to_secret_string(),
            expires,
        };
    }
    // The durable half. Minted here too, deliberately: leaving the escape
    // hatch without renewal would make it a second-class citizen.
    let refresh = forgs_http::session::mint_refresh(ctx, user)
        .await
        .map_err(|e| anyhow::anyhow!("minting the refresh token: {e}"))?;

    println!(
        "Session token for '{username}'{} — {} of org '{org}':",
        if created { " (new user)" } else { "" },
        args.role.label()
    );
    println!();
    println!("  {}", session.token);
    println!();
    println!("  expires: {} (epoch seconds)", session.expires);
    println!();
    println!("Refresh token (renews the session without a browser):");
    println!();
    println!("  {refresh}");
    println!();
    println!("Point `ctl` and the probe-rs shim at the fleet with both:");
    println!("  probefleet login --fleet-url <url> \\");
    println!("      --token <session token> --refresh-token <refresh token> --org {org}");
    println!();
    println!("The refresh token can do exactly one thing: mint session tokens for this");
    println!("user. It opens no connection and enrolls nothing, and");
    println!("`probefleet logout --all` revokes it.");
    println!();
    println!("Both are bearer credentials and are not stored anywhere (only their");
    println!("hashes). Copy them now.");
    Ok(())
}

/// Run `coordinator org create`: a team org with a first admin.
///
/// # Errors
///
/// Returns an error if the name is invalid, reserved or taken, or the admin
/// does not exist.
pub async fn org_create(args: OrgCreateArgs) -> Result<()> {
    let admin = open(args.config_dir).await?;
    let user = admin
        .store()
        .user_by_username(&args.admin)
        .await
        .context("looking up the admin")?
        .with_context(|| {
            format!(
                "no user `{}`: they must log in once first (or use \
                 `coordinator user-token --username {}`)",
                args.admin, args.admin
            )
        })?;
    let now = admin.now();
    // The same transaction `POST /api/v1/orgs` uses, minus its policy: this is the
    // host-shell escape hatch, so `allow_org_creation` and the per-user cap
    // do not apply.
    let ns = admin
        .db()
        .create_team_org(
            &args.name,
            user.id,
            forgs::schema::NameOrigin::User,
            None,
            now,
        )
        .await
        .with_context(|| format!("creating the org `{}`", args.name))?;
    println!(
        "Created org '{}' ({ns}); admin: {}.",
        args.name, user.username
    );
    println!();
    println!(
        "Members act in it with `--org {}` (or `login --org {}`).",
        args.name, args.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::RoleArg;

    /// Build an `AuthKeyArgs` with the defaults clap would supply, so a test
    /// names only the field it is about.
    fn args_for(config_dir: Option<std::path::PathBuf>) -> AuthKeyArgs {
        AuthKeyArgs {
            org: None,
            tag: Vec::new(),
            ttl: 86_400,
            multi_use: false,
            purpose: PURPOSE_NODE.to_owned(),
            subject_name: None,
            ops: None,
            config_dir,
        }
    }

    /// A coordinator config directory pointing at a fresh sqlite file inside
    /// it. The path must be absolute: `load_coordinator_config` does not
    /// resolve `sqlite_path` relative to the config file.
    fn coordinator_config_dir() -> tempfile::TempDir {
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
        dir
    }

    async fn keys_of(dir: &tempfile::TempDir) -> Vec<forgs_store::ApiKeyRow> {
        let admin = open(Some(dir.path().to_owned())).await.unwrap();
        let ns = admin.org(None).await.unwrap();
        admin.store().scoped(ns).list_api_keys().await.unwrap()
    }

    /// The whole chain: a new local user, a membership in the default org,
    /// and a session that authenticates as that user.
    #[tokio::test]
    async fn user_token_provisions_user_membership_and_session() {
        let dir = coordinator_config_dir();
        user_token(UserTokenArgs {
            username: "alice".to_owned(),
            org: None,
            role: RoleArg::Admin,
            ttl: None,
            config_dir: Some(dir.path().to_owned()),
        })
        .await
        .unwrap();
        let admin = open(Some(dir.path().to_owned())).await.unwrap();
        let alice = admin
            .store()
            .user_by_username("alice")
            .await
            .unwrap()
            .expect("alice exists");
        let org = probefleet_coordinator::subject::org_of(admin.org(None).await.unwrap());
        assert_eq!(
            admin.db().role_of(&org, alice.id).await.unwrap(),
            Some(FleetRole::Admin)
        );
        assert!(
            alice.personal_ns.is_some(),
            "an ordinary user, personal org included"
        );

        // Re-running reuses the user rather than failing on the taken name.
        user_token(UserTokenArgs {
            username: "alice".to_owned(),
            org: None,
            role: RoleArg::Member,
            ttl: Some(60),
            config_dir: Some(dir.path().to_owned()),
        })
        .await
        .unwrap();
        assert_eq!(
            admin.db().role_of(&org, alice.id).await.unwrap(),
            Some(FleetRole::Member)
        );
    }

    #[tokio::test]
    async fn org_create_makes_the_admin_an_admin() {
        let dir = coordinator_config_dir();
        user_token(UserTokenArgs {
            username: "bob".to_owned(),
            org: None,
            role: RoleArg::Member,
            ttl: None,
            config_dir: Some(dir.path().to_owned()),
        })
        .await
        .unwrap();
        org_create(OrgCreateArgs {
            name: "acme".to_owned(),
            admin: "bob".to_owned(),
            config_dir: Some(dir.path().to_owned()),
        })
        .await
        .unwrap();
        let admin = open(Some(dir.path().to_owned())).await.unwrap();
        let ns = admin.org(Some("acme")).await.unwrap();
        let bob = admin
            .store()
            .user_by_username("bob")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            admin
                .db()
                .role_of(&probefleet_coordinator::subject::org_of(ns), bob.id)
                .await
                .unwrap(),
            Some(FleetRole::Admin)
        );
        // An unknown admin is refused, naming the fix.
        let err = org_create(OrgCreateArgs {
            name: "other".to_owned(),
            admin: "nobody".to_owned(),
            config_dir: Some(dir.path().to_owned()),
        })
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("log in once"), "{err:#}");
    }

    /// The point of the verb: a CI-purpose key that never expires, which the
    /// API path cannot mint (it caps the TTL).
    #[tokio::test]
    async fn mints_a_never_expiring_ci_key_with_ops() {
        let dir = coordinator_config_dir();
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            ttl: 0,
            purpose: PURPOSE_CI.to_owned(),
            ops: Some("flash,attach".to_owned()),
            ..args_for(Some(dir.path().to_owned()))
        };
        auth_key(args).await.unwrap();

        let keys = keys_of(&dir).await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].purpose, PURPOSE_CI);
        assert_eq!(keys[0].expires, None, "--ttl 0 means no expiry");
        let payload: probefleet_coordinator::identity::CiKeyPayload =
            serde_json::from_str(keys[0].payload.as_deref().unwrap()).unwrap();
        assert_eq!(payload.tags, vec!["desk".to_owned()]);
        let mut ops = payload.ops.clone();
        ops.sort();
        assert_eq!(ops, vec!["attach".to_owned(), "flash".to_owned()]);
    }

    /// The default is still a node-enrollment key carrying its tags.
    #[tokio::test]
    async fn defaults_to_a_node_key_with_tags() {
        let dir = coordinator_config_dir();
        auth_key(AuthKeyArgs {
            tag: vec!["lab".to_owned()],
            ..args_for(Some(dir.path().to_owned()))
        })
        .await
        .unwrap();
        let keys = keys_of(&dir).await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].purpose, PURPOSE_NODE);
        let payload: probefleet_coordinator::identity::NodeKeyPayload =
            serde_json::from_str(keys[0].payload.as_deref().unwrap()).unwrap();
        assert_eq!(payload.tags, vec!["lab".to_owned()]);
    }

    /// Listing and revoking by prefix work against the same store.
    #[tokio::test]
    async fn keys_can_be_listed_and_revoked() {
        let dir = coordinator_config_dir();
        auth_key(args_for(Some(dir.path().to_owned())))
            .await
            .unwrap();
        let keys = keys_of(&dir).await;
        auth_keys(crate::cli::AuthKeysArgs {
            org: None,
            config_dir: Some(dir.path().to_owned()),
        })
        .await
        .unwrap();
        auth_key_revoke(crate::cli::AuthKeyRevokeArgs {
            prefix: keys[0].key_hash.as_str()[..12].to_owned(),
            org: None,
            config_dir: Some(dir.path().to_owned()),
        })
        .await
        .unwrap();
        assert!(keys_of(&dir).await.is_empty());
    }

    /// A tagless CI key could never redeem — and its empty tag set would be an
    /// empty *selector*. Refused before any config or database work.
    #[tokio::test]
    async fn a_tagless_ci_key_is_refused_before_touching_the_database() {
        let args = AuthKeyArgs {
            purpose: PURPOSE_CI.to_owned(),
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

    /// A wildcard `--tag` is refused at mint too: there is no wildcard
    /// selector, so a key with tag `*` could never redeem.
    #[tokio::test]
    async fn a_wildcard_tag_is_refused_before_touching_the_database() {
        let args = AuthKeyArgs {
            purpose: PURPOSE_CI.to_owned(),
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

    /// A typo in `--ops` names the unknown op, before any database work.
    #[tokio::test]
    async fn an_unknown_op_is_named_before_touching_the_database() {
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            purpose: PURPOSE_CI.to_owned(),
            ops: Some("flash,bogus".to_owned()),
            ..args_for(Some(std::path::PathBuf::from(
                "/nonexistent/coordinator/config/dir",
            )))
        };
        let err = auth_key(args).await.unwrap_err().to_string();
        assert!(err.contains("bogus"), "the refusal must name the op: {err}");
    }

    /// `--name` stores the **normalised** name, so a rotation typed with
    /// different capitalisation months later is the same identity.
    #[tokio::test]
    async fn an_identity_name_is_stored_normalised() {
        let dir = coordinator_config_dir();
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            purpose: PURPOSE_CI.to_owned(),
            subject_name: Some("  Builder-1 ".to_owned()),
            ..args_for(Some(dir.path().to_owned()))
        };
        auth_key(args).await.unwrap();
        let keys = keys_of(&dir).await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject_name.as_deref(), Some("builder-1"));
        assert_eq!(keys[0].purpose, PURPOSE_CI);
    }

    /// `--purpose agent` is a *spelling* of `ci`: the row stores `ci`.
    #[tokio::test]
    async fn the_agent_purpose_alias_stores_ci() {
        let dir = coordinator_config_dir();
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            purpose: PURPOSE_AGENT_ALIAS.to_owned(),
            subject_name: Some("builder".to_owned()),
            ..args_for(Some(dir.path().to_owned()))
        };
        auth_key(args).await.unwrap();
        let keys = keys_of(&dir).await;
        assert_eq!(keys[0].purpose, PURPOSE_CI, "stored as `ci`");
        assert_eq!(keys[0].subject_name.as_deref(), Some("builder"));
    }

    /// A node key confers no subject, so `--name` on one is refused.
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

    /// A name that breaks the charset rule names the rule.
    #[tokio::test]
    async fn an_invalid_identity_name_names_the_rule() {
        let args = AuthKeyArgs {
            tag: vec!["desk".to_owned()],
            purpose: PURPOSE_CI.to_owned(),
            subject_name: Some("key:deadbeef".to_owned()),
            ..args_for(Some(std::path::PathBuf::from(
                "/nonexistent/coordinator/config/dir",
            )))
        };
        let err = auth_key(args).await.unwrap_err().to_string();
        assert!(err.contains("[a-z0-9._-]"), "got: {err}");
    }
}
