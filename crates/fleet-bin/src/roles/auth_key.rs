//! `probe-rs-fleet auth-key {create,list,revoke}`: mint and manage
//! node-enrollment keys with the login you already have.
//!
//! This is the hosted customer's path (architecture §6.4). Before it existed,
//! auth keys could only be minted by `probe-rs-fleet coordinator auth-key`,
//! which reads `coordinator.toml` and writes the coordinator's `SQLite`
//! directly
//! — so it needs **a shell on the coordinator host**. A customer who has only
//! run `probe-rs-fleet login` has no such shell, and therefore could not enroll
//! a headless lab Pi at all: the `agent up` ladder's rung 2 (`--auth-key`)
//! required our shell and rung 3 (an existing `[user]` session) requires a human
//! sitting at the machine.
//!
//! So: mint on your laptop, paste into the Pi.
//!
//! Three properties come from the coordinator rather than from here, and are
//! worth knowing while reading this file:
//!
//! * **the org comes from the session**, never from a flag, so a key can never
//!   exceed the caller's own org (there is deliberately no `--org`);
//! * **membership is sufficient** to mint, consistent with §6.4/§6.5's
//!   "membership is enough to add a node";
//! * **an API-minted key must expire**, within a documented cap. A forever-key
//!   is an operator's informed choice from a shell (`coordinator auth-key
//!   --ttl 0`); it is not a hosted member's.
//!
//! # Work and printing are separate
//!
//! [`create`] / [`list`] / [`revoke`] do the work and return the `fleet_auth`
//! wire types; [`run`] dispatches and prints. The split is not decoration: the
//! minted secret is printed exactly once and stored nowhere, so a test (or any
//! future caller) that needs its value cannot scrape stdout for it.

use anyhow::{Context, Result};

use fleet_auth::api::{AuthKeyCreated, AuthKeyList, AuthKeyRevoked};
use fleet_auth::http_client::ClientError;

use crate::cli::{
    AuthKeyCliArgs, AuthKeyCommand, AuthKeyCreateArgs, AuthKeyListArgs, AuthKeyRevokeCliArgs,
};
use crate::fleet_config::{self, FleetFile};
use crate::roles::node_setup;

/// Run `probe-rs-fleet auth-key <verb>`: do the work, then print it.
///
/// # Errors
///
/// Returns an error if the fleet has no `[user]` credential, the session cannot
/// be refreshed, or the coordinator refuses the request.
pub async fn run(args: AuthKeyCliArgs) -> Result<()> {
    match args.command {
        AuthKeyCommand::Create(args) => {
            let created = create(&args).await?;
            print_created(&created);
        }
        AuthKeyCommand::List(args) => {
            let list = list(&args).await?;
            print_list(&list);
        }
        AuthKeyCommand::Revoke(args) => {
            let revoked = revoke(&args).await?;
            print_revoked(&revoked);
        }
    }
    Ok(())
}

/// Mint an auth key for the caller's org.
///
/// # Errors
///
/// See [`run`]. A TTL of zero (or `never`) is refused locally, with the reason,
/// rather than bouncing the user off a `400`.
pub async fn create(args: &AuthKeyCreateArgs) -> Result<AuthKeyCreated> {
    let ttl = parse_ttl(&args.ttl)?;
    // A CI key's tags become the *selector* of the grant its redemption
    // synthesises, so an empty set would share every board in the org. Refused
    // here as well as at the coordinator, because the local message can say
    // *why* where a `400` cannot.
    anyhow::ensure!(
        args.purpose != "ci" || !args.tag.is_empty(),
        "a `--purpose ci` key needs at least one `--tag`: the tags become the \
         selector of the grant it creates, and an empty selector matches every \
         board in the org"
    );
    let ops = match &args.ops {
        // Validated locally so a typo names the unknown op rather than
        // bouncing off a coarse `400`.
        Some(spec) => crate::roles::grant::parse_ops_arg(spec)?
            .iter()
            .map(|o| o.as_str().to_owned())
            .collect(),
        None => Vec::new(),
    };
    let (file, session) = session_for(&args.fleet, args.config_dir.as_deref()).await?;
    // `--single-use` is the default, so it is accepted and ignored; clap already
    // refuses it together with `--multi-use`.
    fleet_auth::http_client::create_auth_key_with_purpose(
        &file.url,
        file.pin(),
        &session,
        args.tag.clone(),
        ttl,
        args.multi_use,
        Some(&args.purpose),
        ops,
    )
    .await
    .map_err(|e| describe(&e, "minting an auth key"))
}

/// List the caller's org's auth keys.
///
/// # Errors
///
/// See [`run`].
pub async fn list(args: &AuthKeyListArgs) -> Result<AuthKeyList> {
    let (file, session) = session_for(&args.fleet, args.config_dir.as_deref()).await?;
    fleet_auth::http_client::list_auth_keys(&file.url, file.pin(), &session)
        .await
        .map_err(|e| describe(&e, "listing this org's auth keys"))
}

/// Revoke an auth key by hash prefix.
///
/// # Errors
///
/// See [`run`].
pub async fn revoke(args: &AuthKeyRevokeCliArgs) -> Result<AuthKeyRevoked> {
    let (file, session) = session_for(&args.fleet, args.config_dir.as_deref()).await?;
    fleet_auth::http_client::revoke_auth_key(&file.url, file.pin(), &session, &args.prefix)
        .await
        .map_err(|e| describe(&e, "revoking an auth key"))
}

/// Load the fleet file and produce a usable session token.
///
/// Refreshing goes through the shared path rather than reaching for the raw
/// token: a session that expired an hour ago would otherwise surface as an
/// opaque 401 from a command the user has no reason to associate with logging
/// in. Same reasoning, same call, as `share`.
async fn session_for(
    fleet: &str,
    config_dir: Option<&std::path::Path>,
) -> Result<(FleetFile, String)> {
    let (fleet_path, _node_dir) = node_setup::resolve_paths(fleet, config_dir)?;
    let file = fleet_config::load(&fleet_path).with_context(|| {
        format!(
            "loading fleet config {} — log in first with \
             `probe-rs-fleet login --fleet {fleet} --fleet-url <url>`",
            fleet_path.display()
        )
    })?;
    anyhow::ensure!(
        file.user.is_some(),
        "fleet `{fleet}` has no [user] credential on this machine; \
         run `probe-rs-fleet login --fleet {fleet}` first. \
         (With a shell on the coordinator host, `probe-rs-fleet coordinator \
         auth-key` is the self-hosted escape hatch.)"
    );
    let session = fleet_config::ensure_fresh_session(fleet, &file)
        .await
        .context("refreshing the session token")?;
    Ok((file, session))
}

/// Turn a coordinator rejection into remediation-shaped text.
///
/// The wire body is deliberately coarse — one `error` code, no candidate lists —
/// so the sentence that tells the user what to do next has to be written here.
fn describe(e: &ClientError, doing: &str) -> anyhow::Error {
    let ClientError::Rejected { code, status } = e else {
        return anyhow::anyhow!("{doing} failed: {e}");
    };
    let hint = match code.as_str() {
        "forbidden" => {
            "you are not a member of the org your session belongs to, or the key \
             is not yours to revoke (its creator, or an org admin, may revoke it)"
        }
        "ambiguous_prefix" => {
            "that prefix matches more than one auth key in this org. Run \
             `probe-rs-fleet auth-key list` and use a longer prefix"
        }
        "not_found" => "no auth key in this org has a hash starting with that prefix",
        "invalid_request" => {
            "the request was refused: a hash prefix must be at least 8 hex \
             characters, and an auth key minted this way must expire (TTL \
             between 1 second and 30 days)"
        }
        "unauthorized" => "your session was refused. Log in again with `probe-rs-fleet login`",
        _ => return anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {code}"),
    };
    anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {hint}")
}

/// Parse a TTL: bare seconds, or a `s`/`m`/`h`/`d`-suffixed duration.
///
/// A never-expiring key is refused here rather than at the coordinator, so the
/// user gets the reason instead of a `400`.
///
/// # Errors
///
/// Returns an error for an unparseable, zero, or `never` TTL.
fn parse_ttl(raw: &str) -> Result<u64> {
    let s = raw.trim().to_ascii_lowercase();
    anyhow::ensure!(!s.is_empty(), "--ttl is empty; try `24h`");
    anyhow::ensure!(
        s != "never" && s != "0",
        "a key minted over the API must expire: pass a TTL like `24h` (max 30d). \
         A never-expiring key is available only from a shell on the coordinator \
         host, with `probe-rs-fleet coordinator auth-key --ttl 0`."
    );

    let (digits, multiplier) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3_600),
        Some(b'd') => (&s[..s.len() - 1], 86_400),
        _ => (s.as_str(), 1),
    };
    let value: u64 = digits
        .parse()
        .with_context(|| format!("--ttl {raw:?} is not a duration; try `30m`, `24h` or `7d`"))?;
    let secs = value
        .checked_mul(multiplier)
        .context("--ttl is absurdly large")?;
    anyhow::ensure!(
        secs > 0,
        "a key minted over the API must expire: pass a TTL like `24h`"
    );
    Ok(secs)
}

/// The first 16 hex characters of a hash — the handle `revoke` takes.
fn short(hash: &str) -> String {
    hash.chars().take(16).collect()
}

/// Print a freshly minted key. **The only place the secret is printed.**
fn print_created(created: &AuthKeyCreated) {
    println!("Auth key for org '{}':", created.org);
    println!();
    println!("  {}", created.key);
    println!();
    println!("  single use : {}", created.single_use);
    match created.expires {
        Some(e) => println!("  expires    : {e} (epoch seconds)"),
        None => println!("  expires    : never"),
    }
    if !created.tags.is_empty() {
        println!("  tags       : {}", created.tags.join(", "));
    }
    println!("  hash       : {}", short(&created.key_hash));
    println!();
    if created.purpose == "ci" {
        println!("Use it on a CI runner with no workload identity of its own:");
        println!("  probe-rs-fleet ci login --fleet-url <url> --auth-key <key>");
        println!();
        println!("Redeeming it creates a GRANT in this org selecting the tagged boards,");
        println!("so revoking the key also tears down whatever it is holding — not just");
        println!("the credential. This is the weak CI path: prefer GitHub Actions");
        println!("workload identity (`grant --repo owner/name`), which stores no secret");
        println!("anywhere at all. See docs/ci-github-actions.md.");
    } else {
        println!("Enroll a node with it:");
        println!("  probe-rs-fleet agent up --fleet-url <url> --auth-key <key>");
    }
    println!();
    println!("This key is a bearer credential and is not stored anywhere (only its");
    println!("hash). Copy it now; anyone holding it can use it.");
}

/// Print a listing, in the same column layout as `coordinator auth-keys`.
fn print_list(list: &AuthKeyList) {
    if list.keys.is_empty() {
        println!("No auth keys for org '{}'.", list.org);
        return;
    }
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX);
    println!(
        "Auth keys for org '{}' ({} total):",
        list.org,
        list.keys.len()
    );
    println!();
    println!(
        "  {:<16}  {:<8}  {:<10}  {:<12}  {:<12}  {:<16}  TAGS",
        "HASH PREFIX", "PURPOSE", "SINGLE-USE", "EXPIRES", "STATE", "CREATED BY"
    );
    for key in &list.keys {
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
        let created_by = key.created_by.as_deref().unwrap_or("(shell)");
        println!(
            "  {:<16}  {:<8}  {:<10}  {expires:<12}  {state:<12}  {created_by:<16}  {}",
            short(&key.key_hash),
            key.purpose,
            key.single_use,
            key.tags.join(",")
        );
    }
    println!();
    println!("Revoke one with:");
    println!("  probe-rs-fleet auth-key revoke <hash-prefix>");
    if list.keys.iter().any(|k| k.purpose == "ci") {
        // Said out loud because it is the surprising part: a `ci` key carries a
        // grant, so revoking it releases live leases too.
        println!();
        println!("Note a `ci` key also carries a GRANT on this org's boards. Revoking it");
        println!("revokes that grant as well, releasing any lease the runner is holding.");
    }
}

/// Print what a revocation deleted.
fn print_revoked(revoked: &AuthKeyRevoked) {
    for hash in &revoked.revoked {
        println!("Revoked auth key {hash} (org '{}').", revoked.org);
    }
    println!();
    println!("Nodes already enrolled with it keep working: their node tokens are");
    println!("separate credentials. Revoke a node by deleting its row.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_accepts_bare_seconds_and_suffixes() {
        assert_eq!(parse_ttl("3600").unwrap(), 3_600);
        assert_eq!(parse_ttl("90s").unwrap(), 90);
        assert_eq!(parse_ttl("30m").unwrap(), 1_800);
        assert_eq!(parse_ttl("24h").unwrap(), 86_400);
        assert_eq!(parse_ttl("7d").unwrap(), 604_800);
        // Case and surrounding space are not the user's problem.
        assert_eq!(parse_ttl(" 24H ").unwrap(), 86_400);
    }

    /// A forever-key is refused *here*, with the reason and the escape hatch,
    /// rather than as an opaque 400 from the coordinator.
    #[test]
    fn a_never_expiring_ttl_is_refused_locally() {
        for raw in ["0", "never", "0h"] {
            let err = parse_ttl(raw).unwrap_err().to_string();
            assert!(err.contains("must expire"), "{raw}: {err}");
        }
    }

    #[test]
    fn an_unparseable_ttl_names_the_shapes_that_work() {
        let err = parse_ttl("soon").unwrap_err().to_string();
        assert!(err.contains("24h"), "got {err}");
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("12x").is_err());
    }

    /// The rejection codes the coordinator can send all turn into an
    /// actionable sentence, not a bare code.
    #[test]
    fn rejections_become_remediation() {
        let cases = [
            ("forbidden", "not a member"),
            ("ambiguous_prefix", "longer prefix"),
            ("not_found", "no auth key"),
            ("invalid_request", "8 hex"),
        ];
        for (code, needle) in cases {
            let e = ClientError::Rejected {
                status: 400,
                code: code.to_owned(),
            };
            let rendered = describe(&e, "revoking an auth key").to_string();
            assert!(rendered.contains(needle), "{code}: {rendered}");
        }
    }
}
