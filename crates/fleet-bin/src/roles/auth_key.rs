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

/// The `--purpose` spelling that means `ci` but reads like what it is.
///
/// Sugar at the parse boundary only: both mint verbs normalise it to `ci`
/// before anything is stored, so the database holds exactly two purposes, the
/// coordinator's `meta.purpose != AUTH_KEY_PURPOSE_CI` check is untouched, and
/// no listing or migration has to learn a third value. It exists because
/// "ci key" says *per job* about a credential minted `--as <name>`, which is a
/// persistent identity.
///
/// Deliberately **CLI-only**: it is not a wire value, so a browser posting
/// `"purpose":"agent"` to `/api/v1/auth-keys` gets a `400`.
pub(crate) const PURPOSE_AGENT_ALIAS: &str = "agent";

/// Validate an `--as <name>` locally, naming the rule when it fails.
///
/// The coordinator validates it too (with the same function), but a `400`
/// cannot say *which* rule was broken, and this one is easy to break by
/// accident — a hostname with a `:` port, a path-looking name, a leading dash.
/// Never repairs: a repaired name is a **different identity**, and the whole
/// value of the flag is that the operator can retype the same one months later
/// and get the same subject.
///
/// # Errors
///
/// Returns an error naming the charset, the length cap and why they exist.
pub(crate) fn normalise_identity_name(raw: &str) -> Result<String> {
    fleet_proto::ids::normalise_agent_name(raw).with_context(|| {
        format!(
            "`--as {raw}` is not a usable identity name: use 1-{} characters from \
             [a-z0-9._-], starting with a letter or digit. No `:` and no `/`, so a \
             name can never be mistaken for the unnamed `key:<hash>` form or for a \
             `gha/workload:owner/repo` repo subject",
            fleet_proto::ids::MAX_AGENT_NAME_LEN
        )
    })
}

/// The epilogue a named key's mint prints, in both verbs.
///
/// Mandatory, and the sharpest paragraph either verb prints: the feature's
/// whole point is that the grant belongs to the **identity**, not to the key,
/// and that is a security-relevant surprise if it is not said out loud. Shared
/// between `probe-rs-fleet auth-key create` and `coordinator auth-key` so the
/// two cannot drift into telling operators different things.
///
/// Returns the text rather than printing it, so a test can assert the three
/// facts it must carry: one shared grant, other keys' live leases torn down
/// with it, and a surviving key resurrecting it.
pub(crate) fn identity_epilogue(org: &str, name: &str) -> String {
    format!(
        "This key speaks as `{org}/workload:agent:{name}` \u{2014} an identity, not a\n\
         credential. Minting another key with the same `--as` rotates the secret\n\
         without changing the identity: the same grant row, the same audit trail,\n\
         the same concurrency budget.\n\
         \n\
         The trade that makes that work: TWO LIVE KEYS SHARING AN `--as` ARE ONE\n\
         IDENTITY, AND THE GRANT BELONGS TO THE IDENTITY, NOT TO THE KEY. Revoking\n\
         one of them tears down that shared grant and every live lease held under\n\
         the name \u{2014} including another key's runner, mid-job. It does not end the\n\
         identity: a surviving key with the same `--as` re-creates the grant on its\n\
         next redemption, and workload tokens already minted stay valid until they\n\
         expire. So revoking one key of a shared identity is a DISRUPTION, NOT A\n\
         REVOCATION.\n\
         \n\
         To actually retire the agent: revoke every key carrying the name (see the\n\
         IDENTITY column of `auth-key list`), then `probe-rs-fleet grant revoke <id\n\
         from grant list>`. Tokens already issued expire on their own within the\n\
         hour."
    )
}

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
/// rather than bouncing the user off a `400`. So are a `--purpose node` key
/// carrying `--as`, and an `--as` name that breaks the charset rule.
pub async fn create(args: &AuthKeyCreateArgs) -> Result<AuthKeyCreated> {
    let ttl = parse_ttl(&args.ttl)?;
    // `--purpose agent` is a spelling of `ci`, normalised at this boundary so
    // only the epilogue below ever branches on what the operator typed.
    let purpose = if args.purpose == PURPOSE_AGENT_ALIAS {
        "ci"
    } else {
        args.purpose.as_str()
    };
    // A CI key's tags become the *selector* of the grant its redemption
    // synthesises, so an empty set would share every board in the org. Refused
    // here as well as at the coordinator, because the local message can say
    // *why* where a `400` cannot.
    anyhow::ensure!(
        purpose != "ci" || !args.tag.is_empty(),
        "a `--purpose ci` key needs at least one `--tag`: the tags become the \
         selector of the grant it creates, and an empty selector matches every \
         board in the org"
    );
    // Same reasoning as the coordinator's refusal: a node key confers no
    // subject, so a name on one would be a flag that looks effective and is not.
    let subject_name: Option<String> = match &args.subject_name {
        None => None,
        Some(raw) => {
            anyhow::ensure!(
                purpose == "ci",
                "`--as` names the identity a `--purpose ci` (or `agent`) key speaks as; \
                 a node key enrolls a machine and confers no subject for a name to attach to"
            );
            Some(normalise_identity_name(raw)?)
        }
    };
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
    let created = fleet_auth::http_client::create_auth_key_with_purpose(
        &file.url,
        file.pin(),
        &session,
        args.tag.clone(),
        ttl,
        args.multi_use,
        Some(purpose),
        ops,
        subject_name.as_deref(),
    )
    .await
    .map_err(|e| describe(&e, "minting an auth key"))?;
    // Version skew, which is silent otherwise: `/auth/keys` does not
    // `deny_unknown_fields`, so an **older** coordinator ignores `subject_name`
    // and mints an unnamed key while returning `200`. The operator would then
    // believe they have an identity that survives rotation, and only find out
    // on the rotation. The response echoes what was stored, so compare.
    if subject_name.is_some() && created.subject_name != subject_name {
        anyhow::bail!(
            "this coordinator does not support `--as`: it minted an UNNAMED key \
             (it echoed identity {:?}, not {:?}). That key works, but its subject and \
             grant are derived from the key hash, so rotating it forks the identity. \
             Revoke it (`probe-rs-fleet auth-key revoke {}`) and upgrade the coordinator.",
            created.subject_name.as_deref().unwrap_or("none"),
            subject_name.as_deref().unwrap_or("none"),
            short(&created.key_hash)
        );
    }
    Ok(created)
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
             characters, an auth key minted this way must expire (TTL \
             between 1 second and 30 days), and `--as` is only valid on a \
             `--purpose ci`/`agent` key, over [a-z0-9._-] starting with a \
             letter or digit"
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
    if let Some(name) = &created.subject_name {
        println!("  identity   : agent:{name}");
        println!("  subject    : {}/workload:agent:{name}", created.org);
    }
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
        if let Some(name) = &created.subject_name {
            println!();
            println!("{}", identity_epilogue(&created.org, name));
        }
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
        "  {:<16}  {:<8}  {:<10}  {:<12}  {:<12}  {:<16}  {:<16}  TAGS",
        "HASH PREFIX",
        "PURPOSE",
        "SINGLE-USE",
        "EXPIRES",
        "STATE",
        "CREATED BY",
        "IDENTITY"
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
        // Load-bearing rather than decorative: the note below tells an operator
        // to check which keys share an identity *before* revoking one.
        let identity = key.subject_name.as_deref().unwrap_or("-");
        println!(
            "  {:<16}  {:<8}  {:<10}  {expires:<12}  {state:<12}  {created_by:<16}  {identity:<16}  {}",
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
    if list.keys.iter().any(|k| k.subject_name.is_some()) {
        println!();
        println!("Keys sharing an IDENTITY share ONE grant, so revoking any one of them takes");
        println!("that grant and every live lease under the name down with it — including");
        println!("another key's runner. A surviving key with the same identity re-creates the");
        println!("grant on its next redemption.");
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

    /// A bad `--as` names the rule locally, rather than bouncing the operator
    /// off a coarse `400` that cannot say which rule was broken.
    #[test]
    fn an_invalid_identity_name_names_the_rule() {
        for bad in ["key:deadbeef", "owner/repo", "", "-builder", "..", &"x".repeat(65)] {
            let err = normalise_identity_name(bad).unwrap_err().to_string();
            assert!(err.contains("[a-z0-9._-]"), "{bad:?}: {err}");
            assert!(err.contains(bad) || bad.is_empty(), "{bad:?}: {err}");
        }
    }

    /// And a good one is normalised rather than merely accepted — the property
    /// that makes a rotation typed months later the same identity.
    #[test]
    fn a_valid_identity_name_is_lowercased() {
        assert_eq!(normalise_identity_name("  Builder-1 ").unwrap(), "builder-1");
    }

    /// The mandatory epilogue carries the three facts an operator needs about
    /// a shared identity: it is one grant, revoking one key takes another
    /// key's live leases down with it, and a surviving key brings it back.
    /// Asserted rather than only written, because it is the paragraph the
    /// whole design's safety story rests on.
    #[test]
    fn the_identity_epilogue_states_the_trade() {
        let text = identity_epilogue("acme", "builder");
        assert!(text.contains("acme/workload:agent:builder"), "{text}");
        for needle in [
            // one identity, one grant
            "ARE ONE\nIDENTITY",
            // another key's live leases go down with it
            "every live lease held under",
            "another key's runner",
            // a surviving key resurrects it
            "re-creates the grant on its",
            // and how to actually kill the agent
            "grant revoke",
            "DISRUPTION, NOT A\nREVOCATION",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
    }
}
