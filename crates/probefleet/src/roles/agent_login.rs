//! `probe-rs-fleet agent login`: a persistent, self-renewing sandbox session
//! from a stored auth key (architecture §6.7).
//!
//! ```text
//! probe-rs-fleet agent login --fleet-url https://fleet.example \
//!     --auth-key prfk1_… --as desk-bot
//! ```
//!
//! # Who this is for, and what it grants
//!
//! A long-running sandbox — a dev container, a shared build box, an agent's
//! workspace — with **concurrent processes** that all want to reach the fleet.
//! Such a machine can already hold a persistent *identity*
//! (`auth-key create --purpose agent --as <name>`), but not a persistent
//! *session*: the `prfw1_` workload token it authenticates with lives about an
//! hour and nothing renews it. Without this verb every sandbox threads its own
//! hourly `eval "$(probe-rs-fleet ci login …)"` — a cron job or retry wrapper
//! reimplemented per sandbox, which does not even propagate between the
//! concurrent processes sharing the machine.
//!
//! So this verb writes the durable credential to disk, in `[agent]`, and
//! `ctl` / the `probe-rs` shim re-redeem it as the session nears expiry. That
//! **is** the trust decision: anyone who can read the fleet file can mint
//! sessions as that identity until the key is revoked or expires. It is taken
//! per machine, by running this verb, on the stated premise that the operator
//! is content to let this sandbox hold a persistent key in its filesystem
//! reach. It is not a default and no other verb takes it.
//!
//! # How it differs from the two neighbouring verbs
//!
//! * [`crate::roles::login`] is the rotating, single-human path: a GitHub
//!   device flow writing `[user]`, refreshed by *replacing* the session.
//! * [`crate::roles::ci`] writes **no fleet file**, deliberately — a CI
//!   runner's credential comes from the environment and lives for one job, so
//!   persisting it on a shared runner would be the one durable artefact that
//!   path exists to avoid. That rule is unchanged; this verb is a different
//!   machine with a different premise, not a softening of it.
//!
//! # Why a single-use key is refused, and how it is detected
//!
//! In a concurrent sandbox a single-use key breaks on the second *process*, not
//! merely the second hour: the first redemption consumes it and every peer that
//! notices expiry afterwards is refused. So the key must be `--multi-use`, and
//! we would rather find out here than half-work silently.
//!
//! Nothing on the wire says whether a key is single-use — `TokenResponse`
//! carries no such field — so **this verb deliberately redeems twice**. A
//! multi-use key yields two independently valid tokens (the second is stored,
//! the first is left orphaned until its TTL expires: one wasted
//! `workload_token` row per `agent login`, which is the price of the
//! detection). A single-use key's second redemption is *rejected*, and that
//! rejection is the signal.
//!
//! The two failure branches are kept apart on purpose:
//!
//! * a [`ClientError::Rejected`] on the second call means the key is
//!   single-use — nothing is written, and the message says the key has now been
//!   spent;
//! * a transport or malformed-response failure on the second call means we
//!   could not *confirm* anything. The first redemption already succeeded, so
//!   the first token is persisted and a warning says single-use-ness was
//!   unconfirmed. Telling an operator their key is spent because a packet
//!   dropped would be a lie about their credential.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use forgs_client::api::TokenResponse;
use forgs_client::{ClientError, ForgsClient};

use crate::cli::AgentLoginArgs;
use crate::fleet_config::{self, AgentSection};
use crate::paths;

/// What the second redemption told us about the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirmation {
    /// The second redemption succeeded: the key is provably multi-use.
    MultiUse,
    /// The second redemption failed for a transport reason, so nothing about
    /// the key was learnt. See the module docs for why that is not an error.
    Unconfirmed,
}

/// Run `probe-rs-fleet agent login`.
///
/// `fleet` and `config_dir` come from the enclosing `agent` group, which
/// declares them `global = true` — see [`AgentLoginArgs`], which must not
/// redeclare either.
///
/// # Errors
///
/// Returns an error if no coordinator URL is known, the key is not an auth key
/// or the pin/`--as` is malformed (all checked before any request), the
/// redemption is refused, the key turns out to be single-use, or the fleet file
/// cannot be written.
pub async fn run(args: AgentLoginArgs, fleet: &str, config_dir: Option<PathBuf>) -> Result<()> {
    let path = match &config_dir {
        Some(dir) => dir.join(format!("{fleet}.toml")),
        None => paths::fleet_config_path(fleet)?,
    };

    // The URL and pin are remembered across logins, exactly as `login` does:
    // only the first one needs to be told where the fleet is.
    let existing = if path.exists() {
        fleet_config::load(&path).ok()
    } else {
        None
    };
    let url = args
        .fleet_url
        .clone()
        .or_else(|| existing.as_ref().map(|f| f.url.clone()))
        .with_context(|| {
            format!(
                "no coordinator URL for fleet `{fleet}`; pass --fleet-url \
                 <https://fleet.example> the first time (or set \
                 PROBE_RS_FLEET_COORDINATOR)"
            )
        })?;
    let pin_hex = args
        .server_cert_sha256
        .clone()
        .or_else(|| existing.as_ref().and_then(|f| f.server_cert_sha256.clone()));
    if let Some(pin) = &pin_hex {
        anyhow::ensure!(
            fleet_tls::parse_fingerprint(pin).is_some(),
            "--server-cert-sha256 must be 64 hex characters"
        );
    }
    let pin = pin_hex.as_deref().and_then(fleet_tls::parse_fingerprint);

    // Shape checks before any request, so a typo names the flag rather than
    // arriving as a 401 from a machine the user cannot see.
    let auth_key = args.auth_key.trim().to_owned();
    anyhow::ensure!(
        crate::tokens::is_api_key(&auth_key),
        "--auth-key must be an auth key (`prfk1_…`); mint one with \
         `probe-rs-fleet auth-key create --purpose agent --as <name> --multi-use --tag <tag>`"
    );
    // Never repaired, only refused: a repaired name is a *different* identity,
    // and this one is only a display value here anyway.
    let name = match &args.subject_name {
        Some(raw) => Some(crate::roles::auth_key::normalise_identity_name(raw)?),
        None => None,
    };

    let (response, confirmation) = redeem_twice(&url, pin, &auth_key).await?;
    let expires = response.expires;

    let written = fleet_config::update(&path, |f| {
        f.url.clone_from(&url);
        f.server_cert_sha256.clone_from(&pin_hex);
        f.agent = Some(AgentSection {
            auth_key: auth_key.clone(),
            name: name.clone(),
            workload_token: response.token.clone(),
            expires,
        });
    })?;

    for line in summary_lines(fleet, &path, &written, &response, expires, confirmation) {
        println!("{line}");
    }
    Ok(())
}

/// Redeem `auth_key` twice, returning the **second** response.
///
/// The doubling is the single-use detection described in the module docs. On a
/// rejection of the second call the key is single-use and the error says so,
/// naming that the key is now spent; on a transport failure of the second call
/// the first response is returned as [`Confirmation::Unconfirmed`].
async fn redeem_twice(
    url: &str,
    pin: Option<[u8; 32]>,
    auth_key: &str,
) -> Result<(TokenResponse, Confirmation)> {
    let client =
        ForgsClient::new(url, pin).map_err(|e| anyhow::anyhow!("invalid coordinator URL: {e}"))?;
    let first = client
        .exchange_api_key(auth_key)
        .await
        .map_err(|e| crate::roles::ci::describe(&e, "redeeming an agent auth key"))?;

    match client.exchange_api_key(auth_key).await {
        Ok(second) => Ok((second, Confirmation::MultiUse)),
        Err(ClientError::Rejected { .. }) => Err(anyhow::anyhow!("{SINGLE_USE}")),
        Err(e) => {
            // Transport, not rejection: the coordinator did not answer at all,
            // so this says nothing about the key. The first redemption already
            // succeeded — use its token and be honest about what is unknown.
            tracing::warn!(
                error = %e,
                "could not confirm the auth key is multi-use; the confirmation redemption \
                 failed for a transport reason"
            );
            Ok((first, Confirmation::Unconfirmed))
        }
    }
}

/// The refusal for a single-use key.
///
/// Written out rather than assembled, because every clause is load-bearing: why
/// single-use is wrong *here* specifically, that the detection has already spent
/// the key, and the exact mint that replaces it.
const SINGLE_USE: &str = "that auth key is single-use, so it cannot back a persistent session: a \
                          sandbox with concurrent users breaks on the second PROCESS, not merely \
                          the second hour.\nNote the key has now been spent \u{2014} confirming \
                          this costs a redemption, and a single-use key has only one.\nNothing was \
                          written. Mint a replacement with:\n  probe-rs-fleet auth-key create \
                          --purpose agent --as <name> --multi-use --tag <tag>";

/// The lines the summary prints, as data.
///
/// Returned rather than printed so a test can assert the property that matters:
/// **neither the workload token nor the auth key ever appears here.** stdout is
/// a terminal on a machine with other people on it, and a scrollback is an
/// archive.
fn summary_lines(
    fleet: &str,
    path: &Path,
    written: &fleet_config::FleetFile,
    response: &TokenResponse,
    expires: u64,
    confirmation: Confirmation,
) -> Vec<String> {
    let _ = response;
    let name = written
        .agent
        .as_ref()
        .and_then(|a| a.name.as_deref())
        .unwrap_or("(unnamed)");

    let mut lines = vec![
        String::new(),
        format!("Agent session established as `{name}` — fleet `{fleet}`"),
        "  reaches boards through the grants its key's org gave it".to_owned(),
        format!("  expires:    {expires} (epoch seconds)"),
        format!("  {} (0600)", path.display()),
    ];
    if written.user.is_some() || written.node.is_some() {
        // Worth saying: a reader who sees only `[agent]` mentioned may
        // reasonably fear their own login or enrollment was overwritten.
        let mut kept = Vec::new();
        if written.user.is_some() {
            kept.push("[user]");
        }
        if written.node.is_some() {
            kept.push("[node]");
        }
        lines.push(format!(
            "  this machine's existing {} preserved",
            kept.join(" and ")
        ));
    }
    lines.push(String::new());
    lines.push(
        "`ctl` and the `probe-rs` shim now refresh this session automatically as it".to_owned(),
    );
    lines.push("nears expiry — no cron job, no hourly `eval`, and concurrent processes".to_owned());
    lines.push("in this sandbox share the refreshed token through the fleet file.".to_owned());
    lines.push(String::new());
    lines.push("The auth key is stored in that file. Anyone who can read it can mint".to_owned());
    lines.push("sessions as this identity until the key is revoked or expires.".to_owned());
    match confirmation {
        Confirmation::MultiUse => {
            lines.push(
                "The key was confirmed multi-use by a second redemption, whose token is left"
                    .to_owned(),
            );
            lines.push("unused until its TTL expires.".to_owned());
        }
        Confirmation::Unconfirmed => {
            lines.push(
                "The key could NOT be confirmed multi-use (the second redemption failed for a"
                    .to_owned(),
            );
            lines.push(
                "transport reason). If it turns out to be single-use, refreshes will fail."
                    .to_owned(),
            );
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::mint_string;
    use forgs::TokenKind;

    fn args(auth_key: &str) -> AgentLoginArgs {
        AgentLoginArgs {
            fleet_url: Some("http://127.0.0.1:1".to_owned()),
            server_cert_sha256: None,
            auth_key: auth_key.to_owned(),
            subject_name: None,
        }
    }

    fn response() -> TokenResponse {
        TokenResponse {
            token: "prfw1_verysecret".to_owned(),
            expires: 4_600,
            username: None,
            user_id: None,
            refresh_token: None,
        }
    }

    /// The property the whole summary exists to have: it says what happened
    /// without printing either credential.
    #[test]
    fn the_summary_never_prints_a_credential() {
        let key = mint_string(TokenKind::ApiKey);
        let file = fleet_config::FleetFile {
            url: "https://fleet.example".to_owned(),
            agent: Some(AgentSection {
                auth_key: key.clone(),
                name: Some("desk-bot".to_owned()),
                workload_token: response().token,
                expires: 4_600,
            }),
            ..fleet_config::FleetFile::default()
        };
        let text = summary_lines(
            "default",
            Path::new("/tmp/default.toml"),
            &file,
            &response(),
            4_600,
            Confirmation::MultiUse,
        )
        .join("\n");

        assert!(!text.contains(&key), "the auth key must never be printed");
        assert!(
            !text.contains("prfw1_verysecret"),
            "the workload token must never be printed"
        );
        assert!(text.contains("desk-bot"), "got: {text}");
        assert!(text.contains("refresh"), "got: {text}");
    }

    /// A reader must be told their own credentials survived.
    #[test]
    fn the_summary_names_the_tables_it_preserved() {
        let file = fleet_config::FleetFile {
            url: "https://fleet.example".to_owned(),
            user: Some(crate::fleet_config::UserSection {
                session_token: mint_string(TokenKind::Session),
                username: None,
                user_id: None,
                org: None,
                expires: None,
                refresh_token: None,
            }),
            agent: Some(AgentSection {
                auth_key: mint_string(TokenKind::ApiKey),
                name: None,
                workload_token: response().token,
                expires: 4_600,
            }),
            ..fleet_config::FleetFile::default()
        };
        let text = summary_lines(
            "default",
            Path::new("/tmp/default.toml"),
            &file,
            &response(),
            4_600,
            Confirmation::MultiUse,
        )
        .join("\n");
        assert!(text.contains("[user]"), "got: {text}");
        assert!(text.contains("(unnamed)"), "got: {text}");
    }

    /// An unconfirmed key is described as unconfirmed, never as spent.
    #[test]
    fn an_unconfirmed_key_is_not_reported_as_single_use() {
        let file = fleet_config::FleetFile {
            url: "https://fleet.example".to_owned(),
            agent: Some(AgentSection {
                auth_key: mint_string(TokenKind::ApiKey),
                name: None,
                workload_token: response().token,
                expires: 4_600,
            }),
            ..fleet_config::FleetFile::default()
        };
        let text = summary_lines(
            "default",
            Path::new("/tmp/default.toml"),
            &file,
            &response(),
            4_600,
            Confirmation::Unconfirmed,
        )
        .join("\n");
        assert!(text.contains("NOT be confirmed"), "got: {text}");
        assert!(!text.contains("spent"), "got: {text}");
    }

    /// The refusal has to carry all three facts, since the operator's key is
    /// gone by the time they read it.
    #[test]
    fn the_single_use_refusal_names_the_process_case_the_spend_and_the_mint() {
        assert!(SINGLE_USE.contains("PROCESS"));
        assert!(SINGLE_USE.contains("spent"));
        assert!(SINGLE_USE.contains("--multi-use"));
        assert!(SINGLE_USE.contains("Nothing was written"));
    }

    /// Every shape check fires before a socket is opened, and leaves no file.
    ///
    /// The URL is a closed port, so a regression that reached the network would
    /// fail with a transport error rather than these messages.
    #[tokio::test]
    async fn malformed_input_is_refused_before_any_request_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let key = mint_string(TokenKind::ApiKey);

        // Not an auth key: a session token, and outright garbage.
        for bad in [mint_string(TokenKind::Session), "garbage".to_owned()] {
            let err = run(args(&bad), "default", Some(tmp.path().to_path_buf()))
                .await
                .expect_err("wrong token kind");
            assert!(format!("{err:#}").contains("prfk1_"), "got: {err:#}");
        }

        // A malformed pin.
        let mut a = args(&key);
        a.server_cert_sha256 = Some("nope".to_owned());
        let err = run(a, "default", Some(tmp.path().to_path_buf()))
            .await
            .expect_err("bad pin");
        assert!(format!("{err:#}").contains("64 hex"), "got: {err:#}");

        // An `--as` that is not a usable identity name.
        let mut a = args(&key);
        a.subject_name = Some("Not/A Name".to_owned());
        let err = run(a, "default", Some(tmp.path().to_path_buf()))
            .await
            .expect_err("bad --as");
        assert!(format!("{err:#}").contains("--as"), "got: {err:#}");

        assert!(
            !tmp.path().join("default.toml").exists(),
            "a refused login must leave no fleet file behind"
        );
    }

    /// With neither a flag nor a remembered URL there is nothing to dial.
    #[tokio::test]
    async fn a_first_agent_login_needs_a_url() {
        let tmp = tempfile::tempdir().unwrap();
        let key = mint_string(TokenKind::ApiKey);
        let mut a = args(&key);
        a.fleet_url = None;
        let err = run(a, "default", Some(tmp.path().to_path_buf()))
            .await
            .expect_err("no URL");
        assert!(format!("{err:#}").contains("--fleet-url"), "got: {err:#}");
    }
}
