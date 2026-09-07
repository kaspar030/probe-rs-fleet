//! The per-fleet config file: `~/.config/probe-rs-fleet/fleets/<name>.toml`.
//!
//! One file per fleet, holding everything this machine knows about that fleet:
//! where it is, how to verify it, and whichever credentials this machine holds
//! for it.
//!
//! ```toml
//! url = "https://fleet.example"
//! # server_cert_sha256 = "<64 hex>"
//!
//! [user]                # written by `probe-rs-fleet login`
//! session_token = "prfs1_…"
//! org = "gh-4242"
//!
//! [node]                # written by `probe-rs-fleet share` / `node up`
//! node_token = "prfn1_…"
//! node_id = "gh-4242/rpi-lab-1"
//! coordinator_token_pubkey = "<64 hex>"
//!
//! [agent]               # written by `probe-rs-fleet agent login`
//! auth_key = "prffk1_…"        # the durable credential
//! name = "desk-bot"            # the --as identity, display only
//! workload_token = "prfw1_…"   # the current short-lived session
//! expires = 1788999999         # epoch seconds
//! ```
//!
//! # Why both tables live in one file, and why the tokens do not merge
//!
//! A laptop is both a user and a node. Under the old per-role trees that needed
//! two unrelated enrollments with nothing tying them to the same fleet. Here it
//! is one file with two tables: a headless Pi has only `[node]`, a CI runner has
//! neither.
//!
//! The two tokens stay **distinct credentials**. Merging them would make a
//! compromised Pi — a device sitting on a shelf in an office, reachable by
//! anyone who walks past — equivalent to a compromised user account.
//!
//! `[agent]` is the third case: a persistent, multi-user sandbox that holds an
//! *identity* rather than a human session. It is the only table that stores a
//! **durable** credential — `[agent].auth_key` lets anyone who reads it mint
//! fresh sessions as that identity until the key is revoked or expires, which
//! is strictly stronger than either of the other two — and it is written only
//! by a verb (`agent login`) whose documentation names that trust decision.
//!
//! # Writing: read-modify-write, then atomic rename
//!
//! Three independent writers touch this file: `login` refreshing `[user]`, a
//! running agent persisting a rotated `[node]` token, and — the high-frequency
//! one — any `ctl` / sidecar invocation re-redeeming `[agent]`'s workload
//! token as it nears expiry. Every writer therefore re-reads the current file,
//! patches only its own table, and renames a 0600 temp file over the original.
//!
//! The residual race (a login landing at the same instant as a token rotation)
//! is a lost update, recoverable by re-running the command. There is no file
//! locking in v1 — but note the asymmetry: re-running `login` costs a browser
//! tab, whereas silently clobbering a node credential costs a physical visit to
//! the Pi. That is why the node writer patches rather than rewrites.
//!
//! The `[agent]` writer is the benign case: a lost update there costs one
//! redundant redemption, because re-redeeming a multi-use auth key invalidates
//! nothing (see [`ensure_fresh_agent_session`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths;
use crate::secrets::write_secret;

/// The on-disk shape of `fleets/<name>.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetFile {
    /// Base URL of the coordinator (`https://fleet.example`), or a bare
    /// `host:port` (which assumes https).
    pub url: String,
    /// Optional pinned coordinator server-certificate SHA-256, for a
    /// self-hosted deployment with no publicly trusted certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_cert_sha256: Option<String>,
    /// This machine's *user* credential for the fleet, if it has logged in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<UserSection>,
    /// This machine's *node* credential for the fleet, if it is enrolled as one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeSection>,
    /// This machine's *persistent agent* credential for the fleet, if
    /// `probe-rs-fleet agent login` has run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentSection>,
}

/// The `[user]` table, written by `probe-rs-fleet login`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSection {
    /// The user's bearer session token (`prfs1_…`). Short-lived, refreshable.
    pub session_token: String,
    /// The org id the session belongs to.
    ///
    /// For a personal org this is `gh-<github_user_id>`, not the login: GitHub
    /// logins can be renamed and reused, so nothing keys off one.
    pub org: String,
    /// The GitHub login, cached for the CLI's summary line. Display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    /// When the session token expires (epoch seconds), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
}

/// The `[node]` table, written by `probe-rs-fleet share` / `node up` and refreshed by
/// the running agent when the coordinator rotates its token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSection {
    /// This node's bearer token (`prfn1_…`).
    pub node_token: String,
    /// The node id the coordinator assigned at enrollment.
    pub node_id: String,
    /// Hex-encoded ed25519 public key of the coordinator's capability-token
    /// signer, used to verify per-lease tokens.
    pub coordinator_token_pubkey: String,
    /// The token this node used before the most recent rotation.
    ///
    /// Kept for exactly one reconnect: if the new token is refused (the ack
    /// never reached the coordinator), the agent falls back once rather than
    /// bricking itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_node_token: Option<String>,
}

/// The `[agent]` table, written by `probe-rs-fleet agent login` and refreshed
/// in place by `ctl` / the `probe-rs` sidecar shim as the workload token nears
/// expiry.
///
/// This is the *persistent sandbox* case: a long-running, possibly multi-user
/// machine that holds an identity (`auth-key create --purpose agent --as
/// <name>`) rather than a human session. The durable credential lives here so
/// that no cron job or hourly `eval "$(probe-rs-fleet ci login …)"` wrapper has
/// to be reimplemented per sandbox.
///
/// # Why there is no `previous_workload_token`
///
/// `[node]` keeps one because rotation *replaces*: a lost ack would otherwise
/// brick the node. Redeeming a `--multi-use` auth key is **not** a rotation.
/// The coordinator's `consume_auth_key` stamps `consumed_at` only when
/// `single_use != 0`, so a multi-use key is never consumed; each redemption
/// mints an independent `workload_token` row and upserts the *same* grant row
/// (its id is derived from `(org, name)`). Nothing is invalidated, so there is
/// no lost credential to rescue and no advisory locking needed for correctness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSection {
    /// The durable auth key (`prffk1_…`) this session is re-minted from.
    ///
    /// Storing it is a granted trust decision, taken per machine by running
    /// `agent login`: the premise is a sandbox the operator owns and is content
    /// to let hold a persistent identity in its filesystem reach.
    pub auth_key: String,
    /// The `--as` identity name the key speaks as. Display only.
    ///
    /// **Not verified**: the redemption response does not echo the subject
    /// name, so this is what the operator typed, not what the coordinator
    /// resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The current short-lived workload token (`prfw1_…`).
    pub workload_token: String,
    /// When that token expires (epoch seconds).
    ///
    /// Required, unlike `[user].expires`. A self-renewing session has to know
    /// when to renew without a round trip, and the two `None` policies both
    /// misbehave here: "no expiry → just use it" never refreshes, and
    /// "unknown → redeem" makes every invocation redeem, which is a permanent
    /// herd. Both workload mint paths on the coordinator always set an expiry,
    /// so requiring it costs nothing real.
    pub expires: u64,
}

/// The comment header every rendered fleet file carries.
const HEADER: &str = r"# probe-rs-fleet — per-fleet configuration
#
# One file per fleet, at ~/.config/probe-rs-fleet/fleets/<name>.toml. Select it
# with `--fleet <name>` or PROBE_RS_FLEET; the default is `default`.
#
# THIS FILE HOLDS BEARER CREDENTIALS and is written 0600. [user].session_token
# lets anyone act as you until it expires; [node].node_token lets anyone act as
# this node until it rotates or the node row is deleted; [agent].auth_key is the
# strongest of the three — it does not merely act, it MINTS: anyone who reads it
# can keep minting sessions as that identity until the key is revoked or expires.
#
# The tokens are deliberately distinct: merging them would make a compromised
# node equivalent to a compromised user account.
#
# Managed by `probe-rs-fleet login` ([user]), `share` / `node up` ([node]) and
# `agent login` ([agent], refreshed in place by `ctl` and the probe-rs shim).
# All of them preserve the others' tables, so one machine can hold all three.
";

/// Load a fleet file from an explicit path.
///
/// # Errors
///
/// Returns an error if the file cannot be read, the TOML is malformed, or a
/// credential/pin in it is not of the shape it claims.
pub fn load(path: &Path) -> Result<FleetFile> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read fleet config {}", path.display()))?;
    let file: FleetFile = toml::from_str(&text)
        .with_context(|| format!("failed to parse fleet config {}", path.display()))?;
    validate(&file).with_context(|| format!("invalid fleet config {}", path.display()))?;
    Ok(file)
}

/// Load the named fleet's file from the XDG config path.
///
/// # Errors
///
/// See [`load`]; also errors if the XDG path or fleet name cannot be resolved.
pub fn load_named(fleet: &str) -> Result<FleetFile> {
    let path = paths::fleet_config_path(fleet)?;
    anyhow::ensure!(
        path.exists(),
        "no config for fleet `{fleet}` at {}; run `probe-rs-fleet login --fleet {fleet} \
         --fleet-url <url>` first",
        path.display()
    );
    load(&path)
}

/// Load the named fleet's file, or `None` if it does not exist or is unreadable.
///
/// Used where a fleet file is a *fallback* for explicit flags: a missing file is
/// not an error there, it just means the flags must supply everything.
#[must_use]
pub fn load_named_opt(fleet: &str) -> Option<FleetFile> {
    let path = paths::fleet_config_path(fleet).ok()?;
    if !path.exists() {
        return None;
    }
    load(&path).ok()
}

/// Validate a parsed fleet file.
///
/// Catching a wrong-kind token here, where the operator can see what they typed,
/// beats a 403 on a WebSocket upgrade a long way from the mistake.
fn validate(file: &FleetFile) -> Result<()> {
    anyhow::ensure!(!file.url.trim().is_empty(), "`url` must not be empty");
    if let Some(pin) = &file.server_cert_sha256 {
        anyhow::ensure!(
            fleet_tls::parse_fingerprint(pin).is_some(),
            "`server_cert_sha256` must be 64 hex characters"
        );
    }
    if let Some(user) = &file.user {
        anyhow::ensure!(
            fleet_auth::OpaqueToken::parse(&user.session_token)
                .is_ok_and(|t| t.kind() == fleet_auth::TokenKind::Session),
            "[user].session_token must be a session token (`prfs1_…`)"
        );
        anyhow::ensure!(!user.org.trim().is_empty(), "[user].org must not be empty");
    }
    if let Some(node) = &file.node {
        anyhow::ensure!(
            fleet_auth::OpaqueToken::parse(&node.node_token)
                .is_ok_and(|t| t.kind() == fleet_auth::TokenKind::Node),
            "[node].node_token must be a node token (`prfn1_…`)"
        );
        anyhow::ensure!(
            !node.node_id.trim().is_empty(),
            "[node].node_id must not be empty"
        );
        anyhow::ensure!(
            node.coordinator_token_pubkey.len() == 64
                && node
                    .coordinator_token_pubkey
                    .chars()
                    .all(|c| c.is_ascii_hexdigit()),
            "[node].coordinator_token_pubkey must be 64 hex characters"
        );
    }
    if let Some(agent) = &file.agent {
        anyhow::ensure!(
            fleet_auth::OpaqueToken::parse(&agent.auth_key)
                .is_ok_and(|t| t.kind() == fleet_auth::TokenKind::AuthKey),
            "[agent].auth_key must be an auth key (`prffk1_…`)"
        );
        anyhow::ensure!(
            fleet_auth::OpaqueToken::parse(&agent.workload_token)
                .is_ok_and(|t| t.kind() == fleet_auth::TokenKind::Workload),
            "[agent].workload_token must be a workload token (`prfw1_…`)"
        );
        if let Some(name) = &agent.name {
            anyhow::ensure!(
                !name.trim().is_empty(),
                "[agent].name must not be empty (omit it instead)"
            );
        }
    }
    Ok(())
}

/// Render a fleet file as TOML with the standard header.
///
/// # Errors
///
/// Returns an error if the value cannot be serialised (it always can; the
/// signature is fallible because `toml` says so).
pub fn render(file: &FleetFile) -> Result<String> {
    let body = toml::to_string_pretty(file).context("rendering fleet config")?;
    Ok(format!("{HEADER}\n{body}"))
}

/// Write a fleet file atomically, 0600.
///
/// Temp file + rename, so a crash or a concurrent reader never observes a
/// half-written credential file. The temp file is created 0600 *before* the
/// rename, so the secret is never briefly world-readable.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or either step fails.
pub fn save_atomic(path: &Path, file: &FleetFile) -> Result<()> {
    let text = render(file)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating fleet config dir {}", dir.display()))?;
    }
    let tmp = tmp_path(path);
    write_secret(&tmp, text.as_bytes()).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| {
        format!(
            "renaming {} onto {} (fleet config write)",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

/// The temp path a fleet file is written through before being renamed.
///
/// Same directory as the target, so the rename stays within one filesystem and
/// is therefore atomic; a `/tmp` staging file would not be.
fn tmp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("fleet.toml");
    path.with_file_name(format!(".{name}.{}.tmp", std::process::id()))
}

/// Read-modify-write one fleet file: apply `patch` to the current contents (or a
/// fresh default) and save atomically.
///
/// This is the *only* supported way to change a fleet file, because it is what
/// keeps a `login` from dropping a node credential and vice versa.
///
/// # Errors
///
/// Returns an error if the existing file is unparseable, the patched result is
/// invalid, or the write fails.
pub fn update(path: &Path, edit: impl FnOnce(&mut FleetFile)) -> Result<FleetFile> {
    let mut file = if path.exists() {
        load(path)?
    } else {
        FleetFile::default()
    };
    edit(&mut file);
    validate(&file)?;
    save_atomic(path, &file)?;
    Ok(file)
}

/// Read-modify-write the named fleet's file.
///
/// # Errors
///
/// See [`update`].
pub fn update_named(fleet: &str, edit: impl FnOnce(&mut FleetFile)) -> Result<FleetFile> {
    let target = paths::fleet_config_path(fleet)?;
    update(&target, edit)
}

impl FleetFile {
    /// The pinned coordinator server-certificate hash, decoded.
    #[must_use]
    pub fn pin(&self) -> Option<[u8; 32]> {
        self.server_cert_sha256
            .as_deref()
            .and_then(fleet_tls::parse_fingerprint)
    }
}

/// Seconds before expiry at which a session token is proactively refreshed.
const REFRESH_SKEW_SECS: u64 = 60;

/// Return a usable session token for `fleet`, refreshing it if it is about to
/// expire, and writing any fresh token back to the file.
///
/// # Why refresh on a deadline rather than on a 401
///
/// The coordinator's refresh **replaces**: it deletes the old session on
/// success. Two `ctl` invocations racing near expiry would both refresh, and the
/// loser's token would already be dead — an auth failure a long way from the
/// cause. Refreshing ahead of the deadline does not remove that race, so the
/// failure path below re-reads the file once and retries with whatever the other
/// process wrote. One retry, no loop: if the token in the file is still refused
/// after that, the credential is genuinely bad and the user should re-`login`.
///
/// # Errors
///
/// Returns an error if the fleet file has no `[user]` table, or a refresh both
/// fails and leaves no usable token.
pub async fn ensure_fresh_session(fleet: &str, file: &FleetFile) -> Result<String> {
    let user = file
        .user
        .as_ref()
        .context("this fleet has no [user] credential; run `probe-rs-fleet login`")?;

    let Some(expires) = user.expires else {
        // No recorded expiry (an externally minted token): nothing to decide on,
        // use it and let the coordinator judge.
        return Ok(user.session_token.clone());
    };
    let now = now_epoch_secs();
    if expires > now.saturating_add(REFRESH_SKEW_SECS) {
        return Ok(user.session_token.clone());
    }

    match fleet_auth::http_client::refresh_session(&file.url, file.pin(), &user.session_token).await
    {
        Ok(response) => {
            let token = response.token.clone();
            // Best-effort persist: a token we cannot write down still works for
            // this invocation, and failing the command over it would be worse
            // than the next run refreshing again.
            if let Err(e) = update_named(fleet, |f| {
                if let Some(u) = f.user.as_mut() {
                    u.session_token.clone_from(&response.token);
                    u.expires = response.expires;
                    u.org.clone_from(&response.org);
                }
            }) {
                tracing::warn!(error = %e, "refreshed the session token but could not save it");
            }
            Ok(token)
        }
        Err(e) => {
            // Lost the refresh race, most likely: another process refreshed and
            // our token is already deleted. Re-read once and use what it wrote.
            if let Some(reread) = load_named_opt(fleet) {
                if let Some(u) = reread.user {
                    if u.session_token != user.session_token {
                        return Ok(u.session_token);
                    }
                }
            }
            Err(anyhow::anyhow!(
                "session token refresh failed ({e}); run `probe-rs-fleet login --fleet {fleet}`"
            ))
        }
    }
}

/// Return a usable **agent** workload token for `fleet`, re-redeeming the
/// stored auth key if the current one is about to expire, and writing the fresh
/// token back to the file.
///
/// The `[agent]` sibling of [`ensure_fresh_session`], and deliberately built
/// from the same parts: the same [`REFRESH_SKEW_SECS`] deadline, the same
/// best-effort persist, the same single re-read on failure.
///
/// # Why this one cannot lose a race
///
/// [`ensure_fresh_session`] races a **replacing** refresh: the coordinator
/// deletes the old session, so the loser of a concurrent refresh holds a token
/// that is already dead. Redeeming a `--multi-use` auth key is not a rotation —
/// `consume_auth_key` stamps `consumed_at` only for a single-use key, and each
/// redemption mints an independent `workload_token` row — so N processes
/// redeeming at once all succeed and all their tokens stay valid.
///
/// The cost is therefore churn, not breakage, and the damping is correspondingly
/// cheap: **re-read the file immediately before redeeming**, and skip our own
/// redemption if a peer has already written a fresher token. No jitter, no lock
/// file — those would buy correctness that is not at stake here.
///
/// # Errors
///
/// Returns an error if the fleet file has no `[agent]` table, or the redemption
/// fails and no peer has left a usable token behind. Both name
/// `probe-rs-fleet agent login` as the fix.
pub async fn ensure_fresh_agent_session(fleet: &str, file: &FleetFile) -> Result<String> {
    let agent = file.agent.as_ref().with_context(|| {
        format!(
            "this fleet has no [agent] credential; run `probe-rs-fleet agent login \
             --fleet {fleet} --auth-key prffk1_\u{2026}`"
        )
    })?;

    let now = now_epoch_secs();
    let fresh_enough = |expires: u64| expires > now.saturating_add(REFRESH_SKEW_SECS);
    if fresh_enough(agent.expires) {
        return Ok(agent.workload_token.clone());
    }

    // Herd damping. Our `FleetFile` is a snapshot; a peer process on this same
    // sandbox may have redeemed since it was loaded. Re-reading costs one
    // `stat` + parse and saves a redundant round trip and a redundant
    // `workload_token` row.
    if let Some(peer) = reread_agent(fleet) {
        if fresh_enough(peer.expires) {
            return Ok(peer.workload_token);
        }
    }

    match fleet_auth::http_client::exchange_workload_key(
        &file.url,
        file.pin(),
        agent.auth_key.trim(),
    )
    .await
    {
        Ok(response) => {
            let expires = response.expires.context(
                "the coordinator returned a workload token with no expiry, so a \
                 self-renewing agent session cannot know when to renew",
            )?;
            let token = response.token.clone();
            // Best-effort persist: a token we cannot write down still works for
            // this invocation, and failing the command over it would be worse
            // than the next run redeeming again.
            if let Err(e) = update_named(fleet, |f| {
                if let Some(a) = f.agent.as_mut() {
                    a.workload_token.clone_from(&response.token);
                    a.expires = expires;
                }
            }) {
                tracing::warn!(error = %e, "redeemed the agent auth key but could not save the token");
            }
            Ok(token)
        }
        Err(e) => {
            // A peer may have redeemed successfully in the window between our
            // re-read and this failure (or the key may have been re-issued by
            // a fresh `agent login`). One re-read, no loop.
            if let Some(peer) = reread_agent(fleet) {
                if peer.workload_token != agent.workload_token {
                    return Ok(peer.workload_token);
                }
            }
            Err(anyhow::anyhow!(
                "redeeming the agent auth key failed ({e}); run \
                 `probe-rs-fleet agent login --fleet {fleet}`"
            ))
        }
    }
}

/// Re-read the named fleet's `[agent]` table from disk, if there is one.
///
/// Note this resolves the **XDG** path through [`load_named_opt`] and therefore
/// ignores any `--config-dir` override: that flag reaches `load`/`update` with
/// an explicit path, not the `*_named` helpers. A test that wants this code path
/// must point `XDG_CONFIG_HOME` at its tempdir (under the crate's `ENV_LOCK`)
/// rather than passing a config dir that is silently ignored.
fn reread_agent(fleet: &str) -> Option<AgentSection> {
    load_named_opt(fleet).and_then(|f| f.agent)
}

/// Current time in epoch seconds.
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    // The two `ensure_fresh_agent_session` tests below repoint
    // `XDG_CONFIG_HOME` under the crate's `ENV_LOCK` and then await. What the
    // guard protects is the *process environment* for the whole test body, so
    // holding it across the await is the requirement, not an oversight; an
    // async-aware mutex would not change it. Each test is its own
    // `#[tokio::test]` runtime, so there is no task to starve.
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use fleet_auth::{OpaqueToken, TokenKind};

    fn session_token() -> String {
        OpaqueToken::mint(TokenKind::Session).to_secret_string()
    }

    fn node_token() -> String {
        OpaqueToken::mint(TokenKind::Node).to_secret_string()
    }

    fn auth_key() -> String {
        OpaqueToken::mint(TokenKind::AuthKey).to_secret_string()
    }

    fn workload_token() -> String {
        OpaqueToken::mint(TokenKind::Workload).to_secret_string()
    }

    fn user_section() -> UserSection {
        UserSection {
            session_token: session_token(),
            org: "gh-4242".to_owned(),
            login: Some("kaspar".to_owned()),
            expires: Some(9_999_999_999),
        }
    }

    fn node_section() -> NodeSection {
        NodeSection {
            node_token: node_token(),
            node_id: "gh-4242/rpi-lab-1".to_owned(),
            coordinator_token_pubkey: "ab".repeat(32),
            previous_node_token: None,
        }
    }

    fn agent_section() -> AgentSection {
        AgentSection {
            auth_key: auth_key(),
            name: Some("desk-bot".to_owned()),
            workload_token: workload_token(),
            expires: 9_999_999_999,
        }
    }

    #[test]
    fn a_file_with_all_three_tables_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("default.toml");
        let file = FleetFile {
            url: "https://fleet.example".to_owned(),
            server_cert_sha256: Some("cd".repeat(32)),
            user: Some(user_section()),
            node: Some(node_section()),
            agent: Some(agent_section()),
        };
        save_atomic(&path, &file).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.url, "https://fleet.example");
        assert_eq!(loaded.pin(), Some([0xcdu8; 32]));
        assert_eq!(
            loaded.user.as_ref().unwrap().session_token,
            file.user.as_ref().unwrap().session_token
        );
        assert_eq!(loaded.node.as_ref().unwrap().node_id, "gh-4242/rpi-lab-1");
        let agent = loaded.agent.as_ref().unwrap();
        assert_eq!(agent.auth_key, file.agent.as_ref().unwrap().auth_key);
        assert_eq!(agent.name.as_deref(), Some("desk-bot"));
        assert_eq!(agent.expires, 9_999_999_999);
    }

    /// The laptop case, and the reason every writer is read-modify-write: a
    /// `login` must not drop the node credential, because getting it back means
    /// re-enrolling the machine.
    #[test]
    fn updating_one_table_preserves_the_other() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("default.toml");

        // The Pi enrolls first.
        update(&path, |f| {
            f.url = "https://fleet.example".to_owned();
            f.node = Some(node_section());
        })
        .unwrap();
        let node_before = load(&path).unwrap().node.unwrap();

        // Then the human logs in on the same machine.
        update(&path, |f| f.user = Some(user_section())).unwrap();
        let after_login = load(&path).unwrap();
        assert_eq!(
            after_login.node.as_ref().unwrap().node_token,
            node_before.node_token
        );
        assert!(after_login.user.is_some());

        // And the sandbox on the same machine logs its agent in.
        update(&path, |f| f.agent = Some(agent_section())).unwrap();
        let after_agent = load(&path).unwrap();
        assert_eq!(
            after_agent.node.as_ref().unwrap().node_token,
            node_before.node_token
        );
        assert_eq!(
            after_agent.user.as_ref().unwrap().session_token,
            after_login.user.as_ref().unwrap().session_token
        );

        // The high-frequency writer: an agent session refresh patches only
        // `[agent]`'s token and expiry.
        let refreshed = workload_token();
        update(&path, |f| {
            let a = f.agent.as_mut().unwrap();
            a.workload_token.clone_from(&refreshed);
            a.expires = 1_234_567;
        })
        .unwrap();
        let after_refresh = load(&path).unwrap();
        assert_eq!(
            after_refresh.agent.as_ref().unwrap().workload_token,
            refreshed
        );
        assert_eq!(
            after_refresh.agent.as_ref().unwrap().auth_key,
            after_agent.agent.as_ref().unwrap().auth_key
        );
        assert_eq!(
            after_refresh.node.as_ref().unwrap().node_token,
            node_before.node_token
        );
        assert_eq!(
            after_refresh.user.as_ref().unwrap().session_token,
            after_login.user.as_ref().unwrap().session_token
        );

        // Then the coordinator rotates the node token.
        let rotated = node_token();
        update(&path, |f| {
            let n = f.node.as_mut().unwrap();
            n.previous_node_token = Some(std::mem::replace(&mut n.node_token, rotated.clone()));
        })
        .unwrap();
        let after_rotation = load(&path).unwrap();
        assert_eq!(after_rotation.node.as_ref().unwrap().node_token, rotated);
        assert_eq!(
            after_rotation.node.as_ref().unwrap().previous_node_token,
            Some(node_before.node_token)
        );
        // The user credential survived the rotation.
        assert_eq!(
            after_rotation.user.as_ref().unwrap().session_token,
            after_login.user.as_ref().unwrap().session_token
        );
        // ...and so did the agent session.
        assert_eq!(
            after_rotation.agent.as_ref().unwrap().workload_token,
            refreshed
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_0600_after_the_atomic_rename() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("default.toml");
        update(&path, |f| {
            f.url = "https://fleet.example".to_owned();
            f.user = Some(user_section());
            // `[agent]` holds the *durable* credential, so its 0600 matters
            // most of the three.
            f.agent = Some(agent_section());
        })
        .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // The staging file must not be left behind.
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    /// A node token in `[user]` would authenticate against `/agent` and be
    /// refused with a 403 on `/client` — a confusing failure a long way from the
    /// mistake.
    #[test]
    fn wrong_token_kinds_and_bad_pins_are_rejected() {
        let mut file = FleetFile {
            url: "https://fleet.example".to_owned(),
            user: Some(UserSection {
                session_token: node_token(),
                org: "gh-1".to_owned(),
                login: None,
                expires: None,
            }),
            ..FleetFile::default()
        };
        assert!(validate(&file).is_err());

        file.user = Some(user_section());
        file.server_cert_sha256 = Some("nope".to_owned());
        assert!(validate(&file).is_err());

        file.server_cert_sha256 = None;
        file.node = Some(NodeSection {
            node_token: session_token(),
            ..node_section()
        });
        assert!(validate(&file).is_err());

        file.node = Some(NodeSection {
            coordinator_token_pubkey: "zz".repeat(32),
            ..node_section()
        });
        assert!(validate(&file).is_err());

        file.node = Some(node_section());
        assert!(validate(&file).is_ok());

        // A session token where the durable auth key belongs: the file would
        // "work" once and then never renew.
        file.agent = Some(AgentSection {
            auth_key: session_token(),
            ..agent_section()
        });
        assert!(validate(&file).is_err());

        // ...and an auth key where the short-lived session belongs, which would
        // put the durable credential on the wire as a bearer.
        file.agent = Some(AgentSection {
            workload_token: auth_key(),
            ..agent_section()
        });
        assert!(validate(&file).is_err());

        file.agent = Some(AgentSection {
            name: Some("  ".to_owned()),
            ..agent_section()
        });
        assert!(validate(&file).is_err());

        file.agent = Some(agent_section());
        assert!(validate(&file).is_ok());
    }

    #[test]
    fn an_empty_url_is_rejected() {
        let file = FleetFile {
            url: "  ".to_owned(),
            ..FleetFile::default()
        };
        assert!(validate(&file).is_err());
    }

    /// A fleet file may legitimately hold neither credential (a CI runner that
    /// takes its token from the environment), so that must parse.
    #[test]
    fn a_url_only_file_is_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ci.toml");
        update(&path, |f| f.url = "https://fleet.example".to_owned()).unwrap();
        let loaded = load(&path).unwrap();
        assert!(loaded.user.is_none() && loaded.node.is_none() && loaded.agent.is_none());
    }

    // --- ensure_fresh_agent_session ---------------------------------------

    /// A file with no `[agent]` names the verb that writes one.
    #[tokio::test]
    async fn an_agent_session_without_the_table_says_which_verb_writes_it() {
        let file = FleetFile {
            url: "http://127.0.0.1:1".to_owned(),
            ..FleetFile::default()
        };
        let err = ensure_fresh_agent_session("lab1", &file)
            .await
            .expect_err("no [agent] table");
        let text = format!("{err:#}");
        assert!(text.contains("agent login"), "got: {text}");
        assert!(text.contains("lab1"), "got: {text}");
    }

    /// Far from expiry: the stored token is returned with no file access and no
    /// network. The unreachable URL is the assertion.
    #[tokio::test]
    async fn a_token_far_from_expiry_is_used_as_is() {
        let agent = agent_section();
        let file = FleetFile {
            url: "http://127.0.0.1:1".to_owned(),
            agent: Some(agent.clone()),
            ..FleetFile::default()
        };
        assert_eq!(
            ensure_fresh_agent_session("default", &file).await.unwrap(),
            agent.workload_token
        );
    }

    /// The concurrency case this feature exists for: a peer process in the same
    /// sandbox redeemed while our snapshot was in memory, so we take its token
    /// and redeem nothing.
    ///
    /// `url` points at a closed port: a regression that redeems anyway fails
    /// fast and loudly rather than hanging.
    #[tokio::test]
    async fn a_peers_fresher_token_is_used_instead_of_redeeming() {
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("XDG_CONFIG_HOME");
        // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
        std::env::set_var("XDG_CONFIG_HOME", tmp.path());

        let now = now_epoch_secs();
        let peer_token = workload_token();
        let on_disk = FleetFile {
            url: "http://127.0.0.1:1".to_owned(),
            agent: Some(AgentSection {
                workload_token: peer_token.clone(),
                expires: now + 3_600,
                ..agent_section()
            }),
            ..FleetFile::default()
        };
        let path = paths::fleet_config_path("default").unwrap();
        save_atomic(&path, &on_disk).unwrap();

        // Our snapshot is stale: a different token, expired a minute ago.
        let stale = FleetFile {
            agent: Some(AgentSection {
                workload_token: workload_token(),
                expires: now.saturating_sub(60),
                ..on_disk.agent.clone().unwrap()
            }),
            ..on_disk.clone()
        };

        let got = ensure_fresh_agent_session("default", &stale).await.unwrap();
        assert_eq!(got, peer_token, "the peer's fresher token must be reused");

        // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    /// Expired with no peer to borrow from: the redemption is attempted, fails
    /// against a closed port, and the error names the fix.
    #[tokio::test]
    async fn an_expired_session_with_no_peer_names_agent_login() {
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("XDG_CONFIG_HOME");
        // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
        std::env::set_var("XDG_CONFIG_HOME", tmp.path());

        let now = now_epoch_secs();
        let file = FleetFile {
            url: "http://127.0.0.1:1".to_owned(),
            agent: Some(AgentSection {
                expires: now.saturating_sub(60),
                ..agent_section()
            }),
            ..FleetFile::default()
        };
        let path = paths::fleet_config_path("default").unwrap();
        save_atomic(&path, &file).unwrap();

        let err = ensure_fresh_agent_session("default", &file)
            .await
            .expect_err("nothing is listening on 127.0.0.1:1");
        let text = format!("{err:#}");
        assert!(text.contains("agent login"), "got: {text}");

        // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }
}
