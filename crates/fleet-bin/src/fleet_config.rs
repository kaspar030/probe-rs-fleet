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
//! [node]                # written by `probe-rs-fleet agent init`
//! node_token = "prfn1_…"
//! node_id = "gh-4242/rpi-lab-1"
//! coordinator_token_pubkey = "<64 hex>"
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
//! compromised Pi \u2014 a device sitting on a shelf in an office, reachable by
//! anyone who walks past \u2014 equivalent to a compromised user account.
//!
//! # Writing: read-modify-write, then atomic rename
//!
//! Two independent writers touch this file: `login` refreshing `[user]`, and a
//! running agent persisting a rotated `[node]` token. Every writer therefore
//! re-reads the current file, patches only its own table, and renames a 0600
//! temp file over the original.
//!
//! The residual race (a login landing at the same instant as a token rotation)
//! is a lost update, recoverable by re-running the command. There is no file
//! locking in v1 \u2014 but note the asymmetry: re-running `login` costs a browser
//! tab, whereas silently clobbering a node credential costs a physical visit to
//! the Pi. That is why the node writer patches rather than rewrites.

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

/// The `[node]` table, written by `probe-rs-fleet agent init` and refreshed by
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

/// The comment header every rendered fleet file carries.
const HEADER: &str = r"# probe-rs-fleet \u2014 per-fleet configuration
#
# One file per fleet, at ~/.config/probe-rs-fleet/fleets/<name>.toml. Select it
# with `--fleet <name>` or PROBE_RS_FLEET; the default is `default`.
#
# THIS FILE HOLDS BEARER CREDENTIALS and is written 0600. [user].session_token
# lets anyone act as you until it expires; [node].node_token lets anyone act as
# this node until it rotates or the node row is deleted.
#
# The two tokens are deliberately distinct: merging them would make a
# compromised node equivalent to a compromised user account.
#
# Managed by `probe-rs-fleet login` ([user]) and `agent init` ([node]). Both
# preserve the other's table, so a laptop can hold both.
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
    write_secret(&tmp, text.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
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
pub fn update(path: &Path, patch: impl FnOnce(&mut FleetFile)) -> Result<FleetFile> {
    let mut file = if path.exists() {
        load(path)?
    } else {
        FleetFile::default()
    };
    patch(&mut file);
    validate(&file)?;
    save_atomic(path, &file)?;
    Ok(file)
}

/// Read-modify-write the named fleet's file.
///
/// # Errors
///
/// See [`update`].
pub fn update_named(fleet: &str, patch: impl FnOnce(&mut FleetFile)) -> Result<FleetFile> {
    let path = paths::fleet_config_path(fleet)?;
    update(&path, patch)
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
                    u.session_token = response.token.clone();
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

/// Current time in epoch seconds.
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_auth::{OpaqueToken, TokenKind};

    fn session_token() -> String {
        OpaqueToken::mint(TokenKind::Session).to_secret_string()
    }

    fn node_token() -> String {
        OpaqueToken::mint(TokenKind::Node).to_secret_string()
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

    #[test]
    fn a_file_with_both_tables_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("default.toml");
        let file = FleetFile {
            url: "https://fleet.example".to_owned(),
            server_cert_sha256: Some("cd".repeat(32)),
            user: Some(user_section()),
            node: Some(node_section()),
        };
        save_atomic(&path, &file).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.url, "https://fleet.example");
        assert_eq!(loaded.pin(), Some([0xcdu8; 32]));
        assert_eq!(
            loaded.user.as_ref().unwrap().session_token,
            file.user.as_ref().unwrap().session_token
        );
        assert_eq!(
            loaded.node.as_ref().unwrap().node_id,
            "gh-4242/rpi-lab-1"
        );
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
        assert!(loaded.user.is_none() && loaded.node.is_none());
    }
}
