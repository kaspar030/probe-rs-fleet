//! `probe-rs-fleet login`: authenticate through the coordinator's forgs
//! device flow and cache a session token in the fleet file.
//!
//! # The flow, and why it looks like this
//!
//! The coordinator is its own device authorization server (forgs'
//! `/auth/device/*`, RFC 8628): the CLI asks it for a short `user_code`, the
//! human opens the printed URL, logs in with **any** provider the coordinator
//! offers (GitHub, Codeberg, GitLab, an OIDC issuer — choosing a username on
//! first login), confirms the code, and the CLI's poll returns a session plus
//! a refresh token.
//!
//! * **This CLI never talks to an identity provider.** Provider credentials
//!   stay on the coordinator, and nothing here hardcodes one.
//! * **There is no callback URL on this side.** The CLI only polls.
//!
//! # What it writes
//!
//! The `[user]` table of `~/.config/probe-rs-fleet/fleets/<name>.toml`, 0600,
//! **preserving any `[node]` table**: a laptop is legitimately both a user and a
//! node, and dropping a node credential means a re-enrollment.

use std::path::Path;

use anyhow::{Context, Result};

use crate::cli::LoginArgs;
use crate::fleet_config::{self, FleetFile, UserSection};
use crate::paths;

/// Run `probe-rs-fleet login`.
///
/// # Errors
///
/// Returns an error if no coordinator URL can be resolved, the device flow is
/// refused or times out, or the fleet file cannot be written.
pub async fn run(args: LoginArgs) -> Result<()> {
    let LoginArgs {
        fleet_url,
        server_cert_sha256,
        token,
        refresh_token,
        no_browser,
        org,
        fleet,
        config_dir,
    } = args;

    let path = match &config_dir {
        Some(dir) => dir.join(format!("{fleet}.toml")),
        None => paths::fleet_config_path(&fleet)?,
    };

    // The URL is remembered across logins: only the first one needs to be told
    // where the fleet is.
    let existing = if path.exists() {
        fleet_config::load(&path).ok()
    } else {
        None
    };
    let url = fleet_url
        .or_else(|| existing.as_ref().map(|f| f.url.clone()))
        .with_context(|| {
            format!(
                "no coordinator URL for fleet `{fleet}`; pass --fleet-url <https://fleet.example> \
                 the first time"
            )
        })?;
    let pin_hex =
        server_cert_sha256.or_else(|| existing.as_ref().and_then(|f| f.server_cert_sha256.clone()));
    if let Some(pin) = &pin_hex {
        anyhow::ensure!(
            fleet_tls::parse_fingerprint(pin).is_some(),
            "--server-cert-sha256 must be 64 hex characters"
        );
    }
    let pin = pin_hex.as_deref().and_then(fleet_tls::parse_fingerprint);

    if let Some(org) = &org {
        anyhow::ensure!(!org.trim().is_empty(), "--org must not be empty");
    }
    let mut session = match token {
        Some(token) => record_external_token(&token, refresh_token.as_deref())?,
        None => device_flow(&url, pin, no_browser).await?,
    };
    // An explicit `--org` wins; otherwise a re-login keeps the org this
    // machine was already acting in.
    session.org = org.or_else(|| {
        existing
            .as_ref()
            .and_then(|f| f.user.as_ref())
            .and_then(|u| u.org.clone())
    });

    let written = fleet_config::update(&path, |f| {
        f.url.clone_from(&url);
        f.server_cert_sha256.clone_from(&pin_hex);
        f.user = Some(session);
    })?;

    print_summary(&fleet, &path, &written);
    Ok(())
}

/// Validate and wrap an externally minted session token, with the refresh token
/// that goes with it if one was minted.
///
/// Checked here, where the operator can see what they typed: a node token in
/// `[user]` would authenticate against `/agent` and be refused with a 403 on
/// `/client`, a confusing failure a long way from the mistake. The same applies
/// to `--refresh-token`, which `coordinator user-token` prints beside the
/// session token.
fn record_external_token(token: &str, refresh_token: Option<&str>) -> Result<UserSection> {
    anyhow::ensure!(
        crate::tokens::is_session(token),
        "--token must be a session token (`prfs1_…`); mint one with \
         `probe-rs-fleet coordinator user-token --username <name>`"
    );
    if let Some(refresh) = refresh_token {
        anyhow::ensure!(
            crate::tokens::is_refresh(refresh),
            "--refresh-token must be a refresh token (`prfr1_…`); \
             `probe-rs-fleet coordinator user-token --username <name>` prints one"
        );
    }
    Ok(UserSection {
        session_token: token.to_owned(),
        // An externally minted token carries no identity in-band; the
        // coordinator resolves it from the session row on every request.
        username: None,
        user_id: None,
        org: None,
        // No expiry either. With a refresh token present that means
        // `ensure_fresh_session` redeems once on first use and then records the
        // expiry it gets back; with none it means "use it and let the
        // coordinator judge", exactly as before.
        expires: None,
        refresh_token: refresh_token.map(str::to_owned),
    })
}

/// Drive forgs' device flow to completion against `url`.
async fn device_flow(url: &str, pin: Option<[u8; 32]>, no_browser: bool) -> Result<UserSection> {
    let client = forgs_client::ForgsClient::new(url, pin)
        .map_err(|e| anyhow::anyhow!("invalid coordinator URL: {e}"))?;
    let login = forgs_client::DeviceLogin::start(&client)
        .await
        .map_err(|e| describe_start_error(&e))?;

    // Print before opening a browser, always: on a headless box the printed
    // code is the whole interface, and a browser that fails to open silently
    // must not leave the user with nothing.
    println!();
    println!("  Open       {}", login.verification_uri());
    println!("  Enter code {}", login.user_code());
    println!();

    if !no_browser && forgs_client::cli::should_try_browser() {
        let _ = forgs_client::cli::try_open_browser(login.browser_uri());
    }

    println!("Waiting for you to authorise this device…");
    let session = login
        .wait(&client)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(UserSection {
        session_token: session.session_token.into_inner(),
        username: session.username,
        user_id: session.user_id,
        org: None,
        expires: Some(session.expires),
        refresh_token: session.refresh_token.map(forgs_client::Secret::into_inner),
    })
}

/// Turn a `/auth/device/start` failure into remediation-shaped text.
fn describe_start_error(e: &forgs_client::ClientError) -> anyhow::Error {
    if e.status() == Some(404) {
        return anyhow::anyhow!(
            "this coordinator does not offer device login.\nBootstrap with:\n  \
             probe-rs-fleet coordinator user-token --username <name>\n  \
             probe-rs-fleet login --fleet-url <url> --token <token>"
        );
    }
    anyhow::anyhow!(forgs_client::cli::describe(e, "starting the device login"))
}

/// Print the post-login summary.
fn print_summary(fleet: &str, path: &Path, file: &FleetFile) {
    let user = file.user.as_ref();
    let name = user
        .and_then(|u| u.username.as_deref())
        .unwrap_or("(unknown)");
    let org = user
        .and_then(|u| u.org.as_deref())
        .unwrap_or("your personal org");
    println!();
    println!("Logged in as {name} (acting in {org}) — fleet `{fleet}`");
    println!("  {} (0600)", path.display());
    if file.node.is_some() {
        // Worth saying: the whole point of one file per fleet is that this
        // machine can be both, and a user who sees only `[user]` mentioned may
        // reasonably fear the enrollment was overwritten.
        println!("  this machine is also enrolled as a node in this fleet ([node] preserved)");
    }
    if user.is_some_and(|u| u.refresh_token.is_some()) {
        // Only when one was actually stored: a coordinator that minted none
        // must not have this printed about it.
        println!("  this session renews itself — no re-login when it expires");
        println!("  (`probe-rs-fleet logout --all` revokes it everywhere)");
    }
    println!();
    println!("Next steps:");
    println!("  probe-rs-fleet ctl --fleet {fleet} list");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::{mint_string, node_kind};
    use forgs::TokenKind;

    fn args(dir: &std::path::Path, token: Option<&str>) -> LoginArgs {
        LoginArgs {
            fleet_url: Some("https://fleet.example".to_owned()),
            server_cert_sha256: None,
            token: token.map(ToOwned::to_owned),
            refresh_token: None,
            no_browser: true,
            org: None,
            fleet: "default".to_owned(),
            config_dir: Some(dir.to_path_buf()),
        }
    }

    #[tokio::test]
    async fn token_login_writes_a_usable_0600_fleet_file() {
        let tmp = tempfile::tempdir().unwrap();
        let token = mint_string(TokenKind::Session);
        run(args(tmp.path(), Some(&token))).await.unwrap();

        let path = tmp.path().join("default.toml");
        let file = fleet_config::load(&path).unwrap();
        assert_eq!(file.url, "https://fleet.example");
        assert_eq!(file.user.as_ref().unwrap().session_token, token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// The laptop case: logging in must not cost this machine its node
    /// enrollment, which would mean a physical re-provisioning.
    #[tokio::test]
    async fn login_preserves_an_existing_node_table() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("default.toml");
        let node_token = mint_string(node_kind());
        fleet_config::update(&path, |f| {
            f.url = "https://fleet.example".to_owned();
            f.node = Some(crate::fleet_config::NodeSection {
                node_token: node_token.clone(),
                node_id: "01J9Z3Q4ABCDEFGHJKMNPQRSTV/laptop".to_owned(),
                coordinator_token_pubkey: "ab".repeat(32),
                previous_node_token: None,
            });
        })
        .unwrap();

        let token = mint_string(TokenKind::Session);
        run(args(tmp.path(), Some(&token))).await.unwrap();

        let file = fleet_config::load(&path).unwrap();
        assert_eq!(file.node.as_ref().unwrap().node_token, node_token);
        assert_eq!(file.user.as_ref().unwrap().session_token, token);
    }

    #[tokio::test]
    async fn a_token_of_the_wrong_kind_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let node = mint_string(node_kind());
        assert!(run(args(tmp.path(), Some(&node))).await.is_err());
        assert!(run(args(tmp.path(), Some("garbage"))).await.is_err());
        assert!(!tmp.path().join("default.toml").exists());
    }

    /// Without a URL and without a remembered one there is nothing to dial, and
    /// saying so beats a connection error against an empty string.
    #[tokio::test]
    async fn a_first_login_needs_a_url() {
        let tmp = tempfile::tempdir().unwrap();
        let token = mint_string(TokenKind::Session);
        let mut a = args(tmp.path(), Some(&token));
        a.fleet_url = None;
        assert!(run(a).await.is_err());
    }

    /// A second login reuses the URL the first one recorded.
    #[tokio::test]
    async fn a_later_login_remembers_the_url() {
        let tmp = tempfile::tempdir().unwrap();
        let token = mint_string(TokenKind::Session);
        run(args(tmp.path(), Some(&token))).await.unwrap();

        let fresh = mint_string(TokenKind::Session);
        let mut a = args(tmp.path(), Some(&fresh));
        a.fleet_url = None;
        run(a).await.unwrap();

        let file = fleet_config::load(&tmp.path().join("default.toml")).unwrap();
        assert_eq!(file.url, "https://fleet.example");
        assert_eq!(file.user.unwrap().session_token, fresh);
    }

    #[tokio::test]
    async fn a_malformed_pin_is_rejected_before_anything_is_written() {
        let tmp = tempfile::tempdir().unwrap();
        let token = mint_string(TokenKind::Session);
        let mut a = args(tmp.path(), Some(&token));
        a.server_cert_sha256 = Some("nope".to_owned());
        assert!(run(a).await.is_err());
        assert!(!tmp.path().join("default.toml").exists());
    }

    /// The air-gapped escape hatch stores both halves, so the session it writes
    /// renews itself exactly like a device-flow one.
    #[tokio::test]
    async fn an_external_refresh_token_is_stored_beside_the_session() {
        let tmp = tempfile::tempdir().unwrap();
        let token = mint_string(TokenKind::Session);
        let refresh = mint_string(TokenKind::Refresh);
        let mut a = args(tmp.path(), Some(&token));
        a.refresh_token = Some(refresh.clone());
        run(a).await.unwrap();

        let file = fleet_config::load(&tmp.path().join("default.toml")).unwrap();
        let user = file.user.unwrap();
        assert_eq!(user.session_token, token);
        assert_eq!(user.refresh_token.as_deref(), Some(refresh.as_str()));
    }

    /// A wrong-kind `--refresh-token` is caught where the operator can see what
    /// they typed, not as a 401 a day later.
    #[tokio::test]
    async fn a_refresh_token_of_the_wrong_kind_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let token = mint_string(TokenKind::Session);
        let mut a = args(tmp.path(), Some(&token));
        a.refresh_token = Some(mint_string(TokenKind::Session));
        assert!(run(a).await.is_err());
        assert!(!tmp.path().join("default.toml").exists());
    }

    /// A re-login replaces the stored refresh token wholesale — `login` writes
    /// `f.user` in one go, so a stale durable credential cannot survive.
    #[tokio::test]
    async fn a_relogin_replaces_the_refresh_token() {
        let tmp = tempfile::tempdir().unwrap();
        let first = mint_string(TokenKind::Refresh);
        let mut a = args(tmp.path(), Some(&mint_string(TokenKind::Session)));
        a.refresh_token = Some(first.clone());
        run(a).await.unwrap();

        // A second login with no refresh token at all clears it rather than
        // leaving the previous one behind.
        let b = args(tmp.path(), Some(&mint_string(TokenKind::Session)));
        run(b).await.unwrap();
        let file = fleet_config::load(&tmp.path().join("default.toml")).unwrap();
        assert!(file.user.unwrap().refresh_token.is_none());
    }
}
