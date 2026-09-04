//! `probe-rs-fleet login`: authenticate against GitHub and cache a session
//! token in the fleet file.
//!
//! # The flow, and why it looks like this
//!
//! Enrollment used to be **coordinator-operator-rooted**: someone with a shell
//! on the coordinator minted a single-use secret and sent it out of band. Every
//! path — user, agent, CI — funnelled through that. This inverts it: a human
//! authenticates once against GitHub, and every other credential derives from
//! that authority.
//!
//! The mechanism is GitHub's **device flow** (RFC 8628): the coordinator asks
//! GitHub for a short `user_code`, the human types it at
//! `https://github.com/login/device`, and the coordinator polls until GitHub
//! says yes.
//!
//! Two properties worth stating because they are easy to get wrong:
//!
//! * **This CLI never talks to GitHub.** It talks to the coordinator, which
//!   brokers. The OAuth app's client id/secret stay server-side, the user's
//!   *GitHub* access token never leaves the coordinator, and a self-hosted fleet
//!   can point at its own OAuth app without anybody rebuilding this binary.
//! * **There is no callback URL.** The device flow has no `redirect_uri` at all,
//!   so the unresolved "where does the hosted control plane run" question does
//!   not block login and nothing here hardcodes a hostname.
//!
//! # What it writes
//!
//! The `[user]` table of `~/.config/probe-rs-fleet/fleets/<name>.toml`, 0600,
//! **preserving any `[node]` table**: a laptop is legitimately both a user and a
//! node, and dropping a node credential means a re-enrollment.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::cli::LoginArgs;
use crate::fleet_config::{self, FleetFile, UserSection};
use crate::paths;

/// Cap on how long a login attempt runs, if GitHub reports no expiry.
const DEFAULT_EXPIRES_IN: u64 = 900;

/// Floor on the poll interval, whatever GitHub asks for.
///
/// GitHub's `slow_down` response is advisory and its `interval` can be absent;
/// polling faster than this earns a rate limit that looks, from here, like a
/// broken login.
const MIN_POLL_INTERVAL: u64 = 5;

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
        no_browser,
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

    let session = match token {
        Some(token) => record_external_token(&token)?,
        None => device_flow(&url, pin, no_browser).await?,
    };

    let written = fleet_config::update(&path, |f| {
        f.url.clone_from(&url);
        f.server_cert_sha256.clone_from(&pin_hex);
        f.user = Some(session);
    })?;

    print_summary(&fleet, &path, &written);
    Ok(())
}

/// Validate and wrap an externally minted session token.
///
/// Checked here, where the operator can see what they typed: a node token in
/// `[user]` would authenticate against `/agent` and be refused with a 403 on
/// `/client`, a confusing failure a long way from the mistake.
fn record_external_token(token: &str) -> Result<UserSection> {
    anyhow::ensure!(
        fleet_auth::OpaqueToken::parse(token)
            .is_ok_and(|t| t.kind() == fleet_auth::TokenKind::Session),
        "--token must be a session token (`prfs1_…`); mint one with \
         `probe-rs-fleet coordinator user-token <login>`"
    );
    Ok(UserSection {
        session_token: token.to_owned(),
        // An externally minted token carries no org in-band. The coordinator
        // resolves the org from the session row on every request, so this is
        // only a display value; `ctl` never sends it.
        org: "(unknown)".to_owned(),
        login: None,
        expires: None,
    })
}

/// Drive the device flow to completion against `url`.
async fn device_flow(url: &str, pin: Option<[u8; 32]>, no_browser: bool) -> Result<UserSection> {
    let grant = fleet_auth::http_client::device_start(url, pin)
        .await
        .map_err(|e| describe_start_error(&e))?;

    // Print before opening a browser, always: on a headless box the printed
    // code is the whole interface, and a browser that fails to open silently
    // must not leave the user with nothing.
    println!();
    println!("  Open       {}", grant.verification_uri);
    println!("  Enter code {}", grant.user_code);
    println!();

    if !no_browser && should_try_browser() {
        try_open_browser(&grant.verification_uri);
    }

    let expires_in = if grant.expires_in == 0 {
        DEFAULT_EXPIRES_IN
    } else {
        grant.expires_in
    };
    let deadline = Instant::now() + Duration::from_secs(expires_in);
    let mut interval = grant.interval.max(MIN_POLL_INTERVAL);

    println!("Waiting for you to authorise this device…");

    loop {
        if Instant::now() >= deadline {
            anyhow::bail!(
                "the device code expired before it was authorised; run `probe-rs-fleet login` again"
            );
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;

        match fleet_auth::http_client::device_poll(url, pin, &grant.device_code).await {
            Ok(response) => {
                return Ok(UserSection {
                    session_token: response.token,
                    org: response.org,
                    login: response.login,
                    expires: response.expires,
                });
            }
            Err(fleet_auth::http_client::ClientError::Rejected { code, .. }) => match code.as_str()
            {
                "authorization_pending" => {}
                // Back off additively, as RFC 8628 §3.5 requires: GitHub counts
                // a too-fast poll against us, and answering `slow_down` by
                // polling at the same rate is how a login stops working.
                "slow_down" => interval = interval.saturating_add(5),
                "access_denied" => {
                    anyhow::bail!("you cancelled the authorisation on GitHub");
                }
                "expired_token" => {
                    anyhow::bail!(
                        "the device code expired before it was authorised; run \
                         `probe-rs-fleet login` again"
                    );
                }
                "device_flow_unconfigured" => anyhow::bail!(UNCONFIGURED),
                other => anyhow::bail!("the coordinator rejected the login ({other})"),
            },
            Err(e) => return Err(anyhow::anyhow!("polling the coordinator failed: {e}")),
        }
    }
}

/// The message for a coordinator with no GitHub app configured.
///
/// A named error code rather than a 404 exists precisely so this sentence can be
/// printed: "not found" would send the user looking for a version mismatch.
const UNCONFIGURED: &str = "this coordinator has no GitHub app configured, so `login` cannot \
     work against it.\nAsk its operator to add a [github] block to coordinator.toml, or \
     bootstrap with:\n  probe-rs-fleet coordinator user-token <login>\n  probe-rs-fleet login \
     --fleet-url <url> --token <token>";

/// Turn a `/auth/device/start` failure into remediation-shaped text.
fn describe_start_error(e: &fleet_auth::http_client::ClientError) -> anyhow::Error {
    match e {
        fleet_auth::http_client::ClientError::Rejected { code, .. }
            if code == "device_flow_unconfigured" =>
        {
            anyhow::anyhow!(UNCONFIGURED)
        }
        _ => anyhow::anyhow!("could not start the GitHub device flow: {e}"),
    }
}

/// Whether opening a browser is even plausible here.
///
/// Over SSH or with no display, spawning `xdg-open` opens a browser on the wrong
/// machine (or nothing at all) — the printed code is the real interface there.
fn should_try_browser() -> bool {
    if std::env::var_os("SSH_CONNECTION").is_some() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Best-effort browser launch. Failure is ignored: the URL is already printed.
fn try_open_browser(url: &str) {
    let (program, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("open", &[])
    } else if cfg!(target_os = "windows") {
        ("cmd", &["/C", "start", ""])
    } else {
        ("xdg-open", &[])
    };
    // Detached and silenced: a browser's chatter on our stderr would bury the
    // code the user needs to read.
    let _ = std::process::Command::new(program)
        .args(args)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Print the post-login summary.
fn print_summary(fleet: &str, path: &Path, file: &FleetFile) {
    let user = file.user.as_ref();
    let login = user.and_then(|u| u.login.as_deref()).unwrap_or("(unknown)");
    let org = user.map_or("(unknown)", |u| u.org.as_str());
    println!();
    println!("Logged in as {login} (org {org}) — fleet `{fleet}`");
    println!("  {} (0600)", path.display());
    if file.node.is_some() {
        // Worth saying: the whole point of one file per fleet is that this
        // machine can be both, and a user who sees only `[user]` mentioned may
        // reasonably fear the enrollment was overwritten.
        println!("  this machine is also enrolled as a node in this fleet ([node] preserved)");
    }
    println!();
    println!("Next steps:");
    println!("  probe-rs-fleet ctl --fleet {fleet} list");
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_auth::{OpaqueToken, TokenKind};

    fn args(dir: &std::path::Path, token: Option<&str>) -> LoginArgs {
        LoginArgs {
            fleet_url: Some("https://fleet.example".to_owned()),
            server_cert_sha256: None,
            token: token.map(ToOwned::to_owned),
            no_browser: true,
            fleet: "default".to_owned(),
            config_dir: Some(dir.to_path_buf()),
        }
    }

    #[tokio::test]
    async fn token_login_writes_a_usable_0600_fleet_file() {
        let tmp = tempfile::tempdir().unwrap();
        let token = OpaqueToken::mint(TokenKind::Session).to_secret_string();
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
        let node_token = OpaqueToken::mint(TokenKind::Node).to_secret_string();
        fleet_config::update(&path, |f| {
            f.url = "https://fleet.example".to_owned();
            f.node = Some(crate::fleet_config::NodeSection {
                node_token: node_token.clone(),
                node_id: "gh-1/laptop".to_owned(),
                coordinator_token_pubkey: "ab".repeat(32),
                previous_node_token: None,
            });
        })
        .unwrap();

        let token = OpaqueToken::mint(TokenKind::Session).to_secret_string();
        run(args(tmp.path(), Some(&token))).await.unwrap();

        let file = fleet_config::load(&path).unwrap();
        assert_eq!(file.node.as_ref().unwrap().node_token, node_token);
        assert_eq!(file.user.as_ref().unwrap().session_token, token);
    }

    #[tokio::test]
    async fn a_token_of_the_wrong_kind_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let node = OpaqueToken::mint(TokenKind::Node).to_secret_string();
        assert!(run(args(tmp.path(), Some(&node))).await.is_err());
        assert!(run(args(tmp.path(), Some("garbage"))).await.is_err());
        assert!(!tmp.path().join("default.toml").exists());
    }

    /// Without a URL and without a remembered one there is nothing to dial, and
    /// saying so beats a connection error against an empty string.
    #[tokio::test]
    async fn a_first_login_needs_a_url() {
        let tmp = tempfile::tempdir().unwrap();
        let token = OpaqueToken::mint(TokenKind::Session).to_secret_string();
        let mut a = args(tmp.path(), Some(&token));
        a.fleet_url = None;
        assert!(run(a).await.is_err());
    }

    /// A second login reuses the URL the first one recorded.
    #[tokio::test]
    async fn a_later_login_remembers_the_url() {
        let tmp = tempfile::tempdir().unwrap();
        let token = OpaqueToken::mint(TokenKind::Session).to_secret_string();
        run(args(tmp.path(), Some(&token))).await.unwrap();

        let fresh = OpaqueToken::mint(TokenKind::Session).to_secret_string();
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
        let token = OpaqueToken::mint(TokenKind::Session).to_secret_string();
        let mut a = args(tmp.path(), Some(&token));
        a.server_cert_sha256 = Some("nope".to_owned());
        assert!(run(a).await.is_err());
        assert!(!tmp.path().join("default.toml").exists());
    }
}
