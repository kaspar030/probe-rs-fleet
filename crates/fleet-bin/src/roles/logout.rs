//! `probe-rs-fleet logout`: revoke this machine's fleet credentials.
//!
//! # Why this verb exists
//!
//! `login` now stores a **durable** credential: `[user].refresh_token` mints
//! session tokens for its owner until it expires (30 days by default) or is
//! revoked. A durable credential with no way to revoke it is not acceptable,
//! and this is the way.
//!
//! Two modes:
//!
//! * plain — revoke the credentials **this machine** holds: the session it
//!   authenticated with, and the refresh token in its fleet file.
//! * `--all` — revoke **every** session and refresh token the calling user
//!   holds in this fleet, on every machine. This is the lost-machine answer.
//!
//! # What is deliberately not built
//!
//! There is no "list my sessions" verb, and a re-`login` cannot delete the
//! *previous* machine's refresh token — the coordinator never learns that
//! machine's secret, so "revoke that one" is not expressible at all.
//! `logout --all` is therefore the whole answer for a lost machine, and the
//! TTL is the backstop. Building a session-management surface to say more
//! would be a much larger feature than the credential it protects.
//!
//! `POST /api/v1/session/logout` (the browser's) is untouched and is not an
//! oversight: the browser never receives a refresh token (CLI-only,
//! `docs/web-ui.md` D1), so it has none to revoke.
//!
//! # Local state is cleared even when the server call fails
//!
//! A machine being decommissioned offline must still stop holding usable
//! credentials on disk. So a transport failure warns and the `[user]` table is
//! cleared regardless, with a line saying the server-side rows survive until
//! they expire or the command is re-run. `[node]` and `[agent]` are preserved,
//! like every other writer of this file.

use anyhow::{Context, Result};

use crate::cli::LogoutArgs;
use crate::fleet_config;

/// Run `probe-rs-fleet logout`.
///
/// # Errors
///
/// Returns an error if the fleet has no config, no `[user]` table, or the
/// fleet file cannot be rewritten.
pub async fn run(args: LogoutArgs) -> Result<()> {
    let LogoutArgs {
        all,
        fleet,
        config_dir,
    } = args;

    let path = match &config_dir {
        Some(dir) => dir.join(format!("{fleet}.toml")),
        None => crate::paths::fleet_config_path(&fleet)?,
    };
    anyhow::ensure!(
        path.exists(),
        "no config for fleet `{fleet}` at {}; nothing to log out of",
        path.display()
    );
    let file = fleet_config::load(&path)?;
    let user = file
        .user
        .as_ref()
        .with_context(|| format!("fleet `{fleet}` has no [user] credential; nothing to revoke"))?;
    let refresh_token = user.refresh_token.clone();

    // Obtain a live session first: with `--all` this is what lets a revocation
    // work on a machine whose *session* has lapsed but whose refresh token has
    // not — precisely the state a long-idle workstation is in, and the one
    // where "revoke everything" matters most.
    let session = match fleet_config::ensure_fresh_session(&fleet, &file).await {
        Ok(token) => Some(token),
        Err(e) => {
            tracing::warn!(error = %e, "could not obtain a live session to revoke with");
            None
        }
    };

    let mut server_side_done = false;
    if let Some(session) = session.as_deref() {
        let result = match forgs_client::ForgsClient::new(&file.url, file.pin()) {
            Ok(client) => client.logout(session, refresh_token.as_deref(), all).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => server_side_done = true,
            Err(e) => {
                tracing::warn!(error = %e, "the coordinator did not confirm the logout");
            }
        }
    }

    // Clear locally regardless: a machine being decommissioned must not keep
    // usable credentials on disk just because it could not reach the network.
    // Read-modify-write, so `[node]` and `[agent]` survive.
    fleet_config::update(&path, |f| f.user = None)?;

    println!("Logged out of fleet `{fleet}`.");
    println!("  cleared [user] in {}", path.display());
    if server_side_done {
        if all {
            println!("  revoked every session and refresh token you hold in this fleet");
        } else {
            println!("  revoked this machine's session and refresh token");
        }
    } else {
        println!(
            "  the coordinator was not reached, so the server-side rows remain until they\n  \
             expire or you re-run this command with a working connection"
        );
    }
    if !all {
        println!();
        println!("If a machine was lost, revoke everywhere: probe-rs-fleet logout --all");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_config::{NodeSection, UserSection};
    use crate::tokens::{mint_string, node_kind};
    use forgs::TokenKind;

    fn args(dir: &std::path::Path, all: bool) -> LogoutArgs {
        LogoutArgs {
            all,
            fleet: "default".to_owned(),
            config_dir: Some(dir.to_path_buf()),
        }
    }

    fn seeded(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("default.toml");
        fleet_config::update(&path, |f| {
            // A closed port: the coordinator call fails fast, which is the
            // offline-decommission case these tests are about.
            f.url = "http://127.0.0.1:1".to_owned();
            f.user = Some(UserSection {
                session_token: mint_string(TokenKind::Session),
                username: Some("kaspar".to_owned()),
                user_id: None,
                org: None,
                expires: Some(9_999_999_999),
                refresh_token: Some(mint_string(TokenKind::Refresh)),
            });
            f.node = Some(NodeSection {
                node_token: mint_string(node_kind()),
                node_id: "01J9Z3Q4ABCDEFGHJKMNPQRSTV/laptop".to_owned(),
                coordinator_token_pubkey: "ab".repeat(32),
                previous_node_token: None,
            });
        })
        .unwrap();
        path
    }

    /// The credentials go even when the coordinator is unreachable, and the
    /// node enrollment — which costs a physical visit to recreate — does not.
    #[tokio::test]
    async fn an_offline_logout_still_clears_the_local_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let path = seeded(tmp.path());
        run(args(tmp.path(), false)).await.unwrap();

        let file = fleet_config::load(&path).unwrap();
        assert!(file.user.is_none(), "[user] must be cleared");
        assert!(file.node.is_some(), "[node] must survive");
    }

    #[tokio::test]
    async fn logging_out_twice_is_an_error_rather_than_a_silent_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        seeded(tmp.path());
        run(args(tmp.path(), true)).await.unwrap();
        // Nothing left to revoke: saying so beats pretending something happened.
        assert!(run(args(tmp.path(), true)).await.is_err());
    }

    #[tokio::test]
    async fn an_unknown_fleet_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(run(args(tmp.path(), false)).await.is_err());
    }
}
