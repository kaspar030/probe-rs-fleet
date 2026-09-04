//! The `ctl` role: admin / UX CLI talking to the coordinator's `/client` route.
//!
//! The command surface (parsing, selector grammar, output formatting) is fully
//! implemented and unit-tested here. The *transport* is not: `ctl` is a caller
//! of [`fleet_sidecar::transport::CoordSession`], the same client the sidecar
//! uses.
//!
//! That is a deliberate consolidation. Before revision 2, `ctl` hand-rolled a
//! second coordinator client — its own TLS config, its own `server_name`, its
//! own Hello handshake — alongside the sidecar's and the agent's, and the three
//! had drifted. There is now one dial path (`fleet_wire::client::dial`), one
//! trust configuration (`fleet_tls::client_trust_config`), and one session type.

use anyhow::{Context, Result};

use fleet_proto::ids::BoardName;
use fleet_proto::lease::{Constraint, LeaseRequest, Priority};
use fleet_sidecar::transport::CoordSession;
use fleet_wire::{CoordToSidecar, SidecarToCoord};

use crate::cli::{CtlArgs, CtlClientArgs, CtlCommand};
use crate::paths;

/// Resolved connection configuration for the ctl client.
#[derive(Debug, Clone)]
pub struct CtlConnection {
    /// Base URL of the coordinator.
    pub fleet_url: String,
    /// The bearer session token.
    pub token: String,
    /// Optional pinned server-certificate SHA-256 (64 hex chars).
    pub server_cert_sha256: Option<String>,
}

impl CtlConnection {
    /// Resolve the connection config from the CLI/env flags, falling back to a
    /// `client.toml` (at the XDG config path) for any field the flags / env
    /// vars do not supply.
    ///
    /// Precedence: explicit flag / env var > `client.toml`. Errors only if a
    /// required field is supplied by neither source.
    ///
    /// # Errors
    ///
    /// Returns an error if `--coordinator` or `--token` (or their env /
    /// `client.toml` equivalents) cannot be resolved.
    pub fn from_args(args: CtlClientArgs) -> Result<Self> {
        let fallback = load_client_fallback(&args.profile);
        Self::resolve(args, fallback)
    }

    /// Resolve against an explicit (possibly absent) `client.toml` fallback.
    fn resolve(args: CtlClientArgs, fallback: Option<crate::config::ClientConfig>) -> Result<Self> {
        let (fb_url, fb_token, fb_pin) = match fallback {
            Some(c) => (Some(c.fleet_url), Some(c.token), c.server_cert_sha256),
            None => (None, None, None),
        };
        let fleet_url = args
            .coordinator
            .or(fb_url)
            .context("--coordinator (or PROBE_RS_FLEET_COORDINATOR / client.toml) is required")?;
        let token = args.token.or(fb_token).context(
            "--token (or PROBE_RS_FLEET_TOKEN / client.toml) is required; mint one with \
             `probe-rs-fleet coordinator user-token <login>`",
        )?;
        let server_cert_sha256 = args.server_cert_sha256.or(fb_pin);
        if let Some(pin) = &server_cert_sha256 {
            anyhow::ensure!(
                fleet_tls::parse_fingerprint(pin).is_some(),
                "--server-cert-sha256 must be 64 hex characters"
            );
        }
        Ok(Self {
            fleet_url,
            token,
            server_cert_sha256,
        })
    }

    /// The pinned server-certificate hash, decoded.
    #[must_use]
    pub fn pin(&self) -> Option<[u8; 32]> {
        self.server_cert_sha256
            .as_deref()
            .and_then(fleet_tls::parse_fingerprint)
    }
}

/// Load the `client.toml` fallback from the XDG config path, if it exists.
///
/// A missing file (or unresolvable config path) is not an error here — it just
/// means there is no fallback and the flags / env vars must supply everything.
fn load_client_fallback(profile: &str) -> Option<crate::config::ClientConfig> {
    let path = paths::client_config_path(profile).ok()?;
    if !path.exists() {
        return None;
    }
    crate::config::load_client_config(&path).ok()
}

/// Parse a `lease`/board selector into a [`Constraint`].
///
/// Grammar:
/// - `tag=<t>` → [`Constraint::Tags`] with a single tag (repeatable on the
///   wire; the CLI takes one token, callers can refine later),
/// - `chip=<c>` → [`Constraint::Chip`],
/// - anything else → [`Constraint::Board`] (a bare, node-local board name; the
///   coordinator resolves it within the caller's org).
#[must_use]
pub fn parse_selector(selector: &str) -> Constraint {
    if let Some(tag) = selector.strip_prefix("tag=") {
        Constraint::Tags(vec![tag.to_owned()])
    } else if let Some(chip) = selector.strip_prefix("chip=") {
        Constraint::Chip(chip.to_owned())
    } else {
        Constraint::Board(BoardName(selector.to_owned()))
    }
}

/// A thin client of the coordinator's admin/operator surface.
pub struct CtlClient {
    conn: CtlConnection,
}

impl CtlClient {
    /// Build a client from resolved connection config.
    #[must_use]
    pub fn new(conn: CtlConnection) -> Self {
        Self { conn }
    }

    /// Open a `/client` session, presenting the bearer token on the upgrade.
    async fn connect(&self) -> Result<CoordSession> {
        let cfg = fleet_sidecar::selector::FleetConfig {
            coordinator: self.conn.fleet_url.clone(),
            token: self.conn.token.clone(),
            // `ctl` never leases through this path (it sends explicit operator
            // requests), so the selector is a placeholder the session ignores.
            select: Constraint::Tags(Vec::new()),
            server_cert_sha256: self.conn.server_cert_sha256.clone(),
        };
        CoordSession::connect(&cfg)
            .await
            .with_context(|| format!("connecting to coordinator {}", self.conn.fleet_url))
    }

    /// `ctl list` — fleet inventory.
    async fn list(&self) -> Result<()> {
        let session = self.connect().await?;
        match session.request(SidecarToCoord::ListBoards).await? {
            CoordToSidecar::BoardList(boards) => {
                if boards.is_empty() {
                    println!("no boards in the fleet");
                } else {
                    // BOARD is the fleet key "<org>/<node>/<name>", so it is
                    // wider than revision 1's bare id.
                    println!(
                        "{:<32} {:<16} {:<16} {:<12} HOLDER",
                        "BOARD", "AGENT", "CHIP", "STATE"
                    );
                    for b in boards {
                        let state = format!("{:?}", b.availability);
                        // Render the holder as its stable key ("<org>/<kind>:<id>").
                        let holder = b.holder.map_or_else(String::new, |h| h.key().to_string());
                        println!(
                            "{:<32} {:<16} {:<16} {:<12} {}",
                            b.board, b.agent.0, b.chip, state, holder
                        );
                    }
                }
                Ok(())
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }

    /// `ctl lease <selector> [--duration]`.
    async fn lease(&self, request: &LeaseRequest) -> Result<()> {
        let session = self.connect().await?;
        match session
            .request(SidecarToCoord::Lease(request.clone()))
            .await?
        {
            CoordToSidecar::Lease(grant) => {
                println!(
                    "leased {} (lease {}) on agent {} until {} (epoch)",
                    grant.board, grant.lease.0, grant.agent.0, grant.expires
                );
                Ok(())
            }
            CoordToSidecar::Queued { position } => {
                println!("queued at position {position}");
                Ok(())
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }

    /// `ctl release <board>`.
    async fn release(&self, board: &BoardName) -> Result<()> {
        // Resolve the lease holding `board` via the board list, then release it.
        let session = self.connect().await?;
        let lease = match session.request(SidecarToCoord::ListBoards).await? {
            CoordToSidecar::BoardList(boards) => boards
                .into_iter()
                .find(|b| b.board.name == board.0)
                .and_then(|b| b.lease),
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        };
        let Some(lease) = lease else {
            anyhow::bail!("board {board} is not currently leased");
        };
        match session.request(SidecarToCoord::Release { lease }).await? {
            CoordToSidecar::Released { lease } => {
                println!("released lease {} on {board}", lease.0);
                Ok(())
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }

    /// `ctl power-cycle <board>`.
    async fn power_cycle(&self, board: &BoardName) -> Result<()> {
        let session = self.connect().await?;
        match session
            .request(SidecarToCoord::PowerCycle {
                board: board.clone(),
            })
            .await?
        {
            CoordToSidecar::PowerCycled { board } => {
                println!("power-cycled {board}");
                Ok(())
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }

    /// `ctl who` — current lease holders.
    async fn who(&self) -> Result<()> {
        let session = self.connect().await?;
        match session.request(SidecarToCoord::Who).await? {
            CoordToSidecar::LeaseTable(holders) => {
                if holders.is_empty() {
                    println!("no active leases");
                } else {
                    println!("{:<8} {:<32} {:<24} EXPIRES", "LEASE", "BOARD", "HOLDER");
                    for h in holders {
                        println!(
                            "{:<8} {:<32} {:<24} {}",
                            h.lease.0,
                            h.board,
                            h.holder.key(),
                            h.expires
                        );
                    }
                }
                Ok(())
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }

    /// `ctl logs [board] [--follow]`.
    async fn logs(&self, board: Option<&BoardName>, follow: bool) -> Result<()> {
        let session = self.connect().await?;
        match session
            .request(SidecarToCoord::Logs {
                board: board.cloned(),
                follow,
            })
            .await?
        {
            CoordToSidecar::LogLines(lines) => {
                // The coordinator returns newest-first; print oldest-first.
                for line in lines.into_iter().rev() {
                    let board = line.board.unwrap_or_default();
                    let detail = line.detail.unwrap_or_default();
                    println!(
                        "{:>12}  {:<18} {:<24} {}",
                        line.ts, line.action, board, detail
                    );
                }
                Ok(())
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }
}

/// Run a `ctl` command.
///
/// # Errors
///
/// Returns an error if the connection config is incomplete or the coordinator
/// RPC fails.
pub async fn run(args: CtlArgs) -> Result<()> {
    let conn = CtlConnection::from_args(args.client)?;
    let client = CtlClient::new(conn);

    match args.command {
        CtlCommand::Init(_) | CtlCommand::Profiles => {
            // `ctl init` / `ctl profiles` are dispatched in cli.rs before a
            // connection is built; reaching here would be a logic error.
            anyhow::bail!("`ctl init`/`ctl profiles` must be handled before connecting")
        }
        CtlCommand::List => client.list().await,
        CtlCommand::Lease { selector, duration } => {
            let request = LeaseRequest {
                select: parse_selector(&selector),
                duration_secs: duration,
                priority: Priority::Interactive,
            };
            client.lease(&request).await
        }
        CtlCommand::Release { board } => client.release(&BoardName(board)).await,
        CtlCommand::PowerCycle { board } => client.power_cycle(&BoardName(board)).await,
        CtlCommand::Who => client.who().await,
        CtlCommand::Logs { board, follow } => {
            client.logs(board.map(BoardName).as_ref(), follow).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(coordinator: Option<&str>, token: Option<&str>) -> CtlClientArgs {
        CtlClientArgs {
            coordinator: coordinator.map(ToOwned::to_owned),
            token: token.map(ToOwned::to_owned),
            server_cert_sha256: None,
            profile: "default".to_owned(),
        }
    }

    fn fallback(url: &str, token: &str) -> crate::config::ClientConfig {
        crate::config::ClientConfig {
            fleet_url: url.to_owned(),
            token: token.to_owned(),
            server_cert_sha256: None,
        }
    }

    #[test]
    fn bare_id_is_a_board_constraint() {
        assert_eq!(
            parse_selector("nrf52840-dk-3"),
            Constraint::Board(BoardName("nrf52840-dk-3".to_owned()))
        );
    }

    #[test]
    fn tag_prefix_is_a_tags_constraint() {
        assert_eq!(
            parse_selector("tag=nrf52"),
            Constraint::Tags(vec!["nrf52".to_owned()])
        );
    }

    #[test]
    fn chip_prefix_is_a_chip_constraint() {
        assert_eq!(
            parse_selector("chip=nRF52840_xxAA"),
            Constraint::Chip("nRF52840_xxAA".to_owned())
        );
    }

    #[test]
    fn empty_tag_value_is_preserved() {
        assert_eq!(parse_selector("tag="), Constraint::Tags(vec![String::new()]));
    }

    #[test]
    fn connection_requires_a_url_and_a_token() {
        assert!(CtlConnection::resolve(args(None, None), None).is_err());
        assert!(CtlConnection::resolve(args(Some("c:1"), None), None).is_err());
        assert!(CtlConnection::resolve(args(None, Some("prfs1_t")), None).is_err());
    }

    #[test]
    fn connection_resolves_when_both_present() {
        let conn =
            CtlConnection::resolve(args(Some("https://coord"), Some("prfs1_t")), None).unwrap();
        assert_eq!(conn.fleet_url, "https://coord");
        assert_eq!(conn.token, "prfs1_t");
        assert!(conn.pin().is_none());
    }

    #[test]
    fn connection_falls_back_to_client_toml() {
        let conn = CtlConnection::resolve(
            args(None, None),
            Some(fallback("https://fb.example", "prfs1_fb")),
        )
        .unwrap();
        assert_eq!(conn.fleet_url, "https://fb.example");
        assert_eq!(conn.token, "prfs1_fb");
    }

    #[test]
    fn explicit_flag_overrides_client_toml() {
        let conn = CtlConnection::resolve(
            args(Some("https://flag.example"), Some("prfs1_flag")),
            Some(fallback("https://fb.example", "prfs1_fb")),
        )
        .unwrap();
        assert_eq!(conn.fleet_url, "https://flag.example");
        assert_eq!(conn.token, "prfs1_flag");
    }

    /// A malformed pin is rejected at resolution rather than silently ignored:
    /// dropping it would downgrade a pinned self-hosted deployment to `WebPKI`
    /// verification while appearing to work.
    #[test]
    fn malformed_pin_is_rejected() {
        let mut a = args(Some("https://c"), Some("prfs1_t"));
        a.server_cert_sha256 = Some("nope".to_owned());
        assert!(CtlConnection::resolve(a, None).is_err());

        let mut a = args(Some("https://c"), Some("prfs1_t"));
        a.server_cert_sha256 = Some("ab".repeat(32));
        let conn = CtlConnection::resolve(a, None).unwrap();
        assert_eq!(conn.pin(), Some([0xabu8; 32]));
    }
}
