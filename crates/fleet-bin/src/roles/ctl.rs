//! The `ctl` role: admin / UX CLI talking to the coordinator over mTLS.
//!
//! The command surface (parsing, selector grammar, output formatting) is fully
//! implemented and unit-tested here. The *transport* is an mTLS client of the
//! coordinator: each command opens a TLS stream (built from the shared
//! connection flags via [`fleet_tls`]), performs the sidecar-plane Hello
//! handshake, issues the matching operator request
//! ([`fleet_coordinator::proto::SidecarToCoord`]) — `list` / `who` / `logs` /
//! `power-cycle` plus `lease` / `release` — and renders the typed reply.

use anyhow::{Context, Result};

use fleet_proto::ids::BoardName;
use fleet_proto::lease::{Constraint, LeaseRequest, Priority};

use crate::cli::{CtlArgs, CtlClientArgs, CtlCommand};
use crate::paths;

/// Resolved connection configuration for the ctl client.
#[derive(Debug, Clone)]
pub struct CtlConnection {
    /// `host:port` of the coordinator.
    pub coordinator: String,
    /// Client certificate chain (PEM).
    pub cert: std::path::PathBuf,
    /// Client private key (PEM).
    pub key: std::path::PathBuf,
    /// CA used to verify the coordinator's server cert (PEM).
    pub ca: std::path::PathBuf,
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
    /// Returns an error if `--coordinator`, `--cert`, `--key`, or `--ca` (or
    /// their env / `client.toml` equivalents) cannot be resolved.
    pub fn from_args(args: CtlClientArgs) -> Result<Self> {
        let fallback = load_client_fallback(&args.profile);
        Self::resolve(args, fallback)
    }

    /// Resolve against an explicit (possibly absent) `client.toml` fallback.
    fn resolve(args: CtlClientArgs, fallback: Option<crate::config::ClientConfig>) -> Result<Self> {
        let (fb_coordinator, fb_cert, fb_key, fb_ca) = match fallback {
            Some(c) => (Some(c.coordinator), Some(c.cert), Some(c.key), Some(c.ca)),
            None => (None, None, None, None),
        };
        let coordinator = args
            .coordinator
            .or(fb_coordinator)
            .context("--coordinator (or PROBE_RS_FLEET_COORDINATOR / client.toml) is required")?;
        let cert = args
            .cert
            .or(fb_cert)
            .context("--cert (or PROBE_RS_FLEET_CERT / client.toml) is required")?;
        let key = args
            .key
            .or(fb_key)
            .context("--key (or PROBE_RS_FLEET_KEY / client.toml) is required")?;
        let ca = args
            .ca
            .or(fb_ca)
            .context("--ca (or PROBE_RS_FLEET_CA / client.toml) is required")?;
        Ok(Self {
            coordinator,
            cert,
            key,
            ca,
        })
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
///
/// Owns the resolved connection config; methods are the operator commands. The
/// live mTLS transport is the integration seam (task 1711 admin RPC).
pub struct CtlClient {
    conn: CtlConnection,
}

impl CtlClient {
    /// Build a client from resolved connection config.
    #[must_use]
    pub fn new(conn: CtlConnection) -> Self {
        Self { conn }
    }

    /// Build the mTLS client config for connecting to the coordinator.
    ///
    /// This loads and validates the cert/key/CA material now so misconfigured
    /// paths fail fast with a clear error, independent of the RPC seam below.
    ///
    /// # Errors
    ///
    /// Returns an error if any TLS material cannot be loaded.
    fn tls_config(&self) -> Result<rustls::ClientConfig> {
        let chain = fleet_tls::load_cert_chain(&self.conn.cert)
            .with_context(|| format!("loading client cert {}", self.conn.cert.display()))?;
        let key = fleet_tls::load_private_key(&self.conn.key)
            .with_context(|| format!("loading client key {}", self.conn.key.display()))?;
        let server_ca = fleet_tls::load_root_store(&self.conn.ca)
            .with_context(|| format!("loading server CA {}", self.conn.ca.display()))?;
        let config = fleet_tls::client_config(chain, key, server_ca)
            .context("building client TLS config")?;
        Ok(config)
    }

    /// Open an mTLS stream to the coordinator and complete the Hello/Welcome
    /// handshake, returning the connected, split stream halves.
    async fn connect(
        &self,
    ) -> Result<(
        tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
        tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    )> {
        use fleet_coordinator::proto::{read_frame, write_frame, CoordToSidecar, SidecarToCoord};
        use fleet_proto::PROTOCOL_VERSION;
        use tokio_rustls::TlsConnector;

        let tls = self.tls_config()?;
        let connector = TlsConnector::from(std::sync::Arc::new(tls));
        let tcp = tokio::net::TcpStream::connect(&self.conn.coordinator)
            .await
            .with_context(|| format!("connecting to coordinator {}", self.conn.coordinator))?;
        let _ = tcp.set_nodelay(true);
        let name = server_name(&self.conn.coordinator)?;
        let stream = connector
            .connect(name, tcp)
            .await
            .context("TLS handshake (server cert / CA mismatch?)")?;
        let (mut reader, mut writer) = tokio::io::split(stream);

        write_frame(
            &mut writer,
            &SidecarToCoord::Hello {
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .await
        .context("sending Hello")?;
        match read_frame::<_, CoordToSidecar>(&mut reader)
            .await
            .context("reading Welcome")?
        {
            CoordToSidecar::Welcome { protocol_version } if protocol_version == PROTOCOL_VERSION => {}
            CoordToSidecar::Welcome { protocol_version } => {
                anyhow::bail!(
                    "protocol mismatch: coordinator={protocol_version} ctl={PROTOCOL_VERSION}"
                );
            }
            other => anyhow::bail!("expected Welcome, got {other:?}"),
        }
        Ok((reader, writer))
    }

    /// `ctl list` — fleet inventory.
    async fn list(&self) -> Result<()> {
        use fleet_coordinator::proto::{read_frame, write_frame, CoordToSidecar, SidecarToCoord};
        let (mut reader, mut writer) = self.connect().await?;
        write_frame(&mut writer, &SidecarToCoord::ListBoards)
            .await
            .context("sending list request")?;
        match read_frame::<_, CoordToSidecar>(&mut reader).await? {
            CoordToSidecar::BoardList(boards) => {
                if boards.is_empty() {
                    println!("no boards in the fleet");
                } else {
                    // BOARD is now the fleet key "<org>/<node>/<name>", so it
                    // is wider than revision 1's bare id.
                    println!("{:<32} {:<16} {:<16} {:<12} HOLDER", "BOARD", "AGENT", "CHIP", "STATE");
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
        use fleet_coordinator::proto::{read_frame, write_frame, CoordToSidecar, SidecarToCoord};
        let (mut reader, mut writer) = self.connect().await?;
        write_frame(&mut writer, &SidecarToCoord::Lease(request.clone()))
            .await
            .context("sending lease request")?;
        match read_frame::<_, CoordToSidecar>(&mut reader).await? {
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
        use fleet_coordinator::proto::{read_frame, write_frame, CoordToSidecar, SidecarToCoord};
        // Resolve the lease holding `board` via the board list, then release it.
        let (mut reader, mut writer) = self.connect().await?;
        write_frame(&mut writer, &SidecarToCoord::ListBoards)
            .await
            .context("sending list request")?;
        let lease = match read_frame::<_, CoordToSidecar>(&mut reader).await? {
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
        write_frame(&mut writer, &SidecarToCoord::Release { lease })
            .await
            .context("sending release request")?;
        match read_frame::<_, CoordToSidecar>(&mut reader).await? {
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
        use fleet_coordinator::proto::{read_frame, write_frame, CoordToSidecar, SidecarToCoord};
        let (mut reader, mut writer) = self.connect().await?;
        write_frame(
            &mut writer,
            &SidecarToCoord::PowerCycle {
                board: board.clone(),
            },
        )
        .await
        .context("sending power-cycle request")?;
        match read_frame::<_, CoordToSidecar>(&mut reader).await? {
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
        use fleet_coordinator::proto::{read_frame, write_frame, CoordToSidecar, SidecarToCoord};
        let (mut reader, mut writer) = self.connect().await?;
        write_frame(&mut writer, &SidecarToCoord::Who)
            .await
            .context("sending who request")?;
        match read_frame::<_, CoordToSidecar>(&mut reader).await? {
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
        use fleet_coordinator::proto::{read_frame, write_frame, CoordToSidecar, SidecarToCoord};
        let (mut reader, mut writer) = self.connect().await?;
        write_frame(
            &mut writer,
            &SidecarToCoord::Logs {
                board: board.cloned(),
                follow,
            },
        )
        .await
        .context("sending logs request")?;
        match read_frame::<_, CoordToSidecar>(&mut reader).await? {
            CoordToSidecar::LogLines(lines) => {
                // The coordinator returns newest-first; print oldest-first.
                for line in lines.into_iter().rev() {
                    let board = line.board.unwrap_or_default();
                    let detail = line.detail.unwrap_or_default();
                    println!("{:>12}  {:<18} {:<24} {}", line.ts, line.action, board, detail);
                }
                Ok(())
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }
}

/// Derive a TLS `ServerName` from a `host:port` address (IP or DNS).
fn server_name(addr: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    use rustls::pki_types::ServerName;
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid server name '{host}': {e}"))
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
    fn connection_requires_all_fields() {
        let args = CtlClientArgs {
            coordinator: None,
            cert: None,
            key: None,
            ca: None,
            profile: "default".to_owned(),
        };
        assert!(CtlConnection::resolve(args, None).is_err());

        let args = CtlClientArgs {
            coordinator: Some("c:1".to_owned()),
            cert: Some("c.pem".into()),
            key: Some("k.pem".into()),
            ca: None,
            profile: "default".to_owned(),
        };
        assert!(CtlConnection::resolve(args, None).is_err());
    }

    #[test]
    fn connection_resolves_when_all_present() {
        let args = CtlClientArgs {
            coordinator: Some("coord:443".to_owned()),
            cert: Some("c.pem".into()),
            key: Some("k.pem".into()),
            ca: Some("ca.pem".into()),
            profile: "default".to_owned(),
        };
        let conn = CtlConnection::resolve(args, None).unwrap();
        assert_eq!(conn.coordinator, "coord:443");
    }

    #[test]
    fn connection_falls_back_to_client_toml() {
        let args = CtlClientArgs {
            coordinator: None,
            cert: None,
            key: None,
            ca: None,
            profile: "default".to_owned(),
        };
        let fallback = crate::config::ClientConfig {
            coordinator: "fb.example:7000".to_owned(),
            cert: "fb-cert.pem".into(),
            key: "fb-key.pem".into(),
            ca: "fb-ca.pem".into(),
        };
        let conn = CtlConnection::resolve(args, Some(fallback)).unwrap();
        assert_eq!(conn.coordinator, "fb.example:7000");
        assert_eq!(conn.cert, std::path::PathBuf::from("fb-cert.pem"));
    }

    #[test]
    fn explicit_flag_overrides_client_toml() {
        let args = CtlClientArgs {
            coordinator: Some("flag.example:443".to_owned()),
            cert: Some("flag-cert.pem".into()),
            key: Some("flag-key.pem".into()),
            ca: Some("flag-ca.pem".into()),
            profile: "default".to_owned(),
        };
        let fallback = crate::config::ClientConfig {
            coordinator: "fb.example:7000".to_owned(),
            cert: "fb-cert.pem".into(),
            key: "fb-key.pem".into(),
            ca: "fb-ca.pem".into(),
        };
        let conn = CtlConnection::resolve(args, Some(fallback)).unwrap();
        assert_eq!(conn.coordinator, "flag.example:443");
        assert_eq!(conn.cert, std::path::PathBuf::from("flag-cert.pem"));
    }
}
