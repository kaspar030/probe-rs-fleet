//! The `ctl` role: admin / UX CLI talking to the coordinator over mTLS.
//!
//! The command surface (parsing, selector grammar, output formatting) is fully
//! implemented and unit-tested here. The *transport* — an mTLS client of the
//! coordinator — is built from the shared connection flags via [`fleet_tls`].
//!
//! The coordinator's admin RPC surface (fleet inventory `list`, `who`, `logs`,
//! `power-cycle`, plus the `lease`/`release` admin path) is not yet exposed on
//! its control plane (task 1711 wires the sidecar lease envelopes but no
//! operator/admin endpoints). Until that lands, [`CtlClient`] resolves its
//! connection config but each command returns a clear "not yet available"
//! error rather than silently doing nothing. Wiring each command to a
//! coordinator request is then a localised change at the marked seam.

use anyhow::{Context, Result};

use fleet_proto::ids::BoardId;
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
/// - anything else → [`Constraint::Board`] (a bare board id).
#[must_use]
pub fn parse_selector(selector: &str) -> Constraint {
    if let Some(tag) = selector.strip_prefix("tag=") {
        Constraint::Tags(vec![tag.to_owned()])
    } else if let Some(chip) = selector.strip_prefix("chip=") {
        Constraint::Chip(chip.to_owned())
    } else {
        Constraint::Board(BoardId(selector.to_owned()))
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

    /// The integration seam: all admin commands route through this until the
    /// coordinator exposes an operator RPC (task 1711). It validates the TLS
    /// material (failing fast on misconfiguration) and then reports the
    /// not-yet-wired condition.
    fn admin_rpc(&self, command: &str) -> Result<()> {
        // Eagerly validate connection material so operators get a real error
        // for bad cert paths even before the RPC lands.
        let _tls = self.tls_config()?;
        // RESOLVE(1711 admin RPC): open the mTLS stream to
        // `self.conn.coordinator`, send the operator request for `command`,
        // and print the typed response. The lease/release envelopes already
        // exist on the sidecar plane; the operator-facing list/who/logs/
        // power-cycle endpoints are co-owned with task 1711.
        anyhow::bail!(
            "ctl {command}: coordinator admin RPC not yet available (blocked on task 1711); \
             connection to {} is configured and TLS material validated",
            self.conn.coordinator
        )
    }

    /// `ctl list` — fleet inventory.
    fn list(&self) -> Result<()> {
        self.admin_rpc("list")
    }

    /// `ctl lease <selector> [--duration]`.
    fn lease(&self, request: &LeaseRequest) -> Result<()> {
        tracing::debug!(?request, "lease request prepared");
        self.admin_rpc("lease")
    }

    /// `ctl release <board>`.
    fn release(&self, board: &BoardId) -> Result<()> {
        tracing::debug!(%board, "release request prepared");
        self.admin_rpc("release")
    }

    /// `ctl power-cycle <board>`.
    fn power_cycle(&self, board: &BoardId) -> Result<()> {
        tracing::debug!(%board, "power-cycle request prepared");
        self.admin_rpc("power-cycle")
    }

    /// `ctl who` — current lease holders.
    fn who(&self) -> Result<()> {
        self.admin_rpc("who")
    }

    /// `ctl logs [board] [--follow]`.
    fn logs(&self, board: Option<&BoardId>, follow: bool) -> Result<()> {
        tracing::debug!(?board, follow, "logs request prepared");
        self.admin_rpc("logs")
    }
}

/// Run a `ctl` command.
///
/// # Errors
///
/// Returns an error if the connection config is incomplete or the (currently
/// unwired) coordinator RPC fails.
#[allow(clippy::unused_async)] // async to match the uniform role-handler signature; awaits once 1711 lands
pub async fn run(args: CtlArgs) -> Result<()> {
    let conn = CtlConnection::from_args(args.client)?;
    let client = CtlClient::new(conn);

    match args.command {
        CtlCommand::Init(_) | CtlCommand::Profiles => {
            // `ctl init` / `ctl profiles` are dispatched in cli.rs before a
            // connection is built; reaching here would be a logic error.
            anyhow::bail!("`ctl init`/`ctl profiles` must be handled before connecting")
        }
        CtlCommand::List => client.list(),
        CtlCommand::Lease { selector, duration } => {
            let request = LeaseRequest {
                select: parse_selector(&selector),
                duration_secs: duration,
                priority: Priority::Interactive,
            };
            client.lease(&request)
        }
        CtlCommand::Release { board } => client.release(&BoardId(board)),
        CtlCommand::PowerCycle { board } => client.power_cycle(&BoardId(board)),
        CtlCommand::Who => client.who(),
        CtlCommand::Logs { board, follow } => {
            client.logs(board.map(BoardId).as_ref(), follow)
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
            Constraint::Board(BoardId("nrf52840-dk-3".to_owned()))
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
