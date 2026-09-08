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
use std::process::ExitCode;

use fleet_proto::admin::{BoardSummary, NodeSummary};
use fleet_proto::ids::BoardName;
use fleet_proto::lease::{Constraint, LeaseRequest, Priority};
use fleet_proto::token::AllowedOp;
use fleet_sidecar::transport::CoordSession;
use fleet_wire::{CoordToSidecar, SidecarToCoord};

use crate::cli::{CtlArgs, CtlClientArgs, CtlCommand};

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
    /// Resolve the connection config from the CLI/env flags, falling back to the
    /// selected fleet's file for any field the flags / env vars do not supply.
    ///
    /// Precedence: explicit flag / env var > `fleets/<name>.toml`. Errors only
    /// if a required field is supplied by neither source.
    ///
    /// The credential is refreshed on the way through if it is about to expire
    /// (see [`crate::fleet_config::ensure_fresh_session`] and
    /// [`crate::fleet_config::ensure_fresh_agent_session`]) — which is why this
    /// is `async` and why a flag-supplied token bypasses it: a token the user
    /// handed us is not ours to rotate, and redeeming an auth key to replace
    /// one they typed would be worse still.
    ///
    /// # Which table wins
    ///
    /// `[user]` if present, else `[agent]`. A machine holding both is a
    /// developer laptop that also hosts a sandbox, and the human's own
    /// credential must win — mirroring the sidecar's existing rule that a node
    /// credential is never silently substituted for a user's.
    ///
    /// # Errors
    ///
    /// Returns an error if `--coordinator` or `--token` (or their env / fleet
    /// file equivalents) cannot be resolved.
    pub async fn from_args(args: CtlClientArgs) -> Result<Self> {
        let fleet = args.fleet.clone();
        let fallback = crate::fleet_config::load_named_opt(&fleet);
        let token = match (&args.token, &fallback) {
            (None, Some(file)) if file.user.is_some() => Some(
                crate::fleet_config::ensure_fresh_session(&fleet, file)
                    .await
                    .with_context(|| format!("resolving the session token for fleet `{fleet}`"))?,
            ),
            (None, Some(file)) if file.agent.is_some() => Some(
                crate::fleet_config::ensure_fresh_agent_session(&fleet, file)
                    .await
                    .with_context(|| format!("resolving the agent session for fleet `{fleet}`"))?,
            ),
            // Neither table, or an explicit `--token`: leave `resolve` to fire
            // its "no credential" error, which names both login verbs.
            _ => None,
        };
        Self::resolve(args, fallback.as_ref(), token)
    }

    /// Resolve against an explicit (possibly absent) fleet-file fallback.
    ///
    /// `fallback_token` is the (possibly refreshed) session token from the fleet
    /// file, threaded in separately so this stays synchronous and testable.
    fn resolve(
        args: CtlClientArgs,
        fallback: Option<&crate::fleet_config::FleetFile>,
        fallback_token: Option<String>,
    ) -> Result<Self> {
        let (fb_url, fb_pin) = match fallback {
            Some(f) => (Some(f.url.clone()), f.server_cert_sha256.clone()),
            None => (None, None),
        };
        let fleet = args.fleet.clone();
        let fleet_url = args.coordinator.or(fb_url).with_context(|| {
            format!(
                "--coordinator (or PROBE_RS_FLEET_COORDINATOR, or fleets/{fleet}.toml) is \
                 required"
            )
        })?;
        let token = args.token.or(fallback_token).with_context(|| {
            format!(
                "no credential for fleet `{fleet}`; run `probe-rs-fleet login --fleet {fleet}` \
                 (or, for a persistent sandbox, `probe-rs-fleet agent login --fleet {fleet} \
                 --auth-key prffk1_\u{2026}`; or pass --token / PROBE_RS_FLEET_TOKEN)"
            )
        })?;
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

/// Parse a `lease`/board selector into a [`Constraint`].
///
/// A thin delegate to [`fleet_proto::lease::parse_constraint`], the fleet's one
/// selector grammar (architecture §6.5). There is no per-surface dialect: the
/// same expression means the same thing here, in the sidecar's
/// `PROBE_RS_FLEET_SELECT` and in `grant --select`.
///
/// * `id=<name>` — one specific board;
/// * `board=<model>` — any board of that model, e.g. `board=nrf52840dk`;
/// * `chip=<name>` — any board with that probe-rs chip;
/// * `tag=<t>` or a bare word, conjoinable with `&&`.
///
/// A **bare word is a tag**, everywhere: `ctl lease nrf52840-dk-3` is a tag
/// selector, and the board is named with `ctl lease id=nrf52840-dk-3`.
///
/// # Errors
///
/// Returns the parse error's message for a malformed expression.
pub fn parse_selector(selector: &str) -> Result<Constraint, String> {
    fleet_proto::lease::parse_constraint(selector).map_err(|e| e.to_string())
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
    ///
    /// Public because `roles::grant` speaks the same route with the same
    /// credentials — one dial path, per this module's note above.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or the Hello handshake fails.
    pub async fn connect_session(&self) -> Result<CoordSession> {
        let cfg = fleet_sidecar::selector::FleetConfig {
            coordinator: self.conn.fleet_url.clone(),
            token: self.conn.token.clone(),
            // `ctl` never leases through this path (it sends explicit operator
            // requests), so the selector is a placeholder the session ignores.
            select: Constraint::Tags(Vec::new()),
            server_cert_sha256: self.conn.server_cert_sha256.clone(),
            // Likewise: `ctl` never calls `CoordSession::lease`, so it never
            // waits on a queue slip. `ctl lease` prints its position and exits
            // (see `CtlClient::lease`); the bounded wait belongs to the sidecar
            // path, and the two are deliberately kept apart.
            queue_wait_secs: 0,
        };
        CoordSession::connect(&cfg)
            .await
            .with_context(|| format!("connecting to coordinator {}", self.conn.fleet_url))
    }

    /// `ctl list` — fleet inventory.
    ///
    /// `--json` emits the **wire type verbatim** (`Vec<BoardSummary>`), which
    /// is deliberately a *different contract* from `GET /api/v1/boards`: that
    /// body is the web UI's and is re-shaped for it (`BoardKeyView`,
    /// `SubjectView`, a lowercase `availability`), precisely so a field added
    /// for one consumer does not silently appear in the other's response.
    /// Emitting the wire type here means there is exactly one definition of
    /// this output, so it cannot drift from what the coordinator sent; its
    /// stability is the wire's stability, and a `PROTOCOL_VERSION` bump that
    /// reshapes `BoardSummary` reshapes this too.
    ///
    /// Concretely, and unlike the HTTP body: `board` is a nested object rather
    /// than a flattened key, `availability` is `PascalCase` (`"Leased"`),
    /// `holder` carries a `groups` array, `lease` is a bare number, and
    /// `power` is the full variant.
    async fn list(&self, json: bool) -> Result<()> {
        let session = self.connect_session().await?;
        match session.request(SidecarToCoord::ListBoards).await? {
            CoordToSidecar::BoardList(boards) => {
                if json {
                    // `power` is emitted in full, hub/port/gpio-line included.
                    // `api.rs`'s `BoardView` makes the opposite choice for the
                    // browser ("it describes the physical layout of somebody's
                    // lab"); that argument does not transfer here. The wire
                    // already carries the complete `PowerKind` to every `ctl
                    // list` caller, grantees included, so this is a new
                    // rendering of bytes the caller already holds rather than a
                    // new disclosure — and the hub/port is exactly what an
                    // operator debugging "why did power-cycle do nothing"
                    // needs.
                    println!("{}", serde_json::to_string_pretty(&boards)?);
                } else if boards.is_empty() {
                    println!("no boards in the fleet");
                } else {
                    print!("{}", render_board_table(&boards));
                }
                Ok(())
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }

    /// `ctl nodes` — the org's machines and their tags.
    ///
    /// The listing `ctl list` cannot give: it is board-shaped, so a machine
    /// that has plugged in no probes has no row there at all.
    ///
    /// `--json` emits the wire type verbatim for the same reasons as
    /// [`CtlClient::list`], and is likewise a different contract from
    /// `GET /api/v1/nodes`.
    async fn nodes(&self, json: bool) -> Result<()> {
        let session = self.connect_session().await?;
        match session.request(SidecarToCoord::ListNodes).await? {
            CoordToSidecar::NodeList(nodes) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&nodes)?);
                } else if nodes.is_empty() {
                    println!("no nodes in this org");
                } else {
                    print!("{}", render_node_table(&nodes));
                }
                Ok(())
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }

    /// `ctl lease <selector> [--duration]`.
    ///
    /// Deliberately **does not** grow the sidecar's bounded wait: this prints a
    /// queue position and exits 0, the same as it always has. The two paths
    /// stay distinct because they answer different questions — `probe-rs run`
    /// wants a board and will wait for one, an operator running `ctl lease`
    /// wants to know the state of the queue.
    ///
    /// The slip it reports now lasts only while the command runs: `ctl` opens
    /// one connection per command, and a connection closing drops its queued
    /// requests. That is the point — an abandoned `ctl lease` waiter used to
    /// sit in the queue forever and could be promoted onto a board nobody was
    /// holding — but it does mean the position is a snapshot, not a booking.
    async fn lease(&self, request: &LeaseRequest) -> Result<()> {
        let session = self.connect_session().await?;
        match session
            .request(SidecarToCoord::Lease(request.clone()))
            .await?
        {
            CoordToSidecar::Lease(grant) => {
                println!(
                    "leased {} (lease {}) on agent {} until {} (epoch)",
                    grant.board, grant.lease.0, grant.node.0, grant.expires
                );
                Ok(())
            }
            CoordToSidecar::Queued { position } => {
                println!(
                    "queued at position {position} (the slip lasts only while this command runs)"
                );
                Ok(())
            }
            CoordToSidecar::NoCandidate {
                selector,
                reachable,
            } => {
                anyhow::bail!(
                    "no board matches `{selector}`; ctl list shows {reachable} boards you can reach"
                )
            }
            CoordToSidecar::AtCap { held, cap } => anyhow::bail!(
                "you already hold {held} leases (cap max_concurrent_per_subject = {cap}); \
                 release one or raise the cap"
            ),
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }

    /// `ctl release <board>`.
    async fn release(&self, board: &BoardName) -> Result<()> {
        // Resolve the lease holding `board` via the board list, then release it.
        let session = self.connect_session().await?;
        let lease = match session.request(SidecarToCoord::ListBoards).await? {
            CoordToSidecar::BoardList(boards) => boards
                .into_iter()
                .find(|b| b.board.answers_to(&board.0))
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

    /// `ctl delegate --select … --ops … --ttl …`.
    ///
    /// Prints **only** the capability token and the two environment variables a
    /// sandbox needs. No session token, no fleet file, nothing that would give
    /// the sandbox a fleet identity — that is the whole design point of
    /// delegation (architecture §6.5).
    ///
    /// Returns the process exit code: a queue slip is a **failure**
    /// (exit 1, no token), as are `NoCandidate` and `AtCap`. A handoff script
    /// must not mistake "contended" for "here is your board", and blocking a
    /// sandbox-provisioning command on an unbounded queue would be worse than
    /// failing fast. Nothing is left queued behind a refusal either — the
    /// coordinator answers this verb without enqueueing.
    async fn delegate(
        &self,
        select: Constraint,
        ops: Vec<AllowedOp>,
        ttl_secs: u64,
    ) -> Result<ExitCode> {
        let session = self.connect_session().await?;
        match session
            .request(SidecarToCoord::Delegate {
                select,
                duration_secs: ttl_secs,
                ops,
            })
            .await?
        {
            CoordToSidecar::Lease(grant) => {
                let token = fleet_sidecar::transport::hex_encode(&grant.token);
                let ops = decode_token_ops(&grant.token);
                println!("# board {} (lease {})", grant.board, grant.lease.0);
                println!("# expires {} (epoch); ops: {ops}", grant.expires);
                println!("PROBE_RS_FLEET_COORDINATOR={}", self.conn.fleet_url);
                println!("PROBE_RS_FLEET_CAPABILITY={token}");
                println!(
                    "# revoke by releasing the lease: probe-rs-fleet ctl release {}",
                    grant.board.name
                );
                Ok(ExitCode::SUCCESS)
            }
            CoordToSidecar::Queued { position } => {
                eprintln!("board contended; queued at position {position} — no token issued");
                Ok(ExitCode::FAILURE)
            }
            CoordToSidecar::NoCandidate {
                selector,
                reachable,
            } => {
                eprintln!(
                    "no board matches `{selector}`; ctl list shows {reachable} boards you can reach"
                );
                Ok(ExitCode::FAILURE)
            }
            CoordToSidecar::AtCap { held, cap } => {
                eprintln!(
                    "you already hold {held} leases (cap max_concurrent_per_subject = {cap}); \
                     release one or raise the cap"
                );
                Ok(ExitCode::FAILURE)
            }
            CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
            other => anyhow::bail!("unexpected reply: {other:?}"),
        }
    }

    /// `ctl power-cycle <board>`.
    async fn power_cycle(&self, board: &BoardName) -> Result<()> {
        let session = self.connect_session().await?;
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
        let session = self.connect_session().await?;
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
        let session = self.connect_session().await?;
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

/// Render the `ctl list` board table.
///
/// Split out of the RPC so the layout is unit-testable without a coordinator.
///
/// TAGS sits **before** HOLDER because HOLDER is the one frequently-empty,
/// variable-width column and is already last; padding TAGS to a fixed width
/// keeps HOLDER aligned. `exclusive` and `power` stay out of the table — they
/// would push it past any terminal — and are carried by `--json`, which is
/// exactly why `--json` exists.
fn render_board_table(boards: &[BoardSummary]) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    // BOARD is the fleet key "<org>/<node>/<name>", so it is wider than
    // revision 1's bare id. MODEL is what `board=<model>` matches; `-` means
    // the board declared none (every adopted board), so no `board=` selector
    // can reach it.
    let _ = writeln!(
        out,
        "{:<32} {:<16} {:<14} {:<16} {:<12} {:<20} HOLDER",
        "BOARD", "AGENT", "MODEL", "CHIP", "STATE", "TAGS"
    );
    for b in boards {
        let state = format!("{:?}", b.availability);
        // Render the holder as its stable key ("<org>/<kind>:<id>").
        let holder = b
            .holder
            .as_ref()
            .map_or_else(String::new, |h| h.key().to_string());
        let model = b.model.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "{:<32} {:<16} {:<14} {:<16} {:<12} {:<20} {}",
            b.board,
            b.node.0,
            model,
            b.chip,
            state,
            crate::render::tags_cell(&b.tags),
            holder
        );
    }
    out
}

/// Render the `ctl nodes` machine table.
///
/// `LAST-SEEN` is epoch seconds (consistent with `ctl who`'s `EXPIRES`) and
/// `never` when the node has not connected — unambiguous, because the
/// populated value is numeric. BOARDS is an empty cell for a machine that has
/// reported no probes, which is exactly the row `ctl list` cannot show.
fn render_node_table(nodes: &[NodeSummary]) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<24} {:<24} {:<10} {:<8} {:<12} BOARDS",
        "NAME", "TAGS", "ADOPT", "ONLINE", "LAST-SEEN"
    );
    for n in nodes {
        let online = if n.online { "yes" } else { "no" };
        let last_seen = n
            .last_seen
            .map_or_else(|| "never".to_owned(), |ts| ts.to_string());
        let _ = writeln!(
            out,
            "{:<24} {:<24} {:<10} {:<8} {:<12} {}",
            n.name,
            crate::render::tags_cell(&n.tags),
            n.adopt.as_str(),
            online,
            last_seen,
            n.boards.join(",")
        );
    }
    out
}

/// Run a `ctl` command, returning the process exit code.
///
/// Most verbs succeed or bail; `delegate` is the one that reports a *soft*
/// failure (the board was contended, so no token was issued) as a non-zero
/// exit rather than an error, because a handoff script needs to distinguish it.
///
/// # Errors
///
/// Returns an error if the connection config is incomplete or the coordinator
/// RPC fails.
pub async fn run(args: CtlArgs) -> Result<ExitCode> {
    let conn = CtlConnection::from_args(args.client).await?;
    let client = CtlClient::new(conn);

    match args.command {
        CtlCommand::List { json } => client.list(json).await?,
        CtlCommand::Nodes { json } => client.nodes(json).await?,
        CtlCommand::Lease { selector, duration } => {
            let request = LeaseRequest {
                select: parse_selector(&selector).map_err(|e| anyhow::anyhow!("{e}"))?,
                duration_secs: duration,
                priority: Priority::Interactive,
            };
            client.lease(&request).await?;
        }
        CtlCommand::Release { board } => client.release(&BoardName(board)).await?,
        CtlCommand::PowerCycle { board } => client.power_cycle(&BoardName(board)).await?,
        CtlCommand::Who => client.who().await?,
        CtlCommand::Logs { board, follow } => {
            client.logs(board.map(BoardName).as_ref(), follow).await?;
        }
        CtlCommand::Delegate { select, ops, ttl } => {
            let select = parse_selector(&select).map_err(|e| anyhow::anyhow!("{e}"))?;
            let ops = crate::roles::grant::parse_ops_arg(&ops)?;
            let ttl = crate::timearg::parse_duration(&ttl).map_err(|e| anyhow::anyhow!("{e}"))?;
            return client.delegate(select, ops, ttl).await;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Render the ops carried by a signed capability token, for the delegate
/// output. Decode-only — no signature check, since we just received it from
/// the coordinator we authenticated to.
fn decode_token_ops(wire: &[u8]) -> String {
    let Ok(signed) = fleet_proto::token::SignedToken::from_wire(wire) else {
        return "unknown".to_owned();
    };
    let Ok(token) = signed.decode_token() else {
        return "unknown".to_owned();
    };
    let labels: Vec<&str> = token.allowed_ops.iter().map(|o| o.as_str()).collect();
    labels.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(coordinator: Option<&str>, token: Option<&str>) -> CtlClientArgs {
        CtlClientArgs {
            coordinator: coordinator.map(ToOwned::to_owned),
            token: token.map(ToOwned::to_owned),
            server_cert_sha256: None,
            fleet: "default".to_owned(),
        }
    }

    fn fallback(url: &str) -> crate::fleet_config::FleetFile {
        crate::fleet_config::FleetFile {
            url: url.to_owned(),
            ..crate::fleet_config::FleetFile::default()
        }
    }

    /// One reading of a bare word everywhere: it is a **tag**. `ctl lease
    /// nrf52840-dk-3` used to name a board; the board form is now spelled
    /// `id=`, which is fail-closed rather than ambiguous.
    #[test]
    fn a_bare_word_is_a_tag() {
        assert_eq!(
            parse_selector("nrf52840-dk-3").unwrap(),
            Constraint::Tags(vec!["nrf52840-dk-3".to_owned()])
        );
    }

    /// `id=` names one board; `board=` is the board **model**.
    #[test]
    fn id_is_the_instance_and_board_is_the_model() {
        assert_eq!(
            parse_selector("id=nrf52840-dk-3").unwrap(),
            Constraint::Id(BoardName("nrf52840-dk-3".to_owned()))
        );
        assert_eq!(
            parse_selector("board=nrf52840dk").unwrap(),
            Constraint::Model("nrf52840dk".to_owned())
        );
    }

    #[test]
    fn tag_prefix_is_a_tags_constraint() {
        assert_eq!(
            parse_selector("tag=nrf52").unwrap(),
            Constraint::Tags(vec!["nrf52".to_owned()])
        );
    }

    #[test]
    fn chip_prefix_is_a_chip_constraint() {
        assert_eq!(
            parse_selector("chip=nRF52840_xxAA").unwrap(),
            Constraint::Chip("nRF52840_xxAA".to_owned())
        );
    }

    /// Now that the grammar is shared, an empty term value is an error rather
    /// than a constraint on the empty tag: `Tags([""])` matches nothing and
    /// `Tags([])` matches everything, and neither is what the user typed.
    #[test]
    fn empty_term_values_are_refused() {
        assert!(parse_selector("tag=").is_err());
        assert!(parse_selector("chip=").is_err());
        assert!(parse_selector("board=").is_err());
        assert!(parse_selector("id=").is_err());
        assert!(parse_selector("").is_err());
    }

    /// `ctl lease '*'` and `ctl delegate --select '*'` both funnel through
    /// [`parse_selector`], so the shared grammar's refusal is what these
    /// surfaces show — assert it here rather than assume the funnelling.
    #[test]
    fn a_wildcard_selector_names_the_real_answer() {
        let e = parse_selector("*").unwrap_err();
        assert!(e.contains("no wildcard selector"), "{e}");
        assert!(parse_selector("tag=*").is_err());
    }

    #[test]
    fn connection_requires_a_url_and_a_token() {
        assert!(CtlConnection::resolve(args(None, None), None, None).is_err());
        assert!(CtlConnection::resolve(args(Some("c:1"), None), None, None).is_err());
        assert!(CtlConnection::resolve(args(None, Some("prfs1_t")), None, None).is_err());
    }

    #[test]
    fn connection_resolves_when_both_present() {
        let conn = CtlConnection::resolve(args(Some("https://coord"), Some("prfs1_t")), None, None)
            .unwrap();
        assert_eq!(conn.fleet_url, "https://coord");
        assert_eq!(conn.token, "prfs1_t");
        assert!(conn.pin().is_none());
    }

    #[test]
    fn connection_falls_back_to_the_fleet_file() {
        let conn = CtlConnection::resolve(
            args(None, None),
            Some(&fallback("https://fb.example")),
            Some("prfs1_fb".to_owned()),
        )
        .unwrap();
        assert_eq!(conn.fleet_url, "https://fb.example");
        assert_eq!(conn.token, "prfs1_fb");
    }

    #[test]
    fn explicit_flag_overrides_the_fleet_file() {
        let conn = CtlConnection::resolve(
            args(Some("https://flag.example"), Some("prfs1_flag")),
            Some(&fallback("https://fb.example")),
            Some("prfs1_fb".to_owned()),
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
        assert!(CtlConnection::resolve(a, None, None).is_err());

        let mut a = args(Some("https://c"), Some("prfs1_t"));
        a.server_cert_sha256 = Some("ab".repeat(32));
        let conn = CtlConnection::resolve(a, None, None).unwrap();
        assert_eq!(conn.pin(), Some([0xabu8; 32]));
    }

    // ---- rendering -------------------------------------------------------

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn sample_board(name: &str, tags: &[&str]) -> BoardSummary {
        use fleet_proto::admin::BoardAvailability;
        use fleet_proto::board::PowerKind;
        use fleet_proto::ids::{BoardRef, NodeId, OrgId, Subject, SubjectKind};

        BoardSummary {
            board: BoardRef::new(
                OrgId("gh-1".to_owned()),
                NodeId("gh-1/beast".to_owned()),
                name,
            ),
            node: NodeId("gh-1/beast".to_owned()),
            chip: "nRF52840_xxAA".to_owned(),
            model: Some("nrf52840dk".to_owned()),
            tags: owned(tags),
            exclusive: true,
            power: PowerKind::Uhubctl {
                hub: "1-1".to_owned(),
                port: 3,
            },
            availability: BoardAvailability::Leased,
            holder: Some(Subject::new(
                OrgId("gh-1".to_owned()),
                SubjectKind::User,
                "gh-9",
            )),
            lease: Some(fleet_proto::LeaseId(7)),
            expires: Some(123),
        }
    }

    fn sample_node(name: &str, tags: &[&str], boards: &[&str]) -> NodeSummary {
        use fleet_proto::ids::NodeId;

        NodeSummary {
            node: NodeId(format!("gh-1/{name}")),
            name: name.to_owned(),
            tags: owned(tags),
            adopt: fleet_proto::AdoptPolicy::Auto,
            owner: Some("gh-9".to_owned()),
            last_seen: Some(1_700_000_000),
            created_at: 1_600_000_000,
            online: true,
            boards: owned(boards),
        }
    }

    /// The board table shows tags, and an untagged board gets an **empty**
    /// cell rather than a placeholder word: `none` is a legal tag value, so a
    /// placeholder would be ambiguous.
    #[test]
    fn board_table_shows_tags_and_leaves_an_empty_cell_for_none() {
        let out = render_board_table(&[
            sample_board("dk-1", &["nrf52", "desk"]),
            sample_board("dk-2", &[]),
        ]);

        assert!(
            out.contains("TAGS"),
            "the header must name the column: {out}"
        );
        assert!(out.contains("nrf52,desk"), "{out}");
        let untagged = out
            .lines()
            .find(|l| l.contains("dk-2"))
            .expect("the untagged board has a row");
        assert!(
            !untagged.contains("none"),
            "an untagged board must not render a placeholder: {untagged}"
        );
    }

    /// The node table shows what `ctl list` cannot: tags, adopt policy, live
    /// state — and a machine that has reported no boards at all.
    #[test]
    fn node_table_shows_tags_adopt_online_and_a_boardless_node() {
        let mut offline = sample_node("never-seen", &[], &[]);
        offline.online = false;
        offline.last_seen = None;
        let out = render_node_table(&[sample_node("beast", &["desk"], &["dk-1", "dk-2"]), offline]);

        assert!(out.contains("TAGS") && out.contains("ADOPT"), "{out}");
        let beast = out.lines().find(|l| l.starts_with("beast")).unwrap();
        assert!(beast.contains("desk"), "{beast}");
        assert!(beast.contains("auto"), "{beast}");
        assert!(beast.contains("yes"), "{beast}");
        assert!(beast.contains("dk-1,dk-2"), "{beast}");

        let boardless = out
            .lines()
            .find(|l| l.starts_with("never-seen"))
            .expect("a node with no boards still gets a row");
        assert!(boardless.contains("no"), "{boardless}");
        assert!(boardless.contains("never"), "{boardless}");
    }

    /// `--json` emits the **wire type verbatim**, which is a different
    /// contract from `GET /api/v1/boards` (the web UI's). The assertions pin
    /// that shape — including `power` in full and the `PascalCase`
    /// `availability` — so a later `#[serde(rename_all)]` on the wire type
    /// trips here rather than silently breaking somebody's script.
    #[test]
    fn board_json_is_the_wire_shape_and_round_trips() {
        let boards = vec![sample_board("dk-1", &["nrf52", "desk"])];
        let out = serde_json::to_string_pretty(&boards).unwrap();

        assert_eq!(
            serde_json::from_str::<Vec<BoardSummary>>(&out).unwrap(),
            boards
        );

        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v[0]["tags"], serde_json::json!(["nrf52", "desk"]));
        assert_eq!(v[0]["exclusive"], serde_json::json!(true));
        // The power decision, asserted rather than assumed: the CLI does NOT
        // mirror `BoardView`'s redaction of the lab wiring.
        assert_eq!(v[0]["power"]["Uhubctl"]["hub"], serde_json::json!("1-1"));
        assert_eq!(v[0]["power"]["Uhubctl"]["port"], serde_json::json!(3));
        // PascalCase, unlike the HTTP body's lowercase `"leased"`.
        assert_eq!(v[0]["availability"], serde_json::json!("Leased"));
        // A nested key object, not the API's flattened `BoardKeyView`.
        assert_eq!(v[0]["board"]["name"], serde_json::json!("dk-1"));
    }

    /// A JSON consumer must always get JSON — never the "no boards in the
    /// fleet" prose the table path prints.
    #[test]
    fn board_json_of_an_empty_fleet_is_an_empty_array() {
        let boards: Vec<BoardSummary> = Vec::new();
        let out = serde_json::to_string_pretty(&boards).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&out).unwrap(),
            serde_json::json!([])
        );
    }

    /// The same for nodes. `adopt` *is* lowercase (`AdoptPolicy` carries
    /// `#[serde(rename_all = "lowercase")]`) while `availability` above is
    /// not — an asymmetry worth pinning precisely because it is surprising.
    #[test]
    fn node_json_is_the_wire_shape_and_round_trips() {
        let nodes = vec![sample_node("beast", &["desk"], &["dk-1"])];
        let out = serde_json::to_string_pretty(&nodes).unwrap();

        assert_eq!(
            serde_json::from_str::<Vec<NodeSummary>>(&out).unwrap(),
            nodes
        );

        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v[0]["tags"], serde_json::json!(["desk"]));
        assert_eq!(v[0]["adopt"], serde_json::json!("auto"));
        assert_eq!(v[0]["online"], serde_json::json!(true));
    }
}
