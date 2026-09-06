//! Sidecar role implementation for probe-rs-fleet.
//!
//! The sidecar runs on developer workstations and CI. It presents a **vanilla
//! `probe-rs` CLI surface** so that `ariel-os` / `laze` invoke it unmodified
//! (see `docs/architecture.md` §4.3). Depending on the environment it either:
//!
//! * **Local fallback** — no fleet selector set ⇒ transparently exec the real
//!   local `probe-rs` (local DX unchanged), or
//! * **Fleet proxy** — a fleet selector is set ⇒ lease a board from the
//!   coordinator, expose a local relay endpoint, point the genuine probe-rs
//!   client at it via `PROBE_RS_REMOTE_HOST` / `PROBE_RS_REMOTE_TOKEN`, and let
//!   the real client run against the remote board over the relay.
//!
//! Key insight (investigation #1710): the sidecar **runs the genuine probe-rs
//! client**, it does not re-implement it. The real client does probe + chip
//! selection in-band and computes the exit code, so exit-code propagation is
//! free — the sidecar just propagates the child's exit status.
//!
//! ## Install UX (recommendation)
//!
//! Ship the multi-role `fleet` binary with an **argv0 `probe-rs` symlink on
//! `PATH`** as the primary install story: argv0 dispatch is what lets laze run
//! unmodified. Provide `fleet sidecar run -- <args>` as an explicit escape
//! hatch for debugging. argv0 dispatch wiring lives in `fleet-bin` (task 1714);
//! this crate exposes the reusable [`run`] entry point.
//!
//! ## Module map
//!
//! * [`cli`] — parse the six probe-rs invocation shapes (+ passthrough),
//!   preserving every original argument.
//! * [`selector`] — resolve the fleet configuration from the environment, with
//!   a clean no-selector → local fallback.
//! * [`lease_cache`] — time-based lease sharing keyed by selector + subject key.
//! * [`proxy`] — the documented relay seam (lease / byte-splice contract).
//! * [`transport`] — the live `WebSocket` + byte-opaque relay client: lease a board, open
//!   a relay channel, splice the genuine probe-rs client's bytes verbatim.
//! * [`gdb`] — the gdb-tunnel client side: a local TCP listener (default
//!   `127.0.0.1:1337`) byte-spliced to the agent's `probe-rs gdb` stub over a
//!   second relay channel (`probe-rs gdb` is not remote-capable in 0.32).
//! * [`local`] — locate and exec the genuine probe-rs (local + remote env).
//! * [`signal`] — SIGINT/SIGTERM handling for the fleet path, so Ctrl-C
//!   releases the lease instead of stranding the board until it expires.
//!
//! ## Lease lifetime on the fleet path
//!
//! The sidecar asks for `duration_secs: 0`, i.e. the coordinator's own
//! `Policy::default_ttl_secs`, and **heartbeats** (`Extend`) for the life of
//! the invocation, so a long `attach` / `gdb` session is not cut short by a
//! short policy TTL. On SIGINT/SIGTERM it releases before exiting. A sidecar
//! that is killed outright releases nothing — nothing can — but the board comes
//! back after one policy TTL rather than the hardcoded hour this replaced.

pub mod cli;
pub mod gdb;
pub mod lease_cache;
pub mod local;
pub mod proxy;
pub mod selector;
pub mod signal;
pub mod transport;

use std::ffi::OsString;

use selector::{EnvSource, Resolution};

/// Errors from the top-level [`run`] entry point.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The argv could not be parsed.
    #[error(transparent)]
    Cli(#[from] cli::CliError),
    /// The fleet selector environment was partial / contradictory.
    #[error(transparent)]
    Selector(#[from] selector::SelectorError),
    /// Locating or running the real probe-rs failed.
    #[error(transparent)]
    Local(#[from] local::LocalError),
    /// The relay / lease transport failed.
    #[error(transparent)]
    Proxy(#[from] proxy::ProxyError),
    /// The gdb tunnel failed.
    #[error(transparent)]
    Gdb(#[from] gdb::GdbError),
    /// The live relay transport failed.
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
}

/// Parse `args` (a full process argv) and resolve what the sidecar should do,
/// without performing any side effects. Splitting resolution from execution
/// keeps the decision logic unit-testable.
///
/// Returns the parsed invocation and the environment resolution.
///
/// # Errors
///
/// Returns [`RunError`] if the argv is invalid or the fleet environment is
/// partial / contradictory.
pub fn resolve<I, S>(
    args: I,
    env: &impl EnvSource,
) -> Result<(cli::ProbeRsInvocation, Resolution), RunError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let tokens: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let invocation = cli::parse(tokens)?;
    let resolution = selector::resolve(env)?;
    Ok((invocation, resolution))
}

/// Entry point: parse the probe-rs argv, resolve the environment, and either
/// transparently exec the local probe-rs or proxy the session through the
/// fleet, returning the process exit code to propagate.
///
/// The fleet path leases a board over a bearer-authenticated `WebSocket`, opens
/// a relay channel, exposes a
/// local endpoint, and execs the genuine probe-rs (or tunnels gdb) against it
/// via [`transport`]. The local fallback path execs probe-rs directly.
///
/// # Errors
///
/// Returns [`RunError`] on a parse error, a partial fleet environment, a
/// failure to locate / run the real probe-rs, or a relay transport error.
pub fn run<I, S>(args: I, env: &impl EnvSource) -> Result<i32, RunError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let tokens: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let invocation = cli::parse(tokens.clone())?;
    let resolution = selector::resolve(env)?;

    match resolution {
        Resolution::Local => {
            // Transparent local fallback: forward the original argv (after
            // argv[0]) to the real probe-rs and propagate its exit code.
            let code = local::exec_local(tokens.into_iter().skip(1))?;
            Ok(code)
        }
        Resolution::Fleet(cfg) => {
            // The fleet path needs an async runtime. Build a fresh one here for
            // the SYNC entry point (used by library callers / unit tests that
            // are not already inside a runtime). Binaries running inside an
            // existing tokio runtime must use [`run_async`] instead — building
            // a runtime from within a runtime panics.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| transport::TransportError::Io(format!("building runtime: {e}")))?;
            let original_argv: Vec<String> = tokens.iter().map(|t| t.to_string_lossy().into_owned()).collect();
            rt.block_on(run_fleet(cfg, invocation, original_argv))
        }
        Resolution::Delegated(cfg) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| transport::TransportError::Io(format!("building runtime: {e}")))?;
            let original_argv: Vec<String> = tokens.iter().map(|t| t.to_string_lossy().into_owned()).collect();
            rt.block_on(run_delegated(cfg, invocation, original_argv))
        }
    }
}

/// Async entry point: parse the probe-rs argv, resolve the environment, and
/// either transparently exec the local probe-rs or proxy the session through
/// the fleet, returning the process exit code to propagate.
///
/// Unlike the sync [`run`], this drives the fleet path on the *caller's*
/// runtime (`run_fleet(...).await`) instead of building a nested one, so it can
/// be `.await`ed from inside an existing tokio runtime without panicking. The
/// local fallback path (`exec_local`) is synchronous and `execvp`-replaces the
/// process, so it never returns on success.
///
/// # Errors
///
/// Returns [`RunError`] on a parse error, a partial fleet environment, a
/// failure to locate / run the real probe-rs, or a relay transport error.
pub async fn run_async<I, S>(args: I, env: &impl EnvSource) -> Result<i32, RunError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let tokens: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let invocation = cli::parse(tokens.clone())?;
    let resolution = selector::resolve(env)?;

    match resolution {
        Resolution::Local => {
            // Transparent local fallback: forward the original argv (after
            // argv[0]) to the real probe-rs and propagate its exit code.
            let code = local::exec_local(tokens.into_iter().skip(1))?;
            Ok(code)
        }
        Resolution::Fleet(cfg) => {
            // Drive the fleet path directly on the caller's runtime.
            let original_argv: Vec<String> = tokens.iter().map(|t| t.to_string_lossy().into_owned()).collect();
            run_fleet(cfg, invocation, original_argv).await
        }
        Resolution::Delegated(cfg) => {
            let original_argv: Vec<String> = tokens.iter().map(|t| t.to_string_lossy().into_owned()).collect();
            run_delegated(cfg, invocation, original_argv).await
        }
    }
}

/// Drive the fleet path: lease a board, open a relay channel, expose a local
/// endpoint, and either exec the genuine probe-rs against it (data plane) or
/// tunnel the local gdb client (gdb plane).
async fn run_fleet(
    cfg: selector::FleetConfig,
    invocation: cli::ProbeRsInvocation,
    original_argv: Vec<String>,
) -> Result<i32, RunError> {
    use fleet_proto::lease::{LeaseRequest, Priority};

    let session = transport::CoordSession::connect(&cfg).await?;
    let request = LeaseRequest {
        select: cfg.select.clone(),
        // `0` means "the operator's `Policy::default_ttl_secs`". **Do not**
        // reintroduce a constant here, not even as a "sensible fallback": the
        // hardcoded 3600s this replaced meant a killed sidecar sat on a board
        // for an hour, and a knob would just be a slower way back to it. The
        // TTL is the coordinator's policy to set; we keep the lease alive for
        // as long as we actually need it by heartbeating (see `keepalive`).
        duration_secs: 0,
        priority: Priority::Interactive,
    };
    let grant = session.lease(&request).await?;
    tracing::info!(board = %grant.board, lease = ?grant.lease, "leased board");

    let work = async {
        match &invocation {
            cli::ProbeRsInvocation::Gdb {
                connection_string, ..
            } => run_fleet_gdb(&session, grant.lease, connection_string.as_deref()).await,
            _ => run_fleet_data(&session, grant.lease, &original_argv).await,
        }
    };

    hold_and_run(&session, &grant, work, signal::shutdown_signal()).await
}

/// Hold `grant` for the duration of `work`: heartbeat it, abandon it on
/// `shutdown`, and release it on the way out whichever arm wins.
///
/// Split out of [`run_fleet`] so the release-on-signal behaviour is testable
/// without raising real signals at the test process: `shutdown` is a parameter,
/// and `run_fleet` simply passes [`signal::shutdown_signal`]. It is `pub` for
/// the same reason [`gdb::splice`] is — an integration test drives it against a
/// mock coordinator peer (`tests/lease_lifecycle.rs`).
///
/// On shutdown the returned code is `128 + signum`, exactly what the shell sees
/// from a signalled child. `work` is dropped explicitly *before* the release,
/// which kills the genuine probe-rs ([`transport::exec_remote_probe_rs`] sets
/// `kill_on_drop`) rather than leaving it driving a board we are in the middle
/// of handing back.
///
/// # Errors
///
/// Propagates whatever `work` returns.
pub async fn hold_and_run<F>(
    session: &transport::CoordSession,
    grant: &fleet_proto::lease::LeaseGrant,
    work: F,
    shutdown: impl std::future::Future<Output = i32>,
) -> Result<i32, RunError>
where
    F: std::future::Future<Output = Result<i32, RunError>>,
{
    // `Box::pin`, not `tokio::pin!`: the latter lives in a function-scope local
    // that cannot be dropped early, so `work` would outlive the release below
    // (which itself spends up to 2s draining the ack) and the genuine probe-rs
    // would keep running across it. `work` only borrows `session` / `grant`, so
    // dropping it first is fine.
    let mut work = Box::pin(work);
    tokio::pin!(shutdown);

    let result = tokio::select! {
        r = &mut work => r,
        never = keepalive(session, grant) => match never {},
        signum = &mut shutdown => Ok(128 + signum),
    };

    // Kill the genuine probe-rs before handing the lease back: on the shutdown
    // arm the child is still running, and a board we release may be granted to
    // somebody else immediately.
    drop(work);

    // Always release the lease (best-effort). Reached on every arm, including
    // the shutdown one — that is the entire point of the signal handling: a
    // Ctrl-C must not strand the board until the TTL expires.
    session.release(grant.lease).await;
    result
}

/// Renew `grant` for as long as this invocation runs. Never completes.
///
/// Without a heartbeat, a session outliving its TTL is not merely re-leasable:
/// the coordinator's sweep closes the relay channels and power-cycles the board
/// under a live `attach` / `gdb`. With the policy default at 900s that is a
/// routine occurrence, so the keepalive is what makes dropping the hardcoded
/// 3600s safe.
///
/// The heartbeat renews the **lease**, not the channel's capability token. The
/// token's `expires` is stamped at `OpenChannel` time and checked exactly once,
/// by the agent in `on_open_session`; thereafter it is an opaque shared secret
/// handed to `probe-rs serve`. So an open channel outlives its token's nominal
/// expiry, which is precisely what makes a short lease TTL workable.
///
/// A failing heartbeat is logged, not fatal — there is nothing better to do,
/// and the user's real signal is the data plane going quiet when the sweep
/// closes the channel. The interval gives three attempts per TTL.
async fn keepalive(
    session: &transport::CoordSession,
    grant: &fleet_proto::lease::LeaseGrant,
) -> std::convert::Infallible {
    // The *local* clock is used only to pick an interval, never to judge
    // whether the lease is still valid: our clock may skew from the
    // coordinator's, and a slightly wrong interval is harmless where a wrong
    // validity judgement would not be. An implausible remainder (clock skew, a
    // grant already in the past) falls back to a conservative 60s.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let ttl = grant.expires.saturating_sub(now);
    let interval = if ttl == 0 || ttl > 24 * 60 * 60 {
        60
    } else {
        (ttl / 3).clamp(15, 300)
    };
    let interval = std::time::Duration::from_secs(interval);

    let mut failures = 0u32;
    loop {
        tokio::time::sleep(interval).await;
        match session.extend(grant.lease).await {
            Ok(expires) => {
                failures = 0;
                tracing::debug!(lease = ?grant.lease, expires, "renewed lease");
            }
            Err(error) => {
                failures += 1;
                if failures >= 2 {
                    // Two misses in a row means we are probably going to lose
                    // the board mid-session, and the user will see the data
                    // plane stop rather than an error. Say so loudly.
                    tracing::error!(
                        lease = ?grant.lease, %error, failures,
                        "lease renewal keeps failing; the board may be reclaimed mid-session"
                    );
                } else {
                    tracing::warn!(lease = ?grant.lease, %error, "lease renewal failed");
                }
            }
        }
    }
}

/// Drive the **delegated** path: a sandboxed agent using a board somebody else
/// already leased for it (architecture §6.5).
///
/// The differences from [`run_fleet`] are all subtractions, and each is the
/// point rather than a simplification:
///
/// * no `Lease` — the board is already held; the lease id is decoded from the
///   token locally, which needs no key and no round trip;
/// * **no `release`, and no extend** — the delegator owns the lease lifecycle.
///   The sandbox's only lease-affecting power is letting it expire. This is
///   enforced by the coordinator's `/delegate` allowlist, not by this
///   politeness, but the politeness is what makes the intent readable. Renewal
///   is the delegator's job for the same reason: a sandbox that could heartbeat
///   could hold the board indefinitely. There is likewise no shutdown arm —
///   there is no lease of ours to release on Ctrl-C;
/// * no fleet identity of any kind: the connection carries the capability token
///   and nothing else.
async fn run_delegated(
    cfg: selector::DelegatedConfig,
    invocation: cli::ProbeRsInvocation,
    original_argv: Vec<String>,
) -> Result<i32, RunError> {
    let Some(lease) = cfg.lease() else {
        return Err(RunError::Selector(
            selector::SelectorError::InvalidCapability,
        ));
    };
    let session = transport::CoordSession::connect_delegated(&cfg).await?;
    tracing::info!(?lease, "using a delegated lease");

    match &invocation {
        cli::ProbeRsInvocation::Gdb {
            connection_string, ..
        } => run_fleet_gdb(&session, lease, connection_string.as_deref()).await,
        _ => run_fleet_data(&session, lease, &original_argv).await,
    }
    // Deliberately no `session.release(lease)`: the lease is not ours.
}

/// Data-plane path: open a data channel, bind a loopback endpoint the genuine
/// probe-rs client dials as its remote host, splice it onto the relay, and exec
/// the real probe-rs.
///
/// Takes a bare `lease` rather than a whole grant, because the delegated path
/// has no grant — only a token, from which it decodes the lease locally. The
/// data-plane credential comes from `ChannelOpened` either way, so the two
/// paths converge here completely.
async fn run_fleet_data(
    session: &transport::CoordSession,
    lease: fleet_proto::LeaseId,
    original_argv: &[String],
) -> Result<i32, RunError> {
    use fleet_proto::ChannelKind;

    let (channel, channel_token) = session.open_channel(lease, ChannelKind::Data).await?;

    // Bind a loopback listener the probe-rs client treats as its remote host.
    // The client builds `{host}/worker` and dials it as a WebSocket, so `host`
    // must already carry the `ws://` scheme.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| transport::TransportError::Io(format!("binding local endpoint: {e}")))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| transport::TransportError::Io(format!("reading local endpoint: {e}")))?;
    let remote_host = format!("ws://{local_addr}");
    // The **channel** token, not the lease grant's: this is the credential the
    // coordinator handed the agent, and therefore the one `probe-rs serve`
    // accepts. A lease grant's token is the delegation artefact and diverges
    // from it after an `Extend` or under an attenuating grant.
    let token = transport::hex_encode(&channel_token);

    // Accept the single probe-rs client connection and splice it in a task that
    // borrows the session for the duration of the child process.
    let real = transport::find_real_probe_rs()?;
    let args: Vec<String> = original_argv.iter().skip(1).cloned().collect();

    // Run the splice acceptor concurrently with the probe-rs child.
    let splice = async {
        if let Ok((client, _peer)) = listener.accept().await {
            let _ = client.set_nodelay(true);
            let _ = transport::splice_client(session, channel, client).await;
        }
    };
    let child = transport::exec_remote_probe_rs(&real, &args, &remote_host, &token);

    // The child drives the session; when it exits we stop accepting/splicing.
    tokio::pin!(splice);
    tokio::pin!(child);
    let mut splice_done = false;
    loop {
        tokio::select! {
            () = &mut splice, if !splice_done => { splice_done = true; }
            code = &mut child => {
                return Ok(code?);
            }
        }
    }
}

/// gdb-plane fleet path: open a gdb channel, bind the local gdb listener the
/// user's gdb client connects to, and byte-splice it onto the relay.
async fn run_fleet_gdb(
    session: &transport::CoordSession,
    lease: fleet_proto::LeaseId,
    connection_string: Option<&str>,
) -> Result<i32, RunError> {
    use fleet_proto::ChannelKind;

    let (channel, _token) = session.open_channel(lease, ChannelKind::Gdb).await?;
    let addr = gdb::resolve_listen_addr(connection_string)?;
    let listener = gdb::bind(addr).await?;
    tracing::info!(%addr, "gdb tunnel listening; point your gdb client here");
    let client = gdb::accept(&listener).await?;
    transport::splice_client(session, channel, client).await?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MapEnv(HashMap<String, String>);

    impl MapEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            )
        }
    }

    impl EnvSource for MapEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    #[test]
    fn resolve_local_when_no_fleet_env() {
        let env = MapEnv::new(&[]);
        let (inv, res) = resolve(
            ["probe-rs", "run", "--chip", "nrf52", "fw.elf"].map(String::from),
            &env,
        )
        .unwrap();
        assert_eq!(inv.chip(), Some("nrf52"));
        assert_eq!(res, Resolution::Local);
    }

    #[test]
    fn resolve_fleet_when_selector_set() {
        let env = MapEnv::new(&[
            (selector::env::ID, "nrf52840-dk-3"),
            (selector::env::COORDINATOR, "c:4443"),
            (selector::env::TOKEN, "t"),
        ]);
        let (_inv, res) = resolve(
            ["probe-rs", "run", "--chip", "nrf52", "fw.elf"].map(String::from),
            &env,
        )
        .unwrap();
        assert!(matches!(res, Resolution::Fleet(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_async_fleet_path_does_not_nest_runtime() {
        // Regression for the "Cannot start a runtime from within a runtime"
        // panic: when the binary drives the sidecar from inside the outer
        // tokio runtime, the Fleet arm must run on the caller's runtime rather
        // than building a nested one. Before the fix, calling the sync `run`
        // here panicked while building the inner runtime; `run_async` drives
        // `run_fleet` directly and instead surfaces a connection error against
        // the unresolvable host (proving we reached the relay code, not a
        // panic).
        let env = MapEnv::new(&[
            (selector::env::ID, "nrf52840-dk-3"),
            (selector::env::COORDINATOR, "c:4443"),
            (selector::env::TOKEN, "t"),
        ]);
        let err = run_async(
            ["probe-rs", "reset", "--chip", "nrf52"].map(String::from),
            &env,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            RunError::Transport(transport::TransportError::Connect(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_async_propagates_selector_error_within_runtime() {
        // The async entry point still parses + resolves like the sync one;
        // a partial fleet environment surfaces as a selector error without
        // touching any runtime machinery.
        let env = MapEnv::new(&[
            (selector::env::COORDINATOR, "c:4443"),
            (selector::env::TOKEN, "t"),
        ]);
        let err = run_async(["probe-rs", "reset"].map(String::from), &env)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RunError::Selector(selector::SelectorError::MissingSelector)
        ));
    }


    /// The fleet path reaches the transport rather than short-circuiting: with
    /// a bearer token and an unresolvable coordinator it must surface a
    /// *connection* error. Before revision 2 this test asserted the opposite —
    /// that a token-only configuration was refused because mTLS was mandatory —
    /// which is exactly the requirement bearer auth removed.
    #[test]
    fn run_fleet_path_dials_with_the_bearer_token() {
        let env = MapEnv::new(&[
            (selector::env::ID, "nrf52840-dk-3"),
            (selector::env::COORDINATOR, "c:4443"),
            (selector::env::TOKEN, "prfs1_t"),
        ]);
        let err = run(
            ["probe-rs", "reset", "--chip", "nrf52"].map(String::from),
            &env,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RunError::Transport(transport::TransportError::Connect(_))
        ));
    }

    /// A fleet selector plus a *no-board* subcommand (`list`) still goes to the
    /// fleet: it must reach the transport, never silently enumerate local
    /// probes.
    ///
    /// **Recorded decision (task 3595, option (a)): `list` keeps leasing.**
    /// `list` parses to `Passthrough` and runs through the relay against the
    /// agent's per-board `probe-rs serve`, so it prints the *remote* probe —
    /// which is the answer the user asked for. That channel is lease-gated by
    /// construction, so "don't lease for `list`" is not implementable without
    /// synthesising probe-level output from board-level inventory (a different,
    /// weaker answer; `ctl list` is the fleet-level path and needs no lease).
    /// The mitigation for the cost of leasing is the shorter TTL this task
    /// introduces, not a special case here. Please do not re-litigate without
    /// re-reading that: making `list` fall back to *local* probes under a fleet
    /// selector would be the same class of trap as the old local fallback.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fleet_selector_never_falls_back_to_local_probes() {
        let env = MapEnv::new(&[
            (selector::env::ID, "nrf52840-dk-3"),
            (selector::env::COORDINATOR, "unresolvable.invalid:4443"),
            (selector::env::TOKEN, "prfs1_t"),
        ]);
        let err = run_async(["probe-rs", "list"].map(String::from), &env)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                RunError::Transport(transport::TransportError::Connect(_))
            ),
            "a no-board subcommand under a fleet selector must reach the relay, got {err:?}"
        );
    }

    #[test]
    fn run_propagates_selector_error() {
        // Coordinator + auth but no board selector → MissingSelector.
        let env = MapEnv::new(&[
            (selector::env::COORDINATOR, "c:4443"),
            (selector::env::TOKEN, "t"),
        ]);
        let err = run(["probe-rs", "reset"].map(String::from), &env).unwrap_err();
        assert!(matches!(
            err,
            RunError::Selector(selector::SelectorError::MissingSelector)
        ));
    }
}
