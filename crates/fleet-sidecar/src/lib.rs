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
//! * [`lease_cache`] — time-based lease sharing keyed by selector + principal.
//! * [`proxy`] — the documented relay seam (lease / byte-splice contract).
//! * [`transport`] — the live mTLS + byte-opaque relay client: lease a board, open
//!   a relay channel, splice the genuine probe-rs client's bytes verbatim.
//! * [`gdb`] — the gdb-tunnel client side: a local TCP listener (default
//!   `127.0.0.1:1337`) byte-spliced to the agent's `probe-rs gdb` stub over a
//!   second relay channel (`probe-rs gdb` is not remote-capable in 0.32).
//! * [`local`] — locate and exec the genuine probe-rs (local + remote env).

pub mod cli;
pub mod gdb;
pub mod lease_cache;
pub mod local;
pub mod proxy;
pub mod selector;
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
/// The fleet path leases a board over mTLS, opens a relay channel, exposes a
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
        duration_secs: 3600,
        priority: Priority::Interactive,
    };
    let grant = session.lease(&request).await?;
    tracing::info!(board = %grant.board, lease = ?grant.lease, "leased board");

    let result = match &invocation {
        cli::ProbeRsInvocation::Gdb {
            connection_string, ..
        } => run_fleet_gdb(&session, &grant, connection_string.as_deref()).await,
        _ => run_fleet_data(&session, &grant, &original_argv).await,
    };

    // Always release the lease before returning (best-effort).
    session.release(grant.lease).await;
    result
}

/// Data-plane fleet path: open a data channel, bind a loopback endpoint the
/// genuine probe-rs client dials as its remote host, splice it onto the relay,
/// and exec the real probe-rs.
async fn run_fleet_data(
    session: &transport::CoordSession,
    grant: &fleet_proto::lease::LeaseGrant,
    original_argv: &[String],
) -> Result<i32, RunError> {
    use fleet_proto::ChannelKind;

    let channel = session.open_channel(grant.lease, ChannelKind::Data).await?;

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
    let token = transport::hex_encode(&grant.token);

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
    grant: &fleet_proto::lease::LeaseGrant,
    connection_string: Option<&str>,
) -> Result<i32, RunError> {
    use fleet_proto::ChannelKind;

    let channel = session.open_channel(grant.lease, ChannelKind::Gdb).await?;
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
            (selector::env::BOARD, "nrf52840-dk-3"),
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
        // `run_fleet` directly and instead surfaces the mandatory-mTLS
        // transport error (proving we reached the relay code, not a panic).
        let env = MapEnv::new(&[
            (selector::env::BOARD, "nrf52840-dk-3"),
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
            RunError::Transport(transport::TransportError::Tls(_))
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


    #[test]
    fn run_fleet_path_requires_mtls() {
        // Token-only auth is rejected for runtime traffic (mTLS is mandatory);
        // the fleet path surfaces a transport error rather than connecting.
        let env = MapEnv::new(&[
            (selector::env::BOARD, "nrf52840-dk-3"),
            (selector::env::COORDINATOR, "c:4443"),
            (selector::env::TOKEN, "t"),
        ]);
        let err = run(
            ["probe-rs", "reset", "--chip", "nrf52"].map(String::from),
            &env,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RunError::Transport(transport::TransportError::Tls(_))
        ));
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
