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
//! hatch for debugging. argv0 dispatch wiring lives in `probefleet` (task 1714);
//! this crate exposes the reusable [`run`] entry point.
//!
//! ## Module map
//!
//! * [`cli`] — parse the six probe-rs invocation shapes (+ passthrough),
//!   preserving every original argument.
//! * [`selector`] — resolve the fleet configuration from the environment, with
//!   a clean no-selector → local fallback.
//! * [`lease_cache`] — time-based lease sharing keyed by selector + subject key.
//! * [`lease_store`] — the persistence layer under that cache: a locked JSON
//!   file in `$XDG_RUNTIME_DIR` so successive invocations share one lease.
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
//! short policy TTL. A sidecar that is killed outright releases nothing —
//! nothing can — but the board comes back after one policy TTL rather than the
//! hardcoded hour this replaced.
//!
//! Across invocations the lease is **shared**, not re-taken: [`lease_store`]
//! persists the grant under `$XDG_RUNTIME_DIR` and [`acquire_lease`] consults it
//! before leasing, so `probe-rs download` followed by `probe-rs attach` holds
//! one board throughout. A hit still opens a fresh channel and takes a fresh
//! per-channel credential — only the *lease* is reused.
//!
//! That makes the release policy TTL-driven: a shareable lease is deliberately
//! **not** released at the end of an invocation, Ctrl-C included, because
//! releasing it every time is exactly what would make the cache never hit.
//! `fleet ctl release` frees a board immediately; otherwise it returns after one
//! policy TTL. A CI (`Workload`) or node lease, a delegated lease, and anything
//! run under [`selector::env::NO_LEASE_CACHE`] are released at exit exactly as
//! before. [`lease_store`]'s module doc records the decisions in full.

pub mod cli;
pub mod gdb;
pub mod lease_cache;
pub mod lease_store;
pub mod local;
pub mod proxy;
pub mod selector;
pub mod signal;
pub mod transport;

use std::ffi::OsString;
use std::sync::atomic::{AtomicU64, Ordering};

use probefleet_proto::ids::BoardRef;
use probefleet_proto::{ChannelId, ChannelKind, LeaseId};

use lease_store::{Disposition, LeaseStore, UseGuard};
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
            let original_argv: Vec<String> = tokens
                .iter()
                .map(|t| t.to_string_lossy().into_owned())
                .collect();
            rt.block_on(run_fleet(cfg, invocation, original_argv))
        }
        Resolution::Delegated(cfg) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| transport::TransportError::Io(format!("building runtime: {e}")))?;
            let original_argv: Vec<String> = tokens
                .iter()
                .map(|t| t.to_string_lossy().into_owned())
                .collect();
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
            let original_argv: Vec<String> = tokens
                .iter()
                .map(|t| t.to_string_lossy().into_owned())
                .collect();
            run_fleet(cfg, invocation, original_argv).await
        }
        Resolution::Delegated(cfg) => {
            let original_argv: Vec<String> = tokens
                .iter()
                .map(|t| t.to_string_lossy().into_owned())
                .collect();
            run_delegated(cfg, invocation, original_argv).await
        }
    }
}

/// Drive the fleet path: acquire a lease (reusing a cached one when there is
/// one), open a relay channel, expose a local endpoint, and either exec the
/// genuine probe-rs against it (data plane) or tunnel the local gdb client (gdb
/// plane).
async fn run_fleet(
    cfg: selector::FleetConfig,
    invocation: cli::ProbeRsInvocation,
    original_argv: Vec<String>,
) -> Result<i32, RunError> {
    use probefleet_proto::ChannelKind;

    let session = transport::CoordSession::connect(&cfg).await?;
    let mut store = lease_store::LeaseStore::open(&selector::ProcessEnv);
    let now = now_secs();

    let acquired = acquire_lease(&session, &cfg, store.as_mut(), now).await?;
    let kind = if matches!(invocation, cli::ProbeRsInvocation::Gdb { .. }) {
        ChannelKind::Gdb
    } else {
        ChannelKind::Data
    };

    // A *reused* lease id is only as trustworthy as the coordinator's lease
    // numbering, which restarts at 1 on every boot, so the channel token's board
    // is cross-checked against the one we cached. A freshly granted lease needs
    // no such check: the board came straight back from the coordinator.
    let expect = acquired.reused.then(|| acquired.grant.board.clone());
    let opened =
        open_channel_verified(&session, acquired.grant.lease, kind, expect.as_ref()).await?;
    let (acquired, opened) = if let Some(opened) = opened {
        (acquired, opened)
    } else {
        // Exactly one retry, and only from the cache-hit path: the cached
        // lease named somebody else's board (a coordinator restart aliased
        // the id), so drop it and lease cold. `acquire_lease` cannot hit
        // again — the entry is gone — so this cannot loop.
        tracing::debug!("the cached lease named a different board; leasing afresh");
        // Forget *before* dropping `acquired`, i.e. while we still hold the
        // record's use-lock. Releasing it first would let a concurrent
        // invocation claim the slot and record its own entry in the window, and
        // this `forget` would then delete that live entry instead of ours.
        if acquired.owns_slot {
            if let Some(store) = store.as_mut() {
                store.forget(&cfg.coordinator, &cfg.token, &cfg.select);
                store.save(now);
            }
        }
        drop(acquired);
        let fresh = acquire_lease(&session, &cfg, store.as_mut(), now).await?;
        let opened = open_channel_verified(&session, fresh.grant.lease, kind, None)
            .await?
            .expect("a channel opened without an expected board always verifies");
        (fresh, opened)
    };
    let channel = opened.channel;

    let work = async {
        match &invocation {
            cli::ProbeRsInvocation::Gdb {
                connection_string, ..
            } => run_fleet_gdb(&session, channel, connection_string.as_deref()).await,
            _ => run_fleet_data(&session, channel, &opened.serve_token, &original_argv).await,
        }
    };

    // The keepalive publishes each renewal here, so the store records how long
    // the lease actually lives rather than the expiry it was granted with; a
    // stale (too early) expiry would turn a live lease into a miss.
    let latest_expires = AtomicU64::new(acquired.grant.expires);
    let code = hold_and_run(
        &session,
        &acquired.grant,
        acquired.disposition,
        Some(&latest_expires),
        work,
        signal::shutdown_signal(),
    )
    .await;

    release_slot(
        store.as_mut(),
        &cfg,
        &acquired,
        latest_expires.load(Ordering::Relaxed),
        now_secs(),
    );
    // Only now is the record's use-lock dropped: it covers the whole
    // invocation, including the final save.
    drop(acquired);
    code
}

/// Write this invocation's verdict on its cached lease back to the store: keep
/// the entry with its latest expiry, or forget it.
///
/// Split out of [`run_fleet`] purely so a test can drive it — it is where a
/// wrong ownership judgement does its damage, and the damage is invisible from
/// inside one invocation.
///
/// **A slot may only be written by the invocation that holds its use-lock.**
/// [`Disposition::Release`] does not imply ownership: [`acquire_lease`] also
/// returns it when another live invocation held the lock and we leased cold. In
/// that case the record on disk is *theirs*, and one they mean to keep —
/// forgetting it would leave their board held with nothing naming it, so
/// nothing could reuse it and nothing would release it before the policy TTL.
/// Hence the [`Acquired::owns_slot`] gate rather than a disposition check.
pub fn release_slot(
    store: Option<&mut LeaseStore>,
    cfg: &selector::FleetConfig,
    acquired: &Acquired,
    latest_expires: u64,
    now_secs: u64,
) {
    if !acquired.owns_slot {
        return;
    }
    let Some(store) = store else { return };
    if acquired.disposition == Disposition::Keep {
        store.touch_expiry(&cfg.coordinator, &cfg.token, &cfg.select, latest_expires);
    } else {
        store.forget(&cfg.coordinator, &cfg.token, &cfg.select);
    }
    store.save(now_secs);
}

/// A lease this invocation may use, plus what to do with it on the way out.
#[derive(Debug)]
pub struct Acquired {
    /// The lease. On a cache hit this is *reconstructed* from the store and its
    /// `token` is deliberately empty — the data-plane credential comes fresh
    /// from `ChannelOpened` on every path (architecture §6.5).
    pub grant: probefleet_proto::lease::LeaseGrant,
    /// Whether the lease came from the store rather than a fresh `Lease`.
    pub reused: bool,
    /// Release at exit, or keep the lease for the next invocation.
    pub disposition: Disposition,
    /// Whether this invocation holds the record's use-lock, i.e. whether the
    /// store slot for `(coordinator, token, selector)` is **ours**.
    ///
    /// Not the same question as `disposition`, and conflating the two strands
    /// boards. A concurrent invocation that found the slot taken leases cold and
    /// gets [`Disposition::Release`] — but the record on disk belongs to the
    /// *other* invocation, which is still running and deliberately keeping it.
    /// Writing to that slot on the way out would delete a live entry, leaving
    /// its board held with nothing naming it: held until the policy TTL, and
    /// unreusable in the meantime. So every store mutation outside
    /// [`acquire_lease`] is gated on this flag.
    pub owns_slot: bool,
    /// The record's use-lock, held for the whole invocation so a *concurrent*
    /// invocation cannot take the same cached lease (`lease_store` Decision 5).
    _guard: Option<UseGuard>,
}

/// Acquire a lease for `cfg`: reuse the stored one if it is still ours, else
/// lease afresh and store it if it is shareable.
///
/// This is the whole cross-invocation half of lease sharing, in one seam so an
/// integration test can drive it against a mock coordinator peer
/// (`tests/lease_reuse.rs`). The order matters and each step is a decision
/// recorded in [`lease_store`]'s module doc:
///
/// 1. A stored record is only taken if its per-record use-lock is free — that
///    lock is what still prevents two concurrent invocations from driving one
///    board now that the coordinator's `Queued` reply is no longer in the way.
/// 2. A hit is revalidated with a short `Extend` probe. A refusal drops the
///    entry; an inconclusive answer drops it *and* releases first, so the fresh
///    `Lease` below cannot queue behind our own hold.
/// 3. A fresh grant is stored only for a `User` holder: a CI job must not strand
///    a board for a policy TTL after it finishes.
/// 4. The store is written **before** the work starts, so even a `SIGKILL`ed
///    sidecar leaves a reusable entry behind.
///
/// No branch here surfaces a stale cache as an error: every degradation ends in
/// an ordinary fresh lease.
///
/// # Errors
///
/// Returns [`RunError`] only if the fresh `Lease` itself fails (the board is
/// contended, or the connection died).
pub async fn acquire_lease(
    session: &transport::CoordSession,
    cfg: &selector::FleetConfig,
    store: Option<&mut LeaseStore>,
    now_secs: u64,
) -> Result<Acquired, RunError> {
    use probefleet_proto::lease::{LeaseRequest, Priority};
    use transport::Revalidation;

    let mut store = store;
    let mut guard = None;

    if let Some(store) = store.as_deref_mut() {
        if let Some((record, held)) = store.get(&cfg.coordinator, &cfg.token, &cfg.select, now_secs)
        {
            // Whatever happens next, this invocation owns the cache slot: keep
            // the lock for the cold path too, so a concurrent invocation does
            // not record a competing entry underneath us.
            guard = Some(held);
            match session.revalidate_lease(record.lease).await {
                Revalidation::Live(expires) => {
                    tracing::info!(
                        board = %record.board,
                        lease = ?record.lease,
                        "reusing the lease from a previous invocation"
                    );
                    store.touch_expiry(&cfg.coordinator, &cfg.token, &cfg.select, expires);
                    store.save(now_secs);
                    let mut grant = record.grant();
                    grant.expires = expires;
                    return Ok(Acquired {
                        grant,
                        reused: true,
                        disposition: Disposition::Keep,
                        owns_slot: true,
                        _guard: guard,
                    });
                }
                Revalidation::Gone(reason) => {
                    tracing::debug!(%reason, "the cached lease is gone; leasing afresh");
                }
                Revalidation::Inconclusive(reason) => {
                    tracing::debug!(
                        %reason,
                        "could not revalidate the cached lease; releasing it before re-leasing"
                    );
                    // It may still be ours, and a fresh `Lease` under an `Id`
                    // selector would then be queued behind our own hold.
                    // Releasing a lease we no longer hold is a harmless refusal.
                    session.release(record.lease).await;
                }
            }
            store.forget(&cfg.coordinator, &cfg.token, &cfg.select);
            store.save(now_secs);
        }
    }

    if guard.is_none() {
        if let Some(store) = store.as_ref() {
            guard = store.claim(&cfg.coordinator, &cfg.token, &cfg.select);
        }
    }

    let request = LeaseRequest {
        select: cfg.select.clone(),
        // `0` means "the operator's `Policy::default_ttl_secs`". **Do not**
        // reintroduce a constant here, not even as a "sensible fallback": the
        // hardcoded 3600s this replaced meant a killed sidecar sat on a board
        // for an hour, and a knob would just be a slower way back to it. Lease
        // sharing does not change this — a cached lease is minted with exactly
        // the same TTL; what changed is that we stop shortening its life by
        // releasing at exit. The TTL is the coordinator's policy to set; we keep
        // the lease alive for as long as we need it by heartbeating (see
        // `keepalive`).
        duration_secs: 0,
        priority: Priority::Interactive,
    };
    let grant = session
        .lease(
            &request,
            std::time::Duration::from_secs(cfg.queue_wait_secs),
        )
        .await?;
    tracing::info!(board = %grant.board, lease = ?grant.lease, "leased board");

    // Shareable only if we hold the cache slot *and* the store accepts the
    // holder. Anything else is released at exit exactly as before.
    let mut disposition = Disposition::Release;
    if guard.is_some() {
        if let Some(store) = store.as_mut() {
            if store.record(&cfg.coordinator, &cfg.token, &cfg.select, &grant) {
                // Persist before any work starts.
                store.save(now_secs);
                disposition = Disposition::Keep;
            }
        }
    }

    Ok(Acquired {
        grant,
        reused: false,
        disposition,
        owns_slot: guard.is_some(),
        _guard: guard,
    })
}

/// Open a relay channel and, when `expect` is set, check that the credential it
/// came back with really names that board.
///
/// Returns `Ok(None)` on a mismatch, having closed the channel again — the
/// caller's cue to forget the cached lease and lease cold **once**.
///
/// Lease ids are per-coordinator-boot counters starting at 1, and nothing on the
/// wire identifies a boot, so a lease id persisted across a coordinator restart
/// can name a *different* live lease — one the same subject legitimately holds
/// on another board, in which case even the `Extend` revalidation succeeds. The
/// channel token is what settles it: it carries the `BoardRef` the coordinator
/// minted it for. Decoding needs no verification key (the coordinator is what
/// verifies the token; this only reads it), exactly as
/// [`selector::DelegatedConfig::lease`] already does.
///
/// # Errors
///
/// Returns [`RunError`] if the channel cannot be opened at all.
pub async fn open_channel_verified(
    session: &transport::CoordSession,
    lease: LeaseId,
    kind: ChannelKind,
    expect: Option<&BoardRef>,
) -> Result<Option<transport::OpenedChannel>, RunError> {
    let opened = session.open_channel(lease, kind).await?;
    let Some(expected) = expect else {
        return Ok(Some(opened));
    };
    // The **capability** token is what names a board; the serve token is an
    // opaque loopback secret and says nothing about which board it belongs to.
    let named = probefleet_proto::token::SignedToken::from_wire(&opened.token)
        .ok()
        .and_then(|signed| signed.decode_token().ok())
        .map(|decoded| decoded.board);
    match named {
        // An undecodable token is not evidence of a mismatch: the sidecar has no
        // stake in the token's shape, and the agent is what verifies it.
        None => Ok(Some(opened)),
        Some(board) if &board == expected => Ok(Some(opened)),
        Some(board) => {
            tracing::warn!(
                %board, expected = %expected,
                "the reused lease names a different board; discarding it"
            );
            session.close_channel(opened.channel).await;
            Ok(None)
        }
    }
}

/// Epoch seconds, or 0 if the clock is before the epoch.
///
/// Only ever used to *judge* a cached expiry, which is a local, conservative
/// decision: a skewed clock costs an extra lease, never a wrong hold.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Hold `grant` for the duration of `work`: heartbeat it, abandon it on
/// `shutdown`, and release it on the way out **unless** `disposition` says to
/// keep it for the next invocation.
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
/// of handing back. That drop happens whatever the disposition: a kept lease is
/// still a lease nothing should be driving after we return.
///
/// # When the lease is deliberately *not* released
///
/// [`Disposition::Keep`] means the lease is recorded in the cross-invocation
/// store and the next `probe-rs` command under the same selector will reuse it
/// — so releasing here would make the cache miss every single time, which is the
/// whole feature. This holds on the shutdown arm too: a Ctrl-C'd `probe-rs run`
/// is nearly always followed by another one. The board comes back after one
/// policy TTL if nobody picks it up, and `fleet ctl release` frees it at once.
/// A CI or node holder, a delegated lease, and the
/// [`selector::env::NO_LEASE_CACHE`] opt-out all pass
/// [`Disposition::Release`] and behave exactly as before.
///
/// `expires_out`, when given, receives every heartbeat's new expiry, so the
/// caller can persist how long the lease actually lives rather than the expiry
/// it was granted with.
///
/// # Errors
///
/// Propagates whatever `work` returns.
pub async fn hold_and_run<F>(
    session: &transport::CoordSession,
    grant: &probefleet_proto::lease::LeaseGrant,
    disposition: Disposition,
    expires_out: Option<&AtomicU64>,
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
        never = keepalive(session, grant, expires_out) => match never {},
        signum = &mut shutdown => Ok(128 + signum),
    };

    // Kill the genuine probe-rs before handing the lease back: on the shutdown
    // arm the child is still running, and a board we release may be granted to
    // somebody else immediately.
    drop(work);

    // Release the lease (best-effort) on every arm, the shutdown one included —
    // that is the point of the signal handling: a Ctrl-C must not strand a board
    // we are not going to reuse. A shareable lease is kept instead; see the
    // section above for why that is not a regression of the same invariant.
    if disposition == Disposition::Release {
        session.release(grant.lease).await;
    } else {
        tracing::debug!(
            lease = ?grant.lease,
            "keeping the lease for the next invocation (`fleet ctl release` frees it now)"
        );
    }
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
    grant: &probefleet_proto::lease::LeaseGrant,
    expires_out: Option<&AtomicU64>,
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
                if let Some(out) = expires_out {
                    out.store(expires, Ordering::Relaxed);
                }
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

    // Deliberately no lease store on this path: the lease is not ours to cache
    // (architecture §6.5), and a sandbox that could hand a delegated lease to
    // the next invocation would be holding a board past the delegator's intent.
    let kind = if matches!(invocation, cli::ProbeRsInvocation::Gdb { .. }) {
        ChannelKind::Gdb
    } else {
        ChannelKind::Data
    };
    let opened = session.open_channel(lease, kind).await?;

    match &invocation {
        cli::ProbeRsInvocation::Gdb {
            connection_string, ..
        } => run_fleet_gdb(&session, opened.channel, connection_string.as_deref()).await,
        _ => {
            run_fleet_data(
                &session,
                opened.channel,
                &opened.serve_token,
                &original_argv,
            )
            .await
        }
    }
    // Deliberately no `session.release(lease)`: the lease is not ours.
}

/// Run one invocation's work on `channel`, then **hand the channel back**.
///
/// The single place the channel-per-invocation rule is enforced, shared by the
/// data and gdb planes. A channel is per-invocation; a lease is not. On the
/// lease-cache-hit path nothing else would ever close it — `hold_and_run` with
/// [`Disposition::Keep`](lease_store::Disposition::Keep) sends no `Release`,
/// and the node reports `SessionClosed` only in reply to a `KillSession` — so
/// the node's reused `probe-rs serve` would hold this invocation's `ProbeLease`
/// forever and the *next* invocation's `attach` would be refused with
/// `ProbeInUse`. Before serve was reused the same omission showed up as
/// `errno 16` instead.
///
/// The close runs on **every** arm, error included: the `?` is deliberately
/// after it. `Coordinator::drop_sidecar` is the backstop for a sidecar that is
/// killed rather than returning at all.
///
/// # Errors
///
/// Propagates `work`'s error, after closing the channel.
pub async fn run_on_channel<F>(
    session: &transport::CoordSession,
    channel: ChannelId,
    work: F,
) -> Result<i32, RunError>
where
    F: std::future::Future<Output = Result<i32, RunError>>,
{
    let outcome = work.await;
    session.close_channel_acked(channel).await;
    outcome
}

/// Data-plane path: bind a loopback endpoint the genuine probe-rs client dials
/// as its remote host, splice it onto an already-opened relay `channel`, and
/// exec the real probe-rs.
///
/// Takes the opened channel and its serve credential rather than a lease,
/// because the caller has to open the channel anyway: the fleet path
/// cross-checks the board the *capability* token names
/// ([`open_channel_verified`]), and the delegated path has no grant at all —
/// only a token, from which it decodes the lease locally. Both converge here.
///
/// **Closes the channel on the way out** via [`run_on_channel`], whatever the
/// lease disposition.
async fn run_fleet_data(
    session: &transport::CoordSession,
    channel: ChannelId,
    serve_token: &str,
    original_argv: &[String],
) -> Result<i32, RunError> {
    run_on_channel(
        session,
        channel,
        run_fleet_data_inner(session, channel, serve_token, original_argv),
    )
    .await
}

/// [`run_fleet_data`] without the channel close, so the close lives in exactly
/// one place ([`run_on_channel`]) rather than on each of this function's return
/// arms.
async fn run_fleet_data_inner(
    session: &transport::CoordSession,
    channel: ChannelId,
    serve_token: &str,
    original_argv: &[String],
) -> Result<i32, RunError> {
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
    // The **serve** token: the lease-scoped secret the coordinator minted, wrote
    // into the node's `.probe-rs.toml` and handed us verbatim, so it is already
    // the exact string `probe-rs serve` will accept — no hex-encoding.
    //
    // Deliberately *not* the capability token. That one authorises the channel
    // and is checked by the coordinator and the node, per channel; it changes
    // across an `extend` or an attenuating grant, and a reused `serve` reads its
    // config once at startup, so it could not be what the server checks.
    let token = serve_token;

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
    let child =
        transport::exec_remote_probe_rs(&real, &args, &remote_host, token, &selector::ProcessEnv);

    // The child drives the session; when it exits we stop accepting/splicing.
    tokio::pin!(splice);
    tokio::pin!(child);
    let mut splice_done = false;
    loop {
        tokio::select! {
            () = &mut splice, if !splice_done => { splice_done = true; }
            code = &mut child => return Ok(code?),
        }
    }
}

/// gdb-plane fleet path: bind the local gdb listener the user's gdb client
/// connects to and byte-splice it onto the already-opened relay `channel`.
///
/// Closes the channel on the way out through [`run_on_channel`], for the same
/// reason [`run_fleet_data`] does: a gdb tunnel is per-invocation, and nothing
/// else would ever tear it down when the lease is kept.
async fn run_fleet_gdb(
    session: &transport::CoordSession,
    channel: ChannelId,
    connection_string: Option<&str>,
) -> Result<i32, RunError> {
    run_on_channel(session, channel, async {
        let addr = gdb::resolve_listen_addr(connection_string)?;
        let listener = gdb::bind(addr).await?;
        tracing::info!(%addr, "gdb tunnel listening; point your gdb client here");
        let client = gdb::accept(&listener).await?;
        transport::splice_client(session, channel, client).await?;
        Ok(0)
    })
    .await
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
