//! The `node up` subcommand: obtain a node credential by whichever path
//! applies, then **run** the node.
//!
//! This replaces `agent init`, which only ever knew one path (redeem an auth
//! key) and exited afterwards. Architecture §4.2 lists four ways a machine can
//! become a node; `node up` walks them:
//!
//! 1. an existing `[node]` credential in the fleet file → just reconnect;
//! 2. `--auth-key` → redeem it (the unattended / disk-image path; the key comes
//!    from `probe-rs-fleet auth-key create` on a machine that is logged in, or
//!    from `coordinator auth-key` on the coordinator host);
//! 3. an existing `[user]` session → self-register silently (what `share`
//!    does);
//! 4. **interactive approval** → print a URL and a short code, and wait for a
//!    human to run `probe-rs-fleet node approve <code>` on a machine where they
//!    are logged in (§4.2's rung 3);
//! 5. otherwise → an error naming all of the above.
//!
//! **Deviation from §4.2's ordering, deliberate:** the document lists the
//! `[user]` session before the auth key. An explicit `--auth-key` is a
//! deliberate act by whoever typed it, so it beats a session that merely
//! happens to be lying around — a provisioning script run on a developer's own
//! laptop should enroll the node it was told to, not the one the laptop's owner
//! implies. An existing `[node]` credential still wins over everything, and is
//! **reused rather than replaced**: re-registering a working node would
//! invalidate the token it is currently connected with, for nothing.
//!
//! Interactive approval comes **last** among the bootstrapping rungs for the
//! same reason in reverse: it blocks for up to fifteen minutes waiting for a
//! human, so anything that can succeed without one should. It is also gated on
//! there being a human to wait for — `--interactive` / `--no-interactive`,
//! defaulting to whether stdout is a terminal, so a systemd unit fails fast
//! with the terminal error instead of printing a code into the journal and
//! blocking on nobody.
//!
//! There is no key material, no CSR, and no certificate any more. The honest
//! trade: a node token is a pure bearer credential, so anyone who reads the
//! fleet file can impersonate this node until the token rotates or the `node`
//! row is deleted — unlike a private key that never left the host. Rotation is
//! what bounds that window.

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use fleet_auth::api::TokenResponse;
use fleet_proto::AdoptPolicy;

use crate::cli::NodeUpFlags;
use crate::fleet_config::{self, FleetFile};
use crate::roles::node_setup;

/// Cap on how long the interactive rung waits, if the coordinator reports no
/// expiry. Mirrors `login`'s constant of the same name.
const DEFAULT_EXPIRES_IN: u64 = 900;

/// Floor on the poll interval, whatever the coordinator asks for.
const MIN_POLL_INTERVAL: u64 = 5;

/// How many consecutive transport failures to tolerate while polling.
///
/// The human is mid-ceremony at another machine, so one dropped packet must not
/// force them to start again; a sustained run is the coordinator being
/// unreachable, and saying so beats polling a dead endpoint for 15 minutes.
const MAX_TRANSPORT_RETRIES: u32 = 5;

/// Run `node up` for the given fleet: bootstrap a credential if needed, then
/// run the node.
///
/// `config_dir` overrides the XDG config root (test and packaging support); the
/// fleet file then lives at `<config_dir>/<fleet>.toml` and node settings under
/// `<config_dir>/node/`.
///
/// # Errors
///
/// Returns an error if no credential can be obtained (and none can be derived),
/// the credential exchange fails, any file cannot be written, or the node's
/// connection loop exits with a non-retryable error.
pub async fn run(args: NodeUpFlags, fleet: &str, config_dir: Option<PathBuf>) -> Result<()> {
    bootstrap(&args, fleet, config_dir.as_deref()).await?;

    // Then be `probe-rs-fleet node run`: one implementation of "load the config
    // and serve", so `node up` and `node run` cannot drift in how they run.
    crate::roles::node_run::run(fleet, config_dir).await
}

/// The credential half of `node up`, without running the node.
///
/// Split out so the ladder is testable — and reviewable — without a live
/// connection loop.
///
/// # Errors
///
/// See [`run`].
pub async fn bootstrap(args: &NodeUpFlags, fleet: &str, config_dir: Option<&Path>) -> Result<()> {
    let (fleet_path, node_dir) = node_setup::resolve_paths(fleet, config_dir)?;
    let existing = fleet_path
        .exists()
        .then(|| fleet_config::load(&fleet_path).ok())
        .flatten();

    // Rung 1: already a node. Nothing to do, and nothing to overwrite.
    if !args.force {
        if let Some(file) = &existing {
            if file.node.is_some() {
                tracing::debug!(fleet, "using the existing [node] credential");
                return Ok(());
            }
        }
    }

    let node_name = args
        .node_name
        .clone()
        .unwrap_or_else(node_setup::default_node_name);

    // Rung 2: an explicit auth key. See the module doc for why it outranks a
    // session that merely happens to be present.
    if let Some(auth_key) = &args.auth_key {
        let (response, fleet_url, adopt) =
            redeem(args, auth_key, &node_name, existing.as_ref()).await?;
        return finish(
            args,
            fleet,
            &fleet_path,
            &node_dir,
            &response,
            &node_name,
            Some(&fleet_url),
            adopt,
        );
    }

    // Rung 3 (§4.2's rung 2): a `[user]` session on this machine. Identical to
    // what `share` does, by construction — `share` is this rung as a verb.
    if let Some(file) = existing.as_ref().filter(|f| f.user.is_some()) {
        let (response, adopt) = self_register(args, fleet, file, &node_name).await?;
        // `None` for the URL and the pin: the session that authorised this came
        // out of *this* file, so the coordinator it names is already the right
        // one.
        return finish(
            args,
            fleet,
            &fleet_path,
            &node_dir,
            &response,
            &node_name,
            None,
            adopt,
        );
    }

    // Rung 4 (§4.2's rung 3): interactive approval. Nobody is logged in here
    // and no key was handed to us, but a human may be watching this terminal.
    if interactive_allowed(args) {
        let (response, fleet_url, adopt) =
            approval_flow(args, &node_name, existing.as_ref()).await?;
        return finish(
            args,
            fleet,
            &fleet_path,
            &node_dir,
            &response,
            &node_name,
            Some(&fleet_url),
            adopt,
        );
    }

    // Rung 5: nothing to work with. Say so, rather than doing nothing quietly
    // on a machine somebody is waiting on.
    let skipped = if args.interactive_choice() == Some(false) {
        "(Interactive approval was disabled with --no-interactive.)"
    } else {
        "(Interactive approval was skipped: this is not a terminal, so there is nobody\n\
         \x20here to read a code. Pass --interactive to run it anyway — when you are\n\
         \x20tailing this log, say.)"
    };
    anyhow::bail!(
        "fleet `{fleet}` has no [node] credential and no way to obtain one on this machine.\n\
         \n\
         Either log in first, then bring the node up:\n\
         \x20   probe-rs-fleet login --fleet {fleet} --fleet-url <url>\n\
         \x20   probe-rs-fleet node up --fleet {fleet}\n\
         \n\
         ...or have somebody approve this machine from theirs. Run this where you\n\
         can read the output, and give them the code it prints:\n\
         \x20   probe-rs-fleet node up --fleet {fleet} --fleet-url <url> --interactive\n\
         \n\
         ...or enroll unattended with a key. Mint one on a machine where you are\n\
         logged in — no shell on the coordinator needed:\n\
         \x20   probe-rs-fleet auth-key create --tag lab\n\
         ...then, here:\n\
         \x20   probe-rs-fleet node up --fleet {fleet} --fleet-url <url> --auth-key <key>\n\
         (Self-hosted, with a shell on the coordinator: `coordinator auth-key`.)\n\
         \n\
         {skipped}"
    )
}

/// Whether the interactive-approval rung may run.
///
/// Auto by default: a terminal means somebody can read the code; no terminal
/// means a systemd unit that would otherwise print a code into the journal and
/// block for fifteen minutes on nobody. `--interactive` forces it on anyway,
/// for the "I am tailing this log" case, and `--no-interactive` forces it off.
fn interactive_allowed(args: &NodeUpFlags) -> bool {
    args.interactive_choice()
        .unwrap_or_else(|| std::io::stdout().is_terminal())
}

/// Rung 4: print a URL and a short code, and wait for a human to approve.
///
/// Mirrors [`crate::roles::login`]'s device flow closely and deliberately — the
/// two are the same ceremony from opposite ends and should be read side by
/// side. Two differences, both intentional:
///
/// * **no browser is opened.** This machine is, by assumption, not where the
///   human is; a browser here would open on the wrong computer.
/// * both the URL *and* the command are printed, always. The URL is the
///   discoverable half (it explains the ceremony to somebody who has never seen
///   it) and the command is the operative half, and a headless box has no
///   browser to open either way.
///
/// Adopt default: `auto`. A human is approving this live, which is the `share`
/// situation rather than the disk-image one.
async fn approval_flow(
    args: &NodeUpFlags,
    node_name: &str,
    existing: Option<&FleetFile>,
) -> Result<(TokenResponse, String, AdoptPolicy)> {
    let fleet_url = args
        .fleet_url
        .clone()
        .or_else(|| existing.map(|f| f.url.clone()))
        .context(
            "interactive approval needs --fleet-url too: this machine has no fleet \
             config naming a coordinator yet",
        )?;
    let pin = pin_of(args)?;
    let adopt = args.adopt.map_or(AdoptPolicy::Auto, Into::into);

    let grant = fleet_auth::http_client::node_register_start(
        &fleet_url,
        pin,
        node_name,
        args.tag.clone(),
        Some(adopt.as_str()),
    )
    .await
    .map_err(|e| describe_start_error(&e))?;

    // Printed before any polling: on a headless box this output *is* the
    // interface, and a failure afterwards must still leave the human with the
    // code in front of them.
    println!();
    println!("  Open       {}", grant.verification_uri);
    println!(
        "  Then run   probe-rs-fleet node approve {}",
        grant.user_code
    );
    println!();
    println!("...on a machine where you are logged in. Waiting for approval…");

    let expires_in = if grant.expires_in == 0 {
        DEFAULT_EXPIRES_IN
    } else {
        grant.expires_in
    };
    let deadline = Instant::now() + Duration::from_secs(expires_in);
    let mut interval = grant.interval.max(MIN_POLL_INTERVAL);
    // As in `login`: the pending registration stays valid for its whole
    // lifetime whatever our socket did, so a dropped packet must not force the
    // human to start over. Only a *run* of failures means the coordinator is
    // genuinely unreachable.
    let mut consecutive_transport_failures = 0_u32;

    loop {
        if Instant::now() >= deadline {
            anyhow::bail!(EXPIRED);
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;

        match fleet_auth::http_client::node_register_poll(&fleet_url, pin, &grant.device_secret)
            .await
        {
            Ok(response) => return Ok((response, fleet_url, adopt)),
            Err(fleet_auth::http_client::ClientError::Rejected { code, .. }) => {
                consecutive_transport_failures = 0;
                match code.as_str() {
                    "authorization_pending" => {}
                    // The coordinator does not send this today (it has no rate
                    // limiting at all), but additive back-off is the correct
                    // response if it ever starts.
                    "slow_down" => interval = interval.saturating_add(5),
                    "access_denied" => anyhow::bail!(
                        "the request was denied. That code is spent and nothing was enrolled."
                    ),
                    "expired_token" => anyhow::bail!(EXPIRED),
                    other => {
                        anyhow::bail!("the coordinator rejected the registration ({other})")
                    }
                }
            }
            Err(e) => {
                consecutive_transport_failures += 1;
                if consecutive_transport_failures > MAX_TRANSPORT_RETRIES {
                    return Err(anyhow::anyhow!(
                        "polling the coordinator failed {consecutive_transport_failures} times \
                         in a row: {e}"
                    ));
                }
                tracing::debug!(error = %e, "transient failure polling the coordinator; retrying");
            }
        }
    }
}

/// What to say when nobody approved in time. One sentence, two call sites.
const EXPIRED: &str = "nobody approved this machine before the code expired; run \
                       `probe-rs-fleet node up` again for a fresh one";

/// Turn a `/node/register/start` failure into remediation-shaped text.
fn describe_start_error(e: &fleet_auth::http_client::ClientError) -> anyhow::Error {
    let fleet_auth::http_client::ClientError::Rejected { code, status } = e else {
        return anyhow::anyhow!("could not ask the coordinator for an approval code: {e}");
    };
    let hint = match code.as_str() {
        "invalid_request" => {
            "the node name or a tag was refused: each may be letters, digits, \
             `.`, `_` and `-` only. Pass `--node-name <name>` explicitly if this \
             machine's hostname is unusual"
        }
        "too_many_pending" => {
            "the coordinator is already holding as many registrations awaiting \
             approval as it will. Try again in a few minutes, once the abandoned \
             ones expire, or ask its operator to raise `max_pending_nodes`"
        }
        _ => {
            return anyhow::anyhow!(
                "could not ask the coordinator for an approval code ({status}): {code}"
            )
        }
    };
    anyhow::anyhow!("could not start interactive approval ({status}): {hint}")
}

/// Rung 2: redeem an auth key for a node token.
///
/// Defaults to `adopt = declared`: a machine enrolled from an image or a
/// provisioning script is a lab node, and CI wants stable ids and no surprises.
async fn redeem(
    args: &NodeUpFlags,
    auth_key: &str,
    node_name: &str,
    existing: Option<&FleetFile>,
) -> Result<(TokenResponse, String, AdoptPolicy)> {
    let fleet_url = args
        .fleet_url
        .clone()
        .or_else(|| existing.map(|f| f.url.clone()))
        .context(
            "--auth-key needs --fleet-url too: this machine has no fleet config \
             naming a coordinator yet",
        )?;
    let adopt = args.adopt.map_or(AdoptPolicy::Declared, Into::into);
    let response = fleet_auth::http_client::exchange_auth_key(
        &fleet_url,
        pin_of(args)?,
        auth_key,
        node_name,
        args.tag.clone(),
    )
    .await
    .context("redeeming the auth key at <fleet-url>/auth/token")?;
    Ok((response, fleet_url, adopt))
}

/// Rung 3: self-register with the `[user]` session already in the fleet file.
///
/// Defaults to `adopt = auto`, exactly as `share` does: a machine whose owner
/// is offering it wants a probe they plug in to be usable.
async fn self_register(
    args: &NodeUpFlags,
    fleet: &str,
    file: &FleetFile,
    node_name: &str,
) -> Result<(TokenResponse, AdoptPolicy)> {
    // Refresh through the shared path: a session that expired an hour ago would
    // otherwise surface as an opaque 401 from a command the operator has no
    // reason to associate with logging in.
    let session = fleet_config::ensure_fresh_session(fleet, file)
        .await
        .context("refreshing the session token")?;
    let adopt = args.adopt.map_or(AdoptPolicy::Auto, Into::into);
    let response = fleet_auth::http_client::self_register(
        &file.url,
        file.pin(),
        &session,
        node_name,
        args.tag.clone(),
        Some(adopt.as_str()),
    )
    .await
    .context("registering this machine as a node at <fleet-url>/auth/token")?;
    Ok((response, adopt))
}

/// Record the credential, scaffold the node directory, and report.
///
/// Shared by both bootstrapping rungs so they cannot drift in what they leave
/// on disk.
#[allow(clippy::too_many_arguments)]
fn finish(
    args: &NodeUpFlags,
    fleet: &str,
    fleet_path: &Path,
    node_dir: &Path,
    response: &TokenResponse,
    node_name: &str,
    fleet_url: Option<&str>,
    adopt: AdoptPolicy,
) -> Result<()> {
    let node_id = node_setup::record_node_credential(
        fleet_path,
        response,
        node_name,
        fleet_url,
        args.server_cert_sha256.as_deref(),
    )?;
    let (boards_path, node_settings_path) =
        node_setup::scaffold_node_dir(node_dir, adopt, args.force)?;
    node_setup::print_summary(&node_setup::Enrollment {
        node_id: &node_id,
        org: &response.org,
        fleet,
        adopt,
        fleet_path,
        boards_path: &boards_path,
        node_settings_path: &node_settings_path,
        // No run hint: `node up` is about to run the node itself.
        run_hint: false,
    });
    Ok(())
}

/// Decode `--server-cert-sha256`, if given.
fn pin_of(args: &NodeUpFlags) -> Result<Option<[u8; 32]>> {
    match &args.server_cert_sha256 {
        Some(hex) => Ok(Some(
            fleet_tls::parse_fingerprint(hex)
                .context("--server-cert-sha256 must be 64 hex characters")?,
        )),
        None => Ok(None),
    }
}
