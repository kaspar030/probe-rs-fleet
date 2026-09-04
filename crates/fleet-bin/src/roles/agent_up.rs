//! The `agent up` subcommand: obtain a node credential by whichever path
//! applies, then **run** the agent.
//!
//! This replaces `agent init`, which only ever knew one path (redeem an auth
//! key) and exited afterwards. Architecture §4.2 lists four ways a machine can
//! become a node; `agent up` walks them:
//!
//! 1. an existing `[node]` credential in the fleet file → just reconnect;
//! 2. `--auth-key` → redeem it (the unattended / disk-image path);
//! 3. an existing `[user]` session → self-register silently (what `share`
//!    does);
//! 4. otherwise → an error naming `--auth-key`.
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
//! **Path 3 of §4.2 — interactive URL + short-code approval — is not here.** It
//! is task 3451: the coordinator has no browser-authenticated surface (`login`
//! is the GitHub *device* flow, which by design has no `redirect_uri` and no
//! cookie session), so an approval page cannot yet know who is looking at it.
//! Until then, a headless machine with no credential of any kind uses
//! `--auth-key`, and the error in [`bootstrap`] says exactly that rather than
//! failing obscurely.
//!
//! There is no key material, no CSR, and no certificate any more. The honest
//! trade: a node token is a pure bearer credential, so anyone who reads the
//! fleet file can impersonate this node until the token rotates or the `node`
//! row is deleted — unlike a private key that never left the host. Rotation is
//! what bounds that window.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use fleet_auth::api::TokenResponse;
use fleet_proto::AdoptPolicy;

use crate::cli::{AgentArgs, AgentUpArgs};
use crate::fleet_config::{self, FleetFile};
use crate::roles::node_setup;

/// Run `agent up` for the given fleet: bootstrap a credential if needed, then
/// run the agent.
///
/// `config_dir` overrides the XDG config root (test and packaging support); the
/// fleet file then lives at `<config_dir>/<fleet>.toml` and node settings under
/// `<config_dir>/node/`.
///
/// # Errors
///
/// Returns an error if no credential can be obtained (and none can be derived),
/// the credential exchange fails, any file cannot be written, or the agent's
/// connection loop exits with a non-retryable error.
pub async fn run(args: AgentUpArgs, fleet: &str, config_dir: Option<PathBuf>) -> Result<()> {
    bootstrap(&args, fleet, config_dir.as_deref()).await?;

    // Then be `probe-rs-fleet agent`: one implementation of "load the config
    // and serve", so `agent up` and `agent` cannot drift in how they run.
    crate::roles::agent::run(AgentArgs {
        fleet: fleet.to_owned(),
        config_dir,
        command: None,
    })
    .await
}

/// The credential half of `agent up`, without running the agent.
///
/// Split out so the ladder is testable — and reviewable — without a live
/// connection loop.
///
/// # Errors
///
/// See [`run`].
pub async fn bootstrap(
    args: &AgentUpArgs,
    fleet: &str,
    config_dir: Option<&Path>,
) -> Result<()> {
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
            args, fleet, &fleet_path, &node_dir, &response, &node_name, None, adopt,
        );
    }

    // Rung 4: nothing to work with. Say so, rather than doing nothing quietly
    // on a machine somebody is waiting on.
    anyhow::bail!(
        "fleet `{fleet}` has no [node] credential and no way to obtain one on this machine.\n\
         \n\
         Either log in first, then bring the agent up:\n\
         \x20   probe-rs-fleet login --fleet {fleet} --fleet-url <url>\n\
         \x20   probe-rs-fleet agent up --fleet {fleet}\n\
         \n\
         ...or enroll unattended with a key from `coordinator auth-key`:\n\
         \x20   probe-rs-fleet agent up --fleet {fleet} --fleet-url <url> --auth-key <key>\n\
         \n\
         (Interactive URL + short-code approval, for a headless machine with no key,\n\
         is not implemented yet — see task 3451.)"
    )
}

/// Rung 2: redeem an auth key for a node token.
///
/// Defaults to `adopt = declared`: a machine enrolled from an image or a
/// provisioning script is a lab node, and CI wants stable ids and no surprises.
async fn redeem(
    args: &AgentUpArgs,
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
    args: &AgentUpArgs,
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
    args: &AgentUpArgs,
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
        // No run hint: `agent up` is about to run the agent itself.
        run_hint: false,
    });
    Ok(())
}

/// Decode `--server-cert-sha256`, if given.
fn pin_of(args: &AgentUpArgs) -> Result<Option<[u8; 32]>> {
    match &args.server_cert_sha256 {
        Some(hex) => Ok(Some(
            fleet_tls::parse_fingerprint(hex)
                .context("--server-cert-sha256 must be 64 hex characters")?,
        )),
        None => Ok(None),
    }
}
