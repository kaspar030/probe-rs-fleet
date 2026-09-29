//! `probe-rs-fleet share`: offer this machine's probes to the fleet, using the
//! login you already have.
//!
//! This is the story-2 payoff (architecture §6.4): "I'm on my laptop, I plug in
//! a board, I want it in the fleet" is one command with no token and no
//! out-of-band step. The `[user]` session already in the per-fleet config
//! proves membership, and **membership is sufficient** — there is no admin
//! approval step (a decision, not an omission; a device-approval gate can be
//! added later without a data migration).
//!
//! Two consequences worth naming:
//!
//! * The node is **owned by the user** (`node.owner_user_id` on the
//!   coordinator), so "my laptop's boards" is expressible and revoking the user
//!   cascades sensibly.
//! * The node's default adoption policy is `auto`: someone deliberately sharing
//!   their machine wants a probe they plug in to be usable, not to have to
//!   describe it in a file first.
//!
//! `share` deliberately does **not** start the agent. It writes credentials and
//! settings; running the daemon is a separate decision (a service unit, a
//! terminal, whatever the machine's owner prefers), and the summary says so.

use anyhow::{Context, Result};

use fleet_proto::AdoptPolicy;

use crate::cli::ShareArgs;
use crate::fleet_config;
use crate::roles::node_setup;

/// Run `probe-rs-fleet share`.
///
/// # Errors
///
/// Returns an error if the fleet has no `[user]` credential, the session
/// cannot be refreshed, the coordinator refuses the registration (a non-member
/// is a `403`), any file cannot be written, or — without `--force` — the fleet
/// already has a `[node]` credential.
pub async fn run(args: ShareArgs) -> Result<()> {
    let ShareArgs {
        fleet,
        node_name,
        tag,
        adopt,
        org,
        force,
        config_dir,
    } = args;

    let (fleet_path, node_dir) = node_setup::resolve_paths(&fleet, config_dir.as_deref())?;
    node_setup::refuse_if_already_enrolled(&fleet, &fleet_path, force)?;

    let file = fleet_config::load(&fleet_path).with_context(|| {
        format!(
            "loading fleet config {} — log in first with \
             `probe-rs-fleet login --fleet {fleet} --fleet-url <url>`",
            fleet_path.display()
        )
    })?;
    anyhow::ensure!(
        file.user.is_some(),
        "fleet `{fleet}` has no [user] credential on this machine; \
         run `probe-rs-fleet login --fleet {fleet}` first, or enroll this node \
         unattended with `probe-rs-fleet node up --auth-key <key>`"
    );

    // Refresh through the shared path rather than reaching for the raw token: a
    // session that expired an hour ago would otherwise surface here as an
    // opaque 401 from a command the user has no reason to associate with
    // logging in.
    let session = fleet_config::ensure_fresh_session(&fleet, &file)
        .await
        .context("refreshing the session token")?;

    let node_name = node_name.unwrap_or_else(node_setup::default_node_name);
    let adopt: AdoptPolicy = adopt.map_or(AdoptPolicy::Auto, Into::into);

    let org = org.or_else(|| file.user.as_ref().and_then(|u| u.org.clone()));
    let client = crate::node_client::client(&file.url, file.pin())
        .map_err(|e| anyhow::anyhow!("invalid coordinator URL: {e}"))?;
    let response = crate::node_client::self_register(
        &client,
        &session,
        &fleet_proto::auth_api::SelfRegisterRequest {
            node_name: node_name.clone(),
            tags: tag,
            adopt: Some(adopt.as_str().to_owned()),
            org,
        },
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(forgs_client::cli::describe(
            &e,
            "registering this machine as a node at <fleet-url>/node/self-register"
        ))
    })?;

    // `None` for the URL: the session that authorised this came out of *this*
    // file, so the coordinator it names is already the right one. Same for the
    // pin.
    let node_id =
        node_setup::record_node_credential(&fleet_path, &response, &node_name, None, None)?;

    let (boards_path, node_settings_path) = node_setup::scaffold_node_dir(&node_dir, adopt, force)?;

    node_setup::print_summary(&node_setup::Enrollment {
        node_id: &node_id,
        org: response.org_name.as_deref().unwrap_or(&response.org),
        fleet: &fleet,
        adopt,
        fleet_path: &fleet_path,
        boards_path: &boards_path,
        node_settings_path: &node_settings_path,
        // `share` writes the credential but does not start the agent, so the
        // last step is still outstanding and saying so is the difference
        // between a working machine and a confused one.
        run_hint: true,
    });
    Ok(())
}
