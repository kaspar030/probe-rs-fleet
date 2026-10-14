//! `probe-rs-fleet grant`: share a subset of this org's boards with somebody
//! else, and take it back (architecture §6.5).
//!
//! ```text
//! probe-rs-fleet grant bob --select 'tag=nrf52' --ops flash,attach --until 2026-12-31
//! probe-rs-fleet grant --repo ariel-os/ariel-os --select 'tag=nrf52' --ops flash
//! probe-rs-fleet grant list
//! probe-rs-fleet grant revoke a1b2c3d4
//! ```
//!
//! # `--repo` grants a repository, never its owner
//!
//! `--repo owner/name` is the CI half (architecture §6.7): the grantee is a
//! GitHub Actions **workload** that proved, with a signed OIDC token, that it
//! is a job in that repo. The rule this verb has to make visible is that
//! `repository_owner` confers nothing — a fork, or a newly created repo under
//! the same owner, is a different subject with no grant. So the output prints
//! the resolved subject key and says so in as many words.
//!
//! Four properties come from the coordinator rather than from here, and are
//! worth knowing while reading this file:
//!
//! * **the org comes from the session**, never from a flag, so you can only
//!   ever share hardware you are in the org of (there is deliberately no
//!   `--org`);
//! * **creating a grant needs `admin`** — deliberately stricter than
//!   `auth-key create`, where membership suffices. An auth key cannot exceed
//!   the caller's own org; a grant points *outward*, at someone who is not in
//!   the org at all. In a personal org you are the admin, so the single-user
//!   story is unaffected;
//! * **the grantee is resolved to an immutable id at creation.** `grant bob`
//!   means the account that is `bob` today. GitHub logins can be renamed and
//!   reused, and §6.4 records that as an account-takeover vector;
//! * **revocation is real**: the coordinator releases the grantee's leases on
//!   boards they can no longer reach and tears down the relay, rather than
//!   merely deleting a row and waiting out the lease TTL.
//!
//! # What `--ops` actually enforces
//!
//! Only three of the six ops are enforced anywhere (see `AllowedOp`'s docs for
//! the table): `attach` and `gdb` by the agent at channel open, `power-cycle`
//! by the coordinator. Flash, erase and reset travel *in band* inside the data
//! channel as probe-rs RPC, which the fleet relays without parsing, so listing
//! them records intent rather than imposing a control. This module says so out
//! loud when it prints a grant, because a security verb that quietly overstates
//! what it enforces is worse than one that does less.
//!
//! Consequently a data-plane op implies `attach`: `--ops flash` alone would
//! mint a token that cannot open a data channel and therefore cannot flash.
//! The implication is applied coordinator-side and reported here when it fires.

use anyhow::{Context, Result};
use std::process::ExitCode;

use fleet_proto::token::AllowedOp;
use fleet_wire::{CoordToSidecar, SidecarToCoord};

use crate::cli::{GrantArgs, GrantCommand, GrantListArgs, GrantRevokeArgs};
use crate::roles::ctl::{CtlClient, CtlConnection};

/// Default grant lifetime when neither `--until` nor `--ttl` is given.
///
/// A grant always expires (the coordinator refuses an unbounded one over the
/// API), so a default is required rather than optional. 30 days matches the
/// auth-key cap: long enough not to be a nuisance, short enough that a
/// forgotten share lapses.
const DEFAULT_GRANT_TTL_SECS: u64 = 30 * 24 * 3600;

/// Run `probe-rs-fleet grant <verb>`.
///
/// # Errors
///
/// Returns an error if the connection config is incomplete, the arguments are
/// malformed, or the coordinator refuses the request.
pub async fn run(args: GrantArgs) -> Result<ExitCode> {
    match args.command {
        Some(GrantCommand::List(list)) => list_grants(list).await,
        Some(GrantCommand::Revoke(revoke)) => revoke_grant(revoke).await,
        None => create(args).await,
    }
}

/// `grant <subject>|--repo <owner/name> --select … --ops … [--until|--ttl]`.
async fn create(args: GrantArgs) -> Result<ExitCode> {
    // `--repo` is sent as the `repo:` spelling `Coordinator::resolve_grantee`
    // accepts, rather than as a distinct wire field: validation and
    // normalisation stay **server-side**, which is the property that matters
    // (a client cannot talk the coordinator into a subject key it would not
    // build itself), and the spelling is one a human can type directly.
    let is_repo = args.repo.is_some();
    let subject = match (&args.repo, &args.subject) {
        (Some(repo), _) => format!("repo:{}", repo.trim()),
        (None, Some(subject)) => subject.clone(),
        (None, None) => anyhow::bail!(
            "who to share with? A person: `probe-rs-fleet grant bob --select 'tag=nrf52'`. \
             A CI repository: `probe-rs-fleet grant --repo owner/name --select 'tag=nrf52'`."
        ),
    };
    let selector = args
        .select
        .context("--select is required: which boards to share (e.g. 'tag=nrf52', 'board=nrf52840dk', 'id=dk-3')")?;

    // Validate the selector locally so a typo is a clear message rather than a
    // round trip, and normalise it to the canonical form the coordinator
    // stores. Bare terms are tags: a grant describes a *set* of boards, and the
    // individual-board case is spelled `id=<name>`.
    let selector = fleet_proto::lease::parse_constraint(&selector)
        .map_err(|e| anyhow::anyhow!("invalid --select: {e}"))?
        .to_string();

    let requested = parse_ops_arg(&args.ops)?;
    let ops = fleet_proto::token::normalize_ops(requested.clone());
    if !requested.contains(&AllowedOp::Attach) && ops.contains(&AllowedOp::Attach) {
        eprintln!(
            "note: flash/erase/reset run inside a data channel; added `attach`, \
             without which the grant could not be used at all"
        );
    }

    let now = now_secs();
    let expires = match (&args.until, &args.ttl) {
        (Some(until), _) => {
            crate::timearg::parse_until(until, now).map_err(|e| anyhow::anyhow!("--until: {e}"))?
        }
        (None, Some(ttl)) => {
            let secs =
                crate::timearg::parse_duration(ttl).map_err(|e| anyhow::anyhow!("--ttl: {e}"))?;
            now.saturating_add(secs)
        }
        (None, None) => now.saturating_add(DEFAULT_GRANT_TTL_SECS),
    };

    let client = client(args.client).await?;
    let session = client.connect_session().await?;
    match session
        .request(SidecarToCoord::GrantCreate {
            subject,
            selector,
            ops,
            expires: Some(expires),
        })
        .await?
    {
        CoordToSidecar::GrantCreated(grant) => {
            println!("granted {} to {}", grant.selector, grant.subject);
            println!("  id      {}", grant.id);
            println!("  ops     {}", render_ops(&grant.ops));
            println!("  expires {expires} (epoch)");
            println!("  revoke  probe-rs-fleet grant revoke {}", &grant.id[..8]);
            if is_repo {
                // The subject key printed above is the exact identity a CI job
                // authenticates as, and the reminder is not decoration: "I
                // granted the org" is the single most likely misreading of this
                // verb, and the CLI is the right place to correct it before
                // somebody debugs a `403 no_grant` from the other end.
                println!(
                    "  note    this grants exactly that repository. Its OWNER is not \
                     granted: a fork, or a new repo under the same owner, gets nothing \
                     and needs its own grant."
                );
            }
            print_enforcement_note(&grant.ops);
            Ok(ExitCode::SUCCESS)
        }
        CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

/// `grant list`.
async fn list_grants(args: GrantListArgs) -> Result<ExitCode> {
    let client = client(args.client).await?;
    let session = client.connect_session().await?;
    match session.request(SidecarToCoord::GrantList).await? {
        CoordToSidecar::Grants(grants) => {
            if grants.is_empty() {
                println!("this org has shared no boards");
            } else {
                println!(
                    "{:<34} {:<24} {:<28} {:<22} EXPIRES",
                    "ID", "SUBJECT", "SELECTOR", "OPS"
                );
                for g in grants {
                    println!(
                        "{:<34} {:<24} {:<28} {:<22} {}",
                        g.id,
                        g.subject,
                        g.selector,
                        render_ops(&g.ops),
                        g.expires
                            .map_or_else(|| "never".to_owned(), |e| e.to_string())
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

/// `grant revoke <id>`.
async fn revoke_grant(args: GrantRevokeArgs) -> Result<ExitCode> {
    let client = client(args.client).await?;
    let session = client.connect_session().await?;
    match session
        .request(SidecarToCoord::GrantRevoke { id: args.id })
        .await?
    {
        CoordToSidecar::GrantRevoked { ids } => {
            for id in &ids {
                println!("revoked {id}");
            }
            println!(
                "any lease the grantee held on a board it can no longer reach has been released"
            );
            Ok(ExitCode::SUCCESS)
        }
        CoordToSidecar::Error { message } => anyhow::bail!("coordinator error: {message}"),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

/// Parse a `--ops` argument.
///
/// Shared with `ctl delegate`, so the two security verbs cannot disagree about
/// what an op is called. An empty set is refused: a grant or delegation that
/// confers nothing is always a mistake, and a silent one if we stored it.
///
/// # Errors
///
/// Returns an error naming the unrecognised label, or an empty set.
pub fn parse_ops_arg(s: &str) -> Result<Vec<AllowedOp>> {
    let ops = fleet_proto::token::parse_ops(s).map_err(|bad| {
        let known: Vec<&str> = AllowedOp::all().iter().map(|o| o.as_str()).collect();
        anyhow::anyhow!("unknown operation `{bad}`; known: {}", known.join(", "))
    })?;
    anyhow::ensure!(
        !ops.is_empty(),
        "--ops must name at least one operation ({})",
        AllowedOp::all()
            .iter()
            .map(|o| o.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(ops)
}

fn render_ops(ops: &[AllowedOp]) -> String {
    ops.iter().map(|o| o.as_str()).collect::<Vec<_>>().join(",")
}

/// Say which of the granted ops are actually enforced, and which are recorded
/// intent. Printing this is the honest alternative to a doc comment nobody
/// reads.
fn print_enforcement_note(ops: &[AllowedOp]) {
    let advisory: Vec<&str> = ops
        .iter()
        .filter(|o| !o.is_enforced())
        .map(|o| o.as_str())
        .collect();
    if !advisory.is_empty() {
        eprintln!(
            "note: {} run inside the data channel as probe-rs RPC, which the fleet \
             relays without parsing — they are recorded, not enforced. `attach`, \
             `gdb` and `power-cycle` are enforced.",
            advisory.join(", ")
        );
    }
}

async fn client(args: crate::cli::CtlClientArgs) -> Result<CtlClient> {
    Ok(CtlClient::new(CtlConnection::from_args(args).await?))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_parse_and_reject_junk() {
        assert_eq!(
            parse_ops_arg("flash,attach").unwrap(),
            vec![AllowedOp::Flash, AllowedOp::Attach]
        );
        assert_eq!(
            parse_ops_arg("power-cycle").unwrap(),
            vec![AllowedOp::PowerCycle]
        );
        assert!(parse_ops_arg("").is_err(), "an empty op set is a mistake");
        let err = parse_ops_arg("flash,fly").unwrap_err().to_string();
        assert!(
            err.contains("fly"),
            "the message names the bad label: {err}"
        );
    }

    #[test]
    fn ops_render_as_their_labels() {
        assert_eq!(
            render_ops(&[AllowedOp::Flash, AllowedOp::PowerCycle]),
            "flash,power-cycle"
        );
        assert_eq!(render_ops(&[]), "");
    }
}
