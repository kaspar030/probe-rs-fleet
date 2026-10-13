//! `probe-rs-fleet org {create,list,members}`: self-service team orgs and
//! their membership, with the login you already have.
//!
//! Before this existed a team org could only be made from a shell on the
//! coordinator host (`coordinator org create`), and a member only added by
//! minting them a token there (`coordinator user-token --org`). Both stay, as
//! the escape hatch; this is the front door.
//!
//! * `create` posts `/api/v1/orgs`; the caller becomes the org's admin. The
//!   coordinator gates it (`allow_org_creation`, `max_orgs_per_user`) and
//!   owns the name rules.
//! * `list` reads `GET /api/v1/session`, which already carries every
//!   membership with its name and role.
//! * `members` is forgs' `/auth/members` through
//!   [`ForgsClient::list_members`] / [`ForgsClient::set_member`] /
//!   [`ForgsClient::remove_member`]: the admin check and the last-admin guard
//!   are the server's.
//!
//! As in [`super::auth_key`], the work ([`create`], [`list`], [`members`],
//! [`add_member`], …) is separate from the printing in [`run`], so tests
//! assert on values rather than scraping stdout.

use anyhow::{Context, Result};
use serde::Deserialize;

use forgs_client::api::MemberList;
use forgs_client::{ClientError, ForgsClient, Secret};

use crate::cli::{
    OrgCliArgs, OrgCliCommand, OrgCliCreateArgs, OrgMembersArgs, OrgMembersCommand, OrgSessionArgs,
    RoleArg,
};
use crate::fleet_config::{self, FleetFile};
use crate::roles::auth_key::acting_org;
use crate::roles::node_setup;

/// `POST /api/v1/orgs`' answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CreatedOrg {
    /// The org's namespace id.
    pub id: String,
    /// Its name (path).
    pub name: Option<String>,
    /// The caller's role in it (`admin`).
    pub role: String,
}

/// One membership from `GET /api/v1/session`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Membership {
    /// The org's namespace id.
    pub id: String,
    /// Its name (path), if it has one.
    pub name: Option<String>,
    /// The caller's role there.
    pub role: String,
}

/// The parts of `GET /api/v1/session` this verb reads.
#[derive(Debug, Clone, Deserialize)]
struct SessionBody {
    #[serde(default)]
    memberships: Vec<Membership>,
}

/// Run `probe-rs-fleet org <verb>`: do the work, then print it.
///
/// # Errors
///
/// Returns an error if the fleet has no `[user]` credential, the session cannot
/// be refreshed, or the coordinator refuses the request.
pub async fn run(args: OrgCliArgs) -> Result<()> {
    match args.command {
        OrgCliCommand::Create(args) => {
            let created = create(&args).await?;
            let name = created.name.as_deref().unwrap_or(&created.id);
            println!("Created org '{name}' ({}); you are its admin.", created.id);
            println!();
            println!("Act in it with `--org {name}` (or `probe-rs-fleet login --org {name}`).");
            println!("Add people with `probe-rs-fleet org members add <username> --org {name}`.");
        }
        OrgCliCommand::List(args) => {
            let (orgs, acting) = list(&args).await?;
            print_orgs(&orgs, acting.as_deref());
        }
        OrgCliCommand::Members(args) => match &args.command {
            None => {
                let list = members(&args).await?;
                print_members(&list);
            }
            Some(OrgMembersCommand::Add(add)) => {
                let org = add_member(&args, &add.username, add.role).await?;
                println!("Added {} to '{org}' as {}.", add.username, add.role.label());
            }
            Some(OrgMembersCommand::SetRole(set)) => {
                let org = set_role(&args, &set.username, set.role).await?;
                println!("{} is now {} of '{org}'.", set.username, set.role.label());
            }
            Some(OrgMembersCommand::Remove(remove)) => {
                let org = remove_member(&args, &remove.username).await?;
                println!("Removed {} from '{org}'.", remove.username);
            }
        },
    }
    Ok(())
}

/// Create a team org with the caller as its admin.
///
/// # Errors
///
/// See [`run`]; the coordinator's refusal (bad name, name taken, creation
/// disabled, cap reached) is described with what to do about it.
pub async fn create(args: &OrgCliCreateArgs) -> Result<CreatedOrg> {
    let ctx = session(&args.session).await?;
    ctx.client
        .post_json(
            "/api/v1/orgs",
            Some(&Secret::from(ctx.session.as_str())),
            &serde_json::json!({ "name": args.name.trim() }),
        )
        .await
        .map_err(|e| describe(&e, &format!("creating the org `{}`", args.name.trim())))
}

/// The orgs the caller belongs to, plus the fleet file's acting org (by
/// name), for marking.
///
/// # Errors
///
/// See [`run`].
pub async fn list(args: &OrgSessionArgs) -> Result<(Vec<Membership>, Option<String>)> {
    let ctx = session(args).await?;
    let body: SessionBody = crate::api_client::get_json(
        &ctx.file.url,
        ctx.file.pin(),
        Some(&Secret::from(ctx.session.as_str())),
        "/api/v1/session",
    )
    .await
    .map_err(|e| describe(&e, "listing your orgs"))?;
    Ok((body.memberships, acting_org(&ctx.file, None)))
}

/// The members of the acting org.
///
/// # Errors
///
/// See [`run`].
pub async fn members(args: &OrgMembersArgs) -> Result<MemberList> {
    let (ctx, org) = org_session(args).await?;
    ctx.client
        .list_members(&ctx.session, &org)
        .await
        .map_err(|e| describe(&e, &format!("listing the members of `{org}`")))
}

/// Add `username` to the acting org with `role`. Returns the org.
///
/// # Errors
///
/// See [`run`].
pub async fn add_member(args: &OrgMembersArgs, username: &str, role: RoleArg) -> Result<String> {
    let (ctx, org) = org_session(args).await?;
    ctx.client
        .set_member(&ctx.session, &org, username.trim(), role.label())
        .await
        .map_err(|e| describe(&e, &format!("adding {username} to `{org}`")))?;
    Ok(org)
}

/// Change `username`'s role in the acting org. Returns the org.
///
/// Same call as [`add_member`] (forgs' `set` is an upsert); a separate verb so
/// the operator's intent reads plainly in shell history.
///
/// # Errors
///
/// See [`run`].
pub async fn set_role(args: &OrgMembersArgs, username: &str, role: RoleArg) -> Result<String> {
    let (ctx, org) = org_session(args).await?;
    ctx.client
        .set_member(&ctx.session, &org, username.trim(), role.label())
        .await
        .map_err(|e| describe(&e, &format!("changing {username}'s role in `{org}`")))?;
    Ok(org)
}

/// Remove `username` from the acting org. Returns the org.
///
/// # Errors
///
/// See [`run`].
pub async fn remove_member(args: &OrgMembersArgs, username: &str) -> Result<String> {
    let (ctx, org) = org_session(args).await?;
    ctx.client
        .remove_member(&ctx.session, &org, username.trim())
        .await
        .map_err(|e| describe(&e, &format!("removing {username} from `{org}`")))?;
    Ok(org)
}

/// A client, a live session token, and the loaded fleet file.
struct OrgContext {
    client: ForgsClient,
    session: String,
    file: FleetFile,
}

/// Load the fleet file and produce a fresh session (as `auth-key` does).
async fn session(args: &OrgSessionArgs) -> Result<OrgContext> {
    let fleet = &args.fleet;
    let (fleet_path, _node_dir) = node_setup::resolve_paths(fleet, args.config_dir.as_deref())?;
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
         run `probe-rs-fleet login --fleet {fleet}` first. \
         (With a shell on the coordinator host, `probe-rs-fleet coordinator \
         org create` is the self-hosted escape hatch.)"
    );
    let session = fleet_config::ensure_fresh_session(fleet, &file)
        .await
        .context("refreshing the session token")?;
    let client = ForgsClient::new(&file.url, file.pin())
        .map_err(|e| anyhow::anyhow!("invalid coordinator URL: {e}"))?;
    Ok(OrgContext {
        client,
        session,
        file,
    })
}

/// [`session`] plus the org a `members` verb acts in.
async fn org_session(args: &OrgMembersArgs) -> Result<(OrgContext, String)> {
    let ctx = session(&args.session).await?;
    let org = acting_org(&ctx.file, args.org.as_deref()).with_context(|| {
        format!(
            "no org to act in for fleet `{}`: pass `--org <name>`",
            args.session.fleet
        )
    })?;
    Ok((ctx, org))
}

/// Turn a coordinator rejection into remediation-shaped text.
fn describe(e: &ClientError, doing: &str) -> anyhow::Error {
    let ClientError::Rejected { code, status } = e else {
        return anyhow::anyhow!("{doing} failed: {e}");
    };
    let hint = match code.as_str() {
        "forbidden" => {
            "you are not an admin of that org (members may list it; only admins \
             change it), or you are not a member of it at all"
        }
        "not_found" => {
            "no such user (they must log in to this fleet once first), or they \
             are not a member of that org"
        }
        "last_admin" => {
            "that would leave the org with no admin. Make someone else an admin \
             first (`org members set-role <user> admin`)"
        }
        "invalid_name" => {
            "an org name is one path segment of lowercase letters, digits and \
             `-`, with no leading, trailing or doubled `-`, and not a reserved \
             word (api, auth, admin, …)"
        }
        "name_taken" => {
            "that name belongs to an existing org or user (or was used before \
             and released); pick another"
        }
        "org_creation_disabled" => {
            "this coordinator does not allow creating orgs over the API; ask its \
             operator (`probe-rs-fleet coordinator org create` on the host)"
        }
        "org_limit_reached" => {
            "you have created as many orgs as this coordinator allows \
             (`max_orgs_per_user`); ask its operator"
        }
        "invalid_request" | "bad_request" => {
            "the request was refused as malformed (check the role: member or admin)"
        }
        "unauthorized" => "your session was refused. Log in again with `probe-rs-fleet login`",
        _ => return anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {code}"),
    };
    anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {hint}")
}

/// Print `org list`.
fn print_orgs(orgs: &[Membership], acting: Option<&str>) {
    if orgs.is_empty() {
        println!("You are not a member of any org.");
        return;
    }
    let width = orgs
        .iter()
        .map(|m| m.name.as_deref().unwrap_or(&m.id).len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!("  {:<width$}  {:<6}  ID", "NAME", "ROLE");
    for m in orgs {
        let name = m.name.as_deref().unwrap_or(&m.id);
        let mark = if acting.is_some_and(|a| a == name || a == m.id) {
            '*'
        } else {
            ' '
        };
        println!("{mark} {name:<width$}  {:<6}  {}", m.role, m.id);
    }
    if acting.is_some() {
        println!();
        println!("* the org this fleet acts in by default");
    }
}

/// Print `org members`.
fn print_members(list: &MemberList) {
    if list.members.is_empty() {
        println!("No members.");
        return;
    }
    let width = list
        .members
        .iter()
        .map(|m| m.username.as_deref().unwrap_or(&m.subject).len())
        .max()
        .unwrap_or(8)
        .max(8);
    println!("{:<width$}  ROLE", "USERNAME");
    for m in &list.members {
        println!(
            "{:<width$}  {}",
            m.username.as_deref().unwrap_or(&m.subject),
            m.role
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(code: &str, status: u16) -> ClientError {
        ClientError::Rejected {
            status,
            code: code.to_owned(),
        }
    }

    #[test]
    fn rejections_become_remediation() {
        let e = describe(&rejected("last_admin", 409), "removing bob").to_string();
        assert!(e.contains("no admin"), "{e}");
        let e = describe(&rejected("forbidden", 403), "adding bob").to_string();
        assert!(e.contains("not an admin"), "{e}");
        let e = describe(&rejected("not_found", 404), "adding bob").to_string();
        assert!(e.contains("log in"), "{e}");
        let e = describe(&rejected("name_taken", 409), "creating").to_string();
        assert!(e.contains("existing org or user"), "{e}");
        let e = describe(&rejected("weird", 418), "creating").to_string();
        assert!(e.contains("418") && e.contains("weird"), "{e}");
    }
}
