//! `probefleet node move <NAME> --to-org <ORG>`: move a node, with all its
//! boards, to another org.
//!
//! Posts `POST /api/v1/nodes/{name}/move?org=<source>` with the `[user]`
//! session, like `org rename`/`delete`. The coordinator does the work and the
//! authorization: the caller must be an **admin of the source** org and a
//! **member of the target**. The node's token survives the move, so the
//! agent reconnects by itself; nothing needs re-enrolling.
//!
//! Moving a single board is not possible: a board belongs to the machine
//! that hosts it, and a machine belongs to exactly one org.
//!
//! As elsewhere, the work ([`move_node`]) is separate from the printing in
//! [`run`], so tests assert on values.

use anyhow::{Context, Result};
use serde::Deserialize;

use forgs_client::{ClientError, ForgsClient, Secret};

use crate::cli::NodeMoveArgs;
use crate::fleet_config;
use crate::roles::auth_key::acting_org;
use crate::roles::node_setup;
use crate::roles::org::org_route;

/// An org as named in the coordinator's answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OrgRef {
    /// Namespace id.
    pub id: String,
    /// Path (display name), if it has one.
    pub name: Option<String>,
}

impl OrgRef {
    /// The name, else the id.
    #[must_use]
    pub fn label(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }
}

/// The moved node, as the coordinator now stores it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MovedNodeView {
    /// The new node id (`<target org>/<name>`).
    pub id: String,
    /// The node-local name.
    pub name: String,
    /// Its boards' node-local names.
    pub boards: Vec<String>,
}

/// A grant whose coverage the move changed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AffectedGrant {
    /// Grant id.
    pub id: String,
    /// The canonical selector.
    pub selector: String,
    /// The grantee, rendered for humans when the coordinator could.
    pub subject_display: Option<String>,
    /// The grantee's subject key.
    pub subject: AffectedSubject,
}

/// The grantee part of an [`AffectedGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AffectedSubject {
    /// The rendered subject key.
    pub key: String,
}

impl AffectedGrant {
    fn who(&self) -> &str {
        self.subject_display.as_deref().unwrap_or(&self.subject.key)
    }
}

/// `POST /api/v1/nodes/{name}/move`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MovedNode {
    /// The node after the move.
    pub node: MovedNodeView,
    /// Its id before the move.
    pub old_id: String,
    /// The source org.
    pub from_org: OrgRef,
    /// The target org.
    pub to_org: OrgRef,
    /// Leases the move revoked (`--force`).
    pub revoked_leases: u32,
    /// Source-org grants that no longer cover the node's boards.
    pub grants_lost: Vec<AffectedGrant>,
    /// Target-org grants that now cover them.
    pub grants_gained: Vec<AffectedGrant>,
}

/// Run `probefleet node move` and print the outcome.
///
/// # Errors
///
/// See [`move_node`].
pub async fn run(args: &NodeMoveArgs) -> Result<()> {
    let moved = move_node(args).await?;
    print_outcome(&moved);
    Ok(())
}

/// Split `NAME` into an optional source-org prefix and the node-local name:
/// a full `<org>/<name>` id (as `ctl nodes` prints it) carries its org.
fn split_name(raw: &str) -> (Option<&str>, &str) {
    let raw = raw.trim();
    match raw.rsplit_once('/') {
        Some((org, name)) if !org.is_empty() => (Some(org), name),
        Some((_, name)) => (None, name),
        None => (None, raw),
    }
}

/// Move the node, after confirmation.
///
/// # Errors
///
/// No `[user]` credential, a declined (or impossible) confirmation, or the
/// coordinator's refusal, described with what to do about it.
pub async fn move_node(args: &NodeMoveArgs) -> Result<MovedNode> {
    let fleet = &args.fleet;
    let (fleet_path, _node_dir) = node_setup::resolve_paths(fleet, args.config_dir.as_deref())?;
    let file = fleet_config::load(&fleet_path).with_context(|| {
        format!(
            "loading fleet config {} — log in first with \
             `probefleet login --fleet {fleet} --fleet-url <url>`",
            fleet_path.display()
        )
    })?;
    anyhow::ensure!(
        file.user.is_some(),
        "fleet `{fleet}` has no [user] credential on this machine; \
         run `probefleet login --fleet {fleet}` first"
    );
    let (prefix, name) = split_name(&args.name);
    anyhow::ensure!(!name.is_empty(), "no node name given");
    let to = args.to_org.trim();
    anyhow::ensure!(!to.is_empty(), "--to-org must name an org");
    let source = acting_org(&file, args.org.as_deref().or(prefix)).with_context(|| {
        format!("no org to move the node out of for fleet `{fleet}`: pass `--org <name>`")
    })?;

    confirm(args.yes, name, &source, to, args.force)?;

    let session = fleet_config::ensure_fresh_session(fleet, &file)
        .await
        .context("refreshing the session token")?;
    let client = ForgsClient::new(&file.url, file.pin())
        .map_err(|e| anyhow::anyhow!("invalid coordinator URL: {e}"))?;
    client
        .post_json(
            &org_route(&format!("/api/v1/nodes/{}/move", encode(name)), &source),
            Some(&Secret::from(session.as_str())),
            &serde_json::json!({ "to_org": to, "force": args.force }),
        )
        .await
        .map_err(|e| describe(&e, name, &source, to))
}

/// Percent-encode one path segment.
fn encode(segment: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Ask before moving, unless `yes`. Refuses on a non-terminal.
fn confirm(yes: bool, name: &str, from: &str, to: &str, force: bool) -> Result<()> {
    use std::io::{IsTerminal, Write};
    if yes {
        return Ok(());
    }
    anyhow::ensure!(
        std::io::stdin().is_terminal(),
        "stdin is not a terminal, so there is nobody here to confirm this. \
         Re-run with --yes if you really mean to move `{name}` to `{to}`."
    );
    println!("Moving node '{name}' from '{from}' to '{to}':");
    println!("  * all of its boards move with it and leave '{from}';");
    println!("  * grants in '{from}' stop covering them;");
    if force {
        println!("  * active leases on its boards are REVOKED (--force);");
    } else {
        println!("  * the move is refused if any of its boards is leased;");
    }
    println!("  * the machine reconnects by itself with its existing token.");
    print!("Move it? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading the confirmation")?;
    let answer = answer.trim().to_ascii_lowercase();
    anyhow::ensure!(
        answer == "y" || answer == "yes",
        "cancelled — nothing was changed"
    );
    Ok(())
}

/// Turn a coordinator rejection into remediation-shaped text.
fn describe(e: &ClientError, name: &str, from: &str, to: &str) -> anyhow::Error {
    let doing = format!("moving node `{name}` from `{from}` to `{to}`");
    let ClientError::Rejected { code, status } = e else {
        return anyhow::anyhow!("{doing} failed: {e}");
    };
    let hint = match code.as_str() {
        "forbidden" => format!(
            "you must be an admin of `{from}` and a member of `{to}` \
             (or `{to}` does not exist)"
        ),
        "not_found" => format!("`{from}` has no node named `{name}`"),
        "node_name_taken" => format!("a node named `{name}` already exists in `{to}`"),
        "node_leased" => "some of its boards are leased; release them or pass --force".to_owned(),
        "invalid_request" => "the node is already in that org".to_owned(),
        "unauthorized" => {
            "your session was refused. Log in again with `probefleet login`".to_owned()
        }
        _ => return anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {code}"),
    };
    anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {hint}")
}

/// Print the outcome.
fn print_outcome(m: &MovedNode) {
    println!(
        "Moved node '{}' from '{}' to '{}'; it is now {}.",
        m.node.name,
        m.from_org.label(),
        m.to_org.label(),
        m.node.id
    );
    if !m.node.boards.is_empty() {
        println!("Boards: {}", m.node.boards.join(", "));
    }
    if m.revoked_leases > 0 {
        println!("Revoked {} active lease(s).", m.revoked_leases);
    }
    if !m.grants_lost.is_empty() {
        println!(
            "warning: these grants in '{}' no longer cover its boards:",
            m.from_org.label()
        );
        for g in &m.grants_lost {
            println!("  {}  {}  {}", g.id, g.who(), g.selector);
        }
    }
    if !m.grants_gained.is_empty() {
        println!(
            "note: these grants in '{}' now cover its boards:",
            m.to_org.label()
        );
        for g in &m.grants_gained {
            println!("  {}  {}  {}", g.id, g.who(), g.selector);
        }
    }
    println!(
        "The machine reconnects by itself with its existing token; its local \
         config keeps the old id until its next `probefleet node up`."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_node_id_carries_its_org() {
        assert_eq!(split_name("rpi-1"), (None, "rpi-1"));
        assert_eq!(split_name("acme/rpi-1"), (Some("acme"), "rpi-1"));
        assert_eq!(split_name("/rpi-1"), (None, "rpi-1"));
    }

    #[test]
    fn segments_are_encoded() {
        assert_eq!(encode("rpi-1"), "rpi-1");
        assert_eq!(encode("a b/c"), "a%20b%2Fc");
    }
}
