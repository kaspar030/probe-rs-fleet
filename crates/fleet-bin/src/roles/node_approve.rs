//! `probe-rs-fleet node approve`: let a machine that printed a short code join
//! your org (architecture §4.2 rung 3, §6.4).
//!
//! # Why this is a CLI verb and not a web page
//!
//! The headless machine prints a URL and a code. The URL leads to an
//! *informational* page, because the coordinator has no browser-authenticated
//! surface: `login` is the GitHub **device** flow, which deliberately has no
//! `redirect_uri` and no cookie session, so a page served by the coordinator
//! cannot know who is looking at it. Approving therefore happens here, on a
//! machine that already holds a `[user]` session — and the design keeps a real
//! browser flow possible later (see `fleet_coordinator::http`'s module docs).
//!
//! # The phishing problem, which is the whole reason for the ceremony
//!
//! RFC 8628 §5.4 applies here and harder than it does to login: the approver is
//! granting **hardware access in their org to a machine they cannot see**, on
//! the strength of a code someone read out to them. So this verb:
//!
//! * always **inspects first**, printing the requested name, tags, adoption
//!   policy, source address and age;
//! * says plainly that you cannot see the machine and should approve only an
//!   enrollment you started;
//! * requires an explicit confirmation that **defaults to no**, and refuses to
//!   proceed on a non-tty without `--yes` — a piped confirmation is not a
//!   confirmation;
//! * shouts about a name collision, and refuses one without `--replace`.
//!
//! Those sentences are the mitigation. They are the part most likely to be
//! quietly trimmed; please do not.
//!
//! # Everything printed here is attacker-controlled
//!
//! `node_name` and the tags arrive from an *unauthenticated* request. The
//! coordinator validates them against a conservative charset, but this end
//! neuters anything non-printable anyway ([`sanitise`]): a name containing
//! `\x1b[2J\x1b[H` must not be able to repaint the warning above. Defence at
//! both ends is deliberate — the server protects other clients, this protects
//! against rows written before the rule existed.

use std::io::{IsTerminal as _, Write as _};

use anyhow::{Context, Result};

use fleet_auth::api::{NodeApprovalDecision, NodeApprovalResponse};
use fleet_auth::http_client::ClientError;

use crate::cli::NodeApproveArgs;
use crate::fleet_config::{self, FleetFile};
use crate::roles::node_setup;

/// Run `probe-rs-fleet node approve <CODE>`.
///
/// # Errors
///
/// Returns an error if the code is malformed, the fleet has no `[user]`
/// credential, the session cannot be refreshed, the coordinator refuses the
/// request, or the confirmation is declined (or impossible).
pub async fn run(args: &NodeApproveArgs) -> Result<()> {
    // Locally first: a mistyped code fails here, with the shape it should have
    // had, rather than as a 404 from a request that need not have been made.
    let code = fleet_auth::user_code::normalise(&args.code).with_context(|| {
        format!(
            "`{}` is not an approval code: expected 8 characters like `ABCD-1234`, \
             as printed by the machine that is waiting",
            args.code
        )
    })?;

    let (file, session) = session_for(&args.fleet, args.config_dir.as_deref()).await?;

    // Always inspect before acting. This is the mitigation, not a convenience.
    let pending = fleet_auth::http_client::node_approval(
        &file.url,
        file.pin(),
        &session,
        &code,
        NodeApprovalDecision::Inspect,
        false,
    )
    .await
    .map_err(|e| describe(&e, "looking up the approval code"))?;

    let now = now_secs();
    println!("{}", describe_pending(&pending, now, args.deny));

    let decision = if args.deny {
        NodeApprovalDecision::Deny
    } else {
        NodeApprovalDecision::Approve
    };
    confirm(args, &pending)?;

    let outcome = fleet_auth::http_client::node_approval(
        &file.url,
        file.pin(),
        &session,
        &code,
        decision,
        args.replace,
    )
    .await
    .map_err(|e| {
        describe(
            &e,
            if args.deny {
                "denying the request"
            } else {
                "approving the request"
            },
        )
    })?;

    print_outcome(&outcome, args.deny);
    Ok(())
}

/// Load the fleet file and produce a usable session token.
///
/// Refreshing goes through the shared path rather than reaching for the raw
/// token: a session that expired an hour ago would otherwise surface as an
/// opaque 401 from a command the user has no reason to associate with logging
/// in. Same call, same reasoning, as `share` and `auth-key`.
async fn session_for(
    fleet: &str,
    config_dir: Option<&std::path::Path>,
) -> Result<(FleetFile, String)> {
    let (fleet_path, _node_dir) = node_setup::resolve_paths(fleet, config_dir)?;
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
         run `probe-rs-fleet login --fleet {fleet}` first. Approving is an \
         authenticated act: the node joins *your* org."
    );
    let session = fleet_config::ensure_fresh_session(fleet, &file)
        .await
        .context("refreshing the session token")?;
    Ok((file, session))
}

/// Ask for confirmation, defaulting to **no**.
///
/// A non-tty without `--yes` is refused rather than defaulted either way: a
/// piped confirmation is not a confirmation, and defaulting to yes on a
/// pipeline is exactly how a phishing ceremony succeeds unattended.
fn confirm(args: &NodeApproveArgs, pending: &NodeApprovalResponse) -> Result<()> {
    if args.yes {
        return Ok(());
    }
    let verb = if args.deny { "Deny" } else { "Approve" };
    anyhow::ensure!(
        std::io::stdin().is_terminal(),
        "stdin is not a terminal, so there is nobody here to confirm this. \
         Re-run with --yes if you already know what you are approving."
    );
    print!("{verb} '{}'? [y/N] ", sanitise(&pending.node_name));
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading the confirmation")?;
    let answer = answer.trim().to_ascii_lowercase();
    anyhow::ensure!(
        answer == "y" || answer == "yes",
        "cancelled — nothing was changed. The machine keeps waiting until its \
         code expires."
    );
    Ok(())
}

/// Render the pending registration for a human to judge.
///
/// Factored out (and returning a `String`) so the wording is unit-testable: it
/// *is* the RFC 8628 §5.4 mitigation, so it is worth asserting rather than
/// hoping.
fn describe_pending(pending: &NodeApprovalResponse, now: i64, denying: bool) -> String {
    use std::fmt::Write as _;

    // Infallible: writing to a String never fails, so every `let _ =` below is
    // discarding an error that cannot occur.
    let mut out = String::new();
    let org = sanitise(pending.org.as_deref().unwrap_or("your org"));
    let _ = write!(
        out,
        "\nA machine is asking to join org '{org}' as a node:\n\n  node name    {}\n",
        sanitise(&pending.node_name)
    );
    let tags = if pending.tags.is_empty() {
        "(none)".to_owned()
    } else {
        pending
            .tags
            .iter()
            .map(|t| sanitise(t))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = write!(
        out,
        "  tags         {tags}\n  adopt policy {}\n",
        sanitise(&pending.adopt)
    );
    match &pending.source_ip {
        Some(ip) => {
            let _ = writeln!(
                out,
                "  source IP    {}   (as seen by the coordinator; a proxy may mask it)",
                sanitise(ip)
            );
        }
        None => out.push_str(
            "  source IP    (unknown — the coordinator is behind a proxy that hides it)\n",
        ),
    }
    let _ = write!(
        out,
        "  requested    {}, expires in {}\n\n",
        ago(now.saturating_sub(pending.created_at)),
        remaining(pending.expires.saturating_sub(now))
    );

    if let Some(existing) = &pending.collides_with {
        let _ = write!(
            out,
            "  !!  org '{org}' ALREADY HAS a node named '{}'.\n      \
             Approving with --replace re-credentials it: the machine currently\n      \
             running as '{}' loses its token at its next connection.\n\n",
            sanitise(&pending.node_name),
            sanitise(existing),
        );
    }

    if !denying {
        // The mitigation. Both sentences are load-bearing: the first says what
        // is being granted, the second says the only safe reason to grant it.
        out.push_str(
            "Approving grants this machine access to hardware in your org, and you\n\
             cannot see it from here. Approve ONLY if you started this enrollment.\n",
        );
    }
    out
}

/// Report what happened, and what the waiting machine will do next.
fn print_outcome(outcome: &NodeApprovalResponse, denied: bool) {
    println!();
    if denied {
        println!(
            "Denied '{}'. That code can never be used again.",
            sanitise(&outcome.node_name)
        );
        return;
    }
    let org = outcome.org.as_deref().unwrap_or("(unknown)");
    println!(
        "Approved: '{}' joins org '{}'.",
        sanitise(&outcome.node_name),
        sanitise(org)
    );
    println!("The machine picks this up on its next poll, within a few seconds.");
    println!();
    println!(
        "It will print the org it landed in — check that it says '{}'.",
        sanitise(org)
    );
}

/// Neuter anything that is not printable ASCII.
///
/// Everything rendered by this module came from an unauthenticated request. A
/// name carrying ANSI escapes could otherwise repaint or scroll away the
/// warning that is this verb's whole point.
fn sanitise(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(128)
        .collect()
}

/// Human-readable "N ago".
fn ago(secs: i64) -> String {
    match secs {
        s if s < 0 => "just now".to_owned(),
        s if s < 90 => format!("{s} seconds ago"),
        s => format!("{} minutes ago", s / 60),
    }
}

/// Human-readable "in N".
fn remaining(secs: i64) -> String {
    match secs {
        s if s <= 0 => "(expired)".to_owned(),
        s if s < 90 => format!("{s} seconds"),
        s => format!("{} minutes", s / 60),
    }
}

/// Wall-clock seconds, for the age/expiry lines only.
fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

/// Turn a coordinator rejection into remediation-shaped text.
///
/// The wire body is deliberately coarse — one `error` code — so the sentence
/// that says what to do next is written here, as in `auth_key::describe`.
fn describe(e: &ClientError, doing: &str) -> anyhow::Error {
    let ClientError::Rejected { code, status } = e else {
        return anyhow::anyhow!("{doing} failed: {e}");
    };
    let hint = match code.as_str() {
        // Unknown, expired and already-decided are one answer by design: a
        // caller must not be able to probe which. So the remediation names all
        // three rather than guessing.
        "invalid_grant" => {
            "no pending registration matches that code. It may be mistyped, \
             already approved or denied, or expired (codes live 15 minutes) — \
             re-run `agent up` on the machine to get a fresh one"
        }
        "node_name_taken" => {
            "your org already has a node with the name this machine asked for. \
             Approving would re-credential it and knock the running machine off \
             the fleet. If that is genuinely what you want, re-run with \
             --replace; otherwise re-run `agent up --node-name <other>` on the \
             waiting machine"
        }
        "forbidden" => {
            "you are not a member of the org your session belongs to, so you \
             cannot approve a node into it"
        }
        "unauthorized" => "your session was refused. Log in again with `probe-rs-fleet login`",
        _ => return anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {code}"),
    };
    anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(code: &str) -> NodeApproveArgs {
        NodeApproveArgs {
            code: code.to_owned(),
            deny: false,
            yes: false,
            replace: false,
            fleet: "default".to_owned(),
            config_dir: None,
        }
    }

    /// A pending registration in exactly the shape `Inspect` returns.
    ///
    /// `org` is `Some`, and that is load-bearing rather than convenient: the
    /// coordinator reports the **approver's** org on every decision, including
    /// `Inspect`, so the human is told which org they are granting access in
    /// *before* they confirm. `node_approval.rs`'s
    /// `an_inspection_names_the_org_the_machine_would_join` pins that end.
    fn pending(name: &str) -> NodeApprovalResponse {
        NodeApprovalResponse {
            user_code: "ABCD-1234".to_owned(),
            node_name: name.to_owned(),
            tags: vec!["nrf52".to_owned(), "lab".to_owned()],
            adopt: "auto".to_owned(),
            source_ip: Some("203.0.113.7".to_owned()),
            created_at: 1_000,
            expires: 1_900,
            org: Some("acme".to_owned()),
            state: "pending".to_owned(),
            collides_with: None,
        }
    }

    /// Which org the machine would join is part of the decision the ceremony
    /// asks the human to make — a person may hold sessions for several orgs —
    /// so it must appear on the screen they read *before* confirming, not only
    /// in the outcome afterwards.
    #[test]
    fn the_description_names_the_org_before_the_confirmation() {
        let rendered = describe_pending(&pending("rpi-lab-3"), 1_041, false);
        assert!(rendered.contains("join org 'acme'"), "{rendered}");

        // A collision is reported against that same org.
        let mut p = pending("rpi-lab-3");
        p.collides_with = Some("acme/rpi-lab-3".to_owned());
        assert!(
            describe_pending(&p, 1_041, false).contains("org 'acme' ALREADY HAS"),
            "the collision must name the org too"
        );
    }

    /// A coordinator that sends no org (an older one) must degrade to a hedge
    /// rather than inventing a name — the approver can still see the node name
    /// and source IP, and "your org" is honest about what is not known.
    #[test]
    fn a_missing_org_degrades_to_a_hedge_not_a_guess() {
        let mut p = pending("rpi-lab-3");
        p.org = None;
        let rendered = describe_pending(&p, 1_041, false);
        assert!(rendered.contains("join org 'your org'"), "{rendered}");
        assert!(rendered.contains("cannot see it from here"), "{rendered}");
    }

    /// A malformed code must fail locally, before any request: the user typed
    /// it, so the error should describe what they typed.
    #[tokio::test]
    async fn a_malformed_code_is_refused_before_any_request() {
        for code in ["", "ABC", "ABCDEFGHI", "ABCD!234"] {
            let err = run(&args(code)).await.unwrap_err().to_string();
            assert!(err.contains("ABCD-1234"), "{code}: {err}");
        }
    }

    /// The wording *is* the mitigation, so it is asserted rather than hoped.
    #[test]
    fn the_description_states_what_is_granted_and_that_you_cannot_see_it() {
        let rendered = describe_pending(&pending("rpi-lab-3"), 1_041, false);
        assert!(rendered.contains("rpi-lab-3"));
        assert!(rendered.contains("acme"));
        assert!(rendered.contains("nrf52, lab"));
        assert!(rendered.contains("auto"));
        assert!(rendered.contains("203.0.113.7"));
        assert!(rendered.contains("41 seconds ago"));
        assert!(rendered.contains("14 minutes"));
        assert!(
            rendered.contains("cannot see it from here"),
            "the phishing warning must not be trimmed: {rendered}"
        );
        assert!(
            rendered.contains("ONLY if you started this enrollment"),
            "the phishing warning must not be trimmed: {rendered}"
        );
    }

    /// A name carrying terminal escapes must not be able to repaint the block
    /// that warning lives in.
    #[test]
    fn control_characters_in_an_attacker_chosen_name_render_inert() {
        let mut p = pending("\x1b[2J\x1b[Hevil");
        p.tags = vec!["\nApprove ONLY if".to_owned()];
        p.source_ip = Some("1.2.3.4\r\n".to_owned());
        let rendered = describe_pending(&p, 1_041, false);
        assert!(!rendered.contains('\x1b'), "{rendered:?}");
        // The only newlines are the ones this function wrote.
        assert!(!rendered.contains("\nApprove ONLY if\n"), "{rendered:?}");
        assert!(rendered.contains("??[2J??[Hevil") || rendered.contains("?[2J?[Hevil"));
        assert!(
            rendered.contains("cannot see it from here"),
            "the warning survives: {rendered}"
        );
    }

    /// A collision is shouted about, because it is the case where approving
    /// costs someone a running machine.
    #[test]
    fn a_name_collision_is_stated_loudly() {
        let mut p = pending("rpi-lab-3");
        p.collides_with = Some("acme/rpi-lab-3".to_owned());
        let rendered = describe_pending(&p, 1_041, false);
        assert!(rendered.contains("ALREADY HAS"), "{rendered}");
        assert!(rendered.contains("--replace"), "{rendered}");
        assert!(rendered.contains("loses its token"), "{rendered}");
    }

    /// Non-tty without `--yes` refuses rather than defaulting either way.
    ///
    /// Tests run with stdin detached, so this exercises the real branch.
    #[test]
    fn a_non_tty_without_yes_is_refused() {
        let err = confirm(&args("ABCD1234"), &pending("rpi"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--yes"), "{err}");
        // ... and `--yes` is the documented way through.
        let mut a = args("ABCD1234");
        a.yes = true;
        assert!(confirm(&a, &pending("rpi")).is_ok());
    }

    #[test]
    fn rejections_become_remediation() {
        let cases = [
            ("invalid_grant", "expired"),
            ("node_name_taken", "--replace"),
            ("forbidden", "not a member"),
            ("unauthorized", "Log in again"),
        ];
        for (code, needle) in cases {
            let e = ClientError::Rejected {
                status: 404,
                code: code.to_owned(),
            };
            let rendered = describe(&e, "approving the request").to_string();
            assert!(rendered.contains(needle), "{code}: {rendered}");
        }
    }
}
