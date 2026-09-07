//! `probe-rs-fleet ci login`: turn a CI job's workload identity into a
//! short-lived fleet token (architecture §6.7).
//!
//! ```text
//! probe-rs-fleet ci login --fleet-url https://fleet.example
//! probe-rs-fleet ci login --fleet-url https://fleet.example --auth-key prffk1_…
//! ```
//!
//! # The GitHub Actions path holds no secret
//!
//! That is the entire point, and it is worth being precise about *why* it
//! works. A job with `permissions: id-token: write` can call two environment
//! variables' worth of GitHub-provided endpoint — `ACTIONS_ID_TOKEN_REQUEST_URL`
//! and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, injected by the runner and scoped to
//! that job — and get back a **signed JWT** asserting `repository`,
//! `repository_owner`, `ref` and friends. The coordinator verifies that
//! signature against GitHub's JWKS. Nothing was stored in the repository,
//! nothing was pasted into a secret, and nothing survives the job.
//!
//! The request token is a per-job credential the runner injects; it is used
//! once, here, and never written anywhere.
//!
//! # `--auth-key` is the weak path, and says so
//!
//! A self-hosted Jenkins box has no workload identity to offer, and
//! heterogeneous runners are a stated requirement, so the fallback exists. It
//! is a long-lived bearer secret living in somebody else's CI configuration,
//! bounded only by being org-scoped, selector-scoped, op-scoped, expiring and
//! revocable. Prefer the OIDC path wherever the runner can mint an identity.
//!
//! # What it writes, and what it deliberately does not
//!
//! It writes **no fleet file**. `examples/fleet.toml` records the rule: a CI
//! runner's credential comes from the environment and lives for one job, so
//! persisting it to disk on a shared runner would be the one durable artefact
//! this whole design exists to avoid. Instead:
//!
//! * with `$GITHUB_ENV` set (i.e. on GitHub Actions), the variables are
//!   appended there and the token is **never printed** — stdout is the job log;
//! * otherwise, `export …` lines go to stdout for `eval "$(…)"`.
//!
//! The variables are exactly the two the sidecar already reads
//! (`fleet_sidecar::selector`), so nothing in the sidecar changes.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};

use fleet_auth::api::TokenResponse;
use fleet_auth::http_client::ClientError;

use crate::cli::CiLoginArgs;

/// Environment variable GitHub Actions sets to the OIDC token endpoint.
///
/// Present **only** with `permissions: id-token: write`. Its absence is the
/// single most likely reason this command fails, so it gets a named error.
const ENV_REQUEST_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
/// Environment variable holding the bearer for [`ENV_REQUEST_URL`].
const ENV_REQUEST_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
/// Where GitHub Actions wants environment variables appended.
const ENV_GITHUB_ENV: &str = "GITHUB_ENV";

/// Run `probe-rs-fleet ci login`.
///
/// # Errors
///
/// Returns an error if no coordinator URL is known, the runner has no workload
/// identity and no `--auth-key` was given, the exchange is refused, or
/// `$GITHUB_ENV` cannot be written.
pub async fn run(args: CiLoginArgs) -> Result<ExitCode> {
    let url = args.fleet_url.clone().context(
        "no coordinator URL: pass --fleet-url <https://fleet.example> \
         (or set PROBE_RS_FLEET_COORDINATOR)",
    )?;
    if let Some(pin) = &args.server_cert_sha256 {
        anyhow::ensure!(
            fleet_tls::parse_fingerprint(pin).is_some(),
            "--server-cert-sha256 must be 64 hex characters"
        );
    }
    let pin = args
        .server_cert_sha256
        .as_deref()
        .and_then(fleet_tls::parse_fingerprint);

    let response = if let Some(key) = &args.auth_key {
        fleet_auth::http_client::exchange_workload_key(&url, pin, key.trim())
            .await
            .map_err(|e| describe(&e, "redeeming a workload auth key"))
    } else {
        // The audience must match the coordinator's configured one. It
        // defaults to the coordinator's URL because that is what an ordinary
        // deployment sets `audience` to; the coordinator itself has no
        // default, for the replay reason `CiLoginArgs` records.
        let audience = args.audience.clone().unwrap_or_else(|| url.clone());
        let jwt = request_github_oidc_token(&audience).await?;
        fleet_auth::http_client::exchange_github_oidc(&url, pin, &jwt)
            .await
            .map_err(|e| describe(&e, "exchanging this job's GitHub workload identity"))
    }?;

    emit(&args, &url, &response, github_env_destination().as_deref())?;
    print_summary(&response);
    Ok(ExitCode::SUCCESS)
}

/// Ask the runner's own token service for an OIDC JWT with `audience`.
///
/// Delegates the HTTPS call to [`fleet_auth::github::fetch_workload_id_token`],
/// which is where every other egress in this tree lives — keeping `fleet-bin`
/// out of the `hyper`/`rustls` stack and, more importantly, keeping this
/// request and the token exchange on one trust path.
///
/// # Errors
///
/// Returns an error naming the missing permission when the runner injected no
/// token endpoint — by far the most common failure, and one whose fix
/// (`permissions: id-token: write`) is not guessable from a generic message.
async fn request_github_oidc_token(audience: &str) -> Result<String> {
    let (url, token) = match (
        std::env::var(ENV_REQUEST_URL).ok(),
        std::env::var(ENV_REQUEST_TOKEN).ok(),
    ) {
        (Some(url), Some(token)) if !url.is_empty() && !token.is_empty() => (url, token),
        _ => anyhow::bail!(
            "this runner has no GitHub workload identity ({ENV_REQUEST_URL} is not set).\n\
             On GitHub Actions, add to the job:\n\
             \n    permissions:\n      id-token: write\n\n\
             On a runner GitHub does not mint tokens for (a self-hosted Jenkins \
             box, say), use `ci login --auth-key <key>` instead — see \
             docs/ci-github-actions.md, which is honest about that being the \
             weaker path."
        ),
    };

    fleet_auth::github::fetch_workload_id_token(&url, &token, audience)
        .await
        .context("requesting an OIDC token from GitHub's own token service")
}

/// Where GitHub Actions wants environment variables appended, if anywhere.
///
/// Resolved once, at the CLI entry point, and passed *into* [`emit`] — the
/// process environment is global mutable state, and reading it inside the code
/// under test is what made two unit tests race on it.
///
/// An empty value counts as unset: a runner that exports `GITHUB_ENV=` has no
/// file to append to.
fn github_env_destination() -> Option<PathBuf> {
    std::env::var_os(ENV_GITHUB_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Export the credential, to `github_env` or to stdout.
///
/// The destination is a parameter, resolved by the caller
/// ([`github_env_destination`]), not read from the environment here: that keeps
/// this function pure with respect to process-global state and lets the tests
/// below exercise both branches without racing each other.
///
/// **The token is never printed when `$GITHUB_ENV` is written.** stdout is the
/// job log on every CI system worth naming, and a credential in a log is a
/// credential in whatever archives that log.
fn emit(
    args: &CiLoginArgs,
    url: &str,
    response: &TokenResponse,
    github_env: Option<&Path>,
) -> Result<()> {
    let mut vars = vec![
        ("PROBE_RS_FLEET_COORDINATOR", url.to_owned()),
        ("PROBE_RS_FLEET_TOKEN", response.token.clone()),
        ("PROBE_RS_FLEET", args.fleet.clone()),
    ];
    if let Some(pin) = &args.server_cert_sha256 {
        vars.push(("PROBE_RS_FLEET_SERVER_CERT_SHA256", pin.clone()));
    }

    if let Some(path) = github_env {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| {
                format!(
                    "appending to ${ENV_GITHUB_ENV} ({})",
                    path.to_string_lossy()
                )
            })?;
        for (key, value) in &vars {
            // A token has no newline in it (base64url), so the plain `K=V`
            // form is safe here and the heredoc form would only obscure that.
            writeln!(file, "{key}={value}").with_context(|| {
                format!("writing ${ENV_GITHUB_ENV} ({})", path.to_string_lossy())
            })?;
        }
        eprintln!("wrote PROBE_RS_FLEET_COORDINATOR / PROBE_RS_FLEET_TOKEN to ${ENV_GITHUB_ENV}");
        if !args.export {
            return Ok(());
        }
    }

    for (key, value) in &vars {
        println!("export {key}={value}");
    }
    Ok(())
}

/// Print what was obtained — never the token itself.
///
/// The granting orgs are the useful part: a job that can suddenly not reach a
/// board wants to know which org's grant it is running under, and `orgs` is the
/// honest answer where `org` is only the first of them (a workload belongs to
/// no org).
fn print_summary(response: &TokenResponse) {
    let orgs = if response.orgs.is_empty() {
        response.org.clone()
    } else {
        response.orgs.join(", ")
    };
    println!("granted by: {orgs}");
    if let Some(expires) = response.expires {
        println!("expires:    {expires} (epoch seconds)");
        println!(
            "note:       there is no refresh for a CI token. A job that runs past \
             the expiry must re-run `ci login`."
        );
    }
}

/// Turn a coordinator rejection into remediation-shaped text.
///
/// The wire body is one coarse code by design (no oracle), so the sentence that
/// says what to do next has to be written here. `no_grant` is the one that
/// matters: it is the per-repo trust rule firing, and the fix is a command the
/// *fleet admin* runs, not something the CI job can do.
fn describe(e: &ClientError, doing: &str) -> anyhow::Error {
    let ClientError::Rejected { code, status } = e else {
        return anyhow::anyhow!("{doing} failed: {e}");
    };
    let hint = match code.as_str() {
        "no_grant" => {
            "this repository has no grant on that fleet. Note the grant is \
             PER REPO: being under a granted owner is deliberately not enough, \
             so a fork or a new repo needs its own. Ask the fleet admin to run \
             `probe-rs-fleet grant --repo <owner>/<name> --select '<selector>' \
             --ops flash`"
        }
        "workload_oidc_unconfigured" => {
            "that coordinator has no [github_actions] block, so it cannot \
             verify a GitHub workload identity at all. Ask the operator to \
             configure one (see examples/coordinator.toml), or use \
             `ci login --auth-key`"
        }
        "invalid_grant" => {
            "the coordinator refused the credential. It does not say why (that \
             is deliberate — no oracle); the reason is in ITS log. The usual \
             causes are an --audience that does not match the coordinator's \
             configured one, a clock far out of step, or an auth key that has \
             expired or been revoked"
        }
        "forbidden" => {
            "that auth key is not a CI key, or carries no tags. A key that can \
             lease hardware must be minted with `--purpose ci` and at least one \
             `--tag`: an empty tag set is an empty selector, which would match \
             every board in the org"
        }
        _ => return anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {code}"),
    };
    anyhow::anyhow!("{doing} was rejected by the coordinator ({status}): {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> CiLoginArgs {
        CiLoginArgs {
            fleet_url: Some("https://fleet.example".to_owned()),
            server_cert_sha256: None,
            audience: None,
            auth_key: None,
            export: false,
            fleet: "default".to_owned(),
            config_dir: None,
        }
    }

    fn response() -> TokenResponse {
        TokenResponse {
            token: "prfw1_secret".to_owned(),
            node_id: None,
            org: "acme".to_owned(),
            orgs: vec!["acme".to_owned(), "beta".to_owned()],
            expires: Some(4_600),
            coordinator_token_pubkey: None,
            login: None,
        }
    }

    /// The credential lands in the file `$GITHUB_ENV` names, in the `K=V` form
    /// the runner parses.
    #[test]
    fn github_env_receives_the_two_variables_the_sidecar_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("github.env");
        std::fs::write(&path, "PRE=existing\n").unwrap();
        emit(
            &args(),
            "https://fleet.example",
            &response(),
            Some(path.as_path()),
        )
        .unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        // Appended, never truncated: the runner and other steps write here too.
        assert!(written.starts_with("PRE=existing\n"));
        assert!(written.contains("PROBE_RS_FLEET_COORDINATOR=https://fleet.example\n"));
        assert!(written.contains("PROBE_RS_FLEET_TOKEN=prfw1_secret\n"));
        assert!(written.contains("PROBE_RS_FLEET=default\n"));
    }

    /// With no `$GITHUB_ENV`, the `export …` form goes to stdout for
    /// `eval "$(…)"` — the non-Actions runner's path.
    #[test]
    fn without_github_env_the_export_form_is_used() {
        // `emit` prints, which a unit test cannot capture; what is asserted is
        // that it does not fail and writes no file.
        emit(&args(), "https://fleet.example", &response(), None).unwrap();
    }

    /// A malformed audience is refused before any request leaves the process.
    ///
    /// The validation itself lives in `fleet_auth::github`; what this pins is
    /// that `ci login` reaches it rather than building a query string GitHub
    /// would read differently than we meant.
    #[tokio::test]
    async fn a_malformed_audience_never_reaches_the_network() {
        for bad in ["", "https://fleet.example&x=1", "https://fleet.example#f"] {
            let err = temp_env_unset_async(ENV_REQUEST_URL, request_github_oidc_token(bad))
                .await
                .unwrap_err();
            let text = format!("{err:#}");
            // With no runner identity set in the test process, the
            // no-identity error fires first; either way nothing was sent.
            assert!(
                text.contains("audience") || text.contains(ENV_REQUEST_URL),
                "unexpected error for {bad:?}: {text}"
            );
        }
    }

    /// The absent-identity error must name the permission, because that is the
    /// fix and it is not guessable.
    #[tokio::test]
    async fn a_runner_without_workload_identity_is_told_exactly_what_to_add() {
        let err = temp_env_unset_async(ENV_REQUEST_URL, request_github_oidc_token("aud"))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("id-token: write"), "{text}");
        assert!(text.contains("--auth-key"), "{text}");
    }

    #[test]
    fn no_grant_names_the_per_repo_rule_and_the_admin_command() {
        let e = ClientError::Rejected {
            status: 403,
            code: "no_grant".to_owned(),
        };
        let text = describe(&e, "exchanging").to_string();
        assert!(text.contains("PER REPO"), "{text}");
        assert!(text.contains("grant --repo"), "{text}");
    }

    #[test]
    fn invalid_grant_says_the_reason_lives_in_the_coordinator_log() {
        let e = ClientError::Rejected {
            status: 401,
            code: "invalid_grant".to_owned(),
        };
        let text = describe(&e, "exchanging").to_string();
        assert!(text.contains("no oracle"), "{text}");
        assert!(text.contains("audience"), "{text}");
    }

    // --- tiny env helper --------------------------------------------------
    //
    // `emit` takes its `$GITHUB_ENV` destination as a parameter precisely so
    // that the tests above need no environment at all: libtest runs tests as
    // parallel threads in one process, so a test that sets a variable another
    // test reads is a race, not a fixture. That is exactly the flake the
    // set/unset helpers that used to live here caused.
    //
    // What is left mutates only `ACTIONS_ID_TOKEN_REQUEST_URL`, and only ever
    // *removes* it: nothing else in this test binary reads or writes that key
    // (`tests/ci_e2e.rs` is a separate binary with its own `ENV_LOCK`), so the
    // concurrent removes are idempotent. It is still process-global state — if
    // a future test needs that variable *set*, take
    // `crate::test_support::ENV_LOCK` rather than extending this helper.
    //
    // Note `std::env::set_var`/`remove_var` are `unsafe` as of edition 2024 for
    // exactly this reason. The workspace is on 2021 and forbids `unsafe_code`,
    // so this compiles today, but an edition bump turns it into a build problem
    // and the fix is to remove the mutation, not to wrap it.

    async fn temp_env_unset_async<F: std::future::Future>(key: &str, f: F) -> F::Output {
        let old = std::env::var_os(key);
        std::env::remove_var(key);
        let out = f.await;
        if let Some(v) = old {
            std::env::set_var(key, v);
        }
        out
    }
}
