//! Command-line surface and role dispatch.
//!
//! Two entry paths funnel into the same role handlers:
//!
//! 1. **argv0 dispatch** — when the binary is invoked as `probe-rs` (basename
//!    of argv0, with an optional `.exe` suffix stripped), every following
//!    argument is treated as a probe-rs argument and forwarded to the sidecar
//!    shim *without* running clap. This makes a `probe-rs` symlink on `PATH`
//!    route through the fleet transparently.
//! 2. **explicit subcommands** — `probe-rs-fleet <coordinator|agent|sidecar|ctl>`
//!    parsed with clap derive.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::roles;

/// The single multi-role probe-rs-fleet binary.
#[derive(Debug, Parser)]
#[command(
    name = "probe-rs-fleet",
    version,
    about = "probe-rs-fleet: coordinator, agent, sidecar, and admin CLI in one binary",
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level roles.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the fleet coordinator daemon (scheduler / leases / relay).
    Coordinator(CoordinatorArgs),
    /// Run the fleet agent: dials out to the coordinator and drives local probes.
    Agent(AgentArgs),
    /// Sidecar shim: forward a probe-rs invocation through the fleet.
    ///
    /// Usually reached via a `probe-rs` symlink, but also available explicitly:
    /// `probe-rs-fleet sidecar -- <probe-rs args…>`.
    Sidecar(SidecarArgs),
    /// Admin / UX CLI: talk to the coordinator over its `/client` WebSocket.
    Ctl(CtlArgs),
}

/// Arguments for the `coordinator` role.
#[derive(Debug, Args)]
pub struct CoordinatorArgs {
    /// Path to the coordinator config (TOML).
    ///
    /// When unset, defaults to the XDG path
    /// `$XDG_CONFIG_HOME/probe-rs-fleet/coordinator.toml`.
    #[arg(long, env = "PROBE_RS_FLEET_CONFIG")]
    pub config: Option<std::path::PathBuf>,
    /// Optional nested subcommand (e.g. `init`). When absent, the coordinator
    /// daemon runs.
    #[command(subcommand)]
    pub command: Option<CoordinatorCommand>,
}

/// `coordinator` subcommands.
#[derive(Debug, Subcommand)]
pub enum CoordinatorCommand {
    /// Scaffold a ready-to-run coordinator: generate the signing seed and a
    /// populated config under the XDG paths.
    Init(InitArgs),
    /// Mint an org-scoped auth key for unattended node enrollment.
    AuthKey(AuthKeyArgs),
    /// Mint a user session token directly (INTERIM).
    UserToken(UserTokenArgs),
}

/// Arguments for `coordinator init`.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Override the config directory (default: XDG config dir).
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
    /// Override the data directory for keys/seed/db (default: XDG data dir).
    #[arg(long)]
    pub data_dir: Option<std::path::PathBuf>,
    /// The externally reachable base URL clients and nodes will dial
    /// (`https://fleet.example`).
    ///
    /// Behind a reverse proxy this is *not* derivable from `listen_addr`: the
    /// coordinator listens on loopback and the world reaches it at a name it
    /// never sees. Defaults to `http://127.0.0.1:7000` for a local trial.
    #[arg(long)]
    pub public_url: Option<String>,
    /// Overwrite existing files instead of refusing.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `coordinator auth-key`.
///
/// **Interim.** Once the GitHub device flow lands (a later task), an operator
/// will normally get a node enrolled through `fleet login` + `agent init`
/// instead; this verb remains as the unattended / air-gapped escape hatch.
///
/// The key is a pure bearer credential: anyone holding it can enroll a node into
/// the named org until it expires or is used. It is printed once.
#[derive(Debug, Args)]
pub struct AuthKeyArgs {
    /// Org the enrolled nodes join. Defaults to the coordinator's
    /// `default_org`.
    #[arg(long)]
    pub org: Option<String>,
    /// Selection tag to stamp onto enrolled nodes (repeatable).
    #[arg(long)]
    pub tag: Vec<String>,
    /// Time-to-live in seconds (default 24h). 0 means no expiry.
    #[arg(long, default_value_t = 86_400)]
    pub ttl: u64,
    /// Allow the key to enroll more than one node.
    ///
    /// Convenient for provisioning a rack; correspondingly worse if it leaks.
    #[arg(long)]
    pub multi_use: bool,
    /// Override the config directory (default: XDG config dir). Used to locate
    /// `coordinator.toml`.
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
}

/// Arguments for `coordinator user-token`.
///
/// **Interim.** This mints a session token from a shell on the coordinator host,
/// bypassing any login flow. It exists so the fleet is usable before the GitHub
/// device flow lands, and it should not become the way people log in.
#[derive(Debug, Args)]
pub struct UserTokenArgs {
    /// The user's login (the subject id the token authenticates as).
    pub login: String,
    /// Org to place the user in. Defaults to the coordinator's `default_org`.
    #[arg(long)]
    pub org: Option<String>,
    /// Role to grant in that org.
    ///
    /// `admin` by default: this verb is the self-hosted operator's bootstrap,
    /// run by someone with a shell on the coordinator host who therefore
    /// already has total authority. Use `--role member` for teammates.
    #[arg(long, value_enum, default_value_t = RoleArg::Admin)]
    pub role: RoleArg,
    /// Time-to-live in seconds. Defaults to the coordinator's
    /// `session_ttl_secs`.
    #[arg(long)]
    pub ttl: Option<u64>,
    /// Override the config directory (default: XDG config dir). Used to locate
    /// `coordinator.toml`.
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
}

/// An org role, for the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RoleArg {
    /// May add a node and use the org's boards.
    Member,
    /// Additionally acts on other members' leases and reads the audit log.
    Admin,
}

impl From<RoleArg> for fleet_proto::ids::Role {
    fn from(r: RoleArg) -> Self {
        match r {
            RoleArg::Member => fleet_proto::ids::Role::Member,
            RoleArg::Admin => fleet_proto::ids::Role::Admin,
        }
    }
}

/// Arguments for the `agent` role.
#[derive(Debug, Args)]
pub struct AgentArgs {
    /// Path to the agent config (TOML).
    ///
    /// When unset, defaults to the per-profile XDG path
    /// `$XDG_CONFIG_HOME/probe-rs-fleet/agent/<profile>/agent.toml`.
    #[arg(long, env = "PROBE_RS_FLEET_AGENT_CONFIG")]
    pub config: Option<std::path::PathBuf>,
    /// Profile to select (per-profile config/data subdir). An explicit
    /// `--config` takes precedence over the profile.
    #[arg(long, env = "PROBE_RS_FLEET_PROFILE", default_value = crate::paths::DEFAULT_PROFILE, global = true)]
    pub profile: String,
    /// Optional nested subcommand (e.g. `init`). When absent, the agent runs.
    #[command(subcommand)]
    pub command: Option<AgentCommand>,
}

/// `agent` subcommands.
#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Redeem an auth key for a node token and scaffold a ready-to-run agent
    /// config (`agent.toml` + `boards.toml`) under the per-profile XDG paths.
    Init(AgentInitArgs),
    /// List the agent profiles that have a config under the XDG config dir.
    Profiles,
}

/// Arguments for `agent init`.
#[derive(Debug, Args)]
pub struct AgentInitArgs {
    /// Base URL of the coordinator (`https://fleet.example`). A bare
    /// `host:port` is accepted and assumes https.
    #[arg(long)]
    pub fleet_url: String,
    /// The auth key printed by `coordinator auth-key`.
    #[arg(long)]
    pub auth_key: String,
    /// This node's name within its org. Defaults to the machine's hostname.
    ///
    /// Advisory: it names the row, it does not grant anything. The coordinator
    /// derives the node id from it and authenticates by token thereafter.
    #[arg(long)]
    pub node_name: Option<String>,
    /// Selection tag to report for this node (repeatable).
    #[arg(long)]
    pub tag: Vec<String>,
    /// Pin the coordinator's server certificate by its SHA-256 (64 hex chars).
    ///
    /// For a self-hosted coordinator with no publicly trusted certificate.
    /// Without it the coordinator is verified against the public web PKI roots.
    #[arg(long)]
    pub server_cert_sha256: Option<String>,
    /// Override the config directory (default: XDG config dir).
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
    /// Override where `boards.toml` is written (default: profile config dir).
    #[arg(long)]
    pub boards_path: Option<std::path::PathBuf>,
    /// Overwrite existing files instead of refusing.
    #[arg(long)]
    pub force: bool,
}


/// Arguments for the explicit `sidecar` subcommand.
#[derive(Debug, Args)]
pub struct SidecarArgs {
    /// Profile to select (per-profile client config/data subdir).
    #[arg(long, env = "PROBE_RS_FLEET_PROFILE", default_value = crate::paths::DEFAULT_PROFILE)]
    pub profile: String,
    /// The probe-rs subcommand and its arguments, forwarded verbatim.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub probe_rs_args: Vec<OsString>,
}

/// Shared connection flags for the `ctl` client.
#[derive(Debug, Args)]
pub struct CtlClientArgs {
    /// Base URL of the coordinator (`https://fleet.example`), or `host:port`.
    #[arg(long, env = "PROBE_RS_FLEET_COORDINATOR", global = true)]
    pub coordinator: Option<String>,
    /// The bearer session token.
    #[arg(long, env = "PROBE_RS_FLEET_TOKEN", global = true)]
    pub token: Option<String>,
    /// Pinned coordinator server-certificate SHA-256 (64 hex chars), for a
    /// self-hosted deployment with no publicly trusted certificate.
    #[arg(
        long,
        env = "PROBE_RS_FLEET_SERVER_CERT_SHA256",
        global = true
    )]
    pub server_cert_sha256: Option<String>,
    /// Profile to select (per-profile client config/data subdir). An explicit
    /// `--config`/credential flag takes precedence over the profile.
    #[arg(long, env = "PROBE_RS_FLEET_PROFILE", default_value = crate::paths::DEFAULT_PROFILE, global = true)]
    pub profile: String,
}

/// Arguments for the `ctl` role.
#[derive(Debug, Args)]
pub struct CtlArgs {
    #[command(flatten)]
    pub client: CtlClientArgs,
    #[command(subcommand)]
    pub command: CtlCommand,
}

/// `ctl` subcommands.
#[derive(Debug, Subcommand)]
pub enum CtlCommand {
    /// Write `client.toml` so both `ctl` and the `probe-rs` sidecar shim
    /// discover the coordinator and the session token.
    Init(CtlInitArgs),
    /// List the client profiles that have a config under the XDG config dir.
    Profiles,
    /// List the fleet inventory (boards and their state).
    List,
    /// Lease a board by id or selector (`tag=…`, `chip=…`).
    Lease {
        /// Board id or selector: bare id, `tag=<t>` (repeatable), or `chip=<c>`.
        selector: String,
        /// Requested hold duration in seconds (0 = policy default).
        #[arg(long, default_value_t = 0)]
        duration: u64,
    },
    /// Release a held board.
    Release {
        /// Board id to release.
        board: String,
    },
    /// Power-cycle a board.
    PowerCycle {
        /// Board id to power-cycle.
        board: String,
    },
    /// Show who holds which boards.
    Who,
    /// Tail / fetch coordinator-side logs.
    Logs {
        /// Optional board id to scope the logs to.
        board: Option<String>,
        /// Follow the log stream.
        #[arg(long)]
        follow: bool,
    },
}

/// Arguments for `ctl init`.
///
/// Writes `client.toml` (0600) from an already-minted session token; the shared
/// `--coordinator` / `--token` flags are ignored by `init` in favour of the
/// explicit ones below.
#[derive(Debug, Args)]
pub struct CtlInitArgs {
    /// Base URL of the coordinator (`https://fleet.example`), or `host:port`.
    #[arg(long)]
    pub fleet_url: String,
    /// The session token printed by `coordinator user-token`.
    #[arg(long)]
    pub token: String,
    /// Pin the coordinator's server certificate by its SHA-256 (64 hex chars).
    #[arg(long)]
    pub server_cert_sha256: Option<String>,
    /// Override the config directory (default: XDG config dir).
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
    /// Overwrite existing files instead of refusing.
    #[arg(long)]
    pub force: bool,
}

/// What argv0 inspection decided the process should do.
#[derive(Debug, PartialEq, Eq)]
pub enum Dispatch {
    /// Behave as the sidecar shim, forwarding these probe-rs arguments.
    Sidecar(Vec<OsString>),
    /// Parse the remaining arguments with clap.
    Clap,
}

/// Normalise an argv0 to its basename, stripping a trailing `.exe`.
fn argv0_basename(argv0: &OsStr) -> Option<String> {
    let name = Path::new(argv0).file_name()?.to_str()?;
    let name = name.strip_suffix(".exe").unwrap_or(name);
    Some(name.to_owned())
}

/// Decide, purely from argv0, whether to enter sidecar shim mode.
///
/// `rest` is `args[1..]` — everything after the program name. When the program
/// was invoked as `probe-rs`, all of `rest` is forwarded to the sidecar.
#[must_use]
pub fn dispatch_from_argv0(argv0: &OsStr, rest: &[OsString]) -> Dispatch {
    match argv0_basename(argv0).as_deref() {
        Some("probe-rs") => Dispatch::Sidecar(rest.to_vec()),
        _ => Dispatch::Clap,
    }
}

/// Process entry point. Resolves the dispatch mode, sets up the runtime, and
/// runs the selected role, mapping the result to an [`ExitCode`].
#[must_use]
pub fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let argv0 = argv.first().cloned().unwrap_or_default();
    let rest = &argv[1.min(argv.len())..];

    crate::logging::init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(error) => {
            eprintln!("error: failed to start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    let dispatch = dispatch_from_argv0(&argv0, rest);
    let result = runtime.block_on(run(dispatch, argv.clone()));

    match result {
        Ok(code) => code,
        Err(error) => {
            // Print the full error chain to stderr.
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Run the selected role and produce a process exit code.
///
/// `process_args` is the full process argv used when falling through to clap
/// parsing.
///
/// # Errors
///
/// Propagates any error from a role handler.
async fn run(dispatch: Dispatch, process_args: Vec<OsString>) -> anyhow::Result<ExitCode> {
    match dispatch {
        Dispatch::Sidecar(probe_rs_args) => {
            // argv0 (`probe-rs` symlink) path: no clap, so read the profile
            // directly from the env (default profile otherwise).
            let profile = std::env::var("PROBE_RS_FLEET_PROFILE")
                .ok()
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| crate::paths::DEFAULT_PROFILE.to_owned());
            roles::sidecar::run(probe_rs_args, &profile).await
        }
        Dispatch::Clap => {
            let cli = Cli::parse_from(process_args);
            match cli.command {
                Command::Coordinator(args) => match args.command {
                    Some(CoordinatorCommand::Init(init)) => {
                        roles::init::run(init)?;
                        Ok(ExitCode::SUCCESS)
                    }
                    Some(CoordinatorCommand::AuthKey(args)) => {
                        roles::admin::auth_key(args).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                    Some(CoordinatorCommand::UserToken(args)) => {
                        roles::admin::user_token(args).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                    None => {
                        roles::coordinator::run(args).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                },
                Command::Agent(args) => match args.command {
                    Some(AgentCommand::Init(init)) => {
                        roles::agent_init::run(init, args.profile).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                    Some(AgentCommand::Profiles) => {
                        roles::list_profiles(crate::paths::Role::Agent)?;
                        Ok(ExitCode::SUCCESS)
                    }
                    None => {
                        roles::agent::run(args).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                },
                Command::Sidecar(args) => roles::sidecar::run(args.probe_rs_args, &args.profile).await,
                Command::Ctl(args) => match args.command {
                    CtlCommand::Init(init) => {
                        roles::ctl_init::run(init, args.client.profile).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                    CtlCommand::Profiles => {
                        roles::list_profiles(crate::paths::Role::Client)?;
                        Ok(ExitCode::SUCCESS)
                    }
                    _ => {
                        roles::ctl::run(args).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn argv0_probe_rs_routes_to_sidecar() {
        let rest = os(&["run", "--chip", "nRF52840_xxAA", "app.elf"]);
        assert_eq!(
            dispatch_from_argv0(OsStr::new("probe-rs"), &rest),
            Dispatch::Sidecar(rest.clone())
        );
    }

    #[test]
    fn argv0_probe_rs_with_path_and_exe_routes_to_sidecar() {
        let rest = os(&["info"]);
        assert_eq!(
            dispatch_from_argv0(OsStr::new("/usr/local/bin/probe-rs"), &rest),
            Dispatch::Sidecar(rest.clone())
        );
        assert_eq!(
            dispatch_from_argv0(OsStr::new("/opt/tools/probe-rs.exe"), &rest),
            Dispatch::Sidecar(rest)
        );
    }

    #[test]
    fn argv0_probe_rs_fleet_uses_clap() {
        let rest = os(&["coordinator", "--config", "x.toml"]);
        assert_eq!(
            dispatch_from_argv0(OsStr::new("probe-rs-fleet"), &rest),
            Dispatch::Clap
        );
        assert_eq!(
            dispatch_from_argv0(OsStr::new("/opt/bin/probe-rs-fleet"), &rest),
            Dispatch::Clap
        );
    }

    #[test]
    fn argv0_other_names_use_clap() {
        let rest = os(&["ctl", "list"]);
        assert_eq!(dispatch_from_argv0(OsStr::new("fleet"), &rest), Dispatch::Clap);
        assert_eq!(dispatch_from_argv0(OsStr::new("probe-rsx"), &rest), Dispatch::Clap);
        assert_eq!(dispatch_from_argv0(OsStr::new(""), &rest), Dispatch::Clap);
    }

    #[test]
    fn parses_coordinator() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "coordinator", "--config", "c.toml"]));
        match cli.command {
            Command::Coordinator(a) => {
                assert_eq!(a.config.as_deref(), Some(Path::new("c.toml")));
                assert!(a.command.is_none());
            }
            other => panic!("expected coordinator, got {other:?}"),
        }
    }

    #[test]
    fn parses_coordinator_without_config() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "coordinator"]));
        match cli.command {
            Command::Coordinator(a) => {
                assert!(a.config.is_none());
                assert!(a.command.is_none());
            }
            other => panic!("expected coordinator, got {other:?}"),
        }
    }

    #[test]
    fn parses_coordinator_init() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "coordinator",
            "init",
            "--public-url",
            "https://fleet.example",
            "--force",
        ]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::Init(init)) => {
                    assert_eq!(init.public_url.as_deref(), Some("https://fleet.example"));
                    assert!(init.force);
                }
                other => panic!("expected init, got {other:?}"),
            },
            other => panic!("expected coordinator, got {other:?}"),
        }
    }

    #[test]
    fn parses_agent() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "agent", "--config", "a.toml"]));
        match cli.command {
            Command::Agent(a) => {
                assert_eq!(a.config.as_deref(), Some(Path::new("a.toml")));
                assert!(a.command.is_none());
            }
            other => panic!("expected agent, got {other:?}"),
        }
    }

    #[test]
    fn parses_coordinator_auth_key() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "coordinator",
            "auth-key",
            "--org",
            "acme",
            "--tag",
            "nrf52",
            "--ttl",
            "600",
            "--multi-use",
        ]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::AuthKey(k)) => {
                    assert_eq!(k.org.as_deref(), Some("acme"));
                    assert_eq!(k.tag, vec!["nrf52".to_owned()]);
                    assert_eq!(k.ttl, 600);
                    assert!(k.multi_use);
                }
                other => panic!("expected auth-key, got {other:?}"),
            },
            other => panic!("expected coordinator, got {other:?}"),
        }
    }

    /// Single-use and a bounded TTL are the defaults: a key that enrolls a rack
    /// forever should have to be asked for.
    #[test]
    fn auth_key_defaults_are_single_use_and_expiring() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "coordinator", "auth-key"]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::AuthKey(k)) => {
                    assert!(!k.multi_use);
                    assert_eq!(k.ttl, 86_400);
                    assert!(k.org.is_none());
                }
                other => panic!("expected auth-key, got {other:?}"),
            },
            other => panic!("expected coordinator, got {other:?}"),
        }
    }

    /// The interim bootstrap verb defaults to `admin`: the first token minted
    /// on a self-hosted coordinator must be able to administer the fleet.
    #[test]
    fn parses_coordinator_user_token() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "coordinator", "user-token", "alice"]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::UserToken(t)) => {
                    assert_eq!(t.login, "alice");
                    assert_eq!(t.role, RoleArg::Admin);
                    assert!(t.ttl.is_none());
                }
                other => panic!("expected user-token, got {other:?}"),
            },
            other => panic!("expected coordinator, got {other:?}"),
        }

        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "coordinator",
            "user-token",
            "bob",
            "--role",
            "member",
            "--org",
            "acme",
        ]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::UserToken(t)) => {
                    assert_eq!(t.role, RoleArg::Member);
                    assert_eq!(t.org.as_deref(), Some("acme"));
                }
                other => panic!("expected user-token, got {other:?}"),
            },
            other => panic!("expected coordinator, got {other:?}"),
        }
    }

    #[test]
    fn parses_agent_init() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "agent",
            "--profile",
            "lab1",
            "init",
            "--fleet-url",
            "https://fleet.example",
            "--auth-key",
            "prffk1_abc",
        ]));
        match cli.command {
            Command::Agent(a) => {
                assert_eq!(a.profile, "lab1");
                match a.command {
                    Some(AgentCommand::Init(init)) => {
                        assert_eq!(init.fleet_url, "https://fleet.example");
                        assert_eq!(init.auth_key, "prffk1_abc");
                        assert!(init.node_name.is_none());
                    }
                    other => panic!("expected agent init, got {other:?}"),
                }
            }
            other => panic!("expected agent, got {other:?}"),
        }
    }

    #[test]
    fn parses_agent_profiles() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "agent", "profiles"]));
        assert!(matches!(
            cli.command,
            Command::Agent(a) if matches!(a.command, Some(AgentCommand::Profiles))
        ));
    }

    #[test]
    fn parses_ctl_init() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "ctl",
            "--profile",
            "ci",
            "init",
            "--fleet-url",
            "https://fleet.example",
            "--token",
            "prfs1_xyz",
        ]));
        match cli.command {
            Command::Ctl(a) => {
                assert_eq!(a.client.profile, "ci");
                match a.command {
                    CtlCommand::Init(init) => {
                        assert_eq!(init.fleet_url, "https://fleet.example");
                        assert_eq!(init.token, "prfs1_xyz");
                    }
                    other => panic!("expected ctl init, got {other:?}"),
                }
            }
            other => panic!("expected ctl, got {other:?}"),
        }
    }

    #[test]
    fn parses_ctl_profiles() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "ctl", "profiles"]));
        assert!(matches!(
            cli.command,
            Command::Ctl(a) if matches!(a.command, CtlCommand::Profiles)
        ));
    }

    #[test]
    fn sidecar_subcommand_preserves_trailing_args_verbatim() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "sidecar",
            "--",
            "run",
            "--chip",
            "nRF52840_xxAA",
            "app.elf",
        ]));
        match cli.command {
            Command::Sidecar(a) => {
                assert_eq!(a.probe_rs_args, os(&["run", "--chip", "nRF52840_xxAA", "app.elf"]));
            }
            other => panic!("expected sidecar, got {other:?}"),
        }
    }

    #[test]
    fn parses_ctl_subcommands() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "ctl", "list"]));
        assert!(matches!(cli.command, Command::Ctl(a) if matches!(a.command, CtlCommand::List)));

        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet", "ctl", "lease", "nrf52840-dk-3", "--duration", "600",
        ]));
        match cli.command {
            Command::Ctl(a) => match a.command {
                CtlCommand::Lease { selector, duration } => {
                    assert_eq!(selector, "nrf52840-dk-3");
                    assert_eq!(duration, 600);
                }
                other => panic!("expected lease, got {other:?}"),
            },
            other => panic!("expected ctl, got {other:?}"),
        }

        let cli = Cli::parse_from(os(&["probe-rs-fleet", "ctl", "power-cycle", "b1"]));
        match cli.command {
            Command::Ctl(a) => match a.command {
                CtlCommand::PowerCycle { board } => assert_eq!(board, "b1"),
                other => panic!("expected power-cycle, got {other:?}"),
            },
            other => panic!("expected ctl, got {other:?}"),
        }
    }

    #[test]
    fn ctl_client_flags_parse() {
        let pin = "ab".repeat(32);
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet", "ctl",
            "--coordinator", "https://coord.example",
            "--token", "prfs1_abc",
            "--server-cert-sha256", &pin,
            "who",
        ]));
        match cli.command {
            Command::Ctl(a) => {
                assert_eq!(a.client.coordinator.as_deref(), Some("https://coord.example"));
                assert_eq!(a.client.token.as_deref(), Some("prfs1_abc"));
                assert_eq!(a.client.server_cert_sha256.as_deref(), Some(pin.as_str()));
                assert!(matches!(a.command, CtlCommand::Who));
            }
            other => panic!("expected ctl, got {other:?}"),
        }
    }
}
