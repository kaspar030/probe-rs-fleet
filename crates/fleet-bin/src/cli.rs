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
    /// Admin / UX CLI: talk to the coordinator over mTLS.
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
    /// Scaffold a ready-to-run coordinator: generate signing seed, TLS
    /// material, and a populated config under the XDG paths.
    Init(InitArgs),
    /// Issue a one-time bootstrap enrollment token for a principal. The token
    /// is redeemed by `agent init` / `ctl init` for a CA-signed client cert;
    /// runtime auth stays mTLS.
    Enroll(EnrollArgs),
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
    /// DNS hostname(s) to place in the server cert SANs (repeatable).
    ///
    /// Defaults to `localhost` when none are given.
    #[arg(long)]
    pub hostname: Vec<String>,
    /// IP address(es) to place in the server cert SANs (repeatable).
    ///
    /// Defaults to `127.0.0.1` when none are given.
    #[arg(long)]
    pub ip: Vec<std::net::IpAddr>,
    /// Overwrite existing files instead of refusing.
    #[arg(long)]
    pub force: bool,
}

/// The kind of principal an enrollment token is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EnrollKind {
    /// An agent principal. Recorded in the token store; the issued cert is
    /// auto-pinned to this agent id on enrollment.
    Agent,
    /// A non-agent client principal (ctl / sidecar user). No pinning needed.
    Client,
}

/// Arguments for `coordinator enroll`.
///
/// Generates a one-time bootstrap token (printed as one opaque string) that an
/// `agent init` / `ctl init` redeems for a CA-signed client cert. Runtime auth
/// stays mTLS; the token is bootstrap-only.
#[derive(Debug, Args)]
pub struct EnrollArgs {
    /// Principal id to issue a cert for (becomes the cert CN and, for agents,
    /// the agent id).
    pub principal_id: String,
    /// Whether this enrollment is for an agent or a generic client.
    #[arg(long, value_enum, default_value_t = EnrollKind::Client)]
    pub kind: EnrollKind,
    /// Time-to-live of the bootstrap token, in seconds (default 3600).
    #[arg(long, default_value_t = 3600)]
    pub ttl: u64,
    /// Advertised coordinator address (`host:port`) to embed into the token.
    ///
    /// Overrides `advertise_addr` from `coordinator.toml` and the
    /// `listen_addr` fallback. REQUIRED when the coordinator's `listen_addr`
    /// is a wildcard (`0.0.0.0` / `::`), since clients cannot dial a wildcard
    /// address. Example: `--coordinator-addr 192.168.1.163:7000`.
    #[arg(long)]
    pub coordinator_addr: Option<String>,
    /// Override the config directory (default: XDG config dir). Used to locate
    /// `coordinator.toml`.
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
    /// Override the data directory (default: XDG data dir). Used to locate the
    /// server cert and the `SQLite` database.
    #[arg(long)]
    pub data_dir: Option<std::path::PathBuf>,
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
    /// Redeem an enrollment token for a CA-signed client cert and scaffold a
    /// ready-to-run agent config (`agent.toml` + `boards.toml`) under the
    /// per-profile XDG paths.
    Init(AgentInitArgs),
    /// List the agent profiles that have a config under the XDG config dir.
    Profiles,
}

/// Arguments for `agent init`.
#[derive(Debug, Args)]
pub struct AgentInitArgs {
    /// The enrollment token printed by `coordinator enroll … --kind agent`.
    ///
    /// Carries the coordinator address, server-cert pin, and one-time secret.
    #[arg(long)]
    pub token: String,
    /// Override the config directory (default: XDG config dir).
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
    /// Override the data directory for issued creds (default: XDG data dir).
    #[arg(long)]
    pub data_dir: Option<std::path::PathBuf>,
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
    /// `host:port` of the coordinator to connect to.
    #[arg(long, env = "PROBE_RS_FLEET_COORDINATOR", global = true)]
    pub coordinator: Option<String>,
    /// Client certificate chain (PEM).
    #[arg(long, env = "PROBE_RS_FLEET_CERT", global = true)]
    pub cert: Option<std::path::PathBuf>,
    /// Client private key (PEM).
    #[arg(long, env = "PROBE_RS_FLEET_KEY", global = true)]
    pub key: Option<std::path::PathBuf>,
    /// CA used to verify the coordinator's server cert (PEM).
    #[arg(long, env = "PROBE_RS_FLEET_CA", global = true)]
    pub ca: Option<std::path::PathBuf>,
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
    /// Redeem an enrollment token for a CA-signed client cert and write
    /// `client.toml` so both `ctl` and the `probe-rs` sidecar shim discover the
    /// coordinator + credentials.
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
/// The coordinator endpoint, server-cert pin, and one-time secret all come from
/// the enrollment token; the shared `--coordinator`/`--cert`/`--key`/`--ca`
/// flags are ignored by `init`.
#[derive(Debug, Args)]
pub struct CtlInitArgs {
    /// The enrollment token printed by `coordinator enroll … --kind client`.
    #[arg(long)]
    pub token: String,
    /// Override the config directory (default: XDG config dir).
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
    /// Override the data directory for issued creds (default: XDG data dir).
    #[arg(long)]
    pub data_dir: Option<std::path::PathBuf>,
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
            roles::sidecar::run(probe_rs_args, &profile)
        }
        Dispatch::Clap => {
            let cli = Cli::parse_from(process_args);
            match cli.command {
                Command::Coordinator(args) => match args.command {
                    Some(CoordinatorCommand::Init(init)) => {
                        roles::init::run(init)?;
                        Ok(ExitCode::SUCCESS)
                    }
                    Some(CoordinatorCommand::Enroll(enroll)) => {
                        roles::enroll::run(enroll).await?;
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
                Command::Sidecar(args) => roles::sidecar::run(args.probe_rs_args, &args.profile),
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
            "--hostname",
            "coord.example",
            "--ip",
            "10.0.0.1",
            "--force",
        ]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::Init(init)) => {
                    assert_eq!(init.hostname, vec!["coord.example".to_owned()]);
                    assert_eq!(init.ip, vec!["10.0.0.1".parse::<std::net::IpAddr>().unwrap()]);
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
    fn parses_coordinator_enroll() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "coordinator",
            "enroll",
            "rpi-lab-1",
            "--kind",
            "agent",
            "--ttl",
            "600",
        ]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::Enroll(e)) => {
                    assert_eq!(e.principal_id, "rpi-lab-1");
                    assert_eq!(e.kind, EnrollKind::Agent);
                    assert_eq!(e.ttl, 600);
                }
                other => panic!("expected enroll, got {other:?}"),
            },
            other => panic!("expected coordinator, got {other:?}"),
        }
    }

    #[test]
    fn enroll_defaults_to_client_kind() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "coordinator", "enroll", "alice"]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::Enroll(e)) => {
                    assert_eq!(e.kind, EnrollKind::Client);
                    assert_eq!(e.ttl, 3600);
                }
                other => panic!("expected enroll, got {other:?}"),
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
            "--token",
            "prffe1_abc",
        ]));
        match cli.command {
            Command::Agent(a) => {
                assert_eq!(a.profile, "lab1");
                match a.command {
                    Some(AgentCommand::Init(init)) => {
                        assert_eq!(init.token, "prffe1_abc");
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
            "--token",
            "prffe1_xyz",
        ]));
        match cli.command {
            Command::Ctl(a) => {
                assert_eq!(a.client.profile, "ci");
                match a.command {
                    CtlCommand::Init(init) => {
                        assert_eq!(init.token, "prffe1_xyz");
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
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet", "ctl",
            "--coordinator", "coord.example:443",
            "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
            "who",
        ]));
        match cli.command {
            Command::Ctl(a) => {
                assert_eq!(a.client.coordinator.as_deref(), Some("coord.example:443"));
                assert_eq!(a.client.cert.as_deref(), Some(Path::new("c.pem")));
                assert!(matches!(a.command, CtlCommand::Who));
            }
            other => panic!("expected ctl, got {other:?}"),
        }
    }
}
