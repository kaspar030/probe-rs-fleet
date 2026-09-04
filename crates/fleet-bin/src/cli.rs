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
    /// Log in to a fleet with GitHub, caching a session token for `ctl` and the
    /// `probe-rs` sidecar shim.
    Login(LoginArgs),
    /// Offer this machine's probes to the fleet, using the login you already
    /// have. No token, no coordinator shell.
    Share(ShareArgs),
    /// Mint, list and revoke this org's node-enrollment auth keys, using the
    /// login you already have.
    AuthKey(AuthKeyCliArgs),
    /// Node-side operator verbs. Today: approve a machine that is asking to
    /// join your org.
    Node(NodeArgs),
    /// List the fleets this machine has a config for.
    Fleets,
}

/// Arguments for `probe-rs-fleet login`.
///
/// GitHub **device flow**: the CLI asks the coordinator to start one, prints the
/// short code and the URL, opens a browser where it can, and polls until the
/// human has authorised it. The CLI never talks to GitHub directly — the OAuth
/// app's credentials stay on the coordinator, which is also what lets a
/// self-hosted deployment use its own app without a rebuild.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Base URL of the coordinator (`https://fleet.example`), or `host:port`.
    ///
    /// Required the first time; afterwards the fleet file remembers it.
    #[arg(long)]
    pub fleet_url: Option<String>,
    /// Pin the coordinator's server certificate by its SHA-256 (64 hex chars),
    /// for a self-hosted deployment with no publicly trusted certificate.
    #[arg(long)]
    pub server_cert_sha256: Option<String>,
    /// Record an externally minted session token instead of running the device
    /// flow.
    ///
    /// The escape hatch for an air-gapped fleet or one whose coordinator has no
    /// GitHub app: pair it with `coordinator user-token`. Also what the
    /// integration tests use, so they need no GitHub at all.
    #[arg(long)]
    pub token: Option<String>,
    /// Do not try to open a browser; just print the URL and code.
    #[arg(long)]
    pub no_browser: bool,
    /// The fleet to log in to.
    #[arg(long, env = "PROBE_RS_FLEET", default_value = crate::paths::DEFAULT_FLEET)]
    pub fleet: String,
    /// Override the fleets directory (default: XDG config dir). Test and
    /// packaging support.
    #[arg(long, hide = true)]
    pub config_dir: Option<std::path::PathBuf>,
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
    /// List this org's auth keys (by hash prefix — the secrets are not stored).
    AuthKeys(AuthKeysArgs),
    /// Revoke an auth key by hash prefix.
    AuthKeyRevoke(AuthKeyRevokeArgs),
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
/// The **self-hosted / air-gapped escape hatch**, not the front door: a laptop
/// with a login runs `probe-rs-fleet share`, a headless node runs `agent up`
/// with a key its owner minted using `probe-rs-fleet auth-key create`, and
/// neither needs a shell on the coordinator host. What is still only available
/// here: minting with no login at all, and `--ttl 0` (a key that never
/// expires), which the API path refuses.
///
/// Auth keys are the weak link in the model — long-lived credentials that end
/// up in strangers' CI config and disk images — so they are org-scoped, TTL'd,
/// revocable (`auth-key-revoke`) and listable (`auth-keys`). Do not make them
/// the default anyone reaches for.
///
/// The key is a pure bearer credential: anyone holding it can enroll a node
/// into the named org until it expires or is used. It is printed once.
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

/// Arguments for `coordinator auth-keys` (list).
///
/// The secret was never stored — only its SHA-256 — so a listing is safe to
/// print and pipe. It is also the only way to find out what keys exist: an
/// operator who has lost track of which images carry which key can see what is
/// outstanding, and revoke.
#[derive(Debug, Args)]
pub struct AuthKeysArgs {
    /// Org whose keys to list. Defaults to the coordinator's `default_org`.
    #[arg(long)]
    pub org: Option<String>,
    /// Override the config directory (default: XDG config dir). Used to locate
    /// `coordinator.toml`.
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
}

/// Arguments for `coordinator auth-key-revoke`.
#[derive(Debug, Args)]
pub struct AuthKeyRevokeArgs {
    /// Hash prefix of the key to revoke, from `coordinator auth-keys`.
    ///
    /// An **ambiguous** prefix is refused rather than resolved: revoking the
    /// wrong key of a rack's worth silently de-provisions machines nobody is
    /// looking at.
    pub prefix: String,
    /// Org the key belongs to. Defaults to the coordinator's `default_org`.
    #[arg(long)]
    pub org: Option<String>,
    /// Override the config directory (default: XDG config dir). Used to locate
    /// `coordinator.toml`.
    #[arg(long)]
    pub config_dir: Option<std::path::PathBuf>,
}

/// Arguments for `probe-rs-fleet share`.
///
/// "This machine now offers its probes to the fleet", using the login you
/// already have (architecture §6.4). No token, no coordinator shell, no
/// out-of-band step: the `[user]` session in the fleet file proves membership,
/// and membership is sufficient — there is no admin approval step.
#[derive(Debug, Args)]
pub struct ShareArgs {
    /// The fleet to share this machine with.
    #[arg(long, env = "PROBE_RS_FLEET", default_value = crate::paths::DEFAULT_FLEET)]
    pub fleet: String,
    /// This node's name within its org. Defaults to the machine's hostname.
    ///
    /// Advisory: it names the row, it does not grant anything.
    #[arg(long)]
    pub node_name: Option<String>,
    /// Selection tag to report for this node (repeatable).
    #[arg(long)]
    pub tag: Vec<String>,
    /// Probe adoption policy for this node. Defaults to `auto` for `share`.
    #[arg(long, value_enum)]
    pub adopt: Option<AdoptArg>,
    /// Overwrite an existing `[node]` credential instead of refusing.
    #[arg(long)]
    pub force: bool,
    /// Override the config directory (default: XDG config dir). Test and
    /// packaging support.
    #[arg(long, hide = true)]
    pub config_dir: Option<std::path::PathBuf>,
}

/// Arguments for `probe-rs-fleet auth-key`.
///
/// The **hosted** counterpart of `coordinator auth-key`: it mints over the
/// authenticated API with the `[user]` session in the fleet file, so a customer
/// who has only ever run `probe-rs-fleet login` can enroll a headless node
/// (architecture §6.4). `coordinator auth-key` remains the self-hosted
/// operator's shell-on-the-host escape hatch.
///
/// The key inherits the caller's org from their session and can never exceed
/// it: there is no `--org` flag here, and there deliberately is not one.
#[derive(Debug, Args)]
pub struct AuthKeyCliArgs {
    /// The auth-key verb.
    #[command(subcommand)]
    pub command: AuthKeyCommand,
}

/// `auth-key` subcommands.
#[derive(Debug, Subcommand)]
pub enum AuthKeyCommand {
    /// Mint an auth key for this org (printed once).
    Create(AuthKeyCreateArgs),
    /// List this org's auth keys, by hash prefix.
    List(AuthKeyListArgs),
    /// Revoke an auth key by hash prefix.
    Revoke(AuthKeyRevokeCliArgs),
}

/// Arguments for `probe-rs-fleet auth-key create`.
///
/// Two deliberate deviations from the issue's sketch, both for consistency with
/// the existing `coordinator auth-key`:
///
/// * single use is the **default**; `--multi-use` opts out (`--single-use` is
///   accepted as an explicit no-op so the sketch's spelling is not an error);
/// * `--tag` is repeatable and **not** comma-split, so `--tags lab,nrf52` is
///   one tag named `lab,nrf52`. Write `--tag lab --tag nrf52`. Neither existing
///   `--tag` splits, and two verbs that mint the same object must not disagree
///   about what a tag is.
#[derive(Debug, Args)]
pub struct AuthKeyCreateArgs {
    /// Selection tag to stamp onto nodes enrolled with this key (repeatable;
    /// not comma-split — pass `--tag` twice).
    #[arg(long, visible_alias = "tags")]
    pub tag: Vec<String>,
    /// Time-to-live: bare seconds, or a suffixed duration (`30m`, `24h`, `7d`).
    ///
    /// Unlike `coordinator auth-key`, a never-expiring key is not offered here:
    /// the coordinator refuses one on this path and caps the TTL at 30 days.
    #[arg(long, default_value = "24h")]
    pub ttl: String,
    /// Allow the key to enroll more than one node.
    ///
    /// Convenient for provisioning a rack; correspondingly worse if it leaks.
    #[arg(long)]
    pub multi_use: bool,
    /// Explicitly single-use. The default; accepted so the spelling is not an
    /// error.
    #[arg(long, conflicts_with = "multi_use")]
    pub single_use: bool,
    /// The fleet whose `[user]` session authorises the mint.
    #[arg(long, env = "PROBE_RS_FLEET", default_value = crate::paths::DEFAULT_FLEET)]
    pub fleet: String,
    /// Override the config directory (default: XDG config dir). Test and
    /// packaging support.
    #[arg(long, hide = true)]
    pub config_dir: Option<std::path::PathBuf>,
}

/// Arguments for `probe-rs-fleet auth-key list`.
#[derive(Debug, Args)]
pub struct AuthKeyListArgs {
    /// The fleet whose `[user]` session authorises the listing.
    #[arg(long, env = "PROBE_RS_FLEET", default_value = crate::paths::DEFAULT_FLEET)]
    pub fleet: String,
    /// Override the config directory (default: XDG config dir). Test and
    /// packaging support.
    #[arg(long, hide = true)]
    pub config_dir: Option<std::path::PathBuf>,
}

/// Arguments for `probe-rs-fleet auth-key revoke`.
///
/// Named `…CliArgs` because `AuthKeyRevokeArgs` belongs to
/// `coordinator auth-key-revoke` and must keep its name.
#[derive(Debug, Args)]
pub struct AuthKeyRevokeCliArgs {
    /// Hash prefix of the key to revoke, from `probe-rs-fleet auth-key list`
    /// (at least 8 hex characters).
    pub prefix: String,
    /// The fleet whose `[user]` session authorises the revocation.
    #[arg(long, env = "PROBE_RS_FLEET", default_value = crate::paths::DEFAULT_FLEET)]
    pub fleet: String,
    /// Override the config directory (default: XDG config dir). Test and
    /// packaging support.
    #[arg(long, hide = true)]
    pub config_dir: Option<std::path::PathBuf>,
}

/// Arguments for `probe-rs-fleet node`.
///
/// A namespace rather than a bare `node-approve`, because the node-side
/// operator verbs that will want to live beside it (list pending, revoke) are
/// obvious follow-ups.
#[derive(Debug, Args)]
pub struct NodeArgs {
    /// The node verb.
    #[command(subcommand)]
    pub command: NodeCommand,
}

/// `node` subcommands.
#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// Approve (or deny) a machine that printed a short code and is waiting.
    Approve(NodeApproveArgs),
}

/// Arguments for `probe-rs-fleet node approve`.
///
/// The approving half of architecture §4.2's rung 3: a headless machine ran
/// `agent up`, printed a URL and a code, and is polling. This verb runs on a
/// machine where you are **already logged in**, because the coordinator has no
/// browser-authenticated surface (§6.4: `login` is the GitHub *device* flow,
/// with no `redirect_uri` and no cookie session).
///
/// It always inspects before it acts: you are granting hardware access in your
/// org to a machine you cannot see, which is RFC 8628 §5.4's remote-phishing
/// case sharpened.
#[derive(Debug, Args)]
pub struct NodeApproveArgs {
    /// The short code the waiting machine printed (`ABCD-1234`).
    ///
    /// Case, hyphens and the Crockford confusables (`O`/`0`, `I`/`L`/`1`) are
    /// all folded, so type what you see.
    pub code: String,
    /// Deny the request instead of approving it. Permanent.
    #[arg(long)]
    pub deny: bool,
    /// Skip the confirmation prompt.
    ///
    /// For scripts that already know what they are approving. Required when
    /// stdin is not a terminal: a piped confirmation is not a confirmation.
    #[arg(long)]
    pub yes: bool,
    /// Approve even though your org already has a node with the requested
    /// name, re-credentialing it.
    ///
    /// The machine currently running as that node loses its token at its next
    /// connection, so this is refused by default — the requesting machine
    /// chose the name, and it may not be the one you think.
    #[arg(long)]
    pub replace: bool,
    /// The fleet whose `[user]` session authorises the approval.
    #[arg(long, env = "PROBE_RS_FLEET", default_value = crate::paths::DEFAULT_FLEET)]
    pub fleet: String,
    /// Override the config directory (default: XDG config dir). Test and
    /// packaging support.
    #[arg(long, hide = true)]
    pub config_dir: Option<std::path::PathBuf>,
}

/// A probe adoption policy, for the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AdoptArg {
    /// Adopt discovered probes automatically, tags inferred from the probe.
    Auto,
    /// Report undeclared probes but keep them unleasable until declared.
    Declared,
}

impl From<AdoptArg> for fleet_proto::AdoptPolicy {
    fn from(a: AdoptArg) -> Self {
        match a {
            AdoptArg::Auto => fleet_proto::AdoptPolicy::Auto,
            AdoptArg::Declared => fleet_proto::AdoptPolicy::Declared,
        }
    }
}

/// Arguments for the `agent` role.
#[derive(Debug, Args)]
pub struct AgentArgs {
    /// The fleet whose `[node]` credential this agent connects with.
    ///
    /// Resolves to `~/.config/probe-rs-fleet/fleets/<name>.toml`. There is no
    /// `--config` any more: `agent.toml` is gone, the credential lives in the
    /// fleet file and the node-local settings in `node/node.toml`.
    #[arg(long, env = "PROBE_RS_FLEET", default_value = crate::paths::DEFAULT_FLEET, global = true)]
    pub fleet: String,
    /// Override the config directory (default: XDG config dir). Test and
    /// packaging support.
    #[arg(long, hide = true, global = true)]
    pub config_dir: Option<std::path::PathBuf>,
    /// Optional nested subcommand (e.g. `up`). When absent, the agent runs.
    #[command(subcommand)]
    pub command: Option<AgentCommand>,
}

/// `agent` subcommands.
#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Register this machine as a node if it is not one yet, then run the
    /// agent.
    Up(AgentUpArgs),
}

/// Arguments for `agent up`.
///
/// `agent up` resolves a node credential by the §4.2 ladder and then **runs**
/// the agent. Plain `probe-rs-fleet agent` is the subset that requires an
/// existing `[node]` credential.
#[derive(Debug, Args)]
pub struct AgentUpArgs {
    /// Base URL of the coordinator (`https://fleet.example`). A bare
    /// `host:port` is accepted and assumes https.
    ///
    /// Required only when bootstrapping with `--auth-key`; otherwise the fleet
    /// file already knows where the coordinator is.
    #[arg(long)]
    pub fleet_url: Option<String>,
    /// An auth key from `probe-rs-fleet auth-key create` (or, self-hosted,
    /// `coordinator auth-key`) — the unattended/image path.
    #[arg(long)]
    pub auth_key: Option<String>,
    /// This node's name within its org. Defaults to the machine's hostname.
    ///
    /// Advisory: it names the row, it does not grant anything. The coordinator
    /// derives the node id from it and authenticates by token thereafter.
    #[arg(long)]
    pub node_name: Option<String>,
    /// Selection tag to report for this node (repeatable).
    #[arg(long)]
    pub tag: Vec<String>,
    /// Probe adoption policy for this node.
    ///
    /// Defaults to `declared` when bootstrapping with `--auth-key` (a lab node
    /// wants stable ids and no surprises) and `auto` when bootstrapping from an
    /// existing `[user]` session (the `share` path).
    #[arg(long, value_enum)]
    pub adopt: Option<AdoptArg>,
    /// Pin the coordinator's server certificate by its SHA-256 (64 hex chars).
    ///
    /// For a self-hosted coordinator with no publicly trusted certificate.
    /// Without it the coordinator is verified against the public web PKI roots.
    #[arg(long)]
    pub server_cert_sha256: Option<String>,
    /// Overwrite an existing `[node]` credential instead of reusing it.
    #[arg(long)]
    pub force: bool,
    /// Fall back to interactive approval even without a terminal: print a URL
    /// and a short code, and wait for somebody to run
    /// `probe-rs-fleet node approve`.
    ///
    /// The default is *auto* — on when stdout is a terminal, off otherwise —
    /// so a service unit with no tty fails fast with remediation instead of
    /// printing a code into the journal and blocking for 15 minutes on nobody.
    /// Pass this when you are tailing the log of a machine with no terminal of
    /// its own.
    #[arg(long, conflicts_with = "no_interactive")]
    pub interactive: bool,
    /// Never fall back to interactive approval; fail instead.
    #[arg(long)]
    pub no_interactive: bool,
}

impl AgentUpArgs {
    /// The operator's explicit choice about interactive approval, or `None`
    /// for "decide from whether there is a terminal".
    ///
    /// Two flags rather than one `--interactive=<bool>` because that is what a
    /// person types; they collapse to one tri-state here so the ladder has a
    /// single thing to consult.
    #[must_use]
    pub fn interactive_choice(&self) -> Option<bool> {
        match (self.interactive, self.no_interactive) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => None,
        }
    }
}

/// Arguments for the explicit `sidecar` subcommand.
#[derive(Debug, Args)]
pub struct SidecarArgs {
    /// The fleet whose `[user]` credential the shim connects with.
    #[arg(long, env = "PROBE_RS_FLEET", default_value = crate::paths::DEFAULT_FLEET)]
    pub fleet: String,
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
    /// The fleet to talk to. An explicit credential flag takes precedence over
    /// what the fleet file holds.
    #[arg(long, env = "PROBE_RS_FLEET", default_value = crate::paths::DEFAULT_FLEET, global = true)]
    pub fleet: String,
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
            // argv0 (`probe-rs` symlink) path: no clap, so read the fleet
            // selector directly from the env (default fleet otherwise).
            let fleet = std::env::var("PROBE_RS_FLEET")
                .ok()
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| crate::paths::DEFAULT_FLEET.to_owned());
            roles::sidecar::run(probe_rs_args, &fleet).await
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
                    Some(CoordinatorCommand::AuthKeys(args)) => {
                        roles::admin::auth_keys(args).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                    Some(CoordinatorCommand::AuthKeyRevoke(args)) => {
                        roles::admin::auth_key_revoke(args).await?;
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
                    Some(AgentCommand::Up(up)) => {
                        roles::agent_up::run(up, &args.fleet, args.config_dir).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                    None => {
                        roles::agent::run(args).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                },
                Command::Sidecar(args) => {
                    roles::sidecar::run(args.probe_rs_args, &args.fleet).await
                }
                Command::Ctl(args) => {
                    roles::ctl::run(args).await?;
                    Ok(ExitCode::SUCCESS)
                }
                Command::Login(args) => {
                    roles::login::run(args).await?;
                    Ok(ExitCode::SUCCESS)
                }
                Command::Share(args) => {
                    roles::share::run(args).await?;
                    Ok(ExitCode::SUCCESS)
                }
                Command::AuthKey(args) => {
                    roles::auth_key::run(args).await?;
                    Ok(ExitCode::SUCCESS)
                }
                Command::Node(args) => match args.command {
                    NodeCommand::Approve(approve) => {
                        roles::node_approve::run(&approve).await?;
                        Ok(ExitCode::SUCCESS)
                    }
                },
                Command::Fleets => {
                    roles::list_fleets()?;
                    Ok(ExitCode::SUCCESS)
                }
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

    /// The hosted verb: `auth-key create|list|revoke`, minting with the login
    /// you already have rather than a shell on the coordinator.
    #[test]
    fn parses_auth_key_create_list_revoke() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "auth-key",
            "create",
            "--tag",
            "lab",
            "--tag",
            "nrf52",
            "--ttl",
            "7d",
            "--multi-use",
            "--fleet",
            "lab1",
        ]));
        match cli.command {
            Command::AuthKey(a) => match a.command {
                AuthKeyCommand::Create(c) => {
                    assert_eq!(c.tag, vec!["lab".to_owned(), "nrf52".to_owned()]);
                    assert_eq!(c.ttl, "7d");
                    assert!(c.multi_use);
                    assert_eq!(c.fleet, "lab1");
                }
                other => panic!("expected create, got {other:?}"),
            },
            other => panic!("expected auth-key, got {other:?}"),
        }

        let cli = Cli::parse_from(os(&["probe-rs-fleet", "auth-key", "list"]));
        match cli.command {
            Command::AuthKey(a) => match a.command {
                AuthKeyCommand::List(_) => {}
                other => panic!("expected list, got {other:?}"),
            },
            other => panic!("expected auth-key, got {other:?}"),
        }

        let cli = Cli::parse_from(os(&["probe-rs-fleet", "auth-key", "revoke", "aabbccdd"]));
        match cli.command {
            Command::AuthKey(a) => match a.command {
                AuthKeyCommand::Revoke(r) => assert_eq!(r.prefix, "aabbccdd"),
                other => panic!("expected revoke, got {other:?}"),
            },
            other => panic!("expected auth-key, got {other:?}"),
        }
    }

    /// Defaults match `coordinator auth-key`'s: single use, 24h. There is no
    /// `--org` — the org comes from the session, and a key can never exceed it.
    #[test]
    fn auth_key_create_defaults_are_single_use_and_expiring() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "auth-key", "create"]));
        match cli.command {
            Command::AuthKey(a) => match a.command {
                AuthKeyCommand::Create(c) => {
                    assert!(!c.multi_use, "single use by default");
                    assert_eq!(c.ttl, "24h");
                    assert!(c.tag.is_empty());
                }
                other => panic!("expected create, got {other:?}"),
            },
            other => panic!("expected auth-key, got {other:?}"),
        }
    }

    /// `--tags` is a plain visible alias for `--tag`, **not** a comma-splitter:
    /// `coordinator auth-key --tag a,b` means one tag, and two verbs that mint
    /// the same object must not disagree about what a tag is.
    #[test]
    fn auth_key_tags_alias_does_not_split_on_commas() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "auth-key",
            "create",
            "--tags",
            "lab,nrf52",
        ]));
        match cli.command {
            Command::AuthKey(a) => match a.command {
                AuthKeyCommand::Create(c) => assert_eq!(c.tag, vec!["lab,nrf52".to_owned()]),
                other => panic!("expected create, got {other:?}"),
            },
            other => panic!("expected auth-key, got {other:?}"),
        }
    }

    /// `--single-use` is the default spelled out; pairing it with `--multi-use`
    /// is a contradiction clap must catch.
    #[test]
    fn auth_key_single_use_and_multi_use_conflict() {
        assert!(Cli::try_parse_from(os(&[
            "probe-rs-fleet",
            "auth-key",
            "create",
            "--single-use",
        ]))
        .is_ok());
        assert!(Cli::try_parse_from(os(&[
            "probe-rs-fleet",
            "auth-key",
            "create",
            "--single-use",
            "--multi-use",
        ]))
        .is_err());
    }

    #[test]
    fn parses_agent() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "agent", "--fleet", "lab1"]));
        match cli.command {
            Command::Agent(a) => {
                assert_eq!(a.fleet, "lab1");
                assert!(a.command.is_none());
            }
            other => panic!("expected agent, got {other:?}"),
        }
    }

    /// The default fleet is what an unconfigured invocation gets, so a fresh
    /// install needs no flags at all once `login` has run.
    #[test]
    fn fleet_defaults_to_default() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "agent"]));
        match cli.command {
            Command::Agent(a) => assert_eq!(a.fleet, "default"),
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
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "coordinator",
            "user-token",
            "alice",
        ]));
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
    fn parses_agent_up() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "agent",
            "--fleet",
            "lab1",
            "up",
            "--fleet-url",
            "https://fleet.example",
            "--auth-key",
            "prffk1_abc",
        ]));
        match cli.command {
            Command::Agent(a) => {
                assert_eq!(a.fleet, "lab1");
                match a.command {
                    Some(AgentCommand::Up(up)) => {
                        assert_eq!(up.fleet_url.as_deref(), Some("https://fleet.example"));
                        assert_eq!(up.auth_key.as_deref(), Some("prffk1_abc"));
                        assert!(up.node_name.is_none());
                        assert!(up.adopt.is_none());
                    }
                    other => panic!("expected agent up, got {other:?}"),
                }
            }
            other => panic!("expected agent, got {other:?}"),
        }
    }

    /// The whole point of `agent up`: on a machine that has already logged in,
    /// it needs no flags at all. Both `--auth-key` and `--fleet-url` are
    /// optional, which is what makes paths 1 and 2 of the §4.2 ladder reachable
    /// without the operator knowing they exist.
    #[test]
    fn agent_up_needs_no_flags() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "agent", "up"]));
        match cli.command {
            Command::Agent(a) => match a.command {
                Some(AgentCommand::Up(up)) => {
                    assert!(up.auth_key.is_none());
                    assert!(up.fleet_url.is_none());
                }
                other => panic!("expected agent up, got {other:?}"),
            },
            other => panic!("expected agent, got {other:?}"),
        }
    }

    /// `share` is the story-2 payoff: one word, no flags.
    #[test]
    fn parses_share_with_no_flags() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "share"]));
        match cli.command {
            Command::Share(s) => {
                assert_eq!(s.fleet, "default");
                assert!(s.node_name.is_none());
                assert!(s.adopt.is_none());
                assert!(!s.force);
            }
            other => panic!("expected share, got {other:?}"),
        }
    }

    #[test]
    fn parses_share_with_an_explicit_adopt_policy() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "share",
            "--adopt",
            "declared",
            "--tag",
            "nrf52",
        ]));
        match cli.command {
            Command::Share(s) => {
                assert_eq!(s.adopt, Some(AdoptArg::Declared));
                assert_eq!(s.tag, vec!["nrf52".to_owned()]);
            }
            other => panic!("expected share, got {other:?}"),
        }
    }

    #[test]
    fn parses_auth_key_list_and_revoke() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "coordinator", "auth-keys"]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::AuthKeys(k)) => assert!(k.org.is_none()),
                other => panic!("expected auth-keys, got {other:?}"),
            },
            other => panic!("expected coordinator, got {other:?}"),
        }

        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "coordinator",
            "auth-key-revoke",
            "deadbeef",
        ]));
        match cli.command {
            Command::Coordinator(a) => match a.command {
                Some(CoordinatorCommand::AuthKeyRevoke(r)) => assert_eq!(r.prefix, "deadbeef"),
                other => panic!("expected auth-key-revoke, got {other:?}"),
            },
            other => panic!("expected coordinator, got {other:?}"),
        }
    }

    #[test]
    fn parses_login() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "login",
            "--fleet",
            "ci",
            "--fleet-url",
            "https://fleet.example",
            "--no-browser",
        ]));
        match cli.command {
            Command::Login(a) => {
                assert_eq!(a.fleet, "ci");
                assert_eq!(a.fleet_url.as_deref(), Some("https://fleet.example"));
                assert!(a.no_browser);
                assert!(a.token.is_none());
            }
            other => panic!("expected login, got {other:?}"),
        }
    }

    /// The escape hatch for a coordinator with no GitHub app (and the hook the
    /// e2e tests use, so they need no GitHub at all).
    #[test]
    fn parses_login_with_an_explicit_token() {
        let cli = Cli::parse_from(os(&[
            "probe-rs-fleet",
            "login",
            "--fleet-url",
            "https://fleet.example",
            "--token",
            "prfs1_xyz",
        ]));
        match cli.command {
            Command::Login(a) => {
                assert_eq!(a.token.as_deref(), Some("prfs1_xyz"));
                assert_eq!(a.fleet, "default");
            }
            other => panic!("expected login, got {other:?}"),
        }
    }

    #[test]
    fn parses_fleets() {
        let cli = Cli::parse_from(os(&["probe-rs-fleet", "fleets"]));
        assert!(matches!(cli.command, Command::Fleets));
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
