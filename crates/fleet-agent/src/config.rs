//! Configuration: agent-local `boards.toml` and the agent runtime config.
//!
//! `boards.toml` (architecture §8) maps physical probe serials to leasable
//! board metadata. Example:
//!
//! ```toml
//! [[board]]
//! id        = "nrf52840-dk-3"
//! serial    = "001050257890"
//! chip      = "nRF52840_xxAA"
//! tags      = ["nrf52", "bluetooth"]
//! exclusive = true
//!
//! [board.power]
//! kind = "uhubctl"
//! hub  = "1-1"
//! port = 2
//! ```

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fleet_proto::{BoardName, PowerKind};
use serde::Deserialize;

/// Errors arising from configuration parsing and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("failed to read {path}: {source}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The TOML could not be parsed.
    #[error("failed to parse TOML: {0}")]
    Parse(#[from] toml::de::Error),

    /// A semantic validation rule was violated.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// USB power-control specification as written in `boards.toml`.
///
/// Deserialised from the `[board.power]` table (tagged by `kind`). Maps to
/// [`fleet_proto::PowerKind`], which is the canonical wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PowerSpec {
    /// Per-port USB hub control via `uhubctl`.
    Uhubctl {
        /// uhubctl hub location, e.g. `"1-1"`.
        hub: String,
        /// Hub port number.
        port: u8,
    },
    /// GPIO-driven relay (Linux gpiod char device).
    Gpio {
        /// gpiochip device name, e.g. `"gpiochip0"`.
        chip: String,
        /// GPIO line offset.
        line: u32,
    },
    /// No external power control.
    None,
}

impl From<PowerSpec> for PowerKind {
    fn from(spec: PowerSpec) -> Self {
        match spec {
            PowerSpec::Uhubctl { hub, port } => PowerKind::Uhubctl { hub, port },
            PowerSpec::Gpio { chip, line } => PowerKind::Gpio { chip, line },
            PowerSpec::None => PowerKind::None,
        }
    }
}

impl PowerSpec {
    /// Borrow this spec as the canonical [`PowerKind`].
    #[must_use]
    pub fn to_power_kind(&self) -> PowerKind {
        self.clone().into()
    }
}

fn default_exclusive() -> bool {
    true
}

fn default_power() -> PowerSpec {
    PowerSpec::None
}

/// A single board declared in `boards.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BoardSpec {
    /// Stable board id (unique across the fleet).
    pub id: String,
    /// Physical probe serial bound to this board (→ `serve`
    /// `ProbeAccess::Allow(["<vid>:<pid>:<serial>"])`).
    pub serial: String,
    /// USB vendor id of the bound probe. Not declared in `boards.toml`; filled
    /// in at runtime from USB discovery (see [`crate::discovery`]) so the serve
    /// config can emit the canonical `vid:pid:serial` allow selector that
    /// probe-rs 0.32's allow-list matcher accepts.
    #[serde(skip)]
    pub vid: u16,
    /// USB product id of the bound probe. Filled in at runtime from USB
    /// discovery (see [`vid`](Self::vid)).
    #[serde(skip)]
    pub pid: u16,
    /// probe-rs target/chip name (informational; the caller still passes
    /// `--chip` in-band).
    pub chip: String,
    /// Free-form selection tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether the board admits only one lease at a time.
    #[serde(default = "default_exclusive")]
    pub exclusive: bool,
    /// USB power-control wiring.
    #[serde(default = "default_power")]
    pub power: PowerSpec,
}

impl BoardSpec {
    /// This board's id as a [`BoardName`].
    #[must_use]
    pub fn board_id(&self) -> BoardName {
        BoardName(self.id.clone())
    }
}

/// The parsed `boards.toml` document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BoardsConfig {
    /// Declared boards (`[[board]]` array).
    #[serde(default, rename = "board")]
    pub boards: Vec<BoardSpec>,
}

impl BoardsConfig {
    /// Parse and validate from TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] on malformed TOML and
    /// [`ConfigError::Invalid`] if a validation rule fails (see [`validate`]).
    ///
    /// [`validate`]: BoardsConfig::validate
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read, parse, and validate from a file path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] on I/O failure, then as [`from_str`].
    ///
    /// [`from_str`]: BoardsConfig::from_str
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let cfg = Self::from_str(&text)?;
        Ok(cfg)
    }

    /// Validate semantic invariants: non-empty ids/serials, unique ids, unique
    /// serials.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] describing the first violation found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen_ids: HashSet<&str> = HashSet::new();
        let mut seen_serials: HashSet<&str> = HashSet::new();
        for board in &self.boards {
            if board.id.trim().is_empty() {
                return Err(ConfigError::Invalid("board id must not be empty".into()));
            }
            if board.serial.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "board {:?} has an empty serial",
                    board.id
                )));
            }
            if !seen_ids.insert(&board.id) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate board id {:?}",
                    board.id
                )));
            }
            if !seen_serials.insert(&board.serial) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate probe serial {:?} (used by board {:?})",
                    board.serial, board.id
                )));
            }
        }
        Ok(())
    }

    /// Look up a board by its id.
    #[must_use]
    pub fn board(&self, id: &BoardName) -> Option<&BoardSpec> {
        self.boards.iter().find(|b| b.id == id.0)
    }
}

/// The heartbeat interval `fleet-bin` applies when `node.toml` omits one.
#[must_use]
pub fn default_heartbeat_secs() -> u64 {
    15
}

/// Agent runtime configuration (separate from `boards.toml`).
///
/// # Not a file format
///
/// Revision 2 deleted `agent.toml`: a node's credential now lives in the
/// `[node]` table of its fleet file and its non-credential settings in
/// `~/.config/probe-rs-fleet/node/node.toml`, both owned by `fleet-bin`. This
/// struct is therefore a plain **parameter struct** that `fleet-bin` assembles,
/// not something with a `Deserialize` impl and a source path.
///
/// That is the point: this crate has no business knowing where credentials are
/// stored, and giving it a file path was what made the old "one config tree per
/// role" layout hard to unpick. Persisting a rotated token is now a
/// [`NodeTokenStore`] the binary supplies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// This node's id, as returned by the token exchange at `agent init`.
    ///
    /// **Advisory.** The coordinator identifies this node by the token it
    /// presents, not by this field; it is carried here so logs and
    /// `AgentReport::Register` are legible, and the coordinator refuses the
    /// connection if it contradicts the token.
    pub agent_id: String,
    /// The coordinator's base URL (`https://fleet.example`), or a bare
    /// `host:port` (which defaults to `https`).
    pub fleet_url: String,
    /// This node's bearer token (`prfn1_…`).
    ///
    /// Rotated by the coordinator over the established connection; the new value
    /// is written down through a [`NodeTokenStore`].
    pub node_token: String,
    /// The node token this one replaced, kept until a connection with
    /// `node_token` succeeds.
    ///
    /// This closes the one rotation window the coordinator's ack-then-retire
    /// scheme cannot: if the *ack* is lost after the node persisted the new
    /// token, the node holds the new token while the coordinator still holds the
    /// old. Retrying once with the previous token recovers without any server
    /// state, and without it that case would need a physical visit.
    pub previous_node_token: Option<String>,
    /// Optional pinned coordinator server-certificate SHA-256 (64 hex chars),
    /// for a self-hosted deployment with no publicly trusted certificate.
    pub server_cert_sha256: Option<String>,
    /// Hex-encoded ed25519 public key of the coordinator's token signer.
    pub coordinator_token_pubkey: String,
    /// Path to `boards.toml`.
    pub boards_path: PathBuf,
    /// Heartbeat interval, seconds.
    pub heartbeat_secs: u64,
    /// Whether to erase the target's flash on lease release.
    pub erase_on_release: bool,
}

/// Where a rotated node token is written down.
///
/// The coordinator rotates node tokens over the established connection, and the
/// agent must persist the replacement **before** acking it — an ack the node
/// cannot honour after a restart is how a Pi bricks itself. Where "persist"
/// writes to is `fleet-bin`'s business (today: the `[node]` table of the fleet
/// file, read-modify-write so a concurrent `login` is not clobbered), so this
/// crate takes the capability rather than a path.
pub trait NodeTokenStore: Send + Sync {
    /// Record `new_token` as the current token, retaining `previous` for the
    /// one-shot fallback.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message if the write fails. The caller does not
    /// ack the rotation in that case, so the coordinator keeps the old token
    /// valid and the node stays reachable.
    fn persist(&self, new_token: &str, previous: Option<&str>) -> Result<(), String>;

    /// Forget the retained previous token once the current one has proven
    /// itself.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message if the write fails.
    fn clear_previous(&self) -> Result<(), String>;
}

/// A [`NodeTokenStore`] that discards writes.
///
/// For tests and for any caller that genuinely has nowhere to persist to. Note
/// what it costs in production: a rotation would be acked and then forgotten
/// across a restart, which is exactly the failure the previous-token fallback
/// exists to survive — so this is deliberately *not* the default.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullTokenStore;

impl NodeTokenStore for NullTokenStore {
    fn persist(&self, _new_token: &str, _previous: Option<&str>) -> Result<(), String> {
        Ok(())
    }

    fn clear_previous(&self) -> Result<(), String> {
        Ok(())
    }
}

impl AgentConfig {
    /// Validate an assembled configuration.
    ///
    /// Called by `fleet-bin` after building the struct from the fleet file plus
    /// `node.toml`, so a malformed pin or pubkey fails at startup rather than at
    /// the dial (where it would silently downgrade to `WebPKI` verification).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if a required string is empty, the pin
    /// is not 64 hex characters, or the pubkey is not valid 32-byte hex.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (name, value) in [
            ("agent_id", &self.agent_id),
            ("fleet_url", &self.fleet_url),
            ("node_token", &self.node_token),
            ("coordinator_token_pubkey", &self.coordinator_token_pubkey),
        ] {
            if value.trim().is_empty() {
                return Err(ConfigError::Invalid(format!("{name} must not be empty")));
            }
        }
        if self.boards_path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("boards_path must not be empty".to_owned()));
        }
        if let Some(pin) = &self.server_cert_sha256 {
            if fleet_tls::parse_fingerprint(pin).is_none() {
                return Err(ConfigError::Invalid(
                    "server_cert_sha256 must be 64 hex characters".to_owned(),
                ));
            }
        }
        let key = self.coordinator_token_pubkey_bytes()?;
        debug_assert_eq!(key.len(), 32);
        Ok(())
    }

    /// The pinned coordinator server-certificate hash, decoded.
    ///
    /// Validated at load time, so a malformed pin cannot reach the dialer and
    /// silently downgrade to `WebPKI` verification.
    #[must_use]
    pub fn server_pin(&self) -> Option<[u8; 32]> {
        self.server_cert_sha256
            .as_deref()
            .and_then(fleet_tls::parse_fingerprint)
    }

    /// Swap in the previous token for a one-shot retry after an auth rejection.
    ///
    /// Returns `false` when there is no previous token to fall back to.
    pub fn fall_back_to_previous_token(&mut self) -> bool {
        let Some(previous) = self.previous_node_token.take() else {
            return false;
        };
        self.previous_node_token = Some(std::mem::replace(&mut self.node_token, previous));
        true
    }

    /// Decode the coordinator's token public key into 32 raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if the hex is malformed or not 32 bytes.
    pub fn coordinator_token_pubkey_bytes(&self) -> Result<[u8; 32], ConfigError> {
        decode_hex_32(&self.coordinator_token_pubkey)
            .ok_or_else(|| ConfigError::Invalid("coordinator_token_pubkey must be 64 hex chars (32 bytes)".into()))
    }

    /// The configured heartbeat interval as a [`Duration`].
    #[must_use]
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_secs)
    }
}

/// Decode exactly 32 bytes from a hex string, returning `None` on any error.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[i * 2] as char).to_digit(16)?;
        let lo = (s.as_bytes()[i * 2 + 1] as char).to_digit(16)?;
        *byte = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[[board]]
id        = "nrf52840-dk-3"
serial    = "001050257890"
chip      = "nRF52840_xxAA"
tags      = ["nrf52", "bluetooth"]
exclusive = true

[board.power]
kind = "uhubctl"
hub  = "1-1"
port = 2

[[board]]
id     = "rp2040-1"
serial = "E6614103E7"
chip   = "RP2040"

[board.power]
kind = "gpio"
chip = "gpiochip0"
line = 17

[[board]]
id     = "stm32-x"
serial = "FFEEDDCC"
chip   = "STM32F4"

[board.power]
kind = "none"
"#;

    #[test]
    fn parses_full_file_with_all_power_kinds() {
        let cfg = BoardsConfig::from_str(FULL).unwrap();
        assert_eq!(cfg.boards.len(), 3);

        let b0 = &cfg.boards[0];
        assert_eq!(b0.id, "nrf52840-dk-3");
        assert_eq!(b0.serial, "001050257890");
        assert_eq!(b0.chip, "nRF52840_xxAA");
        assert_eq!(b0.tags, vec!["nrf52", "bluetooth"]);
        assert!(b0.exclusive);
        assert_eq!(
            b0.power.to_power_kind(),
            PowerKind::Uhubctl {
                hub: "1-1".into(),
                port: 2
            }
        );

        assert_eq!(
            cfg.boards[1].power.to_power_kind(),
            PowerKind::Gpio {
                chip: "gpiochip0".into(),
                line: 17
            }
        );
        assert_eq!(cfg.boards[2].power.to_power_kind(), PowerKind::None);
    }

    #[test]
    fn defaults_exclusive_true_and_power_none_and_empty_tags() {
        let cfg = BoardsConfig::from_str(
            r#"
[[board]]
id = "b1"
serial = "s1"
chip = "c1"
"#,
        )
        .unwrap();
        let b = &cfg.boards[0];
        assert!(b.exclusive);
        assert!(b.tags.is_empty());
        assert_eq!(b.power, PowerSpec::None);
    }

    #[test]
    fn empty_file_is_valid_with_no_boards() {
        let cfg = BoardsConfig::from_str("").unwrap();
        assert!(cfg.boards.is_empty());
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let err = BoardsConfig::from_str(
            r#"
[[board]]
id = "dup"
serial = "s1"
chip = "c1"
[[board]]
id = "dup"
serial = "s2"
chip = "c2"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(m) if m.contains("duplicate board id")));
    }

    #[test]
    fn duplicate_serial_is_rejected() {
        let err = BoardsConfig::from_str(
            r#"
[[board]]
id = "b1"
serial = "same"
chip = "c1"
[[board]]
id = "b2"
serial = "same"
chip = "c2"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(m) if m.contains("duplicate probe serial")));
    }

    #[test]
    fn missing_required_field_is_a_parse_error() {
        // `serial` is required and absent.
        let err = BoardsConfig::from_str(
            r#"
[[board]]
id = "b1"
chip = "c1"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn unknown_power_kind_is_a_parse_error() {
        let err = BoardsConfig::from_str(
            r#"
[[board]]
id = "b1"
serial = "s1"
chip = "c1"
[board.power]
kind = "laser"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn empty_id_is_rejected() {
        let err = BoardsConfig::from_str(
            r#"
[[board]]
id = "  "
serial = "s1"
chip = "c1"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(m) if m.contains("must not be empty")));
    }

    #[test]
    fn board_lookup_by_id() {
        let cfg = BoardsConfig::from_str(FULL).unwrap();
        assert!(cfg.board(&BoardName("rp2040-1".into())).is_some());
        assert!(cfg.board(&BoardName("nope".into())).is_none());
    }

    fn agent_cfg() -> AgentConfig {
        AgentConfig {
            agent_id: "gh-4242/pi-lab-1".to_owned(),
            fleet_url: "https://fleet.example:7000".to_owned(),
            node_token: "prfn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            previous_node_token: None,
            server_cert_sha256: None,
            coordinator_token_pubkey:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            boards_path: PathBuf::from("/etc/fleet/boards.toml"),
            heartbeat_secs: default_heartbeat_secs(),
            erase_on_release: false,
        }
    }

    #[test]
    fn an_assembled_config_validates() {
        let cfg = agent_cfg();
        cfg.validate().unwrap();
        assert_eq!(cfg.heartbeat_interval(), Duration::from_secs(15));
        assert!(cfg.server_pin().is_none());
        let key = cfg.coordinator_token_pubkey_bytes().unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    fn agent_config_rejects_bad_pubkey() {
        let cfg = AgentConfig {
            coordinator_token_pubkey: "xyz".to_owned(),
            ..agent_cfg()
        };
        assert!(matches!(cfg.validate().unwrap_err(), ConfigError::Invalid(_)));
    }

    #[test]
    fn agent_config_rejects_empty_field() {
        let cfg = AgentConfig {
            agent_id: String::new(),
            ..agent_cfg()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(m) if m.contains("agent_id")));

        let cfg = AgentConfig {
            boards_path: PathBuf::new(),
            ..agent_cfg()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(m) if m.contains("boards_path")));
    }

    /// A malformed pin must be rejected at startup, not at dial time: silently
    /// ignoring it would downgrade a deliberately pinned deployment to `WebPKI`
    /// verification, which for a self-signed coordinator means "nothing works"
    /// or, worse, "anything with a public cert works".
    #[test]
    fn agent_config_rejects_a_malformed_pin() {
        let cfg = AgentConfig {
            server_cert_sha256: Some("nope".to_owned()),
            ..agent_cfg()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(m) if m.contains("server_cert_sha256")));

        let cfg = AgentConfig {
            server_cert_sha256: Some("ab".repeat(32)),
            ..agent_cfg()
        };
        cfg.validate().unwrap();
        assert_eq!(cfg.server_pin(), Some([0xabu8; 32]));
    }

    /// The one-shot fallback: if the coordinator never saw the ack, the node
    /// must be able to reconnect with the token the coordinator still holds.
    /// This is a pure in-memory swap now \u2014 where the tokens are *written* is the
    /// binary's business (see [`NodeTokenStore`]).
    #[test]
    fn falling_back_swaps_current_and_previous() {
        let mut cfg = agent_cfg();
        assert!(!cfg.fall_back_to_previous_token(), "nothing to fall back to");

        cfg.previous_node_token = Some("prfn1_old".to_owned());
        let current = cfg.node_token.clone();
        assert!(cfg.fall_back_to_previous_token());
        assert_eq!(cfg.node_token, "prfn1_old");
        assert_eq!(cfg.previous_node_token.as_deref(), Some(current.as_str()));
    }
}
