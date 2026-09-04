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
use std::path::Path;
use std::time::Duration;

use fleet_proto::{BoardName, PowerKind};
use serde::{Deserialize, Serialize};

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

fn default_heartbeat_secs() -> u64 {
    15
}

/// Agent runtime configuration (separate from `boards.toml`).
///
/// Parsed from the agent's own config TOML. Carries connection identity, the
/// coordinator's token-verification public key, and policy knobs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AgentConfig {
    /// This node's id, as returned by the token exchange at `agent init`.
    ///
    /// **Advisory.** The coordinator identifies this node by the token it
    /// presents, not by this field; it is written here so logs and
    /// `AgentReport::Register` are legible, and the coordinator refuses the
    /// connection if it contradicts the token.
    pub agent_id: String,
    /// The coordinator's base URL (`https://fleet.example`), or a bare
    /// `host:port` (which defaults to `https`).
    pub fleet_url: String,
    /// This node's bearer token (`prfn1_…`).
    ///
    /// Rotated by the coordinator over the established connection; see
    /// [`AgentConfig::persist_node_token`].
    pub node_token: String,
    /// The node token this one replaced, kept until a connection with
    /// `node_token` succeeds.
    ///
    /// This closes the one rotation window the coordinator's ack-then-retire
    /// scheme cannot: if the *ack* is lost after the node persisted the new
    /// token, the node holds the new token while the coordinator still holds the
    /// old. Retrying once with the previous token recovers without any server
    /// state, and without it that case would need a physical visit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_node_token: Option<String>,
    /// Optional pinned coordinator server-certificate SHA-256 (64 hex chars),
    /// for a self-hosted deployment with no publicly trusted certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_cert_sha256: Option<String>,
    /// Hex-encoded ed25519 public key of the coordinator's token signer.
    pub coordinator_token_pubkey: String,
    /// Path to `boards.toml`.
    pub boards_path: String,
    /// Heartbeat interval, seconds.
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_secs: u64,
    /// Whether to erase the target's flash on lease release.
    #[serde(default)]
    pub erase_on_release: bool,
    /// The file this configuration was read from, so a rotated token can be
    /// written back. `None` when the config was parsed from a string.
    #[serde(skip)]
    pub source_path: Option<std::path::PathBuf>,
}

impl AgentConfig {
    /// Parse and validate from TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] on malformed TOML and
    /// [`ConfigError::Invalid`] if a required string is empty or the pubkey is
    /// not valid hex of the right length.
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
    /// [`from_str`]: AgentConfig::from_str
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let mut cfg = Self::from_str(&text)?;
        cfg.source_path = Some(path.to_path_buf());
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for (name, value) in [
            ("agent_id", &self.agent_id),
            ("fleet_url", &self.fleet_url),
            ("node_token", &self.node_token),
            ("coordinator_token_pubkey", &self.coordinator_token_pubkey),
            ("boards_path", &self.boards_path),
        ] {
            if value.trim().is_empty() {
                return Err(ConfigError::Invalid(format!("{name} must not be empty")));
            }
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
    /// silently downgrade to WebPKI verification.
    #[must_use]
    pub fn server_pin(&self) -> Option<[u8; 32]> {
        self.server_cert_sha256
            .as_deref()
            .and_then(fleet_tls::parse_fingerprint)
    }

    /// Persist a rotated node token back to the config file, atomically.
    ///
    /// Written to a temporary file in the same directory and renamed, so a crash
    /// mid-write cannot leave a truncated credential — which on a headless node
    /// would mean a physical visit. The previous token is retained for the
    /// one-shot retry described on
    /// [`previous_node_token`](AgentConfig::previous_node_token).
    ///
    /// The file is created 0600: it holds a bearer credential, and a bearer
    /// credential readable by other users on the host is equivalent to no
    /// credential at all.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] if the config has no known source path or
    /// the write fails, and [`ConfigError::Invalid`] if it cannot be rendered.
    pub fn persist_node_token(&mut self, new_token: &str) -> Result<(), ConfigError> {
        let previous = std::mem::replace(&mut self.node_token, new_token.to_owned());
        self.previous_node_token = Some(previous);
        self.write_back()
    }

    /// Forget the previous token once the current one has proven itself.
    ///
    /// # Errors
    ///
    /// As [`AgentConfig::persist_node_token`].
    pub fn clear_previous_token(&mut self) -> Result<(), ConfigError> {
        if self.previous_node_token.is_none() {
            return Ok(());
        }
        self.previous_node_token = None;
        self.write_back()
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

    fn write_back(&self) -> Result<(), ConfigError> {
        let path = self
            .source_path
            .clone()
            .ok_or_else(|| ConfigError::Invalid("agent config has no source path".to_owned()))?;
        let rendered = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Invalid(format!("rendering agent config: {e}")))?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = dir.join(format!(
            ".{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("agent.toml")
        ));
        let read_err = |source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        };
        std::fs::write(&tmp, rendered).map_err(read_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(read_err)?;
        }
        std::fs::rename(&tmp, &path).map_err(read_err)?;
        Ok(())
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

    const AGENT_CFG: &str = r#"
agent_id = "default/pi-lab-1"
fleet_url = "https://fleet.example:7000"
node_token = "prfn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
coordinator_token_pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
boards_path = "/etc/fleet/boards.toml"
"#;

    #[test]
    fn agent_config_parses_with_defaults() {
        let cfg = AgentConfig::from_str(AGENT_CFG).unwrap();
        assert_eq!(cfg.agent_id, "default/pi-lab-1");
        assert_eq!(cfg.fleet_url, "https://fleet.example:7000");
        assert_eq!(cfg.heartbeat_secs, 15);
        assert!(!cfg.erase_on_release);
        assert!(cfg.previous_node_token.is_none());
        assert!(cfg.server_pin().is_none());
        assert_eq!(cfg.heartbeat_interval(), Duration::from_secs(15));
        let key = cfg.coordinator_token_pubkey_bytes().unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    fn agent_config_rejects_bad_pubkey() {
        let bad = AGENT_CFG.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "xyz",
        );
        let err = AgentConfig::from_str(&bad).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn agent_config_rejects_empty_field() {
        let bad = AGENT_CFG.replace("default/pi-lab-1", "");
        let err = AgentConfig::from_str(&bad).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(m) if m.contains("agent_id")));
    }

    /// A malformed pin must be rejected at load, not at dial time: silently
    /// ignoring it would downgrade a deliberately pinned deployment to WebPKI
    /// verification, which for a self-signed coordinator means "nothing works"
    /// or, worse, "anything with a public cert works".
    #[test]
    fn agent_config_rejects_a_malformed_pin() {
        let bad = format!("{AGENT_CFG}server_cert_sha256 = \"nope\"\n");
        let err = AgentConfig::from_str(&bad).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(m) if m.contains("server_cert_sha256")));

        let good = format!("{AGENT_CFG}server_cert_sha256 = \"{}\"\n", "ab".repeat(32));
        let cfg = AgentConfig::from_str(&good).unwrap();
        assert_eq!(cfg.server_pin(), Some([0xabu8; 32]));
    }

    /// Rotation persists the new token and keeps the old one, then forgets it
    /// once the new one has proven itself. The file is rewritten atomically and
    /// stays 0600, because it holds a bearer credential.
    #[test]
    fn node_token_rotation_round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, AGENT_CFG).unwrap();

        let mut cfg = AgentConfig::from_path(&path).unwrap();
        let original = cfg.node_token.clone();
        cfg.persist_node_token("prfn1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
            .unwrap();

        let reloaded = AgentConfig::from_path(&path).unwrap();
        assert_eq!(
            reloaded.node_token,
            "prfn1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        );
        assert_eq!(reloaded.previous_node_token.as_deref(), Some(original.as_str()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "a bearer credential must not be world-readable");
        }

        let mut reloaded = reloaded;
        reloaded.clear_previous_token().unwrap();
        let again = AgentConfig::from_path(&path).unwrap();
        assert!(again.previous_node_token.is_none());
    }

    /// The one-shot fallback: if the coordinator never saw the ack, the node
    /// must be able to reconnect with the token the coordinator still holds.
    #[test]
    fn falling_back_swaps_current_and_previous() {
        let mut cfg = AgentConfig::from_str(AGENT_CFG).unwrap();
        assert!(!cfg.fall_back_to_previous_token(), "nothing to fall back to");

        cfg.previous_node_token = Some("prfn1_old".to_owned());
        let current = cfg.node_token.clone();
        assert!(cfg.fall_back_to_previous_token());
        assert_eq!(cfg.node_token, "prfn1_old");
        assert_eq!(cfg.previous_node_token.as_deref(), Some(current.as_str()));
    }
}
