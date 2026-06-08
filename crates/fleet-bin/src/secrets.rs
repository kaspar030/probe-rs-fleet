//! Shared filesystem + key/cert helpers used by the init/enroll scaffolding.
//!
//! These were originally private to [`crate::roles::init`]; they are factored
//! out here so the enrollment (`coordinator enroll`) and per-role init
//! (`agent init`, `ctl init`) handlers reuse the exact same secret-writing,
//! permission, and TOML-rendering behaviour rather than duplicating it.

use std::path::Path;

use anyhow::{Context, Result};
use rand_core::{OsRng, RngCore};

/// Generate a 32-byte ed25519 seed as 64 lowercase hex chars.
#[must_use]
pub fn generate_seed_hex() -> String {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    hex_encode(&seed)
}

/// Lowercase-hex encode a byte slice.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        // Infallible: writing to a String never fails.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode a 64-hex-char string into a 32-byte seed.
///
/// # Errors
///
/// Returns an error if the string is not exactly 64 hex characters.
pub fn decode_seed_hex(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim();
    anyhow::ensure!(
        hex.len() == 64,
        "seed must be 64 hex chars (32 bytes), got {}",
        hex.len()
    );
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let s = &hex[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(s, 16).context("seed contains non-hex characters")?;
    }
    Ok(out)
}

/// Derive the coordinator's ed25519 token **public** key (hex) from its 32-byte
/// signing seed.
///
/// This mirrors `fleet_coordinator::auth::Ed25519Signer::public_key_bytes`
/// (`SigningKey::from_bytes(seed).verifying_key().to_bytes()`) so an enrollment
/// bundle can carry the value an agent needs in `coordinator_token_pubkey`.
#[must_use]
pub fn token_pubkey_hex_from_seed(seed: &[u8; 32]) -> String {
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    hex_encode(&signing.verifying_key().to_bytes())
}

/// Write a file containing secret material, restricting it to `0600` on unix.
///
/// # Errors
///
/// Returns an error if the file cannot be written or permissions cannot be set.
pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    set_secret_perms(path)?;
    Ok(())
}

/// Write a non-secret file (config / public cert) with default permissions.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub fn write_public(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

/// Copy a public file (e.g. a cert) into `dest` with default permissions.
///
/// # Errors
///
/// Returns an error if the source cannot be read or the destination written.
pub fn import_public(src: &Path, dest: &Path) -> Result<()> {
    let bytes =
        std::fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    write_public(dest, &bytes)
}

/// Copy a secret file (e.g. a private key) into `dest`, restricting it to
/// `0600` on unix.
///
/// # Errors
///
/// Returns an error if the source cannot be read or the destination written.
pub fn import_secret(src: &Path, dest: &Path) -> Result<()> {
    let bytes =
        std::fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    write_secret(dest, &bytes)
}

#[cfg(unix)]
fn set_secret_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("setting 0600 perms on {}", path.display()))
}

#[cfg(not(unix))]
fn set_secret_perms(_path: &Path) -> Result<()> {
    Ok(())
}

/// Render a path as a TOML basic string literal.
#[must_use]
pub fn toml_path(path: &Path) -> String {
    toml::Value::String(path.display().to_string()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_hex_roundtrips() {
        let hex = generate_seed_hex();
        assert_eq!(hex.len(), 64);
        let bytes = decode_seed_hex(&hex).unwrap();
        assert_eq!(hex_encode(&bytes), hex);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(decode_seed_hex("00").is_err());
    }

    #[test]
    fn token_pubkey_matches_coordinator_auth() {
        let seed = [7u8; 32];
        let signer = fleet_coordinator::auth::Ed25519Signer::from_seed(&seed);
        assert_eq!(
            token_pubkey_hex_from_seed(&seed),
            hex_encode(&signer.public_key_bytes())
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_secret_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secret");
        write_secret(&path, b"hunter2").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
