//! Shared filesystem helpers used by the init scaffolding.
//!
//! These were originally private to [`crate::roles::init`]; they are factored
//! out here so `coordinator init`, `agent up`, `share` and `login` reuse the exact same
//! secret-writing, permission, and TOML-rendering behaviour rather than
//! duplicating it. The per-fleet config file holds bearer credentials, so
//! [`crate::fleet_config`] writes through [`write_secret`] too.
//!
//! Random *token* generation deliberately does not live here: it belongs to
//! `fleet_auth::OpaqueToken`, which owns the prefix scheme and the hashing
//! convention that make a token verifiable.

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
    fn seed_hex_is_64_chars() {
        let hex = generate_seed_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn seed_hex_is_random_per_call() {
        // Astronomically unlikely to collide; a fixed seed would mean every
        // coordinator signed capability tokens with the same key.
        assert_ne!(generate_seed_hex(), generate_seed_hex());
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
