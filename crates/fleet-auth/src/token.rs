//! Opaque bearer tokens: minting, parsing, and hashing.
//!
//! A token is a short human prefix plus 32 random bytes in base64url-no-pad:
//!
//! ```text
//! prfn1_<43 chars>      node token     (long-lived, auto-rotating)
//! prfs1_<43 chars>      session token  (user; short TTL, refreshable)
//! prffk1_<43 chars>     auth key       (node enrollment; org-scoped, revocable)
//! prfnd1_<43 chars>     node device    (pending interactive approval; redeemed at a route)
//! ```
//!
//! The prefix is load-bearing, not decoration: it tells the coordinator which
//! table to look in *before* any database access, so a token of the wrong kind
//! for a route is rejected as a 403 rather than silently searched for
//! everywhere.
//!
//! The coordinator stores only the **lowercase-hex SHA-256** of the secret
//! ([`TokenHash`]), never the token itself — the same convention the deleted
//! enrollment code used for its one-time secrets.

use std::fmt;

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Prefix for a node token.
const PREFIX_NODE: &str = "prfn1_";
/// Prefix for a user session token.
const PREFIX_SESSION: &str = "prfs1_";
/// Prefix for a node-enrollment auth key.
const PREFIX_AUTH_KEY: &str = "prffk1_";
/// Prefix for a pending-node device secret (interactive approval).
const PREFIX_NODE_DEVICE: &str = "prfnd1_";

/// Number of random bytes in a token secret.
const SECRET_LEN: usize = 32;

/// Which credential a token is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// A node's long-lived, auto-rotating connection credential.
    Node,
    /// A user's short-lived session token.
    Session,
    /// A pre-minted, org-scoped, revocable node-enrollment key.
    AuthKey,
    /// A machine's poll credential for an approval-pending registration
    /// (architecture §4.2 rung 3).
    ///
    /// Like [`TokenKind::AuthKey`] it is **redeemed at a route, never
    /// presented as a connection credential**, so
    /// [`crate::verify::authenticate`] rejects it as
    /// [`crate::AuthError::WrongKind`].
    NodeDevice,
}

impl TokenKind {
    /// The wire prefix for this kind.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            TokenKind::Node => PREFIX_NODE,
            TokenKind::Session => PREFIX_SESSION,
            TokenKind::AuthKey => PREFIX_AUTH_KEY,
            TokenKind::NodeDevice => PREFIX_NODE_DEVICE,
        }
    }

    /// A short label, for logs and audit entries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Node => "node",
            TokenKind::Session => "session",
            TokenKind::AuthKey => "auth_key",
            TokenKind::NodeDevice => "node_device",
        }
    }
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors raised while parsing a token string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The string carried no recognised token prefix.
    #[error("token has an unrecognised prefix")]
    BadPrefix,
    /// The body was not valid base64url-no-pad.
    #[error("token body is not valid base64url")]
    BadBase64,
    /// The decoded secret was not 32 bytes.
    #[error("token body has the wrong length")]
    BadLength,
}

/// The lowercase-hex SHA-256 of a token secret — what the coordinator stores.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenHash(String);

impl TokenHash {
    /// Borrow the hex digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first 8 hex characters, for logs and audit entries.
    ///
    /// A prefix of a *hash* is safe to log: it identifies a credential across
    /// events without being usable, and 8 characters is far too short to invert
    /// a 32-byte random secret.
    #[must_use]
    pub fn short(&self) -> &str {
        &self.0[..8.min(self.0.len())]
    }

    /// Wrap an already-computed hex digest (e.g. read from the database).
    #[must_use]
    pub fn from_hex(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The hash is not the secret, but printing it in full invites someone to
        // paste it into a bug report; the short form is what logs want anyway.
        write!(f, "TokenHash({}…)", self.short())
    }
}

impl fmt::Display for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An opaque bearer token: the secret itself.
///
/// [`fmt::Debug`] never prints the secret, mirroring the redaction the deleted
/// `EnrollmentToken` carried. Print it exactly once, when it is minted for an
/// operator to copy.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueToken {
    kind: TokenKind,
    secret: [u8; SECRET_LEN],
}

impl OpaqueToken {
    /// Mint a fresh random token of `kind`.
    ///
    /// # Panics
    ///
    /// Panics if the OS random source fails, which is not a condition any caller
    /// can meaningfully recover from.
    #[must_use]
    pub fn mint(kind: TokenKind) -> Self {
        use rand_core::RngCore as _;
        let mut secret = [0u8; SECRET_LEN];
        rand_core::OsRng.fill_bytes(&mut secret);
        Self { kind, secret }
    }

    /// Parse a token from its string form.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if the prefix is unrecognised, the body is not
    /// base64url, or the decoded secret is not 32 bytes.
    pub fn parse(s: &str) -> Result<Self, TokenError> {
        let s = s.trim();
        // Longest prefix first: `prffk1_`, `prfnd1_` and `prfs1_` share no
        // prefix, but ordering by length keeps this correct if a future kind
        // does. **Every kind must appear here** — omitting one makes its
        // tokens unparseable with no compile error.
        let kinds = [
            TokenKind::AuthKey,
            TokenKind::NodeDevice,
            TokenKind::Node,
            TokenKind::Session,
        ];
        let (kind, body) = kinds
            .into_iter()
            .find_map(|k| s.strip_prefix(k.prefix()).map(|body| (k, body)))
            .ok_or(TokenError::BadPrefix)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| TokenError::BadBase64)?;
        let secret: [u8; SECRET_LEN] = bytes.try_into().map_err(|_| TokenError::BadLength)?;
        Ok(Self { kind, secret })
    }

    /// The token's kind, from its prefix.
    #[must_use]
    pub fn kind(&self) -> TokenKind {
        self.kind
    }

    /// The lowercase-hex SHA-256 of the secret: what the coordinator stores and
    /// looks up.
    #[must_use]
    pub fn hash(&self) -> TokenHash {
        let digest = Sha256::digest(self.secret);
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use fmt::Write as _;
            // Infallible: writing to a String never fails.
            let _ = write!(out, "{byte:02x}");
        }
        TokenHash(out)
    }

    /// Render the token in its copy-pasteable string form.
    ///
    /// This is the only place the secret becomes visible; call it exactly where
    /// the token is handed to its owner.
    #[must_use]
    pub fn to_secret_string(&self) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.secret);
        format!("{}{b64}", self.kind.prefix())
    }
}

impl fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueToken")
            .field("kind", &self.kind)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_parse_round_trips_for_every_kind() {
        for kind in [
            TokenKind::Node,
            TokenKind::Session,
            TokenKind::AuthKey,
            TokenKind::NodeDevice,
        ] {
            let token = OpaqueToken::mint(kind);
            let s = token.to_secret_string();
            assert!(s.starts_with(kind.prefix()), "{s} lacks {}", kind.prefix());
            let back = OpaqueToken::parse(&s).unwrap();
            assert_eq!(back.kind(), kind);
            assert_eq!(back, token);
            assert_eq!(back.hash(), token.hash());
        }
    }

    #[test]
    fn distinct_mints_are_distinct() {
        let a = OpaqueToken::mint(TokenKind::Node);
        let b = OpaqueToken::mint(TokenKind::Node);
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn hash_is_stable_and_64_hex() {
        let token = OpaqueToken::mint(TokenKind::Session);
        let h = token.hash();
        assert_eq!(h.as_str().len(), 64);
        assert!(h.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, token.hash());
        assert_eq!(h.short().len(), 8);
    }

    /// The prefix decides the table, so a node token must never parse as a
    /// session token: that is what makes wrong-kind-for-route a 403 rather than
    /// a lookup in the wrong place.
    #[test]
    fn prefix_determines_kind() {
        let node = OpaqueToken::mint(TokenKind::Node).to_secret_string();
        assert_eq!(OpaqueToken::parse(&node).unwrap().kind(), TokenKind::Node);
        let session = OpaqueToken::mint(TokenKind::Session).to_secret_string();
        assert_eq!(
            OpaqueToken::parse(&session).unwrap().kind(),
            TokenKind::Session
        );
        let key = OpaqueToken::mint(TokenKind::AuthKey).to_secret_string();
        assert_eq!(OpaqueToken::parse(&key).unwrap().kind(), TokenKind::AuthKey);
        // `prfnd1_` vs `prfn1_`: unambiguous only because the strip is
        // longest-first, which is exactly what this asserts.
        let device = OpaqueToken::mint(TokenKind::NodeDevice).to_secret_string();
        assert_eq!(
            OpaqueToken::parse(&device).unwrap().kind(),
            TokenKind::NodeDevice
        );
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        assert_eq!(OpaqueToken::parse("nope_abcd"), Err(TokenError::BadPrefix));
        assert_eq!(OpaqueToken::parse(""), Err(TokenError::BadPrefix));
    }

    #[test]
    fn parse_rejects_bad_base64() {
        assert_eq!(
            OpaqueToken::parse("prfn1_!!!not-base64!!!"),
            Err(TokenError::BadBase64)
        );
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert_eq!(
            OpaqueToken::parse(&format!("prfn1_{short}")),
            Err(TokenError::BadLength)
        );
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let token = OpaqueToken::mint(TokenKind::Node);
        let s = format!("  {}\n", token.to_secret_string());
        assert_eq!(OpaqueToken::parse(&s).unwrap(), token);
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let token = OpaqueToken::mint(TokenKind::Node);
        let rendered = format!("{token:?}");
        assert!(rendered.contains("redacted"));
        let secret = token.to_secret_string();
        assert!(!rendered.contains(&secret[6..]));
    }
}
