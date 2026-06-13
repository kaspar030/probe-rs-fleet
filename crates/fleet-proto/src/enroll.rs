//! Bootstrap-enrollment wire types.
//!
//! Enrollment is a one-time *bootstrap* step that lets an agent or client
//! obtain a CA-signed client certificate. Runtime authentication stays mTLS;
//! the [`EnrollmentToken`] is bootstrap-only.
//!
//! The token is one opaque, copy-pasteable string carrying three things:
//!
//! 1. the coordinator address (`host:port`),
//! 2. the SHA-256 hash of the coordinator's server certificate (so the
//!    bootstrap TLS handshake can *pin* the server leaf rather than trusting it
//!    blindly), and
//! 3. a random single-use auth secret (the actual credential; validated
//!    server-side by hash lookup).
//!
//! The token is purely a transport blob — it is **not** signed. The secret is
//! the credential; the coordinator stores only its hash and consumes it on
//! first use.
//!
//! The bootstrap RPC itself uses [`EnrollRequest`] / [`EnrollResponse`]: the
//! client generates a keypair + CSR locally (the private key never leaves the
//! host), sends the CSR plus the token's secret, and receives a CA-signed
//! client certificate back.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Short human prefix on the compact token string: probe-rs-fleet enroll v1.
const TOKEN_PREFIX: &str = "prffe1_";

/// A one-time bootstrap enrollment token.
///
/// Round-trips through [`EnrollmentToken::to_compact_string`] /
/// [`EnrollmentToken::from_compact_string`] (base64-url-no-pad over postcard,
/// with a short human prefix).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentToken {
    /// `host:port` of the coordinator's bootstrap/runtime listener.
    pub coordinator_addr: String,
    /// SHA-256 of the coordinator's server-certificate DER, for bootstrap
    /// server-cert pinning.
    pub server_cert_sha256: [u8; 32],
    /// The random single-use auth secret (the credential).
    pub secret: [u8; 32],
}

impl std::fmt::Debug for EnrollmentToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the secret (or the full server-cert hash) in Debug output.
        f.debug_struct("EnrollmentToken")
            .field("coordinator_addr", &self.coordinator_addr)
            .field("server_cert_sha256", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Errors raised while encoding / decoding an [`EnrollmentToken`].
#[derive(Debug, thiserror::Error)]
pub enum EnrollTokenError {
    /// postcard serialisation failed.
    #[error("failed to encode enrollment token: {0}")]
    Encode(String),
    /// postcard deserialisation failed.
    #[error("failed to decode enrollment token: {0}")]
    Decode(String),
    /// The compact string did not start with the expected prefix.
    #[error("enrollment token has an unrecognised prefix (expected `{TOKEN_PREFIX}`)")]
    BadPrefix,
    /// The base64 body could not be decoded.
    #[error("enrollment token is not valid base64-url: {0}")]
    BadBase64(String),
}

impl EnrollmentToken {
    /// Encode the token into its compact, copy-pasteable string form.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollTokenError::Encode`] if postcard serialisation fails
    /// (not expected for this fixed-shape struct).
    pub fn to_compact_string(&self) -> Result<String, EnrollTokenError> {
        let bytes =
            postcard::to_stdvec(self).map_err(|e| EnrollTokenError::Encode(e.to_string()))?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        Ok(format!("{TOKEN_PREFIX}{b64}"))
    }

    /// Decode a token from its compact string form.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollTokenError::BadPrefix`] if the prefix is missing,
    /// [`EnrollTokenError::BadBase64`] if the body is not valid base64-url, and
    /// [`EnrollTokenError::Decode`] if the postcard payload is malformed.
    pub fn from_compact_string(s: &str) -> Result<Self, EnrollTokenError> {
        let body = s
            .trim()
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(EnrollTokenError::BadPrefix)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|e| EnrollTokenError::BadBase64(e.to_string()))?;
        postcard::from_bytes(&bytes).map_err(|e| EnrollTokenError::Decode(e.to_string()))
    }
}

/// The bootstrap request a client sends over the pinned bootstrap TLS
/// connection (no client cert) to obtain a CA-signed client certificate.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// The token's single-use auth secret.
    pub secret: [u8; 32],
    /// A PEM-encoded certificate signing request whose key was generated
    /// locally on the client (the private key never leaves the host).
    pub csr_pem: String,
}

impl std::fmt::Debug for EnrollRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollRequest")
            .field("secret", &"<redacted>")
            .field("csr_pem", &"<csr>")
            .finish()
    }
}

/// The coordinator's reply to an [`EnrollRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnrollResponse {
    /// The secret was valid and single-use; the CSR was signed.
    Accepted {
        /// The CA-signed client certificate (PEM).
        client_cert_pem: String,
        /// The client CA certificate (PEM), to be saved for runtime mTLS
        /// server verification.
        ca_cert_pem: String,
        /// Hex-encoded ed25519 public key of the coordinator's token signer,
        /// so an enrolled agent can populate `coordinator_token_pubkey`.
        coordinator_token_pubkey: String,
    },
    /// Enrollment was rejected (bad/expired/reused secret, malformed CSR, …).
    Rejected {
        /// Human-readable reason.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_compact_string_round_trips() {
        let token = EnrollmentToken {
            coordinator_addr: "coord.example:7000".to_owned(),
            server_cert_sha256: [0xABu8; 32],
            secret: [0xCDu8; 32],
        };
        let s = token.to_compact_string().unwrap();
        assert!(s.starts_with(TOKEN_PREFIX));
        let back = EnrollmentToken::from_compact_string(&s).unwrap();
        assert_eq!(back, token);
    }

    #[test]
    fn decode_rejects_bad_prefix() {
        assert!(matches!(
            EnrollmentToken::from_compact_string("nope_abcd"),
            Err(EnrollTokenError::BadPrefix)
        ));
    }

    #[test]
    fn decode_rejects_bad_base64() {
        let s = format!("{TOKEN_PREFIX}!!!not-base64!!!");
        assert!(matches!(
            EnrollmentToken::from_compact_string(&s),
            Err(EnrollTokenError::BadBase64(_))
        ));
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let token = EnrollmentToken {
            coordinator_addr: "c:1".to_owned(),
            server_cert_sha256: [1u8; 32],
            secret: [2u8; 32],
        };
        let dbg = format!("{token:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("0202"));
    }
}
