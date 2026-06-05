//! Capability tokens: short-TTL, signed grants scoped to a single lease/board.
//!
//! The coordinator (the signer) issues a [`CapabilityToken`] when a lease is
//! granted; the agent (the verifier) checks the signature locally before
//! opening a probe-rs session, so no per-operation coordinator round-trip is
//! needed (see `docs/architecture.md` §6).
//!
//! This module is **pure data + a transport-agnostic signing seam**: it defines
//! the token shape, the canonical bytes that get signed
//! ([`CapabilityToken::serialize_for_signing`]), the on-wire framing of a signed
//! token ([`SignedToken`]), and the [`TokenSigner`] / [`TokenVerifier`] traits.
//! The concrete signature algorithm (ed25519) lives in the coordinator (signer)
//! and agent (verifier) crates, behind these traits. Keeping the algorithm out
//! of `fleet-proto` keeps this crate dependency-light while letting both ends
//! share one definition and the same test vectors.
//!
//! Wire shape of a signed token (what travels in [`crate::LeaseGrant::token`]):
//!
//! ```text
//! serialize_for_signing(CapabilityToken)  ||  64-byte ed25519 signature
//! ```

use serde::{Deserialize, Serialize};

use crate::ids::{BoardId, LeaseId};

/// One capability a token may grant. A token carries the set of operations its
/// holder is allowed to perform against the leased board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AllowedOp {
    /// Flash/download firmware to the target.
    Flash,
    /// Attach to a running target (RTT, monitor).
    Attach,
    /// Open a gdb session (raw-TCP tunnel; see architecture §4.2 gap).
    Gdb,
    /// Reset the target.
    Reset,
    /// Erase the target's flash.
    Erase,
    /// Cut/restore USB power to the board.
    PowerCycle,
}

/// A signed capability scoped to `{lease, board, allowed_ops}` with an expiry.
///
/// The token is meaningless on its own — it must be paired with a signature
/// (see [`SignedToken`]) produced by a trusted [`TokenSigner`]. The agent
/// verifies the signature and then checks `expires` and `allowed_ops` against
/// the requested operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// The lease this token authorises.
    pub lease: LeaseId,
    /// The board this token authorises operations against.
    pub board: BoardId,
    /// Operations the holder may perform.
    pub allowed_ops: Vec<AllowedOp>,
    /// Expiry as epoch seconds. The agent rejects the token once the wall
    /// clock passes this value.
    pub expires: u64,
}

impl CapabilityToken {
    /// Serialize the token to its canonical signing bytes.
    ///
    /// These bytes — and *only* these bytes — are what a [`TokenSigner`] signs
    /// and a [`TokenVerifier`] verifies. The encoding is postcard with the
    /// field order fixed by this struct's declaration, so signer and verifier
    /// agree byte-for-byte across crates.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Encode`] if postcard serialization fails (only
    /// possible on pathological inputs; in practice infallible for this type).
    pub fn serialize_for_signing(&self) -> Result<Vec<u8>, TokenError> {
        postcard::to_allocvec(self).map_err(|e| TokenError::Encode(e.to_string()))
    }

    /// Whether this token grants `op`.
    #[must_use]
    pub fn allows(&self, op: AllowedOp) -> bool {
        self.allowed_ops.contains(&op)
    }

    /// Whether the token is still valid at `now` (epoch seconds).
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now < self.expires
    }
}

/// Length in bytes of an ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// A [`CapabilityToken`] paired with its detached signature, ready for the
/// wire. This is the in-memory view of the bytes carried in
/// [`crate::LeaseGrant::token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedToken {
    /// The canonical signing bytes of the token (`serialize_for_signing`).
    pub token_bytes: Vec<u8>,
    /// The 64-byte ed25519 signature over `token_bytes`.
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedToken {
    /// Encode to the wire framing: `token_bytes || signature`.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.token_bytes.len() + SIGNATURE_LEN);
        out.extend_from_slice(&self.token_bytes);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode from the wire framing `token_bytes || signature`.
    ///
    /// The trailing [`SIGNATURE_LEN`] bytes are taken as the signature; the
    /// remainder is the token's signing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Truncated`] if `wire` is shorter than a signature.
    pub fn from_wire(wire: &[u8]) -> Result<Self, TokenError> {
        if wire.len() < SIGNATURE_LEN {
            return Err(TokenError::Truncated {
                len: wire.len(),
                min: SIGNATURE_LEN,
            });
        }
        let split = wire.len() - SIGNATURE_LEN;
        let (token_bytes, sig) = wire.split_at(split);
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(sig);
        Ok(Self {
            token_bytes: token_bytes.to_vec(),
            signature,
        })
    }

    /// Decode the [`CapabilityToken`] from `token_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Decode`] if the bytes are not a valid token.
    pub fn decode_token(&self) -> Result<CapabilityToken, TokenError> {
        postcard::from_bytes(&self.token_bytes).map_err(|e| TokenError::Decode(e.to_string()))
    }
}

/// Signs capability tokens. Implemented by the coordinator, which holds the
/// private key.
pub trait TokenSigner {
    /// Sign `token`, returning a wire-ready [`SignedToken`].
    ///
    /// # Errors
    ///
    /// Returns a [`TokenError`] if the token cannot be encoded or signed.
    fn sign(&self, token: &CapabilityToken) -> Result<SignedToken, TokenError>;
}

/// Verifies capability tokens. Implemented by the agent, which holds only the
/// coordinator's public key.
pub trait TokenVerifier {
    /// Verify `signed`'s signature against the trusted public key and return
    /// the decoded [`CapabilityToken`]. Does **not** check expiry or ops — the
    /// caller does that against the operation being authorised.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::BadSignature`] if verification fails, or a decode
    /// error if the token bytes are malformed.
    fn verify(&self, signed: &SignedToken) -> Result<CapabilityToken, TokenError>;
}

/// Errors arising from capability-token handling.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    /// The token could not be encoded to its signing bytes.
    #[error("failed to encode token: {0}")]
    Encode(String),

    /// The token bytes could not be decoded.
    #[error("failed to decode token: {0}")]
    Decode(String),

    /// The wire bytes were too short to contain a signature.
    #[error("signed token too short: {len} bytes (need at least {min})")]
    Truncated {
        /// Actual length supplied.
        len: usize,
        /// Minimum required length.
        min: usize,
    },

    /// The signature did not verify against the trusted public key.
    #[error("token signature verification failed")]
    BadSignature,

    /// The token has expired.
    #[error("token expired at {expires} (now {now})")]
    Expired {
        /// The token's expiry (epoch seconds).
        expires: u64,
        /// The current time (epoch seconds).
        now: u64,
    },

    /// The token does not grant the requested operation.
    #[error("token does not allow operation {op:?}")]
    OpNotAllowed {
        /// The operation that was denied.
        op: AllowedOp,
    },

    /// The token's lease or board did not match what was expected.
    #[error("token scope mismatch: {what}")]
    ScopeMismatch {
        /// What part of the scope mismatched.
        what: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CapabilityToken {
        CapabilityToken {
            lease: LeaseId(7),
            board: BoardId("nrf52840-dk-3".to_owned()),
            allowed_ops: vec![AllowedOp::Flash, AllowedOp::Attach],
            expires: 1_780_000_000,
        }
    }

    #[test]
    fn signing_bytes_are_deterministic() {
        let t = sample();
        let a = t.serialize_for_signing().unwrap();
        let b = t.serialize_for_signing().unwrap();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn allows_and_validity() {
        let t = sample();
        assert!(t.allows(AllowedOp::Flash));
        assert!(!t.allows(AllowedOp::Erase));
        assert!(t.is_valid_at(t.expires - 1));
        assert!(!t.is_valid_at(t.expires));
    }

    #[test]
    fn signed_token_wire_roundtrip() {
        let t = sample();
        let token_bytes = t.serialize_for_signing().unwrap();
        let signature = [0xABu8; SIGNATURE_LEN];
        let signed = SignedToken {
            token_bytes,
            signature,
        };
        let wire = signed.to_wire();
        let back = SignedToken::from_wire(&wire).unwrap();
        assert_eq!(signed, back);
        assert_eq!(back.decode_token().unwrap(), t);
    }

    #[test]
    fn from_wire_rejects_truncated() {
        let err = SignedToken::from_wire(&[0u8; 10]).unwrap_err();
        assert_eq!(
            err,
            TokenError::Truncated {
                len: 10,
                min: SIGNATURE_LEN
            }
        );
    }
}
