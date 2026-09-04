//! Capability-token signing (ed25519).
//!
//! The coordinator is the **signer**: it holds the ed25519 private key and
//! mints a [`fleet_proto::token::SignedToken`] for every lease it grants. The
//! agent (task 1712) holds only the public key and verifies the signature
//! locally — no per-operation coordinator round-trip (architecture §6).
//!
//! This module is intentionally thin: the token *shape*, the canonical signing
//! bytes ([`CapabilityToken::serialize_for_signing`]), the on-wire framing
//! ([`SignedToken`]), and the [`TokenSigner`] trait all live in
//! [`fleet_proto::token`]. Here we only (a) hold the signing key, (b) implement
//! [`TokenSigner`] with ed25519, and (c) build a [`LeaseGrant`]'s `token` field
//! from a scheduler [`GrantedLease`].

use ed25519_dalek::{Signer, SigningKey};

use fleet_core::scheduler::GrantedLease;
use fleet_proto::lease::LeaseGrant;
use fleet_proto::token::{
    AllowedOp, CapabilityToken, SignedToken, TokenError, TokenSigner,
};

/// Signs capability tokens with the coordinator's ed25519 private key.
#[derive(Clone)]
pub struct Ed25519Signer {
    key: SigningKey,
}

impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key material.
        f.debug_struct("Ed25519Signer")
            .field("public_key", &hex32(&self.key.verifying_key().to_bytes()))
            .finish()
    }
}

impl Ed25519Signer {
    /// Build a signer from a 32-byte ed25519 secret seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// The coordinator's 32-byte ed25519 **public** key.
    ///
    /// This is the value agents pin in their config to verify tokens.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Sign `token` and return its wire bytes (`token_bytes || signature`).
    ///
    /// This is what goes in [`LeaseGrant::token`].
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if the token cannot be encoded.
    pub fn sign_to_wire(&self, token: &CapabilityToken) -> Result<Vec<u8>, TokenError> {
        Ok(self.sign(token)?.to_wire())
    }

    /// Build a wire [`LeaseGrant`] from a scheduler [`GrantedLease`].
    ///
    /// Mints a capability token scoped to `{lease, board, allowed_ops}` with the
    /// grant's `expires`, signs it, and frames the signed bytes into the grant's
    /// `token` field.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if the token cannot be encoded.
    pub fn grant_to_wire(
        &self,
        granted: &GrantedLease,
        allowed_ops: Vec<AllowedOp>,
    ) -> Result<LeaseGrant, TokenError> {
        let token = CapabilityToken {
            lease: granted.lease,
            board: granted.board.clone(),
            allowed_ops,
            expires: granted.expires,
        };
        let wire = self.sign_to_wire(&token)?;
        Ok(LeaseGrant {
            lease: granted.lease,
            board: granted.board.clone(),
            agent: granted.agent.clone(),
            holder: granted.holder.clone(),
            expires: granted.expires,
            token: wire,
        })
    }
}

impl TokenSigner for Ed25519Signer {
    fn sign(&self, token: &CapabilityToken) -> Result<SignedToken, TokenError> {
        let token_bytes = token.serialize_for_signing()?;
        let signature = self.key.sign(&token_bytes).to_bytes();
        Ok(SignedToken {
            token_bytes,
            signature,
        })
    }
}

/// The default operation set granted by a lease in v1: every operation.
///
/// Finer-grained scoping (per-request `allowed_ops`) is a future extension; for
/// now a lease authorises the full set of board operations.
#[must_use]
pub fn default_allowed_ops() -> Vec<AllowedOp> {
    vec![
        AllowedOp::Flash,
        AllowedOp::Attach,
        AllowedOp::Gdb,
        AllowedOp::Reset,
        AllowedOp::Erase,
        AllowedOp::PowerCycle,
    ]
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};
    use fleet_proto::ids::{AgentId, BoardRef, LeaseId, OrgId, Subject, SubjectKind};

    /// RFC 8032 ed25519 test-vector seed. The agent's verifier tests
    /// (`fleet-agent/src/token.rs`) use the same seed, so a token signed here
    /// verifies there: shared cross-crate test vector.
    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_seed(&TEST_SEED)
    }

    fn test_board() -> BoardRef {
        BoardRef::new(
            OrgId("acme".to_owned()),
            AgentId("rpi-1".to_owned()),
            "nrf52840-dk-3",
        )
    }

    fn token() -> CapabilityToken {
        CapabilityToken {
            lease: LeaseId(7),
            board: test_board(),
            allowed_ops: vec![AllowedOp::Flash, AllowedOp::Attach],
            expires: 1_780_000_000,
        }
    }

    /// Verify a signed token the way the agent does (signature check only).
    fn verify(pubkey: &[u8; 32], signed: &SignedToken) -> Result<CapabilityToken, TokenError> {
        let key = VerifyingKey::from_bytes(pubkey).map_err(|_| TokenError::BadSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&signed.signature);
        key.verify(&signed.token_bytes, &sig)
            .map_err(|_| TokenError::BadSignature)?;
        signed.decode_token()
    }

    #[test]
    fn sign_verify_roundtrip() {
        let s = signer();
        let t = token();
        let signed = s.sign(&t).unwrap();
        let back = verify(&s.public_key_bytes(), &signed).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn tampered_token_rejected() {
        let s = signer();
        let mut signed = s.sign(&token()).unwrap();
        // Flip a byte in the claim bytes.
        signed.token_bytes[0] ^= 0xff;
        let err = verify(&s.public_key_bytes(), &signed).unwrap_err();
        assert_eq!(err, TokenError::BadSignature);
    }

    #[test]
    fn tampered_signature_rejected() {
        let s = signer();
        let mut signed = s.sign(&token()).unwrap();
        signed.signature[0] ^= 0xff;
        let err = verify(&s.public_key_bytes(), &signed).unwrap_err();
        assert_eq!(err, TokenError::BadSignature);
    }

    #[test]
    fn wrong_key_rejected() {
        let s = signer();
        let signed = s.sign(&token()).unwrap();
        let other = Ed25519Signer::from_seed(&[7u8; 32]);
        let err = verify(&other.public_key_bytes(), &signed).unwrap_err();
        assert_eq!(err, TokenError::BadSignature);
    }

    #[test]
    fn grant_to_wire_produces_verifiable_token() {
        let s = signer();
        let granted = GrantedLease {
            lease: LeaseId(11),
            board: BoardRef::new(
                OrgId("acme".to_owned()),
                AgentId("agent-a".to_owned()),
                "b1",
            ),
            agent: AgentId("agent-a".to_owned()),
            holder: Subject::new(OrgId("acme".to_owned()), SubjectKind::User, "alice"),
            expires: 2_000_000_000,
        };
        let grant = s.grant_to_wire(&granted, default_allowed_ops()).unwrap();
        assert_eq!(grant.lease, granted.lease);
        assert_eq!(grant.board, granted.board);
        assert_eq!(grant.expires, granted.expires);

        let signed = SignedToken::from_wire(&grant.token).unwrap();
        let tok = verify(&s.public_key_bytes(), &signed).unwrap();
        assert_eq!(tok.lease, granted.lease);
        assert_eq!(tok.board, granted.board);
        assert_eq!(tok.expires, granted.expires);
        assert!(tok.allows(AllowedOp::Flash));
        assert!(tok.is_valid_at(granted.expires - 1));
        assert!(!tok.is_valid_at(granted.expires));
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let s = signer();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("public_key"));
        // The seed's first byte rendered as hex must not appear as a "secret".
        assert!(!dbg.contains("SigningKey"));
    }
}
