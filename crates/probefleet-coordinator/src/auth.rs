//! Capability-token signing (ed25519).
//!
//! The coordinator is the **signer**: it holds the ed25519 private key and
//! mints a [`probefleet_proto::token::SignedToken`] for every lease it grants. The
//! node (task 1712) holds only the public key and verifies the signature
//! locally — no per-operation coordinator round-trip (architecture §6).
//!
//! This module is intentionally thin: the token *shape*, the canonical signing
//! bytes ([`CapabilityToken::serialize_for_signing`]), the on-wire framing
//! ([`SignedToken`]), and the [`TokenSigner`] trait all live in
//! [`probefleet_proto::token`]. Here we only (a) hold the signing key, (b) implement
//! [`TokenSigner`] with ed25519, and (c) build a [`LeaseGrant`]'s `token` field
//! from a scheduler [`GrantedLease`].

use ed25519_dalek::{Signer, SigningKey};
use hmac::{Mac as _, SimpleHmac};
use sha2::Sha256;

use probefleet_core::scheduler::GrantedLease;
use probefleet_proto::ids::{BoardRef, LeaseId};
use probefleet_proto::lease::LeaseGrant;
use probefleet_proto::token::{
    AllowedOp, CapabilityToken, SignedToken, TokenError, TokenSigner, TokenVerifier,
};

/// Domain separator for [`serve_token`], so no other HMAC over the signing seed
/// can ever collide with it. Frozen wire label: changing it changes every
/// derived serve token.
const SERVE_TOKEN_LABEL: &[u8] = b"probe-rs-fleet/serve-token/v1";

/// The `probe-rs serve` user token for one lease's board session:
/// `HMAC-SHA256(seed, label || lease || board)`, lowercase hex.
///
/// This is the **loopback** credential, not an authorization one: the node
/// writes it into the board's `.probe-rs.toml` and the sidecar exports it as
/// `PROBE_RS_REMOTE_TOKEN`, so the genuine probe-rs client authenticates to the
/// `probe-rs serve` process the node runs for it. Authorization stays with the
/// per-channel capability token, which the node verifies at every open.
///
/// **Derived, not stored.** It mirrors
/// the old browser CSRF key: an HMAC over the signing seed the
/// coordinator already holds. That buys the property that actually matters —
/// stable for the whole lease, across every channel open, with no per-lease map
/// to populate, expire, or forget to clean up in `tear_down_lease`,
/// `sweep_once` and the revocation cascade.
///
/// Caveat, deliberately accepted: lease ids restart at 1 on a coordinator
/// reboot, so a post-restart lease can re-derive a pre-restart token. Exposure
/// is nil — the serve port is loopback-only, every path to it is authorized by
/// the coordinator per channel, and the process the old token addressed was
/// killed when its lease was released.
///
/// # Panics
///
/// Never in practice: `SimpleHmac` accepts a key of any length, so the only
/// fallible step cannot fail for a 32-byte seed.
#[must_use]
pub fn serve_token(seed: &[u8; 32], lease: LeaseId, board: &BoardRef) -> String {
    let mut mac =
        <SimpleHmac<Sha256>>::new_from_slice(seed).expect("SimpleHmac accepts a key of any length");
    mac.update(SERVE_TOKEN_LABEL);
    mac.update(&lease.0.to_be_bytes());
    mac.update(board.to_string().as_bytes());
    let bytes: [u8; 32] = mac.finalize().into_bytes().into();
    hex32(&bytes)
}

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
    /// This is the value nodes pin in their config to verify tokens.
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
            node: granted.node.clone(),
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

/// The coordinator can verify the tokens it minted.
///
/// Normally only the node verifies (it holds the public key and nothing else),
/// which is the point of §6.3. The coordinator needs it for exactly one route:
/// `GET /delegate`, where a sandboxed node presents a capability token as its
/// *only* credential. Deriving the verifying key from the signing key it
/// already holds means no new key material and no new configuration.
impl TokenVerifier for Ed25519Signer {
    fn verify(&self, signed: &SignedToken) -> Result<CapabilityToken, TokenError> {
        use ed25519_dalek::Verifier as _;
        let sig = ed25519_dalek::Signature::from_bytes(&signed.signature);
        self.key
            .verifying_key()
            .verify(&signed.token_bytes, &sig)
            .map_err(|_| TokenError::BadSignature)?;
        signed.decode_token()
    }
}

/// Every operation a board supports.
///
/// Until architecture §6.5 landed this was the *default* op set a lease minted:
/// v1 had no attenuation, so every token carried everything. It has no
/// production caller any more — [`crate::authz::board_access`] computes the ops
/// from the caller's [`probefleet_core::access::Access`] at every mint, and it is
/// *ownership* that expands to the full set. Kept as the name for "all of
/// them", and deliberately renamed so nothing reads it as a fallback somebody
/// still falls back to.
#[must_use]
pub fn all_allowed_ops() -> Vec<AllowedOp> {
    AllowedOp::all()
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
    use probefleet_proto::ids::{BoardRef, LeaseId, OrgId};

    /// RFC 8032 ed25519 test-vector seed. The node's verifier tests
    /// (`probefleet-agent/src/token.rs`) use the same seed, so a token signed here
    /// verifies there: shared cross-crate test vector.
    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_seed(&TEST_SEED)
    }

    /// The fleet-unique board key a token is scoped to, with a
    /// **production-shaped** node id.
    ///
    /// `state.rs::node_id_for` namespaces node ids by org, so the node half is
    /// `"{org}/{name}"`. Built via that constructor rather than a literal, and
    /// kept in step with `probefleet-agent/src/token.rs`'s `board()` — the two are a
    /// shared cross-crate vector, so a token signed here verifies there.
    fn test_board() -> BoardRef {
        let org = OrgId("acme".to_owned());
        let node = crate::state::node_id_for(&org, "rpi-1");
        BoardRef::new(org, node, "nrf52840-dk-3")
    }

    fn token() -> CapabilityToken {
        CapabilityToken {
            lease: LeaseId(7),
            board: test_board(),
            allowed_ops: vec![AllowedOp::Flash, AllowedOp::Attach],
            expires: 1_780_000_000,
        }
    }

    /// Verify a signed token the way the node does (signature check only).
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
        let org = OrgId("acme".to_owned());
        let node = crate::state::node_id_for(&org, "node-a");
        let granted = GrantedLease {
            lease: LeaseId(11),
            board: BoardRef::new(org.clone(), node.clone(), "b1"),
            node,
            holder: crate::subject::user_key(forgs::UserId::from_parts(1, 1)),
            expires: 2_000_000_000,
        };
        let grant = s.grant_to_wire(&granted, all_allowed_ops()).unwrap();
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
    fn the_signer_verifies_its_own_tokens_and_rejects_others() {
        let s = signer();
        let signed = s.sign(&token()).unwrap();
        assert_eq!(s.verify(&signed).unwrap(), token());

        // Another key's token does not verify — which is what makes `/delegate`
        // safe to authenticate with nothing but a capability token.
        let other = Ed25519Signer::from_seed(&[7u8; 32]);
        let foreign = other.sign(&token()).unwrap();
        assert_eq!(s.verify(&foreign).unwrap_err(), TokenError::BadSignature);

        let mut tampered = signed.clone();
        tampered.token_bytes[0] ^= 0xff;
        assert_eq!(s.verify(&tampered).unwrap_err(), TokenError::BadSignature);
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
