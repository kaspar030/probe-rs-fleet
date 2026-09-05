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

use crate::ids::{BoardRef, LeaseId};

/// One capability a token may grant. A token carries the set of operations its
/// holder is allowed to perform against the leased board.
///
/// # Where each op is actually enforced
///
/// Be honest about this, because "the agent enforces `--ops`" is true for only
/// two of the six labels:
///
/// | op | enforced where |
/// |---|---|
/// | [`AllowedOp::Attach`] | agent, at data-channel open (`ChannelKind::Data`) |
/// | [`AllowedOp::Gdb`] | agent, at gdb-channel open (`ChannelKind::Gdb`) |
/// | [`AllowedOp::PowerCycle`] | coordinator, in the operator power-cycle handler |
/// | [`AllowedOp::Flash`], [`AllowedOp::Erase`], [`AllowedOp::Reset`] | **not enforced** |
///
/// Flash, erase and reset all happen *in band*, as probe-rs RPC inside an open
/// data channel, which the fleet relays without parsing. Recording them is
/// intent and audit, not a control. Enforcing them would mean the agent parsing
/// probe-rs postcard-rpc frames; that is deliberately out of scope.
///
/// The practical consequence, handled by [`normalize_ops`]: a token with
/// `Flash` but not `Attach` cannot open a data channel at all, so it cannot
/// flash either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AllowedOp {
    /// Flash/download firmware to the target. In-band; not enforced.
    Flash,
    /// Attach to a running target (RTT, monitor). Enforced by the agent at
    /// data-channel open.
    Attach,
    /// Open a gdb session (raw-TCP tunnel; see architecture §4.2 gap).
    /// Enforced by the agent at gdb-channel open.
    Gdb,
    /// Reset the target. In-band; not enforced.
    Reset,
    /// Erase the target's flash. In-band; not enforced.
    Erase,
    /// Cut/restore USB power to the board. Enforced coordinator-side.
    PowerCycle,
}

impl AllowedOp {
    /// Every operation, in canonical order.
    #[must_use]
    pub fn all() -> Vec<AllowedOp> {
        vec![
            AllowedOp::Flash,
            AllowedOp::Attach,
            AllowedOp::Gdb,
            AllowedOp::Reset,
            AllowedOp::Erase,
            AllowedOp::PowerCycle,
        ]
    }

    /// The CLI/DB label for this op.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AllowedOp::Flash => "flash",
            AllowedOp::Attach => "attach",
            AllowedOp::Gdb => "gdb",
            AllowedOp::Reset => "reset",
            AllowedOp::Erase => "erase",
            AllowedOp::PowerCycle => "power-cycle",
        }
    }

    /// Parse an op from its label. `power_cycle` and `powercycle` are accepted
    /// as spellings of `power-cycle`.
    #[must_use]
    pub fn from_label(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "flash" => Some(AllowedOp::Flash),
            "attach" => Some(AllowedOp::Attach),
            "gdb" => Some(AllowedOp::Gdb),
            "reset" => Some(AllowedOp::Reset),
            "erase" => Some(AllowedOp::Erase),
            "power-cycle" | "power_cycle" | "powercycle" => Some(AllowedOp::PowerCycle),
            _ => None,
        }
    }

    /// Whether the fleet actually *enforces* this op somewhere, as opposed to
    /// merely recording it. See the type docs for the table.
    #[must_use]
    pub fn is_enforced(self) -> bool {
        matches!(
            self,
            AllowedOp::Attach | AllowedOp::Gdb | AllowedOp::PowerCycle
        )
    }

    /// Whether this op is carried in band inside an open data channel, and
    /// therefore needs [`AllowedOp::Attach`] to be usable at all.
    #[must_use]
    pub fn needs_data_channel(self) -> bool {
        matches!(self, AllowedOp::Flash | AllowedOp::Erase | AllowedOp::Reset)
    }
}

impl std::fmt::Display for AllowedOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse a comma-separated op list (`"flash,attach"`).
///
/// # Errors
///
/// Returns the first unrecognised label.
pub fn parse_ops(s: &str) -> Result<Vec<AllowedOp>, String> {
    let mut out = Vec::new();
    for label in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let op = AllowedOp::from_label(label).ok_or_else(|| label.to_owned())?;
        out.push(op);
    }
    Ok(out)
}

/// Canonicalise an op set: sort, dedup, and **add [`AllowedOp::Attach`]** if a
/// data-plane op (flash/erase/reset) is present without it.
///
/// Without the implication, `--ops flash` mints a token that cannot open a data
/// channel and is therefore useless — a silent dud from a security verb, which
/// is worse than an error. With it, `--ops flash` means what the user meant.
/// Callers should tell the user when the implication fired.
#[must_use]
pub fn normalize_ops(ops: Vec<AllowedOp>) -> Vec<AllowedOp> {
    let mut ops = ops;
    if ops.iter().any(|o| o.needs_data_channel()) && !ops.contains(&AllowedOp::Attach) {
        ops.push(AllowedOp::Attach);
    }
    ops.sort_unstable();
    ops.dedup();
    ops
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
    ///
    /// Fleet-unique by construction (`(org, node, name)`), so a token minted
    /// for one org's `nrf52840-dk` cannot be replayed against another org's
    /// same-named board.
    pub board: BoardRef,
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
    use crate::ids::{AgentId, OrgId};

    fn sample() -> CapabilityToken {
        CapabilityToken {
            lease: LeaseId(7),
            board: BoardRef::new(
                OrgId("acme".to_owned()),
                AgentId("rpi-1".to_owned()),
                "nrf52840-dk-3",
            ),
            allowed_ops: vec![AllowedOp::Flash, AllowedOp::Attach],
            expires: 1_780_000_000,
        }
    }

    #[test]
    fn op_labels_round_trip_and_reject_junk() {
        for op in AllowedOp::all() {
            assert_eq!(AllowedOp::from_label(op.as_str()), Some(op));
            assert_eq!(AllowedOp::from_label(&op.to_string().to_uppercase()), Some(op));
        }
        assert_eq!(AllowedOp::from_label("power_cycle"), Some(AllowedOp::PowerCycle));
        assert_eq!(AllowedOp::from_label("root"), None);
    }

    #[test]
    fn parse_ops_takes_a_comma_list() {
        assert_eq!(
            parse_ops("flash, attach").unwrap(),
            vec![AllowedOp::Flash, AllowedOp::Attach]
        );
        assert_eq!(parse_ops("").unwrap(), vec![]);
        assert_eq!(parse_ops("flash,nope").unwrap_err(), "nope");
    }

    /// `--ops flash` alone would mint a token that cannot open a data channel,
    /// and therefore cannot flash. Adding `Attach` is what stops the verb from
    /// silently producing a dud.
    #[test]
    fn normalize_adds_attach_for_in_band_ops() {
        assert_eq!(
            normalize_ops(vec![AllowedOp::Flash]),
            vec![AllowedOp::Flash, AllowedOp::Attach]
        );
        assert_eq!(
            normalize_ops(vec![AllowedOp::Erase]),
            vec![AllowedOp::Attach, AllowedOp::Erase]
        );
        assert_eq!(
            normalize_ops(vec![AllowedOp::Reset]),
            vec![AllowedOp::Attach, AllowedOp::Reset]
        );
        // Ops that stand on their own are left alone.
        assert_eq!(normalize_ops(vec![AllowedOp::Gdb]), vec![AllowedOp::Gdb]);
        assert_eq!(
            normalize_ops(vec![AllowedOp::PowerCycle]),
            vec![AllowedOp::PowerCycle]
        );
        // Sorted and deduped.
        assert_eq!(
            normalize_ops(vec![AllowedOp::Attach, AllowedOp::Flash, AllowedOp::Attach]),
            vec![AllowedOp::Flash, AllowedOp::Attach]
        );
        assert_eq!(normalize_ops(vec![]), vec![]);
    }

    /// The enforcement table in the type docs, asserted so the docs cannot
    /// drift from the code.
    #[test]
    fn only_three_ops_are_actually_enforced() {
        let enforced: Vec<AllowedOp> = AllowedOp::all()
            .into_iter()
            .filter(|o| o.is_enforced())
            .collect();
        assert_eq!(
            enforced,
            vec![AllowedOp::Attach, AllowedOp::Gdb, AllowedOp::PowerCycle]
        );
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
