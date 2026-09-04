//! Bearer-token primitives for probe-rs-fleet.
//!
//! Architecture revision 2 (§3.5, §6.2) replaces the private CA and mTLS client
//! certificates with **one credential model**: every principal — user, node,
//! workload — presents `Authorization: Bearer …` on the WebSocket upgrade (or on
//! the `/auth/*` HTTP surface), and the coordinator resolves that token to an
//! authenticated identity.
//!
//! This crate owns the token *format*, its *verification*, and the node-token
//! *rotation policy*. It deliberately does **not**:
//!
//! * mint a [`fleet_proto::ids::Subject`] — that stays in the coordinator, the
//!   only crate that knows about orgs and membership. Minting identities in a
//!   crate with no membership knowledge is exactly how tenancy holes appear (the
//!   same reasoning that kept it out of `fleet-tls`). [`verify::Authenticated`]
//!   carries org/kind/id and the coordinator builds the `Subject`.
//! * talk to a database — the coordinator implements [`store::TokenStore`].
//!
//! # Honest cost of bearer tokens
//!
//! A bearer token is a pure bearer credential: a leak is immediately usable,
//! unlike a private key that never left the host. Three mitigations bound the
//! window, and all three live here:
//!
//! * user **session** tokens are short-lived and refreshable;
//! * **node** tokens auto-rotate ([`rotation`]) over the established connection,
//!   so a leaked one has bounded value, and revocation is deleting the row;
//! * workload (CI) tokens are exchanged per job.
//!
//! There is deliberately **no mTLS fallback**.

#![allow(clippy::module_name_repetitions)]

pub mod rotation;
pub mod store;
pub mod token;
pub mod verify;

#[cfg(feature = "client")]
pub mod github;
#[cfg(feature = "client")]
pub mod http_client;

pub use rotation::{should_rotate, RotationPolicy};
pub use store::{AuthKeyRecord, NodeRecord, SessionRecord, TokenStore};
pub use token::{OpaqueToken, TokenError, TokenHash, TokenKind};
pub use verify::{authenticate, AuthError, Authenticated};

/// Wire types for the `POST /auth/token` endpoint (architecture §3.5).
///
/// Defined once and shared by the coordinator handler and the client, so the
/// contract cannot drift between the two ends. JSON (not postcard) because this
/// surface must be curl-able and proxy-friendly; the WS planes stay postcard.
pub mod api {
    use serde::{Deserialize, Serialize};

    /// A token-exchange request.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "grant_type", rename_all = "snake_case")]
    pub enum TokenRequest {
        /// Redeem a pre-minted org-scoped auth key for a node token.
        AuthKey {
            /// The auth key (`prffk1_…`).
            auth_key: String,
            /// The node's self-chosen name. Advisory: it names the row, it does
            /// not grant anything.
            node_name: String,
            /// Optional selection tags to record on the node.
            #[serde(default)]
            tags: Vec<String>,
        },
        /// Exchange a still-valid session token for a fresh one.
        Refresh {
            /// The current session token (`prfs1_…`).
            session_token: String,
        },
    }

    /// A successful token exchange.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TokenResponse {
        /// The minted token.
        pub token: String,
        /// The node id the token authenticates as, for an `AuthKey` grant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub node_id: Option<String>,
        /// The org the token belongs to.
        pub org: String,
        /// Expiry (epoch seconds), if the token has one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires: Option<u64>,
        /// Hex-encoded ed25519 public key of the coordinator's capability-token
        /// signer, so a freshly enrolled node can populate
        /// `coordinator_token_pubkey`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub coordinator_token_pubkey: Option<String>,
        /// The GitHub login the session belongs to, for the CLI's summary line.
        ///
        /// Display only — identity is keyed off the immutable numeric GitHub
        /// user id, never this string (a login can be renamed and reused).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub login: Option<String>,
    }

    /// A request to begin the GitHub device flow.
    ///
    /// Empty today: the CLI supplies nothing, because the OAuth app's client id
    /// and scope are the *coordinator's* (see `DeviceStartResponse`). The struct
    /// exists so a future field (a requested scope, say) is an additive change
    /// rather than a shape change.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct DeviceStartRequest {}

    /// The device-code grant, relayed from GitHub.
    ///
    /// `device_code` is handed straight back to the CLI and returned to the
    /// coordinator on each poll: brokering is **stateless**, so a coordinator
    /// restart mid-login is survivable and there is no expiry sweep to write.
    /// That is safe because the device code is exactly the credential the
    /// device-flow client is meant to hold, it is only redeemable with the
    /// coordinator's `client_id`, and the resulting GitHub access token never
    /// leaves the coordinator.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DeviceStartResponse {
        /// The opaque device code, presented back on each poll.
        pub device_code: String,
        /// The short code the human types into the browser.
        pub user_code: String,
        /// Where the human types it (`https://github.com/login/device`).
        pub verification_uri: String,
        /// Minimum seconds between polls.
        pub interval: u64,
        /// Seconds until the device code expires.
        pub expires_in: u64,
    }

    /// A poll for the outcome of a device flow.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DevicePollRequest {
        /// The device code from [`DeviceStartResponse`].
        pub device_code: String,
    }

    /// A rejected token exchange.
    ///
    /// Deliberately coarse: the body never distinguishes "unknown" from
    /// "expired" (no oracle). Detail lives in the coordinator's audit log.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ErrorResponse {
        /// A short machine-readable code (`invalid_grant`, `invalid_request`).
        pub error: String,
    }
}
