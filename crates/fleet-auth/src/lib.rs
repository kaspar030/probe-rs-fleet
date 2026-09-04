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
        /// Register the calling machine as a node in the caller's own org,
        /// proving membership with a user session token (architecture §4.2
        /// path 2, §6.4). This is what `probe-rs-fleet share` sends.
        ///
        /// Self-approving: **membership is sufficient**. There is deliberately
        /// no admin approval step at v1 (a device-approval gate can be added
        /// later without a data migration).
        SelfRegister {
            /// The caller's session token (`prfs1_…`).
            session_token: String,
            /// The node's self-chosen name. Advisory; it names the row.
            node_name: String,
            /// Optional selection tags to record on the node.
            #[serde(default)]
            tags: Vec<String>,
            /// Probe adoption policy for this node (`auto` | `declared`).
            ///
            /// Absent means the endpoint's default for this grant, which is
            /// `auto` — a machine its owner is deliberately sharing wants its
            /// probes usable without a second edit. An unrecognised value is a
            /// `400`, never a silent default.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            adopt: Option<String>,
        },
    }

    /// A successful token exchange.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TokenResponse {
        /// The minted token.
        pub token: String,
        /// The node id the token authenticates as, for an `AuthKey` or
        /// `SelfRegister` grant.
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

    /// A request to `POST /auth/keys`, the authenticated auth-key surface.
    ///
    /// One route with an `action` tag rather than REST verbs, mirroring
    /// `grant_type` on [`TokenRequest`]: one handler, one client helper, and no
    /// key handle in a URL path (which proxies log).
    ///
    /// **The caller authenticates with `Authorization: Bearer <session token>`,
    /// not with a token in the body.** `/auth/token`'s grants are precisely
    /// *about* a credential in the body; this is an ordinary authenticated API
    /// call, so it goes through the coordinator's one authentication path and
    /// the org is taken from the session — a minted key can never exceed the
    /// caller's org.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "action", rename_all = "snake_case")]
    pub enum AuthKeyRequest {
        /// Mint an org-scoped node-enrollment key.
        Create {
            /// Selection tags to stamp onto nodes enrolled with the key.
            #[serde(default)]
            tags: Vec<String>,
            /// Time-to-live in seconds. Zero (never expires) is refused over
            /// the API, and the value is capped by the coordinator.
            ttl_secs: u64,
            /// Allow the key to enroll more than one node.
            #[serde(default)]
            multi_use: bool,
        },
        /// List the caller's org's auth keys (hashes only).
        List {},
        /// Revoke keys whose hash starts with `prefix`.
        Revoke {
            /// Hash prefix, from a [`AuthKeyList`]. At least 8 hex characters.
            prefix: String,
        },
    }

    /// A freshly minted auth key. **The only time the secret exists.**
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthKeyCreated {
        /// The key itself (`prffk1_…`). Stored nowhere, only its hash.
        pub key: String,
        /// Lowercase-hex SHA-256 of the key — the handle for revocation.
        pub key_hash: String,
        /// The org the key enrolls nodes into (the caller's own).
        pub org: String,
        /// Selection tags stamped onto nodes enrolled with it.
        pub tags: Vec<String>,
        /// Whether redeeming the key consumes it.
        pub single_use: bool,
        /// Expiry (epoch seconds). Always set on this path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires: Option<i64>,
    }

    /// One auth key as a listing shows it. Hash-only, never a secret.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthKeyInfo {
        /// Lowercase-hex SHA-256 of the key.
        pub key_hash: String,
        /// Selection tags stamped onto nodes enrolled with it.
        pub tags: Vec<String>,
        /// Whether redeeming the key consumes it.
        pub single_use: bool,
        /// Expiry (epoch seconds), or `None` for a key that never expires.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires: Option<i64>,
        /// When the key was consumed (epoch seconds), if it was.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub consumed_at: Option<i64>,
        /// When the key was minted (epoch seconds).
        pub created_at: i64,
        /// The user who minted it, or `None` for a shell-minted key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub created_by: Option<String>,
    }

    /// The org's auth keys, newest first.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthKeyList {
        /// The org listed (the caller's own).
        pub org: String,
        /// The keys, newest first.
        pub keys: Vec<AuthKeyInfo>,
    }

    /// The outcome of a revocation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthKeyRevoked {
        /// The org the keys were revoked from.
        pub org: String,
        /// The hashes deleted.
        pub revoked: Vec<String>,
    }

    /// A rejected token exchange.
    ///
    /// Deliberately coarse: the body never distinguishes "unknown" from
    /// "expired" (no oracle). Detail lives in the coordinator's audit log.
    ///
    /// `/auth/keys` reuses this shape, including for `ambiguous_prefix`: the
    /// candidate hashes are *not* on the wire, because [`ErrorResponse`] is the
    /// one rejection body and widening it would touch every caller. The CLI
    /// turns the code into "run `auth-key list` and use a longer prefix".
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ErrorResponse {
        /// A short machine-readable code (`invalid_grant`, `invalid_request`).
        pub error: String,
    }
}
