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
pub mod user_code;
pub mod verify;

/// GitHub Actions workload identity (feature `oidc`).
///
/// Off by default, and `fleet-coordinator` is the only crate that enables it:
/// `jsonwebtoken/rust_crypto` drags in `rsa`, `p256`, `p384`, `ed25519-dalek`
/// and friends, and this crate's other consumer path ends up in the Raspberry
/// Pi binary (see `docs/cross-compiling.md`). Only the coordinator verifies a
/// JWT.
#[cfg(feature = "oidc")]
pub mod oidc;

#[cfg(feature = "client")]
pub mod github;
#[cfg(feature = "client")]
pub mod http_client;

pub use rotation::{should_rotate, RotationPolicy};
pub use store::{AuthKeyRecord, NodeRecord, SessionRecord, TokenStore, WorkloadRecord};
pub use token::{OpaqueToken, TokenError, TokenHash, TokenKind};
pub use verify::{authenticate, AuthError, Authenticated};

/// Wire types for the `POST /auth/token` endpoint (architecture §3.5).
///
/// Defined once and shared by the coordinator handler and the client, so the
/// contract cannot drift between the two ends. JSON (not postcard) because this
/// surface must be curl-able and proxy-friendly; the WS planes stay postcard.
pub mod api {
    use serde::{Deserialize, Serialize};

    /// `auth_key.purpose` for an older peer that does not send the field.
    ///
    /// Node enrollment is the historical meaning, so an absent field must keep
    /// meaning exactly that — a `ci` default would silently reinterpret every
    /// existing key as a board-access credential.
    fn default_auth_key_purpose() -> String {
        "node".to_owned()
    }

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
        /// Exchange a **GitHub Actions OIDC token** for a per-job workload
        /// token (architecture §6.7).
        ///
        /// This is the zero-secrets CI path: the runner holds no credential at
        /// all, it asks GitHub's own token service for a signed JWT (which
        /// needs `permissions: id-token: write` and nothing else) and hands
        /// that here. The coordinator verifies the signature against the
        /// issuer's JWKS and looks for an explicit **per-repo** grant.
        GithubOidc {
            /// The OIDC JWT, as `ACTIONS_ID_TOKEN_REQUEST_URL` returned it.
            oidc_token: String,
        },
        /// Redeem a **workload auth key** for a workload token: the fallback
        /// for a runner with no workload identity of its own (a self-hosted
        /// Jenkins box).
        ///
        /// Honestly the weak path — a long-lived bearer secret living in
        /// somebody else's CI configuration. It is bounded by being org-scoped,
        /// selector-scoped, op-scoped, expiring and revocable, and that is all.
        WorkloadKey {
            /// The workload auth key (`prffk1_…`, minted with `--purpose ci`).
            auth_key: String,
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
        ///
        /// For a **workload** token this is not a scope: a workload belongs to
        /// no org (see [`TokenResponse::orgs`]). It carries the first, sorted,
        /// granting org purely so the CLI has something to print.
        pub org: String,
        /// Every org that granted this workload access, for provenance.
        ///
        /// Empty for every other grant type. A workload is **not a member** of
        /// any of these: it reaches their boards through explicit per-repo
        /// grants and nothing else.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub orgs: Vec<String>,
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
            /// What the key is for: `node` (the default — enroll a machine
            /// that *offers* probes) or `ci` (architecture §6.7 — a runner that
            /// *leases* them).
            ///
            /// Absent means `node`, so an older client's request keeps its
            /// exact previous meaning. An unrecognised value is a `400`, never
            /// a silent default: the two purposes are different credentials.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            purpose: Option<String>,
            /// For a `ci` key: the operations its synthesised grant confers.
            /// Empty means the coordinator's default set.
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            ops: Vec<String>,
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
        /// What the key is for (`node` | `ci`), echoed so the CLI can print it
        /// and an operator can see which credential they just minted.
        #[serde(default = "default_auth_key_purpose")]
        pub purpose: String,
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
        /// What the key is for (`node` | `ci`).
        ///
        /// Listed because revoking a `ci` key also tears down the grant it
        /// synthesised, and therefore live leases — an operator must be able to
        /// see which kind they are about to revoke.
        #[serde(default = "default_auth_key_purpose")]
        pub purpose: String,
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

    /// Begin an approval-pending node registration (architecture §4.2 rung 3).
    ///
    /// Unauthenticated by construction: the machine sending it has no
    /// credential of any kind — that is what the ceremony is for. Everything
    /// in it is therefore **attacker-controlled**, and the coordinator
    /// validates `node_name` and each tag against a conservative charset
    /// before storing them, because they are later rendered into a human
    /// approver's terminal.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NodeRegisterStartRequest {
        /// The machine's self-chosen name. Advisory; it names the row.
        pub node_name: String,
        /// Optional selection tags to record on the node.
        #[serde(default)]
        pub tags: Vec<String>,
        /// Probe adoption policy (`auto` | `declared`). Absent means this
        /// grant's default, `auto` — a human is approving this enrollment
        /// live, which is the `share` situation rather than the disk-image
        /// one. An unrecognised value is a `400`, never a silent default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub adopt: Option<String>,
    }

    /// The pending registration, as the enrolling machine sees it.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NodeRegisterStartResponse {
        /// The short code a human types into `node approve`, hyphenated for
        /// display (`ABCD-1234`).
        pub user_code: String,
        /// This machine's poll credential (`prfnd1_…`). Never presented as a
        /// connection credential; it is redeemed at `/node/register/poll`.
        pub device_secret: String,
        /// Where a human can read what to do (`<public_url>/node/approve`).
        ///
        /// Deliberately carries **no code**: the page reflects nothing, so it
        /// can never become a confused-deputy or injection surface. The code
        /// is printed separately by the enrolling machine, exactly as GitHub's
        /// device flow does.
        pub verification_uri: String,
        /// Minimum seconds between polls.
        pub interval: u64,
        /// Seconds until the pending registration expires.
        pub expires_in: u64,
    }

    /// A poll for the outcome of a pending node registration.
    ///
    /// Success is the ordinary [`TokenResponse`] — the same shape
    /// `SelfRegister` returns, because it is minted by the same code path.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NodeRegisterPollRequest {
        /// The device secret from [`NodeRegisterStartResponse`].
        pub device_secret: String,
    }

    /// What an approver is doing with a pending registration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum NodeApprovalDecision {
        /// Describe the pending registration without changing anything.
        ///
        /// The CLI always inspects first: an approver is granting hardware
        /// access in their org to a machine they cannot see, so they must be
        /// shown what they are approving (RFC 8628 §5.4, sharpened).
        Inspect,
        /// Bind the pending registration to the approver's org and user.
        Approve,
        /// Refuse it permanently.
        Deny,
    }

    /// An approval request, authenticated with `Authorization: Bearer <session>`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NodeApprovalRequest {
        /// The short code, in any spelling `fleet_auth::user_code::normalise`
        /// accepts.
        pub user_code: String,
        /// Inspect, approve or deny.
        pub decision: NodeApprovalDecision,
        /// Approve even though the requested node name already exists in the
        /// approver's org, re-credentialing (and thereby taking over) that
        /// node.
        ///
        /// Default `false`, and the refusal is enforced by the **handler**:
        /// the requesting machine chose `node_name` before any org existed, so
        /// without this guard an approver could be talked into silently
        /// handing over a production node.
        #[serde(default)]
        pub replace: bool,
    }

    /// A pending registration as an approver sees it.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NodeApprovalResponse {
        /// The code, hyphenated for display.
        pub user_code: String,
        /// The name the machine asked for. **Attacker-controlled**: render it
        /// defensively.
        pub node_name: String,
        /// The tags it asked for. Attacker-controlled, as above.
        pub tags: Vec<String>,
        /// The adoption policy it asked for (`auto` | `declared`).
        pub adopt: String,
        /// The source address the coordinator saw, if any.
        ///
        /// **Advisory.** Behind the expected reverse proxy this is the proxy's
        /// address, and `X-Forwarded-For` is deliberately not trusted — an
        /// unauthenticated header would let the requester choose what the
        /// approver sees, which is worse than showing nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source_ip: Option<String>,
        /// When the registration was started (epoch seconds).
        pub created_at: i64,
        /// When it expires (epoch seconds).
        pub expires: i64,
        /// The org this registration would join, or joined: **the approver's**
        /// org, on every decision including `Inspect`.
        ///
        /// Not the pending row's `org_id`, which is `NULL` until an approval
        /// binds it — answering "which org am I granting hardware access in?"
        /// only *after* the decision would put it on the wrong side of the
        /// confirmation. The whole response is approver-relative for the same
        /// reason `collides_with` is.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub org: Option<String>,
        /// `pending` | `approved` | `denied`.
        pub state: String,
        /// The existing node id this registration would re-credential, if the
        /// approver's org already has a node by the requested name.
        ///
        /// Resolved at `Inspect` time and not before: there is no org until
        /// approval, so the collision cannot be known any earlier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub collides_with: Option<String>,
    }
}
