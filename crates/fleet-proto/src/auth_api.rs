//! JSON wire types for fleet's node-enrollment HTTP surface (`/node/*`).
//!
//! Generic identity endpoints (`/auth/*`: login, sessions, refresh, API keys,
//! the device flow) belong to forgs and are described by its crates. What is
//! left here is what only fleet knows about: turning a machine into a **node**.
//!
//! * `POST /node/register/start` → [`NodeRegisterStartRequest`] /
//!   [`NodeRegisterStartResponse`] (unauthenticated, approval-pending);
//! * `POST /node/register/poll` → [`NodeRegisterPollRequest`] /
//!   [`NodeRegisterPollResponse`];
//! * `POST /node/register/approve` → [`NodeApprovalRequest`] /
//!   [`NodeApprovalResponse`] (a user session);
//! * `POST /node/enroll` → [`NodeEnrollRequest`] / [`NodeTokenResponse`]
//!   (redeem a `node`-purpose API key);
//! * `POST /node/self-register` → [`SelfRegisterRequest`] /
//!   [`NodeTokenResponse`] (a user session; `probe-rs-fleet share`).
//!
//! Defined once and shared by the coordinator handler and the CLI, so the
//! contract cannot drift between the two ends. JSON (not postcard) because
//! this surface must be curl-able and proxy-friendly; the WS planes stay
//! postcard. Serde only — no I/O and no forgs dependency, so the CLI's node
//! path stays light.
//!
//! Every type carrying a secret implements [`Debug`] by hand with the secret
//! redacted, so a `tracing` line or a panic message can never leak one.

use std::fmt;

use serde::{Deserialize, Serialize};

const REDACTED: &str = "<redacted>";

/// Begin an approval-pending node registration (architecture §4.2 rung 3).
///
/// Unauthenticated by construction: the machine sending it has no credential
/// of any kind — that is what the ceremony is for. Everything in it is
/// therefore **attacker-controlled**, and the coordinator validates
/// `node_name` and each tag against a conservative charset before storing
/// them, because they are later rendered into a human approver's terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegisterStartRequest {
    /// The machine's self-chosen name. Advisory; it names the row.
    pub node_name: String,
    /// Optional selection tags to record on the node.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Probe adoption policy (`auto` | `declared`). Absent means this grant's
    /// default, `auto` — a human is approving this enrollment live, which is
    /// the `share` situation rather than the disk-image one. An unrecognised
    /// value is a `400`, never a silent default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adopt: Option<String>,
}

/// The pending registration, as the enrolling machine sees it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegisterStartResponse {
    /// The short code a human types into `node approve`, hyphenated for
    /// display (`ABCD-1234`).
    pub user_code: String,
    /// This machine's poll credential. Never presented as a connection
    /// credential; it is redeemed at `/node/register/poll`.
    pub device_secret: String,
    /// Where a human can read what to do (`<public_url>/node/approve`).
    ///
    /// Deliberately carries **no code**: the page reflects nothing, so it can
    /// never become a confused-deputy or injection surface. The code is
    /// printed separately by the enrolling machine.
    pub verification_uri: String,
    /// Minimum seconds between polls.
    pub interval: u64,
    /// Seconds until the pending registration expires.
    pub expires_in: u64,
}

impl fmt::Debug for NodeRegisterStartResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeRegisterStartResponse")
            .field("user_code", &self.user_code)
            .field("device_secret", &REDACTED)
            .field("verification_uri", &self.verification_uri)
            .field("interval", &self.interval)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// A poll for the outcome of a pending node registration.
///
/// Success is a [`NodeRegisterPollResponse`] — a [`NodeTokenResponse`], the
/// same shape `/node/enroll` and `/node/self-register` return.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegisterPollRequest {
    /// The device secret from [`NodeRegisterStartResponse`].
    pub device_secret: String,
}

impl fmt::Debug for NodeRegisterPollRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeRegisterPollRequest")
            .field("device_secret", &REDACTED)
            .finish()
    }
}

/// A freshly minted node credential: what every node-enrollment path returns
/// on success.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTokenResponse {
    /// The node token (`prfn1_…`), presented on the `/agent` upgrade.
    pub token: String,
    /// The node id the token authenticates as (`<org id>/<name>`).
    pub node_id: String,
    /// The org the node belongs to (its namespace id).
    pub org: String,
    /// The org's path (display name), for the CLI's summary line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
    /// Hex-encoded ed25519 public key of the coordinator's capability-token
    /// signer, so a freshly enrolled node can populate
    /// `coordinator_token_pubkey`.
    pub coordinator_token_pubkey: String,
}

impl fmt::Debug for NodeTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeTokenResponse")
            .field("token", &REDACTED)
            .field("node_id", &self.node_id)
            .field("org", &self.org)
            .field("org_name", &self.org_name)
            .field("coordinator_token_pubkey", &self.coordinator_token_pubkey)
            .finish()
    }
}

/// A successful `/node/register/poll`: the approved node's credential.
pub type NodeRegisterPollResponse = NodeTokenResponse;

/// Redeem a `node`-purpose API key for a node token (`POST /node/enroll`).
///
/// The key's namespace is the org the node joins, and its payload carries the
/// selection tags stamped onto the node — the enrolling machine cannot choose
/// either.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEnrollRequest {
    /// The API key (`prfk1_…`, minted with purpose `node`).
    pub auth_key: String,
    /// The node's self-chosen name. Advisory: it names the row, it does not
    /// grant anything.
    pub node_name: String,
}

impl fmt::Debug for NodeEnrollRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeEnrollRequest")
            .field("auth_key", &REDACTED)
            .field("node_name", &self.node_name)
            .finish()
    }
}

/// Register the calling machine as a node, proving membership with a user
/// session (`POST /node/self-register`, `Authorization: Bearer <session>`).
/// This is what `probe-rs-fleet share` sends.
///
/// Self-approving: **membership of the target org is sufficient**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfRegisterRequest {
    /// The node's self-chosen name. Advisory; it names the row.
    pub node_name: String,
    /// Optional selection tags to record on the node.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Probe adoption policy for this node (`auto` | `declared`).
    ///
    /// Absent means `auto` — a machine its owner is deliberately sharing wants
    /// its probes usable without a second edit. An unrecognised value is a
    /// `400`, never a silent default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adopt: Option<String>,
    /// The org to register into, as a path or namespace id. `None` means the
    /// caller's personal org. The caller must be a member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// What an approver is doing with a pending registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeApprovalDecision {
    /// Describe the pending registration without changing anything.
    ///
    /// The CLI always inspects first: an approver is granting hardware access
    /// in their org to a machine they cannot see, so they must be shown what
    /// they are approving (RFC 8628 §5.4, sharpened).
    Inspect,
    /// Bind the pending registration to the target org and the approver.
    Approve,
    /// Refuse it permanently.
    Deny,
}

/// An approval request, authenticated with `Authorization: Bearer <session>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeApprovalRequest {
    /// The short code, in any spelling the coordinator's user-code
    /// normalisation accepts (case, hyphens and spaces are forgiven).
    pub user_code: String,
    /// Inspect, approve or deny.
    pub decision: NodeApprovalDecision,
    /// Approve even though the requested node name already exists in the
    /// target org, re-credentialing (and thereby taking over) that node.
    ///
    /// Default `false`, and the refusal is enforced by the **handler**: the
    /// requesting machine chose `node_name` before any org existed, so without
    /// this guard an approver could be talked into silently handing over a
    /// production node.
    #[serde(default)]
    pub replace: bool,
    /// The org to approve the node into, as a path or namespace id. `None`
    /// means the approver's personal org. The approver must be a member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// A pending registration as an approver sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// address, and `X-Forwarded-For` is deliberately not trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// When the registration was started (epoch seconds).
    pub created_at: i64,
    /// When it expires (epoch seconds).
    pub expires: i64,
    /// The org this registration would join, or joined: the **request's**
    /// target org, on every decision including `Inspect`, so "which org am I
    /// granting hardware access in?" is answered before the confirmation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// `pending` | `approved` | `denied`.
    pub state: String,
    /// The existing node id this registration would re-credential, if the
    /// target org already has a node by the requested name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collides_with: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_a_secret() {
        let secret = "prfk1_supersecret";
        let dbg = [
            format!(
                "{:?}",
                NodeEnrollRequest {
                    auth_key: secret.to_owned(),
                    node_name: "rpi-1".to_owned(),
                }
            ),
            format!(
                "{:?}",
                NodeRegisterPollRequest {
                    device_secret: secret.to_owned(),
                }
            ),
            format!(
                "{:?}",
                NodeRegisterStartResponse {
                    user_code: "ABCD-1234".to_owned(),
                    device_secret: secret.to_owned(),
                    verification_uri: "https://x/node/approve".to_owned(),
                    interval: 5,
                    expires_in: 600,
                }
            ),
            format!(
                "{:?}",
                NodeTokenResponse {
                    token: secret.to_owned(),
                    node_id: "o/rpi-1".to_owned(),
                    org: "o".to_owned(),
                    org_name: None,
                    coordinator_token_pubkey: "ab".repeat(32),
                }
            ),
        ];
        for d in dbg {
            assert!(!d.contains("supersecret"), "{d}");
            assert!(d.contains(REDACTED), "{d}");
        }
    }

    #[test]
    fn optional_fields_default_when_absent() {
        let req: SelfRegisterRequest = serde_json::from_str(r#"{"node_name":"n"}"#).unwrap();
        assert!(req.tags.is_empty() && req.adopt.is_none() && req.org.is_none());
        let req: NodeApprovalRequest =
            serde_json::from_str(r#"{"user_code":"ABCD1234","decision":"inspect"}"#).unwrap();
        assert!(!req.replace && req.org.is_none());
        assert_eq!(req.decision, NodeApprovalDecision::Inspect);
    }
}
