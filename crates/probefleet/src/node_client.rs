//! fleet's own `/node/*` routes, called over [`forgs_client::ForgsClient`].
//!
//! Generic identity (`/auth/*`) is forgs' and lives in `forgs-client`; what
//! is left is fleet-specific: turning a machine into a node. Every call goes
//! through [`ForgsClient::post_json`], so a certificate pin covers these
//! routes exactly as it covers `/auth/*` — one trust path.

use forgs_client::{ClientError, ForgsClient, Secret};
use probefleet_proto::auth_api::{
    NodeApprovalDecision, NodeApprovalRequest, NodeApprovalResponse, NodeEnrollRequest,
    NodeRegisterPollRequest, NodeRegisterStartRequest, NodeRegisterStartResponse,
    NodeTokenResponse, SelfRegisterRequest,
};

/// Build a client for the coordinator at `url`, pinned to `pin` if given.
///
/// # Errors
///
/// [`ClientError::Url`] for an unusable URL.
pub fn client(url: &str, pin: Option<[u8; 32]>) -> Result<ForgsClient, ClientError> {
    ForgsClient::new(url, pin)
}

/// `POST /node/enroll`: redeem a `node`-purpose API key for a node token.
///
/// # Errors
///
/// Any [`ClientError`]; a bad key is `401 invalid_grant`, a key of another
/// purpose `403 forbidden`.
pub async fn enroll(
    client: &ForgsClient,
    auth_key: &str,
    node_name: &str,
) -> Result<NodeTokenResponse, ClientError> {
    client
        .post_json(
            "/node/enroll",
            None,
            &NodeEnrollRequest {
                auth_key: auth_key.to_owned(),
                node_name: node_name.to_owned(),
            },
        )
        .await
}

/// `POST /node/self-register`: register this machine with a user session.
///
/// # Errors
///
/// Any [`ClientError`].
pub async fn self_register(
    client: &ForgsClient,
    session_token: &str,
    request: &SelfRegisterRequest,
) -> Result<NodeTokenResponse, ClientError> {
    client
        .post_json(
            "/node/self-register",
            Some(&Secret::from(session_token)),
            request,
        )
        .await
}

/// `POST /node/register/start`: begin an approval-pending registration.
///
/// # Errors
///
/// Any [`ClientError`].
pub async fn register_start(
    client: &ForgsClient,
    request: &NodeRegisterStartRequest,
) -> Result<NodeRegisterStartResponse, ClientError> {
    client
        .post_json("/node/register/start", None, request)
        .await
}

/// `POST /node/register/poll`: the pending outcomes are named `401`s
/// (`authorization_pending`, `slow_down`, `access_denied`, `expired_token`).
///
/// # Errors
///
/// Any [`ClientError`], including those named outcomes.
pub async fn register_poll(
    client: &ForgsClient,
    device_secret: &str,
) -> Result<NodeTokenResponse, ClientError> {
    client
        .post_json(
            "/node/register/poll",
            None,
            &NodeRegisterPollRequest {
                device_secret: device_secret.to_owned(),
            },
        )
        .await
}

/// `POST /node/register/approve`: inspect, approve or deny a pending
/// registration into `org` (default: the caller's personal org).
///
/// # Errors
///
/// Any [`ClientError`].
pub async fn approve(
    client: &ForgsClient,
    session_token: &str,
    user_code: &str,
    decision: NodeApprovalDecision,
    replace: bool,
    org: Option<&str>,
) -> Result<NodeApprovalResponse, ClientError> {
    client
        .post_json(
            "/node/register/approve",
            Some(&Secret::from(session_token)),
            &NodeApprovalRequest {
                user_code: user_code.to_owned(),
                decision,
                replace,
                org: org.map(ToOwned::to_owned),
            },
        )
        .await
}
