//! GitHub Actions **workload identity**: JWT verification and a JWKS cache
//! (architecture §6.7). Feature `oidc`.
//!
//! # This one really is OIDC
//!
//! [`crate::github`] opens by explaining why user login is *not* OIDC — no
//! discovery document, no ID token, no JWKS, nothing to verify. GitHub Actions
//! is the other half of that sentence: a job with `permissions: id-token:
//! write` can mint a signed JWT from
//! `https://token.actions.githubusercontent.com`, whose public keys are
//! published at a JWKS endpoint. So this module has real signature
//! verification, and no secret ever enters the runner — which is the entire
//! point of the CI path.
//!
//! # What is verified, and what is merely recorded
//!
//! Verified, all explicitly and never by inheriting a library default:
//!
//! * the **signature**, against a JWKS key selected by the token's `kid`;
//! * the **algorithm**, against an allowlist of exactly `[RS256]`. This is the
//!   fence against the `alg: none` / HS256-key-confusion family, where a token
//!   is signed with the *public* key as an HMAC secret;
//! * the **issuer** and the **audience**, both exact-match against configured
//!   values;
//! * **expiry** and **not-before**, against an injected `now` (see below);
//! * the presence of `repository` and `repository_owner`, and that
//!   `repository` is exactly one `owner/name` pair over a conservative charset.
//!
//! Recorded but **never authorizing**: `repository_owner`, `ref`, `workflow`,
//! `job_workflow_ref`, `run_id`. In particular `repository_owner` is *not*
//! sufficient to reach hardware — a fork, or a new repo under a granted owner,
//! must not inherit access. Only the full `owner/repo` is matched, against an
//! explicit per-repo grant. That is the security-relevant decision of this
//! whole path and it is enforced by the caller, not here: [`verify`] returns
//! claims, the coordinator maps them to a subject and looks for a grant.
//!
//! # One clock
//!
//! `jsonwebtoken` reads the wall clock itself for `exp`/`nbf`. This module sets
//! `validate_exp`/`validate_nbf` to **false** and does the only time comparison
//! against the `now` parameter, keeping `exp` in `required_spec_claims` so a
//! token without one is still refused. The coordinator has a [`Clock`] seam its
//! tests move; a second, invisible clock inside the JWT library would disagree
//! with it and produce a test that passes for the wrong reason.
//!
//! [`Clock`]: https://docs.rs/fleet-coordinator

use std::collections::HashSet;

use jsonwebtoken::jwk::{JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// What the coordinator configured this verifier to accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcPolicy {
    /// The expected `iss` claim
    /// (`https://token.actions.githubusercontent.com`).
    pub issuer: String,
    /// The expected `aud` claim.
    ///
    /// **Required, with no default.** GitHub's default audience is
    /// `https://github.com/<owner>`, which is not fleet-specific: a token
    /// minted for some *other* service that also took the default would then be
    /// replayable here. The coordinator's own `public_url` is the intended
    /// value, and the workflow asks for it explicitly.
    pub audience: String,
    /// Clock-skew margin, in seconds, applied to `exp` and `nbf`.
    pub leeway_secs: u64,
}

/// The claims this fleet cares about from a GitHub Actions OIDC token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadClaims {
    /// `owner/name`, already validated and **lowercased**. The only claim that
    /// takes part in an authorization decision.
    pub repository: String,
    /// The repository's owner. Recorded for audit; **never** authorizing.
    pub repository_owner: String,
    /// The git ref the job ran on (`refs/heads/main`). Recorded, not evaluated
    /// — per-ref conditions are a follow-up, not v1.
    pub git_ref: Option<String>,
    /// The workflow's name.
    pub workflow: Option<String>,
    /// The fully-qualified workflow reference, which identifies a reusable
    /// workflow's *defining* repo.
    pub job_workflow_ref: Option<String>,
    /// The Actions run id, the handle an operator uses to find the job.
    pub run_id: Option<String>,
    /// The token's `sub` claim, verbatim.
    pub sub: String,
    /// The token's expiry, epoch seconds.
    pub exp: u64,
}

/// Why a workload JWT was refused.
///
/// Detail for the log and the audit trail — **never** for the response body,
/// which is a flat `invalid_grant` for every variant. Same no-oracle rule
/// [`crate::AuthError`] follows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OidcError {
    /// The string is not three base64url segments, or its header will not
    /// decode.
    #[error("malformed JWT")]
    Malformed,
    /// The header named a `kid` that is not in the JWKS.
    ///
    /// The one variant the caller may act on: it is what a key **rotation**
    /// looks like, so the caller may refresh the JWKS once and retry.
    #[error("unknown key id `{0}`")]
    UnknownKid(String),
    /// The signature did not verify against the selected key.
    #[error("bad signature")]
    BadSignature,
    /// The `iss` claim is not the configured issuer.
    #[error("wrong issuer")]
    WrongIssuer,
    /// The `aud` claim is not the configured audience.
    #[error("wrong audience")]
    WrongAudience,
    /// `exp` is in the past (allowing for leeway).
    #[error("expired")]
    Expired,
    /// `nbf` is in the future (allowing for leeway).
    #[error("not yet valid")]
    NotYetValid,
    /// A claim this fleet requires is absent or unusable.
    #[error("missing or invalid claim `{0}`")]
    MissingClaim(&'static str),
    /// The header's `alg` is not on the allowlist.
    #[error("unsupported algorithm `{0}`")]
    UnsupportedAlg(String),
    /// The JWKS could not be fetched or parsed.
    #[error("JWKS unavailable: {0}")]
    Jwks(String),
}

impl OidcError {
    /// A short stable label for structured logging and audit rows.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            OidcError::Malformed => "oidc.reject.malformed",
            OidcError::UnknownKid(_) => "oidc.reject.unknown_kid",
            OidcError::BadSignature => "oidc.reject.bad_signature",
            OidcError::WrongIssuer => "oidc.reject.wrong_issuer",
            OidcError::WrongAudience => "oidc.reject.wrong_audience",
            OidcError::Expired => "oidc.reject.expired",
            OidcError::NotYetValid => "oidc.reject.not_yet_valid",
            OidcError::MissingClaim(_) => "oidc.reject.missing_claim",
            OidcError::UnsupportedAlg(_) => "oidc.reject.unsupported_alg",
            OidcError::Jwks(_) => "oidc.reject.jwks_unavailable",
        }
    }
}

/// The raw claim set, as it arrives on the wire.
#[derive(Debug, Deserialize)]
struct RawClaims {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    repository_owner: Option<String>,
    #[serde(default, rename = "ref")]
    git_ref: Option<String>,
    #[serde(default)]
    workflow: Option<String>,
    #[serde(default)]
    job_workflow_ref: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    sub: Option<String>,
    // Deserialised as `Option` even though it is required: `jsonwebtoken`
    // deserialises `T` *before* running its own `required_spec_claims` check,
    // so a hard `u64` here would turn a missing `exp` into an anonymous JSON
    // error. Requiring it ourselves keeps the rejection nameable.
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
}

/// The one algorithm this fleet accepts.
///
/// GitHub signs Actions OIDC tokens with RS256. Pinning a single algorithm (as
/// opposed to a family, or whatever the header asks for) is what makes the
/// `alg` confusion attacks unrepresentable rather than merely unlikely.
const ALLOWED_ALGS: [Algorithm; 1] = [Algorithm::RS256];

/// Verify a GitHub Actions OIDC JWT against `jwks` and `policy` at `now`.
///
/// Pure: no I/O, no clock. That is what makes the whole rule set table-testable
/// and what keeps a test's fixed clock authoritative.
///
/// # Errors
///
/// Returns [`OidcError`]. Every variant maps to the same flat `401
/// invalid_grant` at the HTTP boundary; the distinction exists for the log.
pub fn verify(
    jwt: &str,
    jwks: &JwkSet,
    policy: &OidcPolicy,
    now: u64,
) -> Result<WorkloadClaims, OidcError> {
    let jwt = jwt.trim();
    let header = jsonwebtoken::decode_header(jwt).map_err(|_| OidcError::Malformed)?;

    // The allowlist is checked here *as well as* through `Validation`, so the
    // rejection is nameable in the log rather than an anonymous decode failure.
    if !ALLOWED_ALGS.contains(&header.alg) {
        return Err(OidcError::UnsupportedAlg(format!("{:?}", header.alg)));
    }
    // A `kid` is mandatory: without one there is no way to say *which* key was
    // meant, and "try every key in the set" turns a rotation window into an
    // attacker's second chance.
    let kid = header.kid.ok_or(OidcError::MissingClaim("kid"))?;
    let jwk = jwks
        .find(&kid)
        .filter(|jwk| {
            // A key published for encryption is not a signing key. Absent
            // `use` is accepted: it is optional in RFC 7517 and GitHub does
            // set it, but a stricter reading would break on a compliant IdP.
            !matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption))
        })
        .ok_or_else(|| OidcError::UnknownKid(kid.clone()))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| OidcError::Jwks(e.to_string()))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = ALLOWED_ALGS.to_vec();
    validation.set_issuer(&[policy.issuer.as_str()]);
    validation.set_audience(&[policy.audience.as_str()]);
    // Presence is still required; the *comparison* is ours (see the module
    // docs: one clock).
    validation.required_spec_claims =
        HashSet::from_iter(["exp", "iss", "aud", "sub"].map(str::to_owned));
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let data =
        jsonwebtoken::decode::<RawClaims>(jwt, &key, &validation).map_err(|e| map_jwt_error(&e))?;
    let claims = data.claims;
    let exp = claims.exp.ok_or(OidcError::MissingClaim("exp"))?;
    let sub = claims
        .sub
        .filter(|s| !s.is_empty())
        .ok_or(OidcError::MissingClaim("sub"))?;

    // Expiry and not-before, against the injected clock only.
    if exp.saturating_add(policy.leeway_secs) <= now {
        return Err(OidcError::Expired);
    }
    if let Some(nbf) = claims.nbf {
        if nbf > now.saturating_add(policy.leeway_secs) {
            return Err(OidcError::NotYetValid);
        }
    }

    // `repository` becomes a subject id, so it is validated and lowercased by
    // the same function `grant --repo` uses — a case mismatch between the two
    // sides would otherwise be a silent denial.
    let repository = claims
        .repository
        .as_deref()
        .and_then(fleet_proto::ids::normalise_repo)
        .ok_or(OidcError::MissingClaim("repository"))?;
    let repository_owner = claims
        .repository_owner
        .filter(|s| !s.trim().is_empty())
        .ok_or(OidcError::MissingClaim("repository_owner"))?
        .to_ascii_lowercase();

    Ok(WorkloadClaims {
        repository,
        repository_owner,
        git_ref: claims.git_ref,
        workflow: claims.workflow,
        job_workflow_ref: claims.job_workflow_ref,
        run_id: claims.run_id,
        sub,
        exp,
    })
}

/// Map a `jsonwebtoken` error onto our own taxonomy.
fn map_jwt_error(e: &jsonwebtoken::errors::Error) -> OidcError {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::InvalidSignature => OidcError::BadSignature,
        ErrorKind::InvalidIssuer => OidcError::WrongIssuer,
        ErrorKind::InvalidAudience => OidcError::WrongAudience,
        ErrorKind::ExpiredSignature => OidcError::Expired,
        ErrorKind::ImmatureSignature => OidcError::NotYetValid,
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            OidcError::UnsupportedAlg("rejected by validation".to_owned())
        }
        // A missing *required* claim is reported by name; anything else
        // (malformed base64, bad JSON, an absent `repository`) is the flat
        // malformed case. The caller logs `label()`, so the distinction is only
        // ever an operator's diagnostic.
        ErrorKind::MissingRequiredClaim(name) => match name.as_str() {
            "exp" => OidcError::MissingClaim("exp"),
            "iss" => OidcError::MissingClaim("iss"),
            "aud" => OidcError::MissingClaim("aud"),
            "sub" => OidcError::MissingClaim("sub"),
            _ => OidcError::Malformed,
        },
        _ => OidcError::Malformed,
    }
}

/// Parse a JWKS document.
///
/// # Errors
///
/// Returns [`OidcError::Jwks`] if the bytes are not a JWK set.
pub fn parse_jwks(bytes: &[u8]) -> Result<JwkSet, OidcError> {
    serde_json::from_slice(bytes).map_err(|e| OidcError::Jwks(e.to_string()))
}

#[cfg(feature = "client")]
pub use cache::JwksCache;

#[cfg(feature = "client")]
mod cache {
    //! The JWKS fetch + cache half, which needs HTTPS egress.

    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use http_body_util::{BodyExt as _, Full};
    use hyper::body::Bytes;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use jsonwebtoken::jwk::JwkSet;

    use super::{parse_jwks, OidcError};

    /// How long a single JWKS fetch may take.
    const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

    /// The cached document plus when it was fetched.
    #[derive(Default)]
    struct State {
        keys: Option<Arc<JwkSet>>,
        fetched_at: Option<Instant>,
        /// When the last fetch of *any* kind was attempted, including one
        /// forced by an unknown `kid`. This is what bounds the amplification.
        last_attempt: Option<Instant>,
    }

    /// A refreshing cache over an issuer's JWKS endpoint.
    ///
    /// Two properties, both load-bearing and both pinned by tests:
    ///
    /// * a **key rotation** — a token carrying a `kid` the cached set does not
    ///   have — is picked up by exactly one extra fetch
    ///   ([`JwksCache::refresh_for_unknown_kid`]), rather than by waiting out
    ///   the refresh interval, which would break every CI job in between;
    /// * that refresh is **rate limited** (`min_refetch`), so an attacker
    ///   feeding a stream of invented `kid`s cannot turn `POST /auth/token`
    ///   into a fetch amplifier aimed at the issuer. Over the limit, the cached
    ///   set is returned unchanged and the token is refused.
    ///
    /// A failed fetch never flushes a good cached set: an issuer outage must
    /// not take the fleet's CI down with it for as long as the cached keys
    /// remain valid.
    pub struct JwksCache {
        url: String,
        refresh_after: Duration,
        min_refetch: Duration,
        inner: tokio::sync::Mutex<State>,
    }

    impl JwksCache {
        /// Build a cache over `url`.
        ///
        /// `refresh_after` is the ordinary staleness horizon; `min_refetch` the
        /// floor between forced refreshes.
        #[must_use]
        pub fn new(url: impl Into<String>, refresh_after: Duration, min_refetch: Duration) -> Self {
            Self {
                url: url.into(),
                refresh_after,
                min_refetch,
                inner: tokio::sync::Mutex::new(State::default()),
            }
        }

        /// The current key set, refetching it if it is missing or stale.
        ///
        /// # Errors
        ///
        /// Returns [`OidcError::Jwks`] only when there is *no* usable cached
        /// set; a stale-but-present set survives a failed refresh.
        pub async fn get(&self) -> Result<Arc<JwkSet>, OidcError> {
            let mut state = self.inner.lock().await;
            let is_stale = state
                .fetched_at
                .is_none_or(|at| at.elapsed() >= self.refresh_after);
            if !is_stale {
                if let Some(keys) = state.keys.as_ref() {
                    return Ok(Arc::clone(keys));
                }
            }
            match self.fetch(&mut state).await {
                Ok(keys) => Ok(keys),
                Err(e) => match state.keys.as_ref() {
                    // Stale keys beat no keys: GitHub's signing keys outlive
                    // the refresh interval by a wide margin, so serving the
                    // cached set through an outage is the safer failure.
                    Some(keys) => {
                        tracing::warn!(error = %e, "JWKS refresh failed; serving the cached set");
                        Ok(Arc::clone(keys))
                    }
                    None => Err(e),
                },
            }
        }

        /// Force a refresh because a token named a `kid` we do not have.
        ///
        /// Rate-limited to one fetch per `min_refetch`; over the limit the
        /// cached set comes back unchanged, so the caller simply refuses the
        /// token.
        ///
        /// # Errors
        ///
        /// As [`JwksCache::get`].
        pub async fn refresh_for_unknown_kid(&self) -> Result<Arc<JwkSet>, OidcError> {
            let mut state = self.inner.lock().await;
            let too_soon = state
                .last_attempt
                .is_some_and(|at| at.elapsed() < self.min_refetch);
            if too_soon {
                tracing::debug!("JWKS refetch suppressed by the rate limit");
                return match state.keys.as_ref() {
                    Some(keys) => Ok(Arc::clone(keys)),
                    None => Err(OidcError::Jwks("no cached key set".to_owned())),
                };
            }
            match self.fetch(&mut state).await {
                Ok(keys) => Ok(keys),
                Err(e) => match state.keys.as_ref() {
                    Some(keys) => Ok(Arc::clone(keys)),
                    None => Err(e),
                },
            }
        }

        /// Fetch and install a fresh key set. Caller holds the lock.
        async fn fetch(&self, state: &mut State) -> Result<Arc<JwkSet>, OidcError> {
            state.last_attempt = Some(Instant::now());
            let bytes = self.get_bytes().await?;
            let keys = Arc::new(parse_jwks(&bytes)?);
            state.keys = Some(Arc::clone(&keys));
            state.fetched_at = Some(Instant::now());
            Ok(keys)
        }

        /// One HTTPS GET, through the same trust path as every other egress in
        /// this crate.
        async fn get_bytes(&self) -> Result<Vec<u8>, OidcError> {
            let uri: http::Uri = self
                .url
                .parse()
                .map_err(|e: http::uri::InvalidUri| OidcError::Jwks(e.to_string()))?;
            // `None` for the pin: the issuer is a public Web PKI host, and
            // `--server-cert-sha256` pins the *coordinator*, not third parties.
            let tls = fleet_tls::client_trust_config(None);
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls)
                .https_or_http()
                .enable_http1()
                .build();
            let client: Client<_, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build(https);
            let req = http::Request::builder()
                .method(http::Method::GET)
                .uri(uri)
                .header(http::header::ACCEPT, "application/json")
                .header(
                    http::header::USER_AGENT,
                    concat!("probe-rs-fleet/", env!("CARGO_PKG_VERSION")),
                )
                .body(Full::new(Bytes::new()))
                .map_err(|e| OidcError::Jwks(e.to_string()))?;
            let resp = tokio::time::timeout(FETCH_TIMEOUT, client.request(req))
                .await
                .map_err(|_| OidcError::Jwks("JWKS fetch timed out".to_owned()))?
                .map_err(|e| OidcError::Jwks(e.to_string()))?;
            let status = resp.status();
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| OidcError::Jwks(e.to_string()))?
                .to_bytes();
            if !status.is_success() {
                return Err(OidcError::Jwks(format!("HTTP {}", status.as_u16())));
            }
            Ok(bytes.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    /// A committed RSA-2048 private key, PKCS#1 DER, base64.
    ///
    /// **Committed rather than generated at test time on purpose**: RSA key
    /// generation in a debug build is slow and its timing is variable enough to
    /// make a test flaky for reasons that have nothing to do with the code
    /// under test. This key exists only in this file and signs only fixtures.
    const KEY_A_DER_B64: &str = concat!(
        "MIIEpAIBAAKCAQEArsL3i977OYrPnKq6SjRYRIYuzkEAd+rd3hvupoNtMt/w7kG6qX2apWgw",
        "tqbMvX06fmswpnBqQuF99lOvBZYQ1AfsV6igmRp9WET0X+kO0ptI0bYs1UGWYc2LMHQWEUJA",
        "tFjH5YzOteoEsw1RwceJ9kDn1WMkotIq/uvx+LlptN98PtnpL3vjIvo+QyYD8ulcEmIygjnE",
        "Vf/Dpx76agi4gRTG9miu7NkU3VgZXnMfQdjh7Exz04Qg3ItN/kTkoxx6Yjn1wuo77fZxj7Sp",
        "AiZbSRix3sRxij/Wt4VfMT2MBwWNb1KjOVxQygPfl9KsxTxD6njiXWtQez89r5RVfoUH0QID",
        "AQABAoIBAAv/eqXxqGcU7pf06KvmLWvW7SkKhru04N06JweWMk2x2NqioewM9tcFm4KOr7O6",
        "qzoOpd0SDq7fcu8RuQxgdxtMx/RksVHm4wAdC8yh4CX5XzshOga8uqmlm463XuR5xfNxEkLi",
        "MzbYsCXoHjAi64fVK5VszxEWmLkTqHMeV5wr4SMQA4JmmMO8Yr/TcmkIQxCwzTlOy+Mm9XBq",
        "3WnKKhiAeDX1V2S+DzXucbiXRNpyHx2o/FDtDpsWe2ZGiiZTrUBM9HgU3lS3FXGwNkhAHKAn",
        "VxVMpiAk0xFoJQ1+ZevTy+SJHf9SeTalhxZENjPmX6FY5095UFNSdHWb2nZKVSECgYEA7OFb",
        "CaoIB3ELnlnwbu3CUiASd8JpxDhViBiKpykwAnO/shrc/meeuzbqn+LGOHW/WicuVJBQwdF8",
        "3LOGHWxqmOnBZbRgdw0His27xQ3BSKm0p90qb3kKqoLTg0gY/sZ9lWsSci4f+OxdqamzNHDV",
        "vof2KiQjCcrZ9CIS8VSB550CgYEAvN4OVeuFM9Q7j2YRnAxSPMIvE0Z35LG9UQYVmwU9/rDm",
        "IQwV6TkrGrjhytz9Ra4neeZDmY8PvgP6KMyzwPtEF8ozop9I4fU40iel+UioAo/+FacctwgM",
        "0geGcG7rsA92udPxwbpNCmJA8tdKRJ9lcp/kNEbAHQEIGhjFs7LJPMUCgYEA5SYj0TeAyOIc",
        "oTTUGBs8jgGkm+GgO0dbxmonRwna/aRHXt4JxrkqnmTDl6PiqR+O2oFomjl5ReWHamDobnJA",
        "tGf8xIw3fTNHhoj7CecCgW5Z6sFSmb94B/bC8g6+z0fomLCZiYcBOuY8vTICv8ofm08fXSjU",
        "FFb9fOOxe2+KsykCgYEAkirIrXY5AIOgFLrJphtjCeK+zAwdfcCQ48PxtKe58wK1F55i1ryH",
        "v4aWOIoO+X5uzsiGSLGPXV92m1zRQOk1KbQzgggEP9uovfwxV1wDqvgFjHxonL5+LY3lXd56",
        "SSeumuKMl4G3XfHskgRMVg+GU8+qrUqUI95IhunlF82mMIECgYAxvXnRxgjI/p/5ERXYvvaL",
        "QfnJ0jFfcGr6hlx3INsMq9JcpI1C2FiWkPuU/folOSKYHQ7bNNxtMh6lkBW2+m4Zm1CAzlRB",
        "DM8oAR00QMf12agzXuXXBqpaDIeq011IJmtUIPwSJAxSBOnrT1lZvff7EIqg8CRj5uUPNLfx",
        "hKhlIA==",
    );

    /// Base64url modulus of [`KEY_A_DER_B64`].
    const KEY_A_N: &str = concat!(
        "rsL3i977OYrPnKq6SjRYRIYuzkEAd-rd3hvupoNtMt_w7kG6qX2apWgwtqbMvX06fmswpnBq",
        "QuF99lOvBZYQ1AfsV6igmRp9WET0X-kO0ptI0bYs1UGWYc2LMHQWEUJAtFjH5YzOteoEsw1R",
        "wceJ9kDn1WMkotIq_uvx-LlptN98PtnpL3vjIvo-QyYD8ulcEmIygjnEVf_Dpx76agi4gRTG",
        "9miu7NkU3VgZXnMfQdjh7Exz04Qg3ItN_kTkoxx6Yjn1wuo77fZxj7SpAiZbSRix3sRxij_W",
        "t4VfMT2MBwWNb1KjOVxQygPfl9KsxTxD6njiXWtQez89r5RVfoUH0Q",
    );

    /// A second key, for the rotation and wrong-key tests.
    const KEY_B_DER_B64: &str = concat!(
        "MIIEowIBAAKCAQEApesnGL/IibSnxbbALzq9yErXD9Hklbk6gpMTvfEOnPmNDw7w/MiHgTSb",
        "3JC9zyZ5Qb9zS8HK3SCMDd/VysZIe2rQ1MvETvkL3ryX3g6qHTtXy8yqLvOIDMrS7abrglWr",
        "EHrYziVHxaB6nxO6X8gVMThi+yAuUoZjm4pirkwohD8Gf/tpYgIP7A/zGOSluQj8vodb1M9q",
        "kfWllxMSTjg0Y2hgxz3/PKTKRoeRmJY1vVQC75VuA716KRGlepi7u0bex49jB3R1gvJRper0",
        "rN+Oidt/bOn3+oIolxCHUmulJrWASpwkwVMnew1AcI9VT8HF4R99TB6LdRUVfjbA1JgJjwID",
        "AQABAoIBAE99V5/N0h/XQ0HAClcWR3I8GMjlgCQTN+ry19R6NswR6vi56c7Rq8nFEJ8dYTJr",
        "dlB/jpdO4wgJ3c+P23dog7VNOXuZnBVRz9QIeqHSWMHkem2TQj14Q0gNq/xbqh0pOemNUW2C",
        "At61wcmQxAu7ahvIrfMuOcMjy3jrVde3ePnSChWoj+bSWKV+XH3cRnPhez6NispbpTb0y35E",
        "z93bixH5bb5CzzH+59DtPF8+9tQ9q3jUQRtsGKm+jgcXNYbr2ENCC5I2LzyfAtzHP6wzUSxv",
        "FeeiOroZ/ChNTOptm3ECH8BJGfBw6LnlGxBcUFIC69ixmLMECSlgWhHYRUmr+uECgYEA3oo/",
        "KYsSsO66bZW5xJTCdsu2vAA21ATRKJptLAghQ1FImLMQYoM9rfW4OWD+Uf4SJ2OqN45B1GtC",
        "Ff8wa1w3dG17gRio1PBw0ctALxm0vbOFiGT2qGBfOJ3IAS0uUw4mSesdiUKpEzzSz+e5Hq3O",
        "Z72UidgmBuarmVLacOupAUcCgYEAvt1/ivhL8u0JDyfw8F72znsRYkXw3DFRq65KoSCrnoek",
        "mj42Z+7B+TVjwhwB9u4q8u0ohtZu6UC2LDWWjg8MSotvjW3TwKQhpwZV8LX1NEcpBU9XI1fD",
        "GbNQu5GT1ESTL1/Dy5Ik4DfJ2Y3yJC/f6jeWnYLm2yqWAc1AXpH1mXkCgYAP/XT+YizMo8qn",
        "dxurAVlbudV+erF12IbC2R3BDTB+qseBmVQzD+UNq9s53DtJ3uylAedIKKOYRMCx3e03uZ+O",
        "cRNvujrfWgtxN558A+fVvaF5pG+It6v/4G5vjzSF6T1dEFTF+RE2/abUI31MtAZhs+CJawuI",
        "cWihEq/5byVsnwKBgGsbT1yEE9LB88h+iHXLRMMASvQT/aMDRiqKhzS+abBvvA4WhV9zm4Sm",
        "0lF2eB/C7XUfYxOvt9PLTa+nbtJPXX1jm/kIvcCoGn5pTsbixTRODpX9PRAHSuPcPZzUh9mh",
        "ldsK6YwOegUdKXedcVmfSA9enHXNpJEu57khHlMzo1g5AoGBANQcvcBfnMDuGPYKSqGsrCn9",
        "G3UZDtJ+mCvXyTdnTif/tP8Xvsi9+h4CYQl/zG8CHNo9aNqdnIoIVS9ZfTVmSF1n9IQTVByr",
        "Y4o97s7rIAqpEVzY0H2fHA5MgO4hmSAAOdWiG0d5ScstfWofmcj/8tYWHv8VZthbkqxtJtW/",
        "bqP0",
    );

    /// Base64url modulus of [`KEY_B_DER_B64`].
    const KEY_B_N: &str = concat!(
        "pesnGL_IibSnxbbALzq9yErXD9Hklbk6gpMTvfEOnPmNDw7w_MiHgTSb3JC9zyZ5Qb9zS8HK",
        "3SCMDd_VysZIe2rQ1MvETvkL3ryX3g6qHTtXy8yqLvOIDMrS7abrglWrEHrYziVHxaB6nxO6",
        "X8gVMThi-yAuUoZjm4pirkwohD8Gf_tpYgIP7A_zGOSluQj8vodb1M9qkfWllxMSTjg0Y2hg",
        "xz3_PKTKRoeRmJY1vVQC75VuA716KRGlepi7u0bex49jB3R1gvJRper0rN-Oidt_bOn3-oIo",
        "lxCHUmulJrWASpwkwVMnew1AcI9VT8HF4R99TB6LdRUVfjbA1JgJjw",
    );

    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const AUDIENCE: &str = "https://fleet.example";

    fn der(b64: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
    }

    fn policy() -> OidcPolicy {
        OidcPolicy {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            leeway_secs: 60,
        }
    }

    /// A JWKS holding the named keys.
    fn jwks(entries: &[(&str, &str)]) -> JwkSet {
        let keys: Vec<serde_json::Value> = entries
            .iter()
            .map(|(kid, n)| {
                json!({
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": kid,
                    "n": n,
                    "e": "AQAB",
                })
            })
            .collect();
        serde_json::from_value(json!({ "keys": keys })).unwrap()
    }

    /// The claim set GitHub actually sends, as a mutable base.
    fn claims() -> serde_json::Value {
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "repo:ariel-os/ariel-os:ref:refs/heads/main",
            "exp": 2_000u64,
            "nbf": 900u64,
            "iat": 900u64,
            "repository": "ariel-os/ariel-os",
            "repository_owner": "ariel-os",
            "ref": "refs/heads/main",
            "workflow": "hil",
            "job_workflow_ref": "ariel-os/ariel-os/.github/workflows/hil.yml@refs/heads/main",
            "run_id": "12345",
        })
    }

    fn sign(kid: &str, key_der_b64: &str, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_der(&der(key_der_b64))).unwrap()
    }

    #[test]
    fn a_well_formed_token_verifies_and_lowercases_its_repo() {
        let mut c = claims();
        // GitHub is case-preserving; the claim can arrive mixed-case.
        c["repository"] = json!("Ariel-OS/Ariel-OS");
        c["repository_owner"] = json!("Ariel-OS");
        let jwt = sign("k1", KEY_A_DER_B64, &c);
        let out = verify(&jwt, &jwks(&[("k1", KEY_A_N)]), &policy(), 1_000).unwrap();
        assert_eq!(out.repository, "ariel-os/ariel-os");
        assert_eq!(out.repository_owner, "ariel-os");
        assert_eq!(out.git_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(out.workflow.as_deref(), Some("hil"));
        assert_eq!(out.run_id.as_deref(), Some("12345"));
        assert_eq!(out.exp, 2_000);
    }

    /// The headline signature property: `alg: HS256` signed with the RSA
    /// *public* key as an HMAC secret must not verify. Pinning `[RS256]` on
    /// `Validation::algorithms` is what makes this whole family unrepresentable
    /// rather than merely unlikely.
    #[test]
    fn algorithm_confusion_is_refused() {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("k1".to_owned());
        let secret = KEY_A_N.as_bytes();
        let jwt = jsonwebtoken::encode(&header, &claims(), &EncodingKey::from_secret(secret))
            .unwrap();
        let err = verify(&jwt, &jwks(&[("k1", KEY_A_N)]), &policy(), 1_000).unwrap_err();
        assert!(
            matches!(err, OidcError::UnsupportedAlg(_)),
            "expected an algorithm rejection, got {err:?}"
        );
    }

    /// A signature made with a different key, published under the same `kid`,
    /// is the "attacker brings their own key" case.
    #[test]
    fn a_signature_from_the_wrong_key_is_refused() {
        let jwt = sign("k1", KEY_B_DER_B64, &claims());
        assert_eq!(
            verify(&jwt, &jwks(&[("k1", KEY_A_N)]), &policy(), 1_000).unwrap_err(),
            OidcError::BadSignature
        );
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        let mut parts: Vec<&str> = jwt.split('.').collect();
        let forged = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(claims().to_string().replace("ariel-os", "attacker"));
        parts[1] = &forged;
        let tampered = parts.join(".");
        assert_eq!(
            verify(&tampered, &jwks(&[("k1", KEY_A_N)]), &policy(), 1_000).unwrap_err(),
            OidcError::BadSignature
        );
    }

    #[test]
    fn issuer_audience_and_expiry_are_each_checked() {
        let keys = jwks(&[("k1", KEY_A_N)]);

        let mut c = claims();
        c["iss"] = json!("https://evil.example");
        assert_eq!(
            verify(&sign("k1", KEY_A_DER_B64, &c), &keys, &policy(), 1_000).unwrap_err(),
            OidcError::WrongIssuer
        );

        // GitHub's *default* audience — fleet-unspecific, and exactly why the
        // configured audience has no default.
        let mut c = claims();
        c["aud"] = json!("https://github.com/ariel-os");
        assert_eq!(
            verify(&sign("k1", KEY_A_DER_B64, &c), &keys, &policy(), 1_000).unwrap_err(),
            OidcError::WrongAudience
        );

        // Expired: `exp` 2000, leeway 60, so 2061 is past it and 2060 is not.
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        assert_eq!(
            verify(&jwt, &keys, &policy(), 2_061).unwrap_err(),
            OidcError::Expired
        );
        assert!(verify(&jwt, &keys, &policy(), 2_059).is_ok());

        // Not yet valid: `nbf` 900, leeway 60.
        assert_eq!(
            verify(&jwt, &keys, &policy(), 800).unwrap_err(),
            OidcError::NotYetValid
        );
    }

    /// The clock is the injected `now` and nothing else — a token that the
    /// library's wall clock would call expired verifies fine under a test
    /// clock, and vice versa. That is what keeps the coordinator's `Clock` seam
    /// authoritative.
    #[test]
    fn expiry_is_decided_only_by_the_injected_clock() {
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        let keys = jwks(&[("k1", KEY_A_N)]);
        // `exp` is 2000 epoch seconds: long past by any wall clock.
        assert!(verify(&jwt, &keys, &policy(), 1_000).is_ok());
    }

    #[test]
    fn required_claims_are_required_not_defaulted() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        for (drop, expected) in [
            ("repository", OidcError::MissingClaim("repository")),
            (
                "repository_owner",
                OidcError::MissingClaim("repository_owner"),
            ),
            ("exp", OidcError::MissingClaim("exp")),
            ("sub", OidcError::MissingClaim("sub")),
        ] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(drop);
            let err = verify(&sign("k1", KEY_A_DER_B64, &c), &keys, &policy(), 1_000).unwrap_err();
            assert_eq!(err, expected, "dropping `{drop}`");
        }

        // A `repository` that is not `owner/name` over the allowed charset must
        // not become a subject id.
        for bad in ["not-a-repo", "a/b/c", "own:er/name"] {
            let mut c = claims();
            c["repository"] = json!(bad);
            assert_eq!(
                verify(&sign("k1", KEY_A_DER_B64, &c), &keys, &policy(), 1_000).unwrap_err(),
                OidcError::MissingClaim("repository"),
                "{bad} should not be accepted as a repository"
            );
        }
    }

    /// A `kid` is mandatory and an unknown one is *distinguishable*, because
    /// that is the signal the caller uses to refresh the JWKS exactly once.
    #[test]
    fn kid_is_required_and_an_unknown_one_is_nameable() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        let jwt = sign("k9", KEY_A_DER_B64, &claims());
        assert_eq!(
            verify(&jwt, &keys, &policy(), 1_000).unwrap_err(),
            OidcError::UnknownKid("k9".to_owned())
        );

        let header = Header::new(Algorithm::RS256); // no kid
        let jwt =
            jsonwebtoken::encode(&header, &claims(), &EncodingKey::from_rsa_der(&der(KEY_A_DER_B64)))
                .unwrap();
        assert_eq!(
            verify(&jwt, &keys, &policy(), 1_000).unwrap_err(),
            OidcError::MissingClaim("kid")
        );
    }

    /// A rotation: the same `kid` is served, but the JWKS now carries the new
    /// key alongside the old. Both a token signed by the old key and one signed
    /// by the new must resolve against the set they belong to.
    #[test]
    fn a_rotated_key_set_resolves_by_kid() {
        let rotated = jwks(&[("k1", KEY_A_N), ("k2", KEY_B_N)]);
        assert!(verify(&sign("k1", KEY_A_DER_B64, &claims()), &rotated, &policy(), 1_000).is_ok());
        assert!(verify(&sign("k2", KEY_B_DER_B64, &claims()), &rotated, &policy(), 1_000).is_ok());
        // …and the keys are not interchangeable within the set.
        assert_eq!(
            verify(&sign("k2", KEY_A_DER_B64, &claims()), &rotated, &policy(), 1_000).unwrap_err(),
            OidcError::BadSignature
        );
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        for bad in ["", "  ", "not.a.jwt", "a.b", "....", "aaaa"] {
            assert_eq!(
                verify(bad, &keys, &policy(), 1_000).unwrap_err(),
                OidcError::Malformed,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn every_error_has_a_distinct_stable_label() {
        let labels = [
            OidcError::Malformed,
            OidcError::UnknownKid("k".to_owned()),
            OidcError::BadSignature,
            OidcError::WrongIssuer,
            OidcError::WrongAudience,
            OidcError::Expired,
            OidcError::NotYetValid,
            OidcError::MissingClaim("exp"),
            OidcError::UnsupportedAlg("HS256".to_owned()),
            OidcError::Jwks("x".to_owned()),
        ]
        .map(|e| e.label());
        let unique: HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(unique.len(), labels.len());
        assert!(labels.iter().all(|l| l.starts_with("oidc.reject.")));
    }

    #[test]
    fn jwks_parsing_rejects_junk() {
        assert!(parse_jwks(b"{\"keys\":[]}").is_ok());
        assert!(matches!(parse_jwks(b"nope"), Err(OidcError::Jwks(_))));
    }
}
