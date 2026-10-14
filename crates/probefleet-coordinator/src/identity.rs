//! fleet on forgs: the [`AuthContext`] the coordinator hands to forgs'
//! HTTP surface, and fleet's two hooks into it.
//!
//! * the token format — brand `prf` plus fleet's app kind `node` (tag `n`, a
//!   connection credential), so tokens read `prfs1_` (session), `prfr1_`
//!   (refresh), `prfk1_` (API key), `prfw1_` (workload), `prfd1_` (device
//!   secret) and `prfn1_` (node);
//! * [`FleetPurposes`] — the API-key purposes: `node` keys are redeemed by
//!   fleet at `POST /node/enroll` (payload `{"tags": [...]}`), `ci` keys by
//!   forgs at `/auth/token` for a workload token (payload
//!   `{"tags": [...], "ops": [...]}`), synthesising a board grant;
//! * [`FleetNodeApprovals`] — the pending-approval hook behind
//!   `/node/register/*`: forgs owns the user-code / device-secret machine,
//!   fleet decides who may approve and mints the node token on redemption.
//!
//! The hooks need the coordinator (its signer, scheduler and database), and
//! the coordinator holds the context, so they reach it through a
//! [`CoordinatorLink`] filled in right after construction.

use std::sync::{Arc, OnceLock, Weak};

use async_trait::async_trait;
use forgs::{NsNodeId, SubjectKey, TokenFormat, TokenKind, TokenUse, UserId};
use forgs_http::{ApiError, ApiKeyPurposes, AuthContext, PendingApprovalHook, PurposeKind, Ttls};
use forgs_idp::{IdentityProvider, WorkloadIssuer};
use forgs_store::{ConsumedApiKey, NewGrant, PendingDevice};
use serde::{Deserialize, Serialize};

use probefleet_proto::adopt::AdoptPolicy;
use probefleet_proto::auth_api::NodeTokenResponse;
use probefleet_proto::token::AllowedOp;

use crate::clock::SharedClock;
use crate::config::{CoordinatorConfig, ProviderConfig, ProviderKind};
use crate::core::Coordinator;
use crate::error::{CoordinatorError, Result};
use crate::state::{AuditEntry, Db};
use crate::subject::{org_of, FleetRole, NODE_KIND};

/// `AuthContext` app label: separates fleet's CSRF / cookie keys from any
/// other forgs app's. Frozen: changing it changes the derived CSRF / cookie
/// keys.
pub const APP_LABEL: &str = "probe-rs-fleet";
/// Cookie brand: `prfs_session`, `prfs_csrf`, …
pub const COOKIE_BRAND: &str = "prfs";
/// The CSRF header the web UI echoes the token in.
pub const CSRF_HEADER: &str = "x-fleet-csrf";
/// The only prefix under which the session cookie is a credential.
pub const COOKIE_API_PREFIX: &str = "/api/v1/";
/// Where a browser lands after login.
pub const POST_LOGIN_REDIRECT: &str = "/";

/// API-key purpose: enroll a node (`POST /node/enroll`).
pub const PURPOSE_NODE: &str = "node";
/// API-key purpose: a CI runner's workload credential.
pub const PURPOSE_CI: &str = "ci";

/// Ops a `ci` key confers when its payload names none. `power-cycle` is
/// deliberately absent: an unattended runner cutting power to a lab board
/// should be an explicit choice.
pub const DEFAULT_CI_KEY_OPS: [AllowedOp; 4] = [
    AllowedOp::Attach,
    AllowedOp::Flash,
    AllowedOp::Reset,
    AllowedOp::Erase,
];

/// Bound on the grant synthesised for a key that never expires (a
/// shell-minted key): an informed choice about the *key* is not a choice to
/// share the org's hardware forever.
pub const DEFAULT_CI_GRANT_TTL_SECS: u64 = 30 * 24 * 3600;

/// fleet's token format: brand `prf`, plus the `node` app kind.
///
/// # Panics
///
/// Never: the format is a constant the unit tests build.
#[must_use]
pub fn token_format() -> TokenFormat {
    let mut b = TokenFormat::builder("prf");
    b.app_kind(NODE_KIND, "n", TokenUse::Connection);
    b.build().expect("fleet's token format is valid")
}

/// The node token kind of `format`.
///
/// # Panics
///
/// If `format` is not [`token_format`]'s.
#[must_use]
pub fn node_token_kind(format: &TokenFormat) -> TokenKind {
    TokenKind::App(
        format
            .app_kind(NODE_KIND)
            .expect("the node kind is registered"),
    )
}

/// The coordinator, as the hooks reach it (set once, right after the
/// coordinator is wrapped in its `Arc`).
pub type CoordinatorLink = Arc<OnceLock<Weak<Coordinator>>>;

fn upgrade(link: &CoordinatorLink) -> std::result::Result<Arc<Coordinator>, ApiError> {
    link.get().and_then(Weak::upgrade).ok_or_else(|| {
        tracing::warn!("auth hook ran without a coordinator");
        ApiError::Internal
    })
}

/// forgs' clock over the coordinator's.
struct ClockAdapter(SharedClock);

impl forgs_http::Clock for ClockAdapter {
    fn now(&self) -> u64 {
        self.0.now_secs()
    }
}

/// Build the login providers from config. Async: an OIDC provider fetches
/// its discovery document.
///
/// # Errors
///
/// [`CoordinatorError::Config`] for an unusable provider.
pub async fn build_providers(
    providers: &[ProviderConfig],
) -> Result<Vec<Arc<dyn IdentityProvider>>> {
    let mut out: Vec<Arc<dyn IdentityProvider>> = Vec::new();
    for p in providers {
        let err = |e: forgs_idp::IdpError| {
            CoordinatorError::Config(format!("auth.providers `{}`: {e}", p.name))
        };
        match p.kind {
            ProviderKind::Github => {
                let endpoints = match (&p.github_endpoints, &p.issuer) {
                    (Some(e), _) => forgs_idp::github::GithubEndpoints {
                        authorize_url: e.authorize_url.clone(),
                        access_token_url: e.access_token_url.clone(),
                        api_base: e.api_base.clone(),
                    },
                    (None, Some(origin)) => forgs_idp::github::GithubEndpoints::enterprise(origin),
                    (None, None) => forgs_idp::github::GithubEndpoints::default(),
                };
                let mut cfg = forgs_idp::github::GithubConfig::new(
                    p.client_id.clone(),
                    p.client_secret.clone(),
                );
                p.name.clone_into(&mut cfg.name);
                cfg.endpoints = endpoints;
                out.push(Arc::new(forgs_idp::GithubProvider::new(cfg).map_err(err)?));
            }
            ProviderKind::Oidc | ProviderKind::Codeberg | ProviderKind::Gitlab => {
                use forgs_idp::oidc::presets;
                let (id, secret) = (p.client_id.clone(), p.client_secret.clone());
                let cfg = match (p.kind, p.issuer.clone()) {
                    (ProviderKind::Codeberg, None) => presets::codeberg(&p.name, id, secret),
                    (ProviderKind::Codeberg, Some(i)) => presets::forgejo(&p.name, i, id, secret),
                    (ProviderKind::Gitlab, None) => presets::gitlab_com(&p.name, id, secret),
                    (ProviderKind::Gitlab, Some(i)) => presets::gitlab(&p.name, i, id, secret),
                    (_, i) => {
                        forgs_idp::oidc::OidcConfig::new(&p.name, i.unwrap_or_default(), id, secret)
                    }
                };
                out.push(Arc::new(
                    forgs_idp::OidcProvider::discover(cfg).await.map_err(err)?,
                ));
            }
        }
    }
    Ok(out)
}

/// The GitHub Actions workload issuer `[github_actions]` configures, if any.
#[must_use]
pub fn gha_issuer(config: &CoordinatorConfig) -> Option<Arc<dyn WorkloadIssuer>> {
    let gha = config.github_actions.as_ref()?;
    let policy = forgs_idp::workload::OidcPolicy {
        issuer: gha.issuer.clone(),
        audience: gha.audience.clone(),
        leeway_secs: 60,
    };
    let jwks = forgs_idp::oidc::JwksCache::new(
        gha.jwks_url.clone(),
        std::time::Duration::from_secs(gha.jwks_refresh_secs),
        std::time::Duration::from_secs(gha.jwks_min_refetch_secs),
    );
    Some(Arc::new(forgs_idp::GithubActionsIssuer::with_parts(
        policy, jwks,
    )))
}

/// Build the forgs [`AuthContext`] for a coordinator.
///
/// # Errors
///
/// [`CoordinatorError::AuthConfig`] for an unusable public URL, secret or
/// provider name.
pub fn build_context(
    config: &CoordinatorConfig,
    db: &Db,
    clock: SharedClock,
    providers: Vec<Arc<dyn IdentityProvider>>,
    link: &CoordinatorLink,
) -> Result<AuthContext> {
    let secret = config.csrf_secret.clone().unwrap_or_else(random_secret);
    let ttl = Ttls {
        session: config.session_ttl_secs,
        refresh: config.refresh_token_ttl_secs,
        workload: config
            .github_actions
            .as_ref()
            .map_or(3600, |g| g.workload_token_ttl_secs),
        // One device machine for CLI login and node approval: fleet's
        // short pending-node TTL bounds both.
        device_flow: config.pending_node_ttl_secs,
        ..Ttls::default()
    };
    let mut b = AuthContext::builder(db.forgs().clone(), &config.public_url, &secret)
        .app_label(APP_LABEL)
        .format(token_format())
        .clock(Arc::new(ClockAdapter(clock)))
        .ttls(ttl)
        .cookie_brand(COOKIE_BRAND)
        .csrf_header(CSRF_HEADER)
        .cookie_api_prefix(Some(COOKIE_API_PREFIX))
        .post_login_redirect(POST_LOGIN_REDIRECT)
        .max_pending_devices(u64::try_from(config.max_pending_nodes).unwrap_or(0))
        .app_tokens(Arc::new(crate::tokens::NodeTokens::new(db.clone())))
        .api_key_purposes(Arc::new(FleetPurposes { link: link.clone() }))
        .pending_approvals(Arc::new(FleetNodeApprovals { link: link.clone() }));
    for p in providers {
        b = b.provider(p);
    }
    if let Some(issuer) = gha_issuer(config) {
        b = b.workload_issuer(issuer);
    }
    Ok(b.build()?)
}

/// A per-process secret for a coordinator built without one (tests).
fn random_secret() -> Vec<u8> {
    use rand_core::RngCore as _;
    let mut s = vec![0u8; 32];
    rand_core::OsRng.fill_bytes(&mut s);
    s
}

// ---------------------------------------------------------------------------
// API-key purposes
// ---------------------------------------------------------------------------

/// A `node` key's payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeKeyPayload {
    /// Selection tags stamped onto every node the key enrolls.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A `ci` key's payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiKeyPayload {
    /// The boards the synthesised grant covers: `tag=a && tag=b`. Required
    /// and non-empty — an empty selector would match every board in the org.
    pub tags: Vec<String>,
    /// The ops it confers (labels); empty means [`DEFAULT_CI_KEY_OPS`].
    #[serde(default)]
    pub ops: Vec<String>,
}

impl CiKeyPayload {
    /// The canonical selector and ops this payload grants, or `None` if it
    /// does not form one (fails closed).
    #[must_use]
    pub fn grant(&self) -> Option<(String, Vec<AllowedOp>)> {
        if self.tags.is_empty() {
            return None;
        }
        let selector = self
            .tags
            .iter()
            .map(|t| format!("tag={t}"))
            .collect::<Vec<_>>()
            .join(" && ");
        let selector = probefleet_proto::lease::parse_constraint(&selector)
            .ok()?
            .to_string();
        let ops = if self.ops.is_empty() {
            DEFAULT_CI_KEY_OPS.to_vec()
        } else {
            let parsed: Vec<AllowedOp> = self
                .ops
                .iter()
                .filter_map(|o| AllowedOp::from_label(o))
                .collect();
            if parsed.len() != self.ops.len() {
                return None;
            }
            probefleet_proto::token::normalize_ops(parsed)
        };
        Some((selector, ops))
    }
}

fn canonical_tags(tags: &[String]) -> Option<Vec<String>> {
    if !crate::http::valid_tags(tags) {
        return None;
    }
    let mut t = tags.to_vec();
    t.sort_unstable();
    t.dedup();
    Some(t)
}

/// The deterministic grant id a `ci` key's redemption upserts, derived from
/// `(org, workload subject)`: a multi-use key redeemed by many runners (and
/// a named key re-minted under the same name) converges on **one** row, and
/// the revocation cascade computes the same id from the same key. The org is
/// mixed in so the same name in two orgs is two rows.
#[must_use]
pub fn ci_grant_id(ns: NsNodeId, subject: &SubjectKey) -> forgs::GrantId {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    // Frozen domain label: changing it changes every ci grant id.
    h.update(b"probe-rs-fleet/ci-grant/v1\0");
    h.update(ns.to_string().as_bytes());
    h.update(b"\0");
    h.update(subject.to_string().as_bytes());
    let d = h.finalize();
    let mut ts = [0u8; 8];
    ts[2..].copy_from_slice(&d[..6]);
    let mut rnd = [0u8; 16];
    rnd[6..].copy_from_slice(&d[6..16]);
    forgs::GrantId::from_parts(u64::from_be_bytes(ts), u128::from_be_bytes(rnd))
}

/// The workload subject a `ci` key speaks as: named (`<ns>/workload:agent:<name>`)
/// or derived from its hash (`<ns>/workload:key:<hash8>`) — forgs' own rule.
fn ci_subject(ns: NsNodeId, subject_name: Option<&str>, hash: &str) -> Option<SubjectKey> {
    match subject_name {
        Some(raw) => {
            let name = forgs::subject::normalise_service_name(raw)?;
            Some(forgs::subject::agent_subject_key(&ns, &name))
        }
        None => SubjectKey::new(
            Some(&ns.to_string()),
            forgs::SubjectKind::Workload,
            &format!("key:{}", hash.get(..8)?),
        ),
    }
}

/// fleet's API-key purposes (see the module docs).
pub struct FleetPurposes {
    link: CoordinatorLink,
}

#[async_trait]
impl ApiKeyPurposes for FleetPurposes {
    fn kind(&self, purpose: &str) -> Option<PurposeKind> {
        match purpose {
            PURPOSE_NODE => Some(PurposeKind::App),
            PURPOSE_CI => Some(PurposeKind::Workload),
            _ => None,
        }
    }

    fn check_payload(
        &self,
        purpose: &str,
        payload: Option<&serde_json::Value>,
    ) -> std::result::Result<Option<String>, ApiError> {
        let v = payload.cloned().unwrap_or(serde_json::Value::Null);
        let v = if v.is_null() {
            serde_json::json!({})
        } else {
            v
        };
        let canonical = match purpose {
            PURPOSE_NODE => {
                let p: NodeKeyPayload =
                    serde_json::from_value(v).map_err(|_| ApiError::BadRequest)?;
                let tags = canonical_tags(&p.tags).ok_or(ApiError::BadRequest)?;
                serde_json::to_string(&NodeKeyPayload { tags })
            }
            PURPOSE_CI => {
                let p: CiKeyPayload =
                    serde_json::from_value(v).map_err(|_| ApiError::BadRequest)?;
                let tags = canonical_tags(&p.tags).ok_or(ApiError::BadRequest)?;
                let p = CiKeyPayload { tags, ops: p.ops };
                let (_, ops) = p.grant().ok_or(ApiError::BadRequest)?;
                serde_json::to_string(&CiKeyPayload {
                    tags: p.tags,
                    ops: ops.iter().map(|o| o.as_str().to_owned()).collect(),
                })
            }
            _ => return Err(ApiError::BadRequest),
        };
        canonical.map(Some).map_err(|_| ApiError::Internal)
    }

    async fn on_workload_redeemed(
        &self,
        ctx: &AuthContext,
        key: &ConsumedApiKey,
        subject: &SubjectKey,
    ) -> std::result::Result<(), ApiError> {
        if key.purpose != PURPOSE_CI {
            return Err(ApiError::Forbidden);
        }
        // Re-validated on read: a payload that no longer forms a selector is
        // refused, never widened into a grant to the whole org.
        let Some((selector, ops)) = key
            .payload
            .as_deref()
            .and_then(|p| serde_json::from_str::<CiKeyPayload>(p).ok())
            .and_then(|p| p.grant())
        else {
            tracing::warn!(ns = %key.ns, "a ci key's payload does not form a grant");
            return Err(ApiError::Forbidden);
        };
        let now = ctx.now();
        let expires = key
            .expires
            .unwrap_or_else(|| now.saturating_add(DEFAULT_CI_GRANT_TTL_SECS));
        let id = ci_grant_id(key.ns, subject);
        ctx.store()
            .scoped(key.ns)
            .upsert_grant(
                id,
                &NewGrant {
                    subject: subject.clone(),
                    selector: selector.clone(),
                    ops: crate::state::join_ops(&ops),
                    expires: Some(expires),
                    created_by: key.created_by,
                },
                now,
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "failed to synthesise a ci key's grant");
                match e {
                    forgs_store::StoreError::GrantConflict => ApiError::Forbidden,
                    _ => ApiError::Internal,
                }
            })?;
        ctx.audit()
            .record(
                forgs_http::AuditEvent::new(now, "grant.synthesise")
                    .ns(key.ns)
                    .subject(subject)
                    .target(id.to_string())
                    .detail(format!("selector={selector}")),
            )
            .await;
        Ok(())
    }

    async fn on_revoked(
        &self,
        ctx: &AuthContext,
        ns: NsNodeId,
        revoked: &[String],
        subject_name: Option<&str>,
    ) {
        let Ok(coord) = upgrade(&self.link) else {
            return;
        };
        let scope = ctx.store().scoped(ns);
        let mut subjects: Vec<SubjectKey> = revoked
            .iter()
            .filter_map(|h| ci_subject(ns, subject_name, h))
            .collect();
        subjects.dedup();
        for subject in subjects {
            match scope.delete_grant(ci_grant_id(ns, &subject)).await {
                Ok(Some(_)) => {
                    if let Some(key) = crate::subject::to_proto(&subject) {
                        if let Err(e) = coord.cascade_revocation(&key, &org_of(ns)).await {
                            tracing::warn!(error = %e, "revocation cascade failed");
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "failed to revoke a ci key's grant"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pending node approvals
// ---------------------------------------------------------------------------

/// What an approval-pending node registration asked for, stored as the
/// forgs pending row's payload. Validated before it is stored (it arrives
/// unauthenticated and is rendered to a human approver).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNodePayload {
    /// The name the machine asked for.
    pub node_name: String,
    /// Its tags.
    pub tags: Vec<String>,
    /// Its adoption policy label.
    pub adopt: String,
}

impl PendingNodePayload {
    /// Parse a stored payload; `None` for anything that is not a node
    /// registration (e.g. a CLI login row).
    #[must_use]
    pub fn of(row: &PendingDevice) -> Option<Self> {
        serde_json::from_str(row.payload.as_deref()?).ok()
    }

    /// The adoption policy (conservative `declared` for a hand-edited row).
    #[must_use]
    pub fn adopt_policy(&self) -> AdoptPolicy {
        AdoptPolicy::from_label(&self.adopt).unwrap_or(AdoptPolicy::Declared)
    }
}

/// fleet's [`PendingApprovalHook`]: membership of the target org is
/// sufficient to approve a node into it; redemption registers the node and
/// mints its token.
///
/// The takeover guard (refusing to approve a name that already exists in
/// the org without `replace`) lives in the `/node/register/approve` and
/// `/api/v1/nodes/pending/{code}` handlers, which know the approver's
/// `replace` flag.
pub struct FleetNodeApprovals {
    link: CoordinatorLink,
}

#[async_trait]
impl PendingApprovalHook for FleetNodeApprovals {
    async fn authorize(
        &self,
        _ctx: &AuthContext,
        row: &PendingDevice,
        approver: UserId,
        ns: Option<NsNodeId>,
    ) -> std::result::Result<(), ApiError> {
        let coord = upgrade(&self.link)?;
        let ns = ns.ok_or(ApiError::BadRequest)?;
        if PendingNodePayload::of(row).is_none() {
            return Err(ApiError::Forbidden);
        }
        match coord.db().role_of(&org_of(ns), approver).await {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(ApiError::Forbidden),
            Err(e) => {
                tracing::warn!(error = %e, "membership lookup failed");
                Err(ApiError::Internal)
            }
        }
    }

    async fn redeem(
        &self,
        ctx: &AuthContext,
        approved_by: UserId,
        ns: Option<NsNodeId>,
        payload: &str,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        let coord = upgrade(&self.link)?;
        let ns = ns.ok_or(ApiError::Forbidden)?;
        let p: PendingNodePayload =
            serde_json::from_str(payload).map_err(|_| ApiError::Forbidden)?;
        let detail = format!("approved by user:{approved_by} (adopt={})", p.adopt);
        let resp = coord
            .register_node_and_mint(
                &org_of(ns),
                &p.node_name,
                &p.tags,
                Some(approved_by),
                p.adopt_policy(),
                "node.approve_register",
                &detail,
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "failed to register an approved node");
                ApiError::Internal
            })?;
        let _ = ctx;
        serde_json::to_value(resp).map_err(|_| ApiError::Internal)
    }
}

impl Coordinator {
    /// Mint a node token, create/refresh the node row in `org`, audit it,
    /// and return the enrollment response. The shared tail of every
    /// enrollment path (`/node/enroll`, `/node/self-register`, approval).
    ///
    /// `owner` is the **user** whose authority created the node (none for
    /// an API-key enrollment).
    ///
    /// # Errors
    ///
    /// A database error.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_node_and_mint(
        &self,
        org: &probefleet_proto::ids::OrgId,
        node_name: &str,
        tags: &[String],
        owner: Option<UserId>,
        adopt: AdoptPolicy,
        audit_action: &str,
        audit_detail: &str,
    ) -> Result<NodeTokenResponse> {
        let now = i64::try_from(self.now()).unwrap_or(i64::MAX);
        let format = self.auth().format();
        let token = format.mint(node_token_kind(format));
        let node = self
            .db()
            .register_node_full(
                org,
                node_name,
                token.hash().as_str(),
                tags,
                owner,
                adopt,
                now,
            )
            .await?;
        let subject = match owner {
            Some(u) => crate::subject::user_key(u).to_string(),
            None => crate::subject::node_key(org, &node)
                .map(|k| k.to_string())
                .unwrap_or_default(),
        };
        let _ = self
            .db()
            .scoped(org.clone())
            .append_audit(&AuditEntry {
                ts: now,
                subject: Some(&subject),
                action: audit_action,
                node: Some(node.0.as_str()),
                board: None,
                lease: None,
                detail: Some(audit_detail),
            })
            .await;
        tracing::info!(node = %node, org = %org, %adopt, action = audit_action, "node registered");
        Ok(NodeTokenResponse {
            token: token.to_secret_string(),
            node_id: node.0,
            org: org.0.clone(),
            org_name: self.db().org_name(org).await.ok().flatten(),
            coordinator_token_pubkey: self.token_pubkey_hex(),
        })
    }
}

/// Minimum role to approve a node or mint keys: membership.
pub const APPROVE_ROLE: FleetRole = FleetRole::Member;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_format_brands_node_tokens_prfn() {
        let f = token_format();
        let t = f.mint(node_token_kind(&f)).to_secret_string();
        assert!(t.starts_with("prfn1_"), "{t}");
        assert!(f
            .mint(TokenKind::Session)
            .to_secret_string()
            .starts_with("prfs1_"));
    }

    #[test]
    fn ci_grant_ids_are_deterministic_and_org_separated() {
        let a = NsNodeId::generate(1);
        let b = NsNodeId::generate(2);
        let s = ci_subject(a, Some("builder"), "abcdef0123").unwrap();
        assert_eq!(ci_grant_id(a, &s), ci_grant_id(a, &s));
        assert_ne!(ci_grant_id(a, &s), ci_grant_id(b, &s));
        let s2 = ci_subject(a, Some("builder2"), "abcdef0123").unwrap();
        assert_ne!(ci_grant_id(a, &s), ci_grant_id(a, &s2));
        let unnamed = ci_subject(a, None, "abcdef0123").unwrap();
        assert_eq!(unnamed.id(), "key:abcdef01");
    }

    #[test]
    fn ci_payloads_are_validated_and_canonicalised() {
        let p = FleetPurposes {
            link: Arc::new(OnceLock::new()),
        };
        let v = serde_json::json!({"tags": ["nrf52", "ble", "nrf52"], "ops": ["flash"]});
        let s = p.check_payload(PURPOSE_CI, Some(&v)).unwrap().unwrap();
        let back: CiKeyPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back.tags, vec!["ble", "nrf52"]);
        assert!(
            back.ops.contains(&"attach".to_owned()),
            "flash implies attach"
        );
        for bad in [
            serde_json::json!({"tags": []}),
            serde_json::json!({"tags": ["a b"]}),
            serde_json::json!({"tags": ["x"], "ops": ["nuke"]}),
            serde_json::json!({"tags": ["x"], "extra": 1}),
        ] {
            assert!(p.check_payload(PURPOSE_CI, Some(&bad)).is_err(), "{bad}");
        }
        assert!(p.check_payload(PURPOSE_NODE, None).is_ok());
        assert!(p.check_payload("other", None).is_err());
    }
}
