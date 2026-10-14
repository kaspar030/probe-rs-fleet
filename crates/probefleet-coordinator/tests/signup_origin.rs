//! Browser signup through fleet's coordinator honours forgs' Origin check the
//! way real browsers exercise it (task 4554).
//!
//! The signup page used to be served `Referrer-Policy: no-referrer`, so the
//! browser's form POST carried `Origin: null` and was refused with a bare
//! 403 `{"error":"forbidden"}`. forgs 0.1.1 serves the page `same-origin` and
//! accepts `Origin: null` only alongside `Sec-Fetch-Site: same-origin`. Fleet's
//! `public_url` may carry a trailing slash or a path: only its origin counts.
//!
//! The coordinator listens on plain `http://127.0.0.1`, while `public_url` is
//! `https`, so cookies (possibly `Secure`) are carried by hand.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use forgs_idp::{AuthRequest, ExternalIdentity, IdentityProvider, IdpError, ProviderTokens};

use common::TestCoordinator;

const ORIGIN: &str = "https://fleet.example";

/// An identity provider that hands out whichever identity was registered
/// under the authorization `code`: `code → (subject, suggested username)`.
struct StubIdp {
    ids: Mutex<HashMap<String, (String, String)>>,
}

impl StubIdp {
    fn add(&self, code: &str, subject: &str, username: &str) {
        self.ids
            .lock()
            .unwrap()
            .insert(code.to_owned(), (subject.to_owned(), username.to_owned()));
    }
}

#[async_trait]
impl IdentityProvider for StubIdp {
    fn name(&self) -> &'static str {
        "stub"
    }
    fn authorization_url(&self, redirect_uri: &str, req: &AuthRequest) -> Result<String, IdpError> {
        Ok(forgs_idp::url::append_query(
            "https://idp.example/authorize",
            &[
                ("state", &req.state),
                ("redirect_uri", redirect_uri),
                ("code_challenge", &req.pkce_challenge()),
            ],
        ))
    }
    async fn exchange_code(
        &self,
        code: &str,
        _redirect_uri: &str,
        _pkce_verifier: &str,
    ) -> Result<ProviderTokens, IdpError> {
        Ok(ProviderTokens::new(code.to_owned(), None))
    }
    async fn fetch_identity(
        &self,
        tokens: ProviderTokens,
        _nonce: &str,
        _now: u64,
    ) -> Result<ExternalIdentity, IdpError> {
        let (code, _) = tokens.into_parts();
        let (sub, name) = self
            .ids
            .lock()
            .unwrap()
            .get(&code)
            .cloned()
            .ok_or_else(|| IdpError::Oauth {
                code: "bad_verification_code".into(),
                description: None,
            })?;
        ExternalIdentity::verified(
            "stub",
            sub,
            Some(format!("{name}@example.com")),
            true,
            Some(name),
        )
    }
}

async fn fleet_at(public_url: &str) -> (TestCoordinator, Arc<StubIdp>) {
    let idp = Arc::new(StubIdp {
        ids: Mutex::new(HashMap::new()),
    });
    let config = probefleet_coordinator::config::CoordinatorConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        sqlite_path: ":memory:".into(),
        signing_key: probefleet_coordinator::config::SigningKeySource::Seed(common::SEED),
        csrf_secret: Some(common::CSRF_SECRET.to_vec()),
        public_url: public_url.to_owned(),
        ..Default::default()
    };
    let providers: Vec<Arc<dyn IdentityProvider>> = vec![idp.clone()];
    (TestCoordinator::start_config(config, providers).await, idp)
}

/// A minimal cookie jar: name → value, fed from `Set-Cookie` headers.
#[derive(Default)]
struct Jar(HashMap<String, String>);

impl Jar {
    fn absorb(&mut self, headers: &[(String, String)]) {
        for (k, v) in headers {
            if k != "set-cookie" {
                continue;
            }
            let pair = v.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                if value.is_empty() {
                    self.0.remove(name.trim());
                } else {
                    self.0.insert(name.trim().to_owned(), value.to_owned());
                }
            }
        }
    }
    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The raw (still URL-encoded) value of a query parameter.
fn query_param<'u>(url: &'u str, key: &str) -> &'u str {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .unwrap_or_else(|| panic!("no {key} in {url}"))
        .1
}

/// First login through the stub provider, up to the signup page. Returns the
/// jar holding the pending-signup ticket.
async fn first_login(fleet: &TestCoordinator, idp: &StubIdp, code: &str, name: &str) -> Jar {
    idp.add(code, &format!("sub-{name}"), name);
    let mut jar = Jar::default();
    let (status, headers, body) = fleet.http_full("GET", "/auth/stub/start", &[], None).await;
    assert_eq!(status, 302, "{body}");
    jar.absorb(&headers);
    let location = header(&headers, "location").unwrap();
    let state = query_param(location, "state").to_owned();

    let cookie = jar.header();
    let (status, headers, body) = fleet
        .http_full(
            "GET",
            &format!("/auth/stub/callback?code={code}&state={state}"),
            &[("cookie", &cookie)],
            None,
        )
        .await;
    assert_eq!(status, 302, "{body}");
    assert_eq!(header(&headers, "location"), Some("/auth/signup"));
    jar.absorb(&headers);

    // The signup page itself: forgs 0.1.1 no longer strips the Origin of
    // its own form posts.
    let cookie = jar.header();
    let (status, headers, body) = fleet
        .http_full("GET", "/auth/signup", &[("cookie", &cookie)], None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(header(&headers, "referrer-policy"), Some("same-origin"));
    jar
}

async fn post_signup(
    fleet: &TestCoordinator,
    jar: &Jar,
    name: &str,
    extra: &[(&str, &str)],
) -> (u16, Vec<(String, String)>, String) {
    let cookie = jar.header();
    let mut headers = vec![
        ("content-type", "application/x-www-form-urlencoded"),
        ("cookie", cookie.as_str()),
    ];
    headers.extend_from_slice(extra);
    fleet
        .http_full(
            "POST",
            "/auth/signup",
            &headers,
            Some(format!("username={name}")),
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signup_post_passes_the_origin_check_for_browser_shapes() {
    let cases: &[(&[(&str, &str)], u16)] = &[
        (&[("origin", ORIGIN)], 303),
        (
            &[("origin", ORIGIN), ("sec-fetch-site", "same-origin")],
            303,
        ),
        // A no-referrer document's form post: the real browser case.
        (
            &[("origin", "null"), ("sec-fetch-site", "same-origin")],
            303,
        ),
        (&[("origin", "null")], 403),
        (&[("origin", "https://evil.example")], 403),
        (&[("sec-fetch-site", "cross-site")], 403),
        (&[("origin", ORIGIN), ("sec-fetch-site", "cross-site")], 403),
    ];
    for public_url in [
        ORIGIN.to_owned(),
        format!("{ORIGIN}/"),
        format!("{ORIGIN}/sub/"),
    ] {
        let (fleet, idp) = fleet_at(&public_url).await;
        for (i, (extra, want)) in cases.iter().enumerate() {
            let name = format!("user{i}");
            let jar = first_login(&fleet, &idp, &format!("code{i}"), &name).await;
            let (status, headers, body) = post_signup(&fleet, &jar, &name, extra).await;
            assert_eq!(
                status, *want,
                "public_url={public_url} headers={extra:?}: {body}"
            );
            if *want == 303 {
                assert!(
                    headers
                        .iter()
                        .any(|(k, v)| k == "set-cookie" && v.contains("_session=")),
                    "public_url={public_url} headers={extra:?}: no session cookie in {headers:?}"
                );
            } else {
                assert!(body.contains("forbidden"), "{body}");
            }
        }
    }
}
