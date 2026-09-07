//! The UI asset surface: routing, headers, cache keys, and the properties the
//! shipped asset tree has to hold (`docs/web-ui.md` D3).
//!
//! Three groups of assertion, in rough order of how badly it would hurt to get
//! them wrong:
//!
//! * **nothing is swallowed.** The coordinator has no global `Router::fallback`
//!   and must not grow one, so `/api/*`, `/agent`, `/client`, `/delegate`,
//!   `/healthz` and `/node/approve` keep their own answers and an unknown
//!   top-level path is an empty 404 rather than the SPA shell;
//! * **the headers are the security control.** The strict CSP, `nosniff` and
//!   `no-referrer` ride on every `/ui*` response, the shell is `no-cache` and a
//!   hashed asset is `immutable`. A hashed URL is taken from the *rendered
//!   shell*, so these cannot pass against a page pointing at URLs the server
//!   will not serve;
//! * **static analysis over the embedded tree.** No `innerHTML`, no
//!   `localStorage`, no inline handler attributes, no CDN — the frontend
//!   properties `docs/web-ui.md` §5 promises, asserted rather than reviewed.
//!   These are cheap only because the bytes are compiled into this binary.

mod common;

use common::TestCoordinator;

/// The CSP D3 fixes, byte-exact. A test that recomputed it from the source
/// would agree with any typo.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                   connect-src 'self'; img-src 'self'; frame-ancestors 'none'; \
                   base-uri 'none'; form-action 'self'";

/// Look one response header up, case-insensitively.
fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Assert the three hardening headers are present and exact.
fn assert_hardened(headers: &[(String, String)], what: &str) {
    assert_eq!(
        header(headers, "content-security-policy"),
        Some(CSP),
        "{what} must carry the CSP"
    );
    assert_eq!(
        header(headers, "x-content-type-options"),
        Some("nosniff"),
        "{what}"
    );
    assert_eq!(
        header(headers, "referrer-policy"),
        Some("no-referrer"),
        "{what}"
    );
    // `frame-ancestors 'none'` already covers framing; a second spelling of one
    // policy is a drift invitation, so it is deliberately absent.
    assert_eq!(header(headers, "x-frame-options"), None, "{what}");
}

/// The hashed asset prefix, read out of the shell the server actually renders.
fn asset_prefix(shell: &str) -> String {
    let at = shell
        .find("/ui/a/")
        .unwrap_or_else(|| panic!("the shell names no hashed asset URL: {shell}"));
    let rest = &shell[at..];
    let end = rest[6..]
        .find('/')
        .expect("a hashed asset URL has a path after the hash")
        + 6;
    rest[..end].to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_shell_is_served_with_the_hardening_headers_and_no_cache() {
    let fleet = TestCoordinator::start().await;

    let (status, headers, body) = fleet.http_full("GET", "/ui/", &[], None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        header(&headers, "content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(header(&headers, "cache-control"), Some("no-cache"));
    assert_hardened(&headers, "the shell");
    assert!(body.contains("<main id=\"app\">"), "{body}");
    // The token must be gone: a shell still carrying it names URLs that 404,
    // and the failure mode is a blank page with no error.
    assert!(!body.contains("__ASSETS__"), "{body}");
    // Asset routes are unauthenticated and set nothing.
    assert_eq!(header(&headers, "set-cookie"), None);
}

/// `/` and a bare `/ui` both land on the canonical path, so relative asset
/// URLs resolve. The callback's existing `302 /ui` keeps working through this.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_root_and_bare_ui_redirect_to_the_canonical_path() {
    let fleet = TestCoordinator::start().await;

    for path in ["/", "/ui"] {
        let (status, headers, _) = fleet.http_full("GET", path, &[], None).await;
        assert_eq!(status, 302, "{path}");
        assert_eq!(header(&headers, "location"), Some("/ui/"), "{path}");
        assert_hardened(&headers, path);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hashed_assets_are_immutable_and_typed_by_extension() {
    let fleet = TestCoordinator::start().await;

    let (_, _, shell) = fleet.http_full("GET", "/ui/", &[], None).await;
    let prefix = asset_prefix(&shell);

    for (path, content_type) in [
        ("app.mjs", "text/javascript; charset=utf-8"),
        ("app.css", "text/css; charset=utf-8"),
        ("pages/login.mjs", "text/javascript; charset=utf-8"),
    ] {
        let url = format!("{prefix}/{path}");
        let (status, headers, body) = fleet.http_full("GET", &url, &[], None).await;
        assert_eq!(status, 200, "{url}: {body}");
        assert_eq!(header(&headers, "content-type"), Some(content_type), "{url}");
        assert_eq!(
            header(&headers, "cache-control"),
            Some("public, max-age=31536000, immutable"),
            "{url}"
        );
        assert_hardened(&headers, &url);
        assert_eq!(header(&headers, "set-cookie"), None, "{url}");
        assert!(!body.is_empty(), "{url}");
    }
}

/// The hash is a cache key, not a check: a stale hash after a restart with new
/// assets must still serve the page rather than break it mid-session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_hash_still_serves_current_bytes() {
    let fleet = TestCoordinator::start().await;

    let (status, headers, body) = fleet
        .http_full("GET", "/ui/a/0000000000000000/app.mjs", &[], None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        header(&headers, "content-type"),
        Some("text/javascript; charset=utf-8")
    );
}

/// Every client-side route answers with the *same* shell, so a deep link and a
/// reload both work — in **both** spellings.
///
/// `web/router.mjs` strips a trailing slash, so once the shell is loaded
/// `/ui/devices/` is the devices page; the bug this pins is that a *cold* load
/// of the slashed form never reached the shell that would have normalised it.
/// The two spellings are one page and must be indistinguishable over the wire,
/// headers included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_side_routes_all_render_the_shell() {
    let fleet = TestCoordinator::start().await;

    let (_, _, canonical) = fleet.http_full("GET", "/ui/", &[], None).await;
    let pages = fleet_coordinator::assets::shell_pages();
    assert!(!pages.is_empty(), "there is at least one client-side page");

    for page in pages {
        for path in [format!("/ui/{page}"), format!("/ui/{page}/")] {
            let (status, headers, body) = fleet.http_full("GET", &path, &[], None).await;
            assert_eq!(status, 200, "{path}");
            assert_eq!(header(&headers, "cache-control"), Some("no-cache"), "{path}");
            assert_hardened(&headers, &path);
            assert_eq!(header(&headers, "set-cookie"), None, "{path}");
            assert_eq!(body, canonical, "{path} must be byte-identical to /ui/");
        }
    }
}

/// The Rust page list and `web/router.mjs`'s `PAGES` are hand-maintained in two
/// files, and this bug is exactly what their drift looks like: the server
/// serving a set of paths the client router does not agree with.
///
/// Scraped out of the shipped bytes rather than imported: there is no build
/// step and `cargo test` must not require a JS toolchain (`docs/web-ui.md` D3).
/// The array literal is one line of string literals, so splitting it is enough,
/// and the `expect`s below fail loudly if it ever stops being that.
#[test]
fn the_rust_and_javascript_page_lists_agree() {
    let source = String::from_utf8(
        fleet_coordinator::assets::asset_bytes("router.mjs")
            .expect("web/router.mjs is embedded")
            .to_vec(),
    )
    .expect("web/router.mjs is UTF-8");

    let (_, rest) = source
        .split_once("export const PAGES = [")
        .expect("web/router.mjs declares `export const PAGES = [...]` on one line");
    let (list, _) = rest
        .split_once(']')
        .expect("the PAGES array literal is closed");
    let js: Vec<&str> = list
        .split(',')
        .map(|entry| entry.trim().trim_matches('\'').trim_matches('"'))
        .filter(|entry| !entry.is_empty())
        .collect();

    assert_eq!(
        js,
        fleet_coordinator::assets::shell_pages(),
        "web/router.mjs's PAGES and src/assets.rs's PAGES have drifted; \
         the server would serve pages the client router does not know, or refuse \
         pages it does"
    );
}

/// A path with an extension is never answered with the shell.
///
/// That is what makes a typo'd `import` surface as a broken import rather than
/// as an HTML document parsed as JavaScript — a failure that reads as "the
/// bundler is broken" and takes an afternoon.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_asset_path_is_a_404_and_never_the_shell() {
    let fleet = TestCoordinator::start().await;

    let (_, _, shell) = fleet.http_full("GET", "/ui/", &[], None).await;
    let prefix = asset_prefix(&shell);

    for path in [
        "/ui/nope.mjs".to_owned(),
        "/ui/pages/nope.mjs".to_owned(),
        // Serving both spellings of a *known* page does not widen the surface:
        // an unknown one still 404s either way.
        "/ui/nope".to_owned(),
        "/ui/nope/".to_owned(),
        "/ui/devices/extra".to_owned(),
        "/ui/devices//".to_owned(),
        format!("{prefix}/nope.mjs"),
        format!("{prefix}/pages/nope.mjs"),
    ] {
        let (status, _, body) = fleet.http_full("GET", &path, &[], None).await;
        assert_eq!(status, 404, "{path}");
        assert!(!body.contains("<main"), "{path} must not be the shell");
    }
}

/// Traversal, in every spelling that reaches the handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traversal_out_of_the_asset_tree_is_refused() {
    let fleet = TestCoordinator::start().await;

    let (_, _, shell) = fleet.http_full("GET", "/ui/", &[], None).await;
    let prefix = asset_prefix(&shell);

    for suffix in [
        "../Cargo.toml",
        "../../Cargo.toml",
        "%2e%2e%2fCargo.toml",
        "%2e%2e%2f%2e%2e%2fCargo.toml",
        "pages/../../Cargo.toml",
        "//etc/passwd",
        "./app.mjs",
    ] {
        let path = format!("{prefix}/{suffix}");
        let (status, _, body) = fleet.http_full("GET", &path, &[], None).await;
        assert_ne!(status, 200, "{path} must not serve anything: {body}");
        assert!(!body.contains("[package]"), "{path} leaked a manifest");
    }
}

/// The property the whole route shape exists for: no global fallback, so the
/// shell cannot swallow another prefix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ui_swallows_no_other_prefix() {
    let fleet = TestCoordinator::start().await;

    // `/healthz` stays plain text.
    let (status, _, body) = fleet.http_full("GET", "/healthz", &[], None).await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok");

    // An unauthenticated API call is JSON, not a login page.
    let (status, headers, body) = fleet.http_full("GET", "/api/v1/session", &[], None).await;
    assert_eq!(status, 401, "{body}");
    assert!(
        header(&headers, "content-type").is_some_and(|ct| ct.starts_with("application/json")),
        "{headers:?}"
    );

    // An unknown `/api/v1` path is a 404 with no body at all, not HTML.
    let (status, _, body) = fleet.http_full("GET", "/api/v1/nope", &[], None).await;
    assert_eq!(status, 404);
    assert!(!body.contains("<main"), "{body}");

    // An unknown top-level path is an *empty* 404 — the signature of a router
    // with no fallback registered.
    for path in ["/zzz", "/ui-not-really", "/api", "/auth"] {
        let (status, _, body) = fleet.http_full("GET", path, &[], None).await;
        assert_eq!(status, 404, "{path}");
        assert!(body.is_empty(), "{path} answered with a body: {body}");
    }

    // The control-plane upgrades still refuse a plain GET their own way.
    for path in ["/agent", "/client", "/delegate"] {
        let (status, _, body) = fleet.http_full("GET", path, &[], None).await;
        assert_ne!(status, 200, "{path}");
        assert!(!body.contains("<main"), "{path} must not be the shell");
    }

    // The page every deployed agent prints is untouched.
    let (status, headers, body) = fleet.http_full("GET", "/node/approve", &[], None).await;
    assert_eq!(status, 200);
    assert_eq!(
        header(&headers, "content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(body.contains("probe-rs-fleet node approve"), "{body}");
}

// ---------------------------------------------------------------------------
// Static analysis over the shipped asset tree
// ---------------------------------------------------------------------------

/// Every embedded file as `(path, text)`.
fn assets() -> Vec<(String, String)> {
    fleet_coordinator::assets::asset_paths()
        .into_iter()
        .map(|path| {
            let bytes =
                fleet_coordinator::assets::asset_bytes(&path).expect("a listed path is embedded");
            let text = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|_| panic!("{path} is not UTF-8; the tree ships only text"));
            (path, text)
        })
        .collect()
}

/// The tree is the shipped surface, so the tests file goes elsewhere. If this
/// ever fails, `web-tests/` was moved under `web/` and every JS test is now
/// public, cache-busting and lint-tripping. See `src/assets.rs`.
#[test]
fn the_embedded_tree_ships_no_tests_and_no_package_manifest() {
    for (path, _) in assets() {
        assert!(!path.contains("test"), "{path} must not be embedded");
        assert!(path != "package.json", "{path} must not be embedded");
        assert!(path != "package-lock.json", "{path} must not be embedded");
    }
}

/// No path from a server string to HTML, and no dynamic evaluation.
///
/// `dom.mjs` sets `textContent` and nothing else, which is what makes
/// `docs/web-ui.md` §5's "inserted as text, never as HTML" structural. These
/// lints are how it stays that way.
#[test]
fn nothing_in_the_tree_can_write_html_or_evaluate_a_string() {
    for (path, text) in assets() {
        for needle in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function(",
        ] {
            assert!(
                !text.contains(needle),
                "{path} contains `{needle}`; see src/assets.rs and web/dom.mjs"
            );
        }
    }
}

/// No secret, and no anything, is persisted client-side.
///
/// `docs/web-ui.md`'s "no capability token or long-lived secret in
/// `localStorage`" as a test rather than as a promise. The minted auth key
/// lives in one variable for the lifetime of a view; nothing else is stored at
/// all, which is a stronger and much cheaper property to check.
#[test]
fn the_tree_touches_no_client_side_storage() {
    for (path, text) in assets() {
        for needle in ["localStorage", "sessionStorage", "indexedDB", "openDatabase"] {
            assert!(!text.contains(needle), "{path} contains `{needle}`");
        }
    }
}

/// The CSP forbids inline script and inline style, so an `on*=` attribute or a
/// `style=` attribute is dead code that silently does nothing. Handlers go
/// through the vnode's `on` channel and visuals through `app.css`.
#[test]
fn the_tree_has_no_inline_handlers_and_no_style_attributes() {
    for (path, text) in assets() {
        assert!(!text.contains("style=\""), "{path} has a style attribute");
        assert!(!text.contains("style='"), "{path} has a style attribute");
        for handler in ["onclick=", "onsubmit=", "onchange=", "onload=", "onerror="] {
            assert!(!text.contains(handler), "{path} has an inline `{handler}`");
        }
        // `setAttribute('on…')` is the same mistake wearing a coat.
        assert!(
            !text.contains("setAttribute('on") && !text.contains("setAttribute(\"on"),
            "{path} sets an inline event-handler attribute"
        );
    }
}

/// No CDN, no third-party origin, no inline `<script>` body.
#[test]
fn the_shell_loads_only_same_origin_assets() {
    let (_, html) = assets()
        .into_iter()
        .find(|(p, _)| p == "index.html")
        .expect("index.html is embedded");

    assert!(!html.contains("http://"), "{html}");
    assert!(!html.contains("https://"), "{html}");
    assert!(!html.contains("//cdn"), "{html}");
    // Every `<script>` is a `src=` module: no inline body anywhere.
    for chunk in html.split("<script").skip(1) {
        let tag_end = chunk.find('>').expect("a script tag closes");
        let (tag, rest) = chunk.split_at(tag_end);
        assert!(tag.contains("src="), "an inline <script> body: {chunk}");
        let body_end = rest.find("</script>").expect("a script tag is closed");
        assert!(
            rest[1..body_end].trim().is_empty(),
            "an inline <script> body: {chunk}"
        );
    }
}

/// Every asset the shell names, and every static import in the tree, resolves
/// to a file that is actually embedded.
///
/// A typo'd import is a blank page in production and a red test here.
#[test]
fn every_referenced_asset_resolves() {
    let tree = assets();
    let paths: std::collections::HashSet<String> = tree.iter().map(|(p, _)| p.clone()).collect();

    // `__ASSETS__/x` in the shell.
    let (_, html) = tree
        .iter()
        .find(|(p, _)| p == "index.html")
        .expect("index.html is embedded");
    let mut referenced = 0;
    for chunk in html.split("__ASSETS__/").skip(1) {
        let end = chunk
            .find(['"', '\''])
            .expect("an asset URL is quoted in the shell");
        let asset = &chunk[..end];
        assert!(paths.contains(asset), "index.html names a missing {asset}");
        referenced += 1;
    }
    assert!(referenced >= 2, "the shell names no assets at all");

    // Relative `import … from './x.mjs'` in every module.
    for (path, text) in &tree {
        // `.mjs` exactly — this is an embedded asset path, not a filesystem
        // path, and the tree ships only lowercase names.
        if std::path::Path::new(path)
            .extension()
            .is_none_or(|ext| ext != "mjs")
        {
            continue;
        }
        let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
        for chunk in text.split("from '").skip(1) {
            let end = chunk.find('\'').expect("an import specifier is quoted");
            let spec = &chunk[..end];
            assert!(
                spec.starts_with('.'),
                "{path} imports the non-relative `{spec}`: there is no bundler and no import map"
            );
            let resolved = resolve(dir, spec);
            assert!(
                paths.contains(&resolved),
                "{path} imports `{spec}`, which resolves to a missing {resolved}"
            );
        }
    }
}

/// Resolve a relative specifier against a directory, the way a browser would.
fn resolve(dir: &str, spec: &str) -> String {
    let mut parts: Vec<&str> = if dir.is_empty() {
        vec![]
    } else {
        dir.split('/').collect()
    };
    for segment in spec.split('/') {
        match segment {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}
