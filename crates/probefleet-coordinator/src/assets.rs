//! The web UI's static assets, embedded in the binary and served under `/ui`
//! (`docs/web-ui.md` D3).
//!
//! # There is no build step, and that is the mechanism
//!
//! The asset tree in `crates/probefleet-coordinator/web/` is hand-written HTML, CSS
//! and plain ES modules. No npm, no bundler, no TypeScript compile, no
//! generated artifact. [`include_dir!`](include_dir::include_dir) embeds it at
//! compile time, so `cargo build` on a machine with no node or npm installed
//! keeps working **structurally** rather than as a fallback: there is no state
//! in which the check could fail, because there is nothing to generate and
//! nothing to keep in sync.
//!
//! The cost, recorded in D3: no type checking, and hand-rolled DOM code. The
//! JavaScript unit tests in `crates/probefleet-coordinator/web-tests/` need `node`
//! on `PATH`, but `tests/ui_js.rs` skips them loudly when it is absent, so
//! neither `cargo build` nor `cargo test` requires a JavaScript toolchain. A CI
//! pipeline that ever exists should install node (one line, no npm, no network)
//! or that coverage silently disappears; `docs/ci-github-actions.md` is the
//! *consumer* workload-identity guide and is deliberately not the place that
//! gets recorded.
//!
//! **`include_dir!` embeds the whole subtree.** Anything under `web/` ships in
//! the binary and is publicly served, so test and tooling files live in
//! `web-tests/`, a sibling. That trap is invisible at the call site: putting the
//! JS tests under `web/` would ship them to every browser, fold them into the
//! asset hash, and make the static-analysis lints in `tests/ui_assets.rs` trip
//! over the very strings those tests exist to assert are absent.
//!
//! # One tree hash, not per-file hashes
//!
//! Nothing hashes filenames at build time (there is no build), so cache busting
//! is done with a single **tree hash**: SHA-256 over every embedded file in
//! sorted path order — path bytes and content bytes — truncated to 16 hex
//! characters. Assets are served under `/ui/a/{tree-hash}/{path}` with a
//! one-year `immutable` `Cache-Control`, and the shell's `__ASSETS__` token is
//! replaced with `/ui/a/{tree-hash}` once, at first use.
//!
//! One hash over the whole tree is load-bearing, not laziness. A module served
//! from `/ui/a/H/app.mjs` doing `import './api.mjs'` resolves to
//! `/ui/a/H/api.mjs`; with per-file hashes that URL would carry `app.mjs`'s
//! hash and `api.mjs`'s invalidation would silently never happen. Relative
//! imports are correct by construction under one hash, and any edit to any
//! asset invalidates the whole (few-kilobyte) set. Per-file hashing is the
//! obvious "improvement" here and it is wrong.
//!
//! The `{hash}` segment is a **cache key, not a check**: a stale hash still
//! serves current bytes. 404ing a mismatched hash would break a page mid-session
//! across a coordinator restart that changed the assets.
//!
//! # There is no global fallback, and please do not add one
//!
//! Every catch-all this module registers is scoped under `/ui/`. There is no
//! `Router::fallback` anywhere in the coordinator, so the SPA shell cannot
//! swallow `/api/*`, `/agent`, `/client`, `/delegate`, `/healthz` or
//! `/node/approve` — not merely "does not today", but *cannot*, which is a
//! property a test can only sample and a router shape can guarantee. The
//! instinct when a client-side route 404s is to add `.fallback(shell)`; the
//! answer is to add the page to [`PAGES`] instead, which registers both its
//! bare and its trailing-slash spelling.
//!
//! # Headers
//!
//! Every `/ui*` response carries the strict CSP D3 fixes, plus `nosniff` and
//! `no-referrer`, applied in one helper so a route cannot ship without them:
//!
//! ```text
//! default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';
//! img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
//! ```
//!
//! No `unsafe-inline` anywhere, which is why the frontend has no inline
//! `<script>`, no `on*=` attribute handlers and no `style=` attributes — see
//! `web/dom.mjs`. `X-Frame-Options` is deliberately **not** sent:
//! `frame-ancestors 'none'` already covers framing and a second spelling of one
//! policy is a drift invitation.
//!
//! Asset routes are **unauthenticated** and set no cookies: the shell has to
//! load before a session exists, since login is a page inside it. They serve
//! only bytes that are compiled into this binary.

use std::sync::{Arc, OnceLock};

use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use include_dir::{include_dir, Dir};
use sha2::{Digest, Sha256};

use crate::core::Coordinator;

/// The embedded asset tree.
///
/// `pub(crate)` so `tests/ui_assets.rs` can lint it through
/// [`asset_paths`] — the static analysis over the shipped tree (no
/// `innerHTML`, no `localStorage`, no absolute-URL imports) is cheap only
/// because the bytes are right here.
static ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/web");

/// The client-side pages the shell answers, as bare page names.
///
/// Listed explicitly rather than "anything under `/ui/`" so that a typo'd asset
/// URL is a 404 rather than an HTML document parsed as JavaScript. [`router`]
/// derives *both* spellings of each page — `/ui/devices` and `/ui/devices/` —
/// from this one list, because `web/router.mjs` treats them as the same page
/// (it strips trailing slashes) and a cold load of the slashed form must not
/// 404 before the shell that would have normalised it is even served.
///
/// Adding a page means adding it here and to `PAGES` in `web/router.mjs`;
/// `web-tests/router.test.mjs` asserts the client router knows each of them and
/// `tests/ui_assets.rs` asserts the two lists have not drifted.
const PAGES: &[&str] = &[
    "devices", "agents", "approve", "access", "keys", "org", "audit",
];

/// The Content-Security-Policy every `/ui*` response carries (D3).
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                   connect-src 'self'; img-src 'self'; frame-ancestors 'none'; \
                   base-uri 'none'; form-action 'self'";

/// The token in `index.html` that is replaced with the hashed asset prefix.
const ASSET_TOKEN: &str = "__ASSETS__";

/// Cache-Control for the shell: it names hashed URLs, so it must never be held.
const SHELL_CACHE: &str = "no-cache";

/// Cache-Control for a hashed asset URL.
const ASSET_CACHE: &str = "public, max-age=31536000, immutable";

/// Build the asset router, merged into the coordinator's by
/// [`crate::http::router`].
///
/// Note what is *not* here: a `fallback`. See the module documentation.
pub(crate) fn router() -> Router<Arc<Coordinator>> {
    let mut router = Router::new()
        // A bare `/ui` (which is what `/auth/github/callback` redirects to)
        // and the site root both land on the shell's canonical path, so
        // relative asset URLs resolve against `/ui/` rather than against `/`.
        .route("/", get(|| async { redirect_to_ui() }))
        .route("/ui", get(|| async { redirect_to_ui() }))
        .route("/ui/a/{hash}/{*path}", get(asset))
        .route("/ui/", get(shell));
    for page in PAGES {
        // Both spellings, from one list: axum matches paths literally, so
        // `/ui/devices` and `/ui/devices/` are distinct routes, and only the
        // pair keeps a hand-typed or link-mangled trailing slash working on a
        // cold load.
        router = router.route(&format!("/ui/{page}"), get(shell));
        router = router.route(&format!("/ui/{page}/"), get(shell));
    }
    router
}

/// `302` to the UI's canonical path.
fn redirect_to_ui() -> Response {
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/ui/"));
    harden(response)
}

/// Attach the CSP and hardening headers.
///
/// One helper, called on every response this module produces, so a route
/// cannot ship without them.
fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// `GET /ui/` and every client-side route — the rendered shell.
async fn shell() -> Response {
    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, SHELL_CACHE),
        ],
        rendered_shell().as_str(),
    )
        .into_response();
    response = harden(response);
    response
}

/// `GET /ui/a/{hash}/{*path}` — one embedded asset.
///
/// The hash is ignored on purpose (it is a cache key, not a check; see the
/// module documentation), so this handler takes only the path.
async fn asset(Path((_hash, path)): Path<(String, String)>) -> Response {
    let Some(file) = lookup(&path) else {
        return harden(StatusCode::NOT_FOUND.into_response());
    };
    let response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type(&path)),
            (header::CACHE_CONTROL, ASSET_CACHE),
        ],
        file,
    )
        .into_response();
    harden(response)
}

/// Resolve a request path to embedded bytes, refusing anything unusual.
///
/// Screening is **rejection, not normalisation**: any segment that is empty,
/// `.` or `..`, or contains a byte outside `[A-Za-z0-9._-]`, means no file. A
/// normaliser has to be right about every encoding; a charset check has to be
/// right about one.
///
/// `axum`'s path extractor percent-decodes before this runs, so `%2e%2e%2f`
/// arrives as `../` and is screened here rather than sneaking past a check on
/// the raw string. There is no filesystem access at runtime at all — the tree is
/// in the binary and `include_dir`'s `get_file` refuses to escape its root
/// anyway — so this is defence in depth. It is written and tested regardless:
/// the day someone swaps the embed for a directory, this is the check that was
/// already there.
fn lookup(path: &str) -> Option<&'static [u8]> {
    if path.is_empty() || path.starts_with('/') {
        return None;
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return None;
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return None;
        }
    }
    ASSETS.get_file(path).map(include_dir::File::contents)
}

/// The `Content-Type` for a path, by extension, from an explicit table.
///
/// An unknown extension is `application/octet-stream` and never sniffed
/// (`X-Content-Type-Options: nosniff` rides on every response), so a file
/// accidentally added to the tree cannot become script by inference.
fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        // Every frontend module is `.mjs`: unambiguous to node on any version
        // with no `package.json` at all, which is what keeps `web-tests/` free
        // of a file whose only job is to placate a module resolver. `.js` is
        // listed anyway so a stray one is not served as a download.
        Some("mjs" | "js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/vnd.microsoft.icon",
        Some("woff2") => "font/woff2",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

/// The tree hash: SHA-256 over every embedded file, path and bytes, in sorted
/// path order, truncated to 16 hex characters.
///
/// Sorted so the value is a function of the tree's contents and not of
/// `include_dir`'s traversal order, and the path goes into the hash as well as
/// the bytes so that *renaming* a file changes it too.
pub(crate) fn assets_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        let mut files: Vec<&include_dir::File<'_>> = collect(&ASSETS);
        files.sort_by_key(|f| f.path());
        let mut hasher = Sha256::new();
        for file in files {
            hasher.update(file.path().to_string_lossy().as_bytes());
            hasher.update([0u8]);
            hasher.update(file.contents());
            hasher.update([0u8]);
        }
        let digest = hasher.finalize();
        digest.iter().take(8).fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
    })
}

/// Every embedded file, recursively.
fn collect<'a>(dir: &'a Dir<'a>) -> Vec<&'a include_dir::File<'a>> {
    let mut out: Vec<&include_dir::File<'_>> = dir.files().collect();
    for sub in dir.dirs() {
        out.extend(collect(sub));
    }
    out
}

/// Every embedded file's path, for the static analysis in `tests/ui_assets.rs`.
#[must_use]
pub fn asset_paths() -> Vec<String> {
    let mut paths: Vec<String> = collect(&ASSETS)
        .into_iter()
        .map(|f| f.path().to_string_lossy().into_owned())
        .collect();
    paths.sort();
    paths
}

/// The client-side page names, for the drift check in `tests/ui_assets.rs`.
///
/// The Rust and JavaScript lists are hand-maintained in two files; this is what
/// lets a test assert they agree rather than a reviewer notice they do not.
#[must_use]
pub fn shell_pages() -> &'static [&'static str] {
    PAGES
}

/// One embedded file's contents, for the static analysis in
/// `tests/ui_assets.rs`.
#[must_use]
pub fn asset_bytes(path: &str) -> Option<&'static [u8]> {
    ASSETS.get_file(path).map(include_dir::File::contents)
}

/// The shell, with `__ASSETS__` replaced by the hashed asset prefix.
///
/// Rendered once. A shell still containing the token would mean every asset URL
/// 404s, which `tests/ui_assets.rs` asserts against directly.
fn rendered_shell() -> &'static String {
    static SHELL: OnceLock<String> = OnceLock::new();
    SHELL.get_or_init(|| {
        let raw = ASSETS
            .get_file("index.html")
            .expect("web/index.html is embedded at compile time")
            .contents_utf8()
            .expect("web/index.html is UTF-8");
        raw.replace(ASSET_TOKEN, &format!("/ui/a/{}", assets_hash()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The traversal screen is a charset check on decoded segments, and every
    /// spelling of "leave the tree" fails it.
    #[test]
    fn traversal_and_odd_paths_resolve_to_nothing() {
        for path in [
            "",
            "/index.html",
            "../Cargo.toml",
            "../../Cargo.toml",
            "pages/../../Cargo.toml",
            "./index.html",
            "pages//login.mjs",
            "pages/li gin.mjs",
            "pages/\u{e9}.mjs",
            "pages/login.mjs\0",
        ] {
            assert!(lookup(path).is_none(), "{path} must not resolve");
        }
    }

    /// The files the shell actually names must be reachable, or the screen is
    /// vacuously safe.
    #[test]
    fn real_assets_resolve() {
        for path in ["index.html", "app.mjs", "app.css", "pages/login.mjs"] {
            assert!(lookup(path).is_some(), "{path} must resolve");
        }
    }

    #[test]
    fn content_types_come_from_the_table_and_default_to_octet_stream() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("app.mjs"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("app.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("logo.svg"), "image/svg+xml");
        assert_eq!(content_type("weird.xyz"), "application/octet-stream");
        assert_eq!(content_type("noextension"), "application/octet-stream");
    }

    /// A 16-hex-character digest, stable across calls.
    #[test]
    fn the_tree_hash_is_stable_hex() {
        let hash = assets_hash();
        assert_eq!(hash.len(), 16, "{hash}");
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()), "{hash}");
        assert_eq!(hash, assets_hash());
    }

    /// If the token survived rendering, every asset URL in the shell would
    /// 404 — the failure mode is a blank page, so it is pinned here as well as
    /// in the integration test.
    #[test]
    fn the_shell_has_no_unrendered_token() {
        let shell = rendered_shell();
        assert!(!shell.contains(ASSET_TOKEN), "{shell}");
        assert!(
            shell.contains(&format!("/ui/a/{}", assets_hash())),
            "{shell}"
        );
    }
}
