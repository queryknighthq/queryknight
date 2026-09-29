//! Embedded Vue SPA delivery: static assets, SPA fallback, and
//! browser security headers.
//!
//! The bundle (`ui/`, a vendored copy of the Vue production `dist/`)
//! is embedded at compile time — one-binary deployment, no asset-path
//! discovery, no version skew, no filesystem traversal class. The
//! daemon never compiles, installs, or rebuilds frontend code.
//!
//! Precedence (frozen): exact API routes first, then embedded files,
//! then the SPA fallback for browser-owned `GET`/`HEAD` paths.
//! API-shaped unknown paths keep the frozen JSON 404; recognizable
//! asset misses are plain 404s, never HTML. Contract:
//! `docs/browser-ui.md`.

use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

include!(concat!(env!("OUT_DIR"), "/ui_table.rs"));

/// Restrictive policy verified against the actual bundle (external
/// hashed JS/CSS only, no inline scripts/styles, data-URI logo,
/// same-origin fetch). No `unsafe-eval`, no wildcards.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
/// The bootstrap query is credential-bearing; referrers must not carry it.
const REFERRER_POLICY: &str = "no-referrer";

/// Frozen API-shape list (mirrors the reference `isApiPath`): these
/// paths belong to the API even when no route matches, so they keep
/// JSON 404s instead of falling into `index.html`.
pub fn is_api_path(path: &str) -> bool {
    path == "/activity"
        || path == "/sessions"
        || path.starts_with("/sessions/")
        || path == "/events"
        || path == "/allows"
        || path == "/connections"
        || path == "/approvals"
        || path.starts_with("/approvals/")
}

/// Look up an embedded asset by URL-relative path (`assets/...`).
fn asset(rel: &str) -> Option<(&'static str, &'static [u8])> {
    UI_ASSETS
        .iter()
        .find(|(path, _, _)| *path == rel)
        .map(|(_, mime, bytes)| (*mime, *bytes))
}

/// The embedded SPA shell. Missing at compile time if `ui/index.html`
/// was not vendored (build failure, never a runtime repair).
pub fn index_html() -> (&'static str, &'static [u8]) {
    asset("index.html").expect("vendored ui/index.html")
}

/// Reject obvious traversal probes before any lookup. Exact-match
/// embedding has no path resolution to exploit, but a `..` request must
/// never be answered with the SPA shell either. Matching is
/// case-insensitive and substring-based (`%2e%2e` must trip it too).
fn is_traversal(raw: &str) -> bool {
    let lowered = raw.to_ascii_lowercase();
    lowered.split('/').any(|segment| {
        segment == ".."
            || segment == "."
            || segment.contains('\\')
            || segment.contains("%2e")
            || segment.contains("%252e")
    }) || lowered.contains("%2f")
        || lowered.contains("%5c")
}

/// Whether the request carries a bootstrap credential (`?token=`):
/// its response must be `no-store` so caches never retain
/// credential-bearing URLs or content.
fn carries_token(uri: &Uri) -> bool {
    uri.query().is_some_and(|query| {
        query
            .split('&')
            .any(|pair| pair == "token" || pair.starts_with("token="))
    })
}

fn html_response(body: &'static [u8], head_only: bool) -> Response {
    let mut response = if head_only {
        axum::body::Body::empty().into_response()
    } else {
        body.into_response()
    };
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(CSP),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static(REFERRER_POLICY),
    );
    headers.insert(
        "x-frame-options",
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    // The shell is always fresh (and any bootstrap response is
    // credential-bearing): never cached.
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    *response.status_mut() = StatusCode::OK;
    response
}

fn asset_response(
    mime: &'static str,
    bytes: &'static [u8],
    immutable: bool,
    no_store: bool,
    head_only: bool,
) -> Response {
    let mut response = if head_only {
        axum::body::Body::empty().into_response()
    } else {
        bytes.into_response()
    };
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(mime),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static(if no_store {
            "no-store"
        } else if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    // Referrer suppression for credential-adjacent navigations costs
    // nothing on subresources; keep the policy uniform.
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static(REFERRER_POLICY),
    );
    *response.status_mut() = StatusCode::OK;
    response
}

/// Axum fallback: static files, SPA shell, or frozen API 404s.
/// Unknown API paths keep JSON 404 (1631702); only browser-owned
/// `GET`/`HEAD` paths fall back to `index.html`.
pub async fn fallback(method: Method, uri: Uri) -> Response {
    let path = uri.path();
    if is_traversal(path) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let browser_route = method == Method::GET || method == Method::HEAD;
    let head_only = method == Method::HEAD;
    let token = carries_token(&uri);
    // Exact embedded file (also reachable as `/index.html` directly).
    let rel = path.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    if let Some((mime, bytes)) = asset(rel) {
        // Hashed build outputs live under `assets/`; anything else
        // embedded (today: only `index.html`) is sharable markup.
        let immutable = rel.starts_with("assets/");
        if rel == "index.html" {
            return html_response(bytes, head_only);
        }
        return asset_response(mime, bytes, immutable, token, head_only);
    }
    if is_api_path(path) {
        // Frozen: unknown API paths are JSON 404, never the SPA shell.
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "not found"})),
        )
            .into_response();
    }
    if path.starts_with("/assets/") {
        // Recognizable asset namespace with no such file: plain 404 so
        // browsers never execute HTML with JS expectations (the
        // reference serves index.html here instead).
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if browser_route {
        let (mime, bytes) = index_html();
        debug_assert_eq!(mime, "text/html; charset=utf-8");
        return html_response(bytes, head_only);
    }
    (StatusCode::NOT_FOUND, "not found").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_shapes() {
        // The vendored bundle is exactly the Vite output shape the
        // headers and cache rules were verified against.
        let names: Vec<&&str> = UI_ASSETS.iter().map(|(path, _, _)| path).collect();
        assert!(names.contains(&&"index.html"));
        let hashed: Vec<&&&str> = names
            .iter()
            .filter(|name| name.starts_with("assets/"))
            .collect();
        assert!(!hashed.is_empty(), "expected hashed assets, got {names:?}");
        for name in hashed {
            let stem = name
                .trim_start_matches("assets/")
                .split('.')
                .next()
                .unwrap_or("");
            assert!(
                stem.split('-').next_back().is_some_and(|hash| hash.len() >= 8),
                "unhashed asset would break the immutable rule: {name}"
            );
        }
        let (mime, _) = index_html();
        assert_eq!(mime, "text/html; charset=utf-8");
    }

    #[test]
    fn api_shapes_stable() {
        for path in [
            "/activity",
            "/sessions",
            "/sessions/qks_1",
            "/events",
            "/allows",
            "/connections",
            "/approvals",
            "/approvals/qka_1/decide",
        ] {
            assert!(is_api_path(path), "{path}");
        }
        for path in ["/", "/approvals-ui", "/assets/index-x.js", "/favicon.ico"] {
            assert!(!is_api_path(path), "{path}");
        }
    }

    #[test]
    fn traversal_rejected() {
        assert!(is_traversal("/../secret"));
        assert!(is_traversal("/assets/%2e%2e/x"));
        assert!(is_traversal("/assets/..%2f..%2fx"));
        assert!(!is_traversal("/assets/index-x.js"));
        assert!(!is_traversal("/sessions/qks_1"));
    }
}
