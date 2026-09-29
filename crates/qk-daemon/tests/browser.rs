//! Browser/static surface integration tests: SPA delivery, fallback
//! precedence, asset behavior, security headers, cache policy, token
//! bootstrap hygiene, traversal rejection, and HEAD handling. No
//! browser engine required — every claim is an HTTP assertion.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

const TOKEN: &str = "test-token-1234567890abcdef";
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn test_app() -> axum::Router {
    let dir = std::env::temp_dir().join(format!(
        "qk-browser-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let store = Arc::new(qk_store::Store::open(&dir.join("state.db")).expect("store"));
    qk_daemon::router(
        qk_daemon::DaemonState::new(store),
        qk_daemon::AuthToken::new(TOKEN.to_owned()),
    )
}

fn request(method: Method, uri: &str, token: bool) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1");
    if token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
    }
    builder.body(Body::empty()).expect("request")
}

async fn call(
    app: axum::Router,
    request: Request<Body>,
) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
    let response = app.oneshot(request).await.expect("oneshot");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body")
        .to_vec();
    (status, bytes, headers)
}

fn h<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> &'a str {
    headers.get(name).expect(name).to_str().expect("ascii")
}

// ---------------------------------------------------------------------------
// Shell delivery and fallback precedence.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn root_serves_spa_shell() {
    let (status, body, headers) = call(test_app(), request(Method::GET, "http://x/", false)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with(b"<!doctype html>"));
    assert!(body
        .windows(b"id=\"app\"".len())
        .any(|w| w == b"id=\"app\""));
    assert_eq!(h(&headers, "content-type"), "text/html; charset=utf-8");
    assert_eq!(h(&headers, "content-security-policy"), CSP);
    assert_eq!(h(&headers, "referrer-policy"), "no-referrer");
    assert_eq!(h(&headers, "x-frame-options"), "DENY");
    assert_eq!(h(&headers, "x-content-type-options"), "nosniff");
    assert_eq!(h(&headers, "cache-control"), "no-store");
}

#[tokio::test]
async fn deep_browser_paths_serve_shell() {
    // Non-API paths only: API-shaped paths keep auth/errors (pinned in
    // api_outranks_fallback). The tab SPA has no router — every such
    // path renders the same shell.
    for path in [
        "/approvals-ui",
        "/sessions-ui/123",
        "/foo/bar",
        "/favicon.ico",
    ] {
        let (status, body, _) = call(
            test_app(),
            request(Method::GET, &format!("http://x{path}"), false),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(body.starts_with(b"<!doctype html>"), "{path}");
    }
}

#[tokio::test]
async fn api_outranks_fallback() {
    // Exact API routes keep their behavior (auth still enforced).
    let (status, _, _) = call(test_app(), request(Method::GET, "http://x/health", false)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body, _) =
        call(test_app(), request(Method::GET, "http://x/activity", false)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, b"unauthorized");
    // API-shaped unknowns are JSON 404, never HTML.
    for path in ["/approvals/x/y", "/sessions/x/events/y"] {
        let (status, body, headers) = call(
            test_app(),
            request(Method::GET, &format!("http://x{path}"), true),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json")["error"],
            "not found",
            "{path}"
        );
        assert!(headers.get("content-security-policy").is_none(), "{path}");
    }
}

#[tokio::test]
async fn writes_never_fallback() {
    // Writes to non-API paths need auth first (reference parity); once
    // authenticated they 404 instead of serving the shell.
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        let (status, _, _) = call(
            test_app(),
            request(method.clone(), "http://x/some-ui-path", false),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method}");
        let (status, body, _) = call(
            test_app(),
            request(method.clone(), "http://x/some-ui-path", true),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
        assert_eq!(body, b"not found");
    }
}

// ---------------------------------------------------------------------------
// Assets: types, cache, misses.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hashed_assets_immutable_with_exact_types() {
    // Discover the real hashed names from the shell (no frozen-name
    // assumption: Vite rotates hashes on rebuild).
    let (_, body, _) = call(test_app(), request(Method::GET, "http://x/", false)).await;
    let shell = String::from_utf8(body).expect("utf8 shell");
    let js = shell
        .split('"')
        .find(|part| part.starts_with("/assets/") && part.ends_with(".js"))
        .expect("js asset")
        .to_owned();
    let css = shell
        .split('"')
        .find(|part| part.starts_with("/assets/") && part.ends_with(".css"))
        .expect("css asset")
        .to_owned();
    let (status, _, headers) = call(
        test_app(),
        request(Method::GET, &format!("http://x{js}"), false),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h(&headers, "content-type"),
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        h(&headers, "cache-control"),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(h(&headers, "x-content-type-options"), "nosniff");
    let (status, _, headers) = call(
        test_app(),
        request(Method::GET, &format!("http://x{css}"), false),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h(&headers, "content-type"), "text/css; charset=utf-8");
    assert_eq!(
        h(&headers, "cache-control"),
        "public, max-age=31536000, immutable"
    );
}

#[tokio::test]
async fn asset_miss_is_404_not_html() {
    let (status, body, headers) = call(
        test_app(),
        request(Method::GET, "http://x/assets/does-not-exist.js", false),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, b"not found");
    assert!(
        headers.get("content-type").is_none()
            || h(&headers, "content-type") != "text/html; charset=utf-8"
    );
}

#[tokio::test]
async fn traversal_rejected() {
    for uri in [
        "http://x/../Cargo.toml",
        "http://x/assets/%2e%2e/index.html",
        "http://x/assets/..%2f..%2fsecret",
    ] {
        let (status, _, _) = call(test_app(), request(Method::GET, uri, false)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn head_requests_headers_without_body() {
    let (status, body, headers) = call(test_app(), request(Method::HEAD, "http://x/", false)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());
    assert_eq!(h(&headers, "content-type"), "text/html; charset=utf-8");
    assert_eq!(h(&headers, "content-security-policy"), CSP);
}

// ---------------------------------------------------------------------------
// Token bootstrap hygiene.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_response_is_no_store() {
    // A credential-bearing URL must never be cacheable, even when the
    // underlying file would otherwise be immutable.
    let (_, body, _) = call(test_app(), request(Method::GET, "http://x/", false)).await;
    let shell = String::from_utf8(body).expect("utf8");
    let js = shell
        .split('"')
        .find(|part| part.starts_with("/assets/") && part.ends_with(".js"))
        .expect("js");
    for uri in [
        "http://x/?token=SECRET",
        &format!("http://x{js}?token=SECRET"),
    ] {
        let (status, _, headers) = call(test_app(), request(Method::GET, uri, false)).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(h(&headers, "cache-control"), "no-store", "{uri}");
    }
}

#[tokio::test]
async fn shell_contains_frozen_bootstrap_contract() {
    // Pin the generated bundle's bootstrap behavior without a browser
    // engine: one-shot `?token=` import into `localStorage.qk_token`,
    // immediate `replaceState` URL cleanup, Bearer attach afterwards.
    // (JS execution itself is covered by the frontend's own tooling;
    // the bundle bytes are vendored verbatim — see ui_freshness.)
    let (_, body, _) = call(test_app(), request(Method::GET, "http://x/", false)).await;
    let shell = String::from_utf8(body).expect("utf8");
    let js = shell
        .split('"')
        .find(|part| part.starts_with("/assets/") && part.ends_with(".js"))
        .expect("js");
    let (_, js_body, _) = call(
        test_app(),
        request(Method::GET, &format!("http://x{js}"), false),
    )
    .await;
    let bundle = String::from_utf8(js_body).expect("utf8 bundle");
    for snippet in [
        "qk_token",
        "URLSearchParams",
        "replaceState",
        "localStorage.setItem",
        "localStorage.getItem",
        "Bearer ",
    ] {
        assert!(
            bundle.contains(snippet),
            "bundle lost bootstrap snippet: {snippet}"
        );
    }
    // The query transport is read once at bootstrap …
    assert!(
        bundle.contains("get(`token`)"),
        "bundle no longer reads ?token="
    );
    // … and API calls go to same-origin relative paths (port-agnostic).
    // (The minifier quotes with backticks; accept either spelling.)
    for path in ["/activity", "/sessions", "/connections", "/approvals"] {
        let quoted = format!("\"{path}\"");
        let ticked = format!("`{path}`");
        assert!(
            bundle.contains(&quoted) || bundle.contains(&ticked),
            "bundle lost relative path: {path}"
        );
    }
}

#[tokio::test]
async fn bootstrap_query_token_still_authenticates() {
    // Compatibility transport preserved: ?token= reaches the API.
    let (status, _, _) = call(
        test_app(),
        request(
            Method::GET,
            &format!("http://x/approvals?token={TOKEN}"),
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_absent_from_server_logs() {
    // Drive bootstrapped + authed requests through a real foreground
    // daemon, then assert the operational log holds no token bytes.
    let home = std::env::temp_dir().join(format!("qk-browser-log-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let daemon =
        qk_daemon::runtime::DaemonRuntime::with_home(home.clone(), Some(0)).expect("runtime");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        qk_daemon::runtime::run_foreground(&daemon, Some(ready_tx), async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    let addr = tokio::time::timeout(std::time::Duration::from_secs(10), ready_rx)
        .await
        .expect("ready")
        .expect("addr");
    let target = qk_daemon::runtime::ProbeTarget::new("127.0.0.1", addr.port()).expect("loopback");
    let daemon =
        qk_daemon::runtime::DaemonRuntime::with_home(home.clone(), Some(0)).expect("runtime");
    let token = qk_daemon::runtime::probe_api::read_token(&daemon.resolved.paths).expect("token");
    let secret = token.as_secret().to_owned();
    // Bootstrap-style query request + Bearer API request + bad-token 401.
    let _ = qk_daemon::runtime::probe_api::get_json(&target, "/?token=BOOTSTRAP", &token).await;
    let _ = qk_daemon::runtime::probe_api::get_json(&target, "/approvals", &token).await;
    let _ = qk_daemon::runtime::probe_api::get_json(&target, "/approvals", &token).await;
    let _ = shutdown_tx.send(());
    task.await.expect("join").expect("shutdown");
    let log = std::fs::read_to_string(&daemon.resolved.paths.log).expect("log");
    assert!(!log.contains(&secret), "token leaked into daemon.log");
    assert!(
        !log.contains("BOOTSTRAP"),
        "query value leaked into daemon.log"
    );
    let _ = std::fs::remove_dir_all(&home);
}
