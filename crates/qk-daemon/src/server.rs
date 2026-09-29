//! Router assembly, middleware order, and serving. Middleware order
//! (outermost first): request timeout, body limit, 405-to-404 mapping,
//! then the gatekeeper (Host/Origin/CORS/auth) closest to the routes.
//! Unauthenticated surface: `/status`, `/health`, `/ready` plus CORS
//! preflights. Everything else requires the daemon token.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::auth::{check_auth, is_local_host, is_local_origin, AuthToken};
use crate::config::DaemonConfig;
use crate::error::DaemonError;
use crate::state::DaemonState;

/// Current time in milliseconds since the Unix epoch, for creation
/// timestamps. Matching and expiry always take explicit timestamps;
/// only creation instants read the clock (like the reference).
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Gatekeeper: Host allowlist, Origin allowlist with CORS headers,
/// preflight short-circuit, then token auth except on the frozen
/// unauthenticated paths. The token never appears in any response.
async fn gatekeeper(
    axum::Extension(token): axum::Extension<Arc<AuthToken>>,
    request: Request,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if !is_local_host(host.as_deref()) {
        return DaemonError::InvalidHost.into_response();
    }
    let origin = request
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if !is_local_origin(origin.as_deref()) {
        return DaemonError::InvalidOrigin.into_response();
    }
    let origin_ref = origin.as_deref();
    // Preflight: 204 with CORS headers, no auth (browsers never send
    // credentials on preflight; matches the reference CORS layer).
    if request.method() == axum::http::Method::OPTIONS {
        return cors_preflight(origin_ref);
    }
    let path = request.uri().path().to_owned();
    if path == "/status" || path == "/health" || path == "/ready" {
        return with_cors(next.run(request).await, origin_ref);
    }
    // Browser surface: GET/HEAD of non-API paths (SPA shell, static
    // assets) need no token — the reference skips auth for GET
    // non-API paths the same way. (HEAD is included even though the
    // reference only exempts GET: HEAD is defined as bodyless GET and
    // browsers/CDNs rely on it; documented in browser-ui.md.)
    if (request.method() == axum::http::Method::GET || request.method() == axum::http::Method::HEAD)
        && !crate::ui::is_api_path(&path)
    {
        return with_cors(next.run(request).await, origin_ref);
    }
    if let Some(response) = check_auth(&request, &token) {
        return with_cors(response, origin_ref);
    }
    with_cors(next.run(request).await, origin_ref)
}

/// Attach CORS headers for validated localhost origins.
fn with_cors(mut response: Response, origin: Option<&str>) -> Response {
    if let Some(origin) = origin {
        if let Ok(value) = HeaderValue::from_str(origin) {
            response
                .headers_mut()
                .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            response
                .headers_mut()
                .insert(axum::http::header::VARY, HeaderValue::from_static("Origin"));
        }
    }
    response
}

fn cors_preflight(origin: Option<&str>) -> Response {
    let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
    if let Some(origin) = origin {
        if let Ok(value) = HeaderValue::from_str(origin) {
            builder = builder.header(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        }
    }
    builder
        .header(
            axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET,POST,OPTIONS",
        )
        .header(
            axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            "Authorization,Content-Type",
        )
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::NO_CONTENT.into_response())
}

/// Map 405 (wrong method on a known path) to the frozen 404 shape: the
/// reference router answers 404 for method mismatches (Hono default).
async fn map_method_not_allowed(response: Response) -> Response {
    if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "not found"})),
        )
            .into_response();
    }
    response
}

/// Unknown paths: the embedded-Vue fallback in [`crate::ui`] (SPA shell
/// for browser-owned routes, frozen JSON 404 for API-shaped unknowns).
/// Kept as a named function so the routing table reads declaratively.
async fn fallback_404(method: axum::http::Method, uri: axum::http::Uri) -> impl IntoResponse {
    crate::ui::fallback(method, uri).await
}

/// Build the router. Pure construction: no sockets, no tasks.
pub fn router(state: DaemonState, token: AuthToken) -> Router {
    let token = Arc::new(token);
    Router::new()
        .route("/status", get(crate::routes::health::status))
        .route("/health", get(crate::routes::health::health))
        .route("/ready", get(crate::routes::health::ready))
        .route("/activity", get(crate::routes::history::activity))
        .route(
            "/sessions",
            get(crate::routes::sessions::list).post(crate::routes::sessions::create),
        )
        .route("/sessions/{id}", get(crate::routes::sessions::get))
        .route(
            "/sessions/{id}/events",
            get(crate::routes::sessions::events),
        )
        .route("/events", post(crate::routes::history::record))
        .route("/allows", get(crate::routes::approvals::allows))
        .route("/connections", get(crate::routes::connections::list))
        .route(
            "/approvals",
            get(crate::routes::approvals::list).post(crate::routes::approvals::create),
        )
        .route("/approvals/{id}", get(crate::routes::approvals::get))
        .route(
            "/approvals/{id}/decide",
            post(crate::routes::approvals::decide),
        )
        .route(
            "/approvals/{id}/schema-diff",
            post(crate::routes::approvals::schema_diff),
        )
        .route(
            "/approvals/{id}/verify",
            post(crate::routes::approvals::verify),
        )
        .fallback(fallback_404)
        .layer(middleware::map_response(map_method_not_allowed))
        .layer(middleware::from_fn(gatekeeper))
        .layer(axum::Extension(token))
        .with_state(state)
}

/// Grace period for in-flight requests during shutdown: connections
/// get a bounded opportunity to complete, then are dropped. There are no
/// long-lived server requests (decide is immediate; clients poll), so
/// this only covers ordinary in-flight work.
pub const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Assemble the serving app (frozen middleware order) without binding.
fn serve_app(config: &DaemonConfig, state: DaemonState) -> axum::Router {
    // Timeouts surface as 408 without touching handler semantics.
    router(state, config.token.clone())
        .layer(
            tower::ServiceBuilder::new()
                .layer(axum::error_handling::HandleErrorLayer::new(
                    |_: Box<dyn std::error::Error + Send + Sync>| async {
                        StatusCode::REQUEST_TIMEOUT
                    },
                ))
                .layer(tower::timeout::TimeoutLayer::new(config.request_timeout)),
        )
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            config.body_limit_bytes,
        ))
}

/// Check the loopback bind rule shared by every serve path.
fn check_bind(config: &DaemonConfig) -> Result<(), DaemonError> {
    if !config.bind.is_loopback() && !config.allow_remote {
        return Err(DaemonError::Internal(
            "refusing non-loopback bind without explicit opt-in".to_owned(),
        ));
    }
    Ok(())
}

/// Bind the configured listener without serving: lets lifecycle layers
/// publish "running" state only after the port is actually held.
pub async fn bind_listener(config: &DaemonConfig) -> Result<tokio::net::TcpListener, DaemonError> {
    check_bind(config)?;
    tokio::net::TcpListener::bind((config.bind, config.port))
        .await
        .map_err(|e| DaemonError::Internal(format!("bind failed: {e}")))
}

/// Serve an already-bound listener until `shutdown` resolves, then drain
/// in-flight requests for at most [`SHUTDOWN_GRACE`] before returning.
pub async fn serve_listener(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), DaemonError> {
    let server = axum::serve(listener, app).with_graceful_shutdown(shutdown);
    match tokio::time::timeout(SHUTDOWN_GRACE, server).await {
        Ok(result) => result.map_err(|e| DaemonError::Internal(format!("serve failed: {e}"))),
        Err(_) => Ok(()),
    }
}

/// Serve on the configured bind address. Refuses non-loopback binds
/// unless explicitly allowed. Returns the bound address for tests and
/// lifecycle layers; serving runs until the returned handle is aborted.
pub async fn serve(
    config: DaemonConfig,
    state: DaemonState,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), DaemonError> {
    let listener = bind_listener(&config).await?;
    let app = serve_app(&config, state);
    let addr: SocketAddr = listener
        .local_addr()
        .map_err(|e| DaemonError::Internal(format!("local address failed: {e}")))?;
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    Ok((addr, handle))
}

/// Serve with graceful shutdown: bind, then serve until `shutdown`
/// resolves. Returns the bound address once the listener is held, so
/// callers can publish readiness before serving completes. The frozen
/// loopback rule applies unchanged.
pub async fn serve_with_shutdown(
    config: &DaemonConfig,
    state: DaemonState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<std::net::SocketAddr, DaemonError> {
    let listener = bind_listener(config).await?;
    let addr: SocketAddr = listener
        .local_addr()
        .map_err(|e| DaemonError::Internal(format!("local address failed: {e}")))?;
    let app = serve_app(config, state);
    serve_listener(listener, app, shutdown).await?;
    Ok(addr)
}
