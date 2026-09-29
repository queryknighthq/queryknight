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

/// Unknown paths: JSON 404 (the reference serves its SPA bundle here when
/// one exists; without static serving the contract is a plain 404).
async fn fallback_404() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({"error": "not found"})),
    )
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
        .fallback(fallback_404)
        .layer(middleware::map_response(map_method_not_allowed))
        .layer(middleware::from_fn(gatekeeper))
        .layer(axum::Extension(token))
        .with_state(state)
}

/// Serve on the configured bind address. Refuses non-loopback binds
/// unless explicitly allowed. Returns the bound address for tests and
/// lifecycle layers; serving runs until the returned handle is aborted.
pub async fn serve(
    config: DaemonConfig,
    state: DaemonState,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), DaemonError> {
    if !config.bind.is_loopback() && !config.allow_remote {
        return Err(DaemonError::Internal(
            "refusing non-loopback bind without explicit opt-in".to_owned(),
        ));
    }
    // Timeouts surface as 408 without touching handler semantics.
    let app = router(state, config.token.clone())
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
        ));
    let listener = tokio::net::TcpListener::bind((config.bind, config.port))
        .await
        .map_err(|e| DaemonError::Internal(format!("bind failed: {e}")))?;
    let addr: SocketAddr = listener
        .local_addr()
        .map_err(|e| DaemonError::Internal(format!("local address failed: {e}")))?;
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    Ok((addr, handle))
}
