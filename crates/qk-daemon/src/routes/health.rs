//! Liveness and readiness. Unauthenticated (frozen); cheap and secret-free.

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::dto::{HealthCheck, Readiness};
use crate::state::{store_op, DaemonState};

/// Liveness: the router is alive. No store contact.
pub async fn status() -> Json<Value> {
    Json(json!({"ok": true, "pid": std::process::id()}))
}

/// Health: static version marker. No store contact.
pub async fn health() -> Json<Value> {
    Json(json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}))
}

/// Readiness: non-destructive store probe (schema readable). Degraded
/// still returns the frozen `{status, checks}` body, with 503. The
/// reference also probes home-directory writability; that belongs to the
/// filesystem lifecycle layer, not this commit.
pub async fn ready(State(state): State<DaemonState>) -> axum::response::Response {
    use axum::response::IntoResponse;
    match store_op(&state.store, |store| store.schema_version()).await {
        Ok(_) => Json(Readiness {
            status: "ok",
            checks: vec![HealthCheck {
                name: "store".to_owned(),
                ok: true,
                detail: None,
            }],
        })
        .into_response(),
        Err(error) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(Readiness {
                status: "degraded",
                checks: vec![HealthCheck {
                    name: "store".to_owned(),
                    ok: false,
                    detail: Some(error.to_string()),
                }],
            }),
        )
            .into_response(),
    }
}
