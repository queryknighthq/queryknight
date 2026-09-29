//! Query-event endpoints: global activity feed and per-event recording.

use axum::extract::State;
use axum::Json;

use crate::dto::{CreateEventRequest, EventViewJson};
use crate::error::DaemonError;
use crate::ids::{connection_profile_from_key, generate_event_id};
use crate::server::now_ms;
use crate::state::{store_op, DaemonState};

/// Shape a stored view for output.
pub fn view_of(view: &qk_store::EventView) -> EventViewJson {
    EventViewJson {
        id: view.id.clone(),
        session_id: view.session_id.clone(),
        source: view.source.clone(),
        fingerprint: view.fingerprint.clone(),
        sql: view.sql.clone(),
        query_class: view.query_class.clone(),
        risk: view.risk.clone(),
        decision: view.decision.clone(),
        started_at: view.started_at_ms,
        rows_returned: view.rows_returned,
        rows_affected: view.rows_affected,
        bytes_returned: view.bytes_returned,
        error_code: view.error_code.clone(),
    }
}

/// GET /activity: newest-first event views (fixed limit of 100, frozen).
pub async fn activity(
    State(state): State<DaemonState>,
) -> Result<Json<Vec<EventViewJson>>, DaemonError> {
    let views = store_op(&state.store, |store| store.list_events(100)).await?;
    Ok(Json(views.iter().map(view_of).collect()))
}

/// POST /events: record one history event (upserts the connection, mints
/// `qke_<12hex>`). Classification is required; decision defaults to
/// `executed` exactly like the reference client default. Missing fields
/// are 400 (the reference hits SQLite NOT NULL violations as 500s).
pub async fn record(
    State(state): State<DaemonState>,
    Json(body): Json<CreateEventRequest>,
) -> Result<Json<serde_json::Value>, DaemonError> {
    let session_id = body
        .session_id
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("sessionId is required".to_owned()))?;
    let connection_key = body
        .connection_key
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("connectionKey is required".to_owned()))?;
    let source = body
        .source
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("source is required".to_owned()))?;
    let fingerprint = body
        .sql_fingerprint
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("sqlFingerprint is required".to_owned()))?;
    let classification = body
        .classification
        .ok_or_else(|| DaemonError::Invalid("classification is required".to_owned()))?;
    if classification.class.is_empty() || classification.risk.is_empty() {
        return Err(DaemonError::Invalid(
            "classification.class and classification.risk are required".to_owned(),
        ));
    }
    let profile = connection_profile_from_key(&connection_key);
    let event = qk_store::SessionEvent {
        id: generate_event_id(),
        session_id,
        connection_id: profile.id.clone(),
        source,
        fingerprint,
        sql: body.sql,
        query_class: classification.class,
        risk: classification.risk,
        decision: body
            .decision
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "executed".to_owned()),
        started_at_ms: now_ms(),
        duration_ms: body.duration_ms,
        rows_returned: body.rows_returned,
        rows_affected: body.rows_affected,
        bytes_returned: body.bytes_returned,
        estimated_tokens_returned: body.estimated_tokens_returned,
        estimated_tokens_avoided: body.estimated_tokens_avoided,
        error_code: body.error_code,
    };
    let id = event.id.clone();
    store_op(&state.store, move |store| {
        store.upsert_connection(&profile)?;
        store.record_event(&event)
    })
    .await?;
    Ok(Json(serde_json::json!({"id": id})))
}
