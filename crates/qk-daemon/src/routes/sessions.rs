//! Session endpoints: list, get (with live-computed summary), create.
//! Summaries are computed on read from session + event rows, mirroring the
//! reference; derived numbers are never persisted.

use axum::extract::{Path, State};
use axum::Json;

use crate::dto::{CreateSessionRequest, SessionSummary};
use crate::error::DaemonError;
use crate::ids::{connection_profile_from_key, generate_session_id};
use crate::server::now_ms;
use crate::state::{store_op, DaemonState};

/// Classify an event row for summary counters. Frozen classes: `read`
/// counts reads, `write` counts writes, `ddl`/`destructive`/`privilege`
/// count schema changes; anything else counts toward queries only.
fn classify_for_summary(query_class: &str) -> (bool, bool, bool) {
    match query_class {
        "read" => (true, false, false),
        "write" => (false, true, false),
        "ddl" | "destructive" | "privilege" => (false, false, true),
        _ => (false, false, false),
    }
}

/// GET /sessions: summaries newest-first.
pub async fn list(
    State(state): State<DaemonState>,
) -> Result<Json<Vec<SessionSummary>>, DaemonError> {
    let sessions = store_op(&state.store, |store| store.list_sessions()).await?;
    let mut summaries = Vec::with_capacity(sessions.len());
    for session in sessions {
        summaries.push(summarize(&state, &session).await?);
    }
    Ok(Json(summaries))
}

/// GET /sessions/:id: one summary or 404 JSON.
pub async fn get(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<SessionSummary>, DaemonError> {
    let session = store_op(&state.store, move |store| store.get_session(&id))
        .await?
        .ok_or_else(|| DaemonError::NotFound("session not found".to_owned()))?;
    Ok(Json(summarize(&state, &session).await?))
}

/// GET /sessions/:id/events: chronological event views or 404 JSON when
/// the session is unknown. (The reference returns an empty list for
/// unknown sessions via the same path; unknown sessions 404 here because
/// the session lookup is explicit — documented.)
pub async fn events(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<crate::dto::EventViewJson>>, DaemonError> {
    let session_id = id.clone();
    let known = store_op(&state.store, move |store| store.get_session(&session_id))
        .await?
        .is_some();
    if !known {
        return Err(DaemonError::NotFound("session not found".to_owned()));
    }
    let views = store_op(&state.store, move |store| {
        store.list_session_events(&id, 500).map(|views| {
            views
                .iter()
                .map(crate::routes::history::view_of)
                .collect::<Vec<_>>()
        })
    })
    .await?;
    Ok(Json(views))
}

/// POST /sessions: upsert the connection, mint a session id
/// (`qks_<8hex>`), return `{id}`. Missing fields are 400 (the reference
/// hits SQLite NOT NULL violations as 500s instead).
pub async fn create(
    State(state): State<DaemonState>,
    Json(body): Json<CreateSessionRequest>,
) -> Result<Json<serde_json::Value>, DaemonError> {
    let connection_key = body
        .connection_key
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("connectionKey is required".to_owned()))?;
    let source = body
        .source
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("source is required".to_owned()))?;
    let profile = connection_profile_from_key(&connection_key);
    let session = qk_store::SessionRecord {
        id: generate_session_id(),
        connection_id: profile.id.clone(),
        agent: body.agent,
        started_at_ms: now_ms(),
        ended_at_ms: None,
        source,
    };
    let id = session.id.clone();
    store_op(&state.store, move |store| {
        store.upsert_connection(&profile)?;
        store.insert_session(&session)
    })
    .await?;
    Ok(Json(serde_json::json!({"id": id})))
}

/// Compute a session summary from the session row plus all its events.
async fn summarize(
    state: &DaemonState,
    session: &qk_store::SessionRecord,
) -> Result<SessionSummary, DaemonError> {
    let session_id = session.id.clone();
    let events = store_op(&state.store, move |store| {
        store.list_session_event_records(&session_id, usize::MAX)
    })
    .await?;
    let mut reads = 0usize;
    let mut writes = 0usize;
    let mut schema_changes = 0usize;
    let mut rows_modified = 0i64;
    let mut bytes_returned = 0i64;
    let mut estimated_tokens_avoided = 0i64;
    for event in &events {
        let (read, write, schema) = classify_for_summary(&event.query_class);
        reads += usize::from(read);
        writes += usize::from(write);
        schema_changes += usize::from(schema);
        rows_modified += event.rows_affected.unwrap_or(0);
        bytes_returned += event.bytes_returned.unwrap_or(0);
        estimated_tokens_avoided += event.estimated_tokens_avoided.unwrap_or(0);
    }
    Ok(SessionSummary {
        id: session.id.clone(),
        connection_id: session.connection_id.clone(),
        started_at: session.started_at_ms,
        ended_at: session.ended_at_ms,
        source: session.source.clone(),
        queries: events.len(),
        reads,
        writes,
        schema_changes,
        rows_modified,
        bytes_returned,
        estimated_tokens_avoided,
    })
}
