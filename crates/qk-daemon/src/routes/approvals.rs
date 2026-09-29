//! Approval endpoints: list, get, create, decide, schema-diff. Handlers
//! validate input, delegate state transitions to `qk-store`, and shape
//! frozen JSON. They never evaluate policy and never mint bindings beyond
//! what the store layer defines.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use qk_approval::{ApprovalBinding, DecisionSource, GrantStatus, Scope, StoredGrant};

use crate::dto::{
    ApprovalView, CreateApprovalRequest, DecideApprovalRequest, DecideStatus, DecisionSourceWire,
    SchemaDiffRequest, ScopeWire,
};
use crate::error::DaemonError;
use crate::ids::generate_approval_id;
use crate::server::now_ms;
use crate::state::{store_op, DaemonState};

/// Parse stored schema JSON leniently for display (invalid content
/// degrades to omitted fields; authorization validity is unaffected
/// because matching never reads these columns).
fn parse_schema_json(raw: Option<&String>) -> Option<serde_json::Value> {
    raw.and_then(|text| serde_json::from_str(text).ok())
}

fn view_of(grant: &StoredGrant) -> ApprovalView {
    ApprovalView::from_grant(
        grant,
        parse_schema_json(grant.schema_ddl.as_ref()),
        parse_schema_json(grant.schema_diff.as_ref()),
    )
}

/// GET /approvals: all rows newest-first, including legacy history rows
/// (marked `bindingKind: legacy_shape`, never authorizable).
pub async fn list(
    State(state): State<DaemonState>,
) -> Result<Json<Vec<ApprovalView>>, DaemonError> {
    let now = now_ms();
    let grants = store_op(&state.store, move |store| store.list_grants(now)).await?;
    Ok(Json(grants.iter().map(view_of).collect()))
}

/// GET /approvals/:id: one row or 404 JSON (the reference masks API GET
/// 404s with its SPA fallback when a UI bundle exists; without static
/// serving the contract is a plain 404, documented).
pub async fn get(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
) -> Result<Json<ApprovalView>, DaemonError> {
    let grant = store_op(&state.store, move |store| store.get_grant(&id))
        .await?
        .ok_or_else(|| DaemonError::NotFound("approval not found".to_owned()))?;
    Ok(Json(view_of(&grant)))
}

/// POST /approvals: create a waiting row. Server mints the id
/// (`qka_<8hex>`); scope dims default to empty (matching only empty
/// contexts); timeout defaults to 60s; binding is always `ShapeV1` here
/// because HTTP creation never sees SQL (frozen daemon semantics).
/// Missing required fields are 400 (the reference hits SQLite NOT NULL
/// violations as 500s instead).
pub async fn create(
    State(state): State<DaemonState>,
    Json(body): Json<CreateApprovalRequest>,
) -> Result<Json<ApprovalView>, DaemonError> {
    let fingerprint = body
        .fingerprint
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("fingerprint is required".to_owned()))?;
    if fingerprint.len() != 16 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DaemonError::Invalid(
            "fingerprint must be 16 hex characters".to_owned(),
        ));
    }
    let reason = body
        .reason
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("reason is required".to_owned()))?;
    let risk = body
        .risk
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("risk is required".to_owned()))?;
    let operation_summary = body
        .operation_summary
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonError::Invalid("operationSummary is required".to_owned()))?;
    if let Some(ref ddl) = body.schema_ddl {
        if !ddl.is_array() {
            return Err(DaemonError::Invalid(
                "schemaDdl must be an array".to_owned(),
            ));
        }
    }
    let timeout_ms = body.timeout_ms.unwrap_or(60_000);
    let now = now_ms();
    let grant = StoredGrant {
        id: qk_approval::ApprovalId::new(generate_approval_id()),
        shape: qk_core::QueryShapeFingerprint::new(fingerprint),
        binding: ApprovalBinding::ShapeV1,
        scope: qk_approval::ApprovalScope {
            session_id: body.session_id,
            integration: body.integration.unwrap_or_default(),
            environment: body.environment.unwrap_or_default(),
            database: body.database.unwrap_or_default(),
            agent_id: body.agent_id.unwrap_or_default(),
            tool: body.tool.unwrap_or_default(),
        },
        status: GrantStatus::Waiting,
        reuse: Scope::Once,
        expires_at_ms: now.saturating_add(timeout_ms),
        reason_code: qk_core::ReasonCode::RequireApproval,
        message: reason,
        risk,
        operation_summary,
        schema_ddl: body.schema_ddl.map(|v| v.to_string()),
        schema_diff: None,
        matched_policy: None,
        decided_at_ms: None,
        decided_by: None,
    };
    if let Some(key) = body.connection_key {
        let profile = crate::ids::connection_profile_from_key(&key);
        let store: Arc<qk_store::Store> = state.store.clone();
        store_op(&store, move |store| store.upsert_connection(&profile)).await?;
    }
    let created = grant.clone();
    store_op(&state.store, move |store| store.insert_grant(&created, now)).await?;
    Ok(Json(view_of(&grant)))
}

/// POST /approvals/:id/decide: record approved/denied with once/session
/// reuse. Unknown, decided, or expired rows are 400 with the frozen
/// `Error: approval not waiting` text (the reference collapses all three).
pub async fn decide(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(body): Json<DecideApprovalRequest>,
) -> Response {
    let status = match body.status {
        DecideStatus::Approved => GrantStatus::Approved,
        DecideStatus::Denied => GrantStatus::Denied,
    };
    let reuse = match body.scope.unwrap_or(ScopeWire::Once) {
        ScopeWire::Once => Scope::Once,
        ScopeWire::Session => Scope::Session,
    };
    let source = match body.source.unwrap_or(DecisionSourceWire::Ui) {
        DecisionSourceWire::Tui => DecisionSource::Tui,
        DecisionSourceWire::Cli => DecisionSource::Cli,
        DecisionSourceWire::Ui => DecisionSource::Ui,
        DecisionSourceWire::Mcp => DecisionSource::Mcp,
    };
    let now = now_ms();
    let lookup = id.clone();
    let outcome = store_op(&state.store, move |store| {
        store.decide_grant(&id, status, reuse, source, now)
    })
    .await;
    match outcome {
        Ok(()) => self::get(State(state), Path(lookup)).await.into_response(),
        Err(_) => (
            axum::http::StatusCode::BAD_REQUEST,
            "Error: approval not waiting",
        )
            .into_response(),
    }
}

/// POST /approvals/:id/schema-diff: attach the after-image diff. Unknown
/// ids are 404 JSON; non-array bodies are 400.
pub async fn schema_diff(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    Json(body): Json<SchemaDiffRequest>,
) -> Result<Json<ApprovalView>, DaemonError> {
    if let Some(ref diff) = body.schema_diff {
        if !diff.is_array() {
            return Err(DaemonError::Invalid(
                "schemaDiff must be an array".to_owned(),
            ));
        }
    }
    let text = body.schema_diff.map(|v| v.to_string());
    let lookup = id.clone();
    store_op(&state.store, move |store| {
        store.record_schema_diff(&id, text)
    })
    .await?;
    self::get(State(state), Path(lookup)).await
}

/// GET /allows?sessionId=&fingerprint=: session-shape check used by legacy
/// enforcement paths. Missing params answer false (frozen tolerance), and
/// only fully-bound session grants count (legacy rows never authorize).
pub async fn allows(
    State(state): State<DaemonState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, DaemonError> {
    let session_id = params.get("sessionId").cloned().unwrap_or_default();
    let fingerprint = params.get("fingerprint").cloned().unwrap_or_default();
    if session_id.is_empty() || fingerprint.is_empty() {
        return Ok(Json(serde_json::json!({"allowed": false})));
    }
    let now = now_ms();
    // An explicit empty scope matches nothing with dimensions; only
    // dimension-less legacy rows could match it, and those are
    // structurally excluded from authorization.
    let empty = qk_approval::ApprovalScope {
        session_id: Some(session_id.clone()),
        integration: String::new(),
        environment: String::new(),
        database: String::new(),
        agent_id: String::new(),
        tool: String::new(),
    };
    let shape = qk_core::QueryShapeFingerprint::new(fingerprint);
    let allowed = store_op(&state.store, move |store| {
        store.find_session_grant(&session_id, &shape, &empty, now)
    })
    .await?
    .is_some();
    Ok(Json(serde_json::json!({"allowed": allowed})))
}
