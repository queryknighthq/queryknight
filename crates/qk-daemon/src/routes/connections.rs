//! Connection metadata listing. Control-plane state only: no connection
//! is ever opened here, and no secrets are stored or returned (the store
//! holds no URLs by design).

use axum::extract::State;
use axum::Json;

use crate::dto::ConnectionView;
use crate::error::DaemonError;
use crate::state::{store_op, DaemonState};

/// GET /connections: stored connection metadata. The reference additionally
/// serves a redacted `url` from a separate JSON file; the store holds no
/// URLs, so the field is absent here (documented delta, not a leak).
pub async fn list(
    State(state): State<DaemonState>,
) -> Result<Json<Vec<ConnectionView>>, DaemonError> {
    let connections = store_op(&state.store, |store| store.list_connections()).await?;
    Ok(Json(
        connections
            .into_iter()
            .map(|connection| ConnectionView {
                id: connection.id,
                name: connection.name,
                engine: connection.engine,
                environment: connection.environment,
                database: connection.database,
                host_label: connection.host_label,
            })
            .collect(),
    ))
}
