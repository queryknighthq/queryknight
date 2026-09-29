//! Shared daemon state and the single sync-to-async persistence boundary.
//!
//! `qk-store` is synchronous by design. Every handler reaches it through
//! `store_op`, which runs one closure on the blocking pool — centralized
//! here, never scattered across handlers, never holding the SQLite mutex
//! across an await point inside handler code.

use std::sync::Arc;

use qk_store::{Store, StoreError};

/// Shared state: the store behind `Arc`. Configuration (bind, token,
/// limits) is passed separately at router construction, never read from
/// the environment inside handlers.
#[derive(Debug, Clone)]
pub struct DaemonState {
    /// Typed SQLite state.
    pub store: Arc<Store>,
}

impl DaemonState {
    /// Wrap an opened store.
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

/// Run one synchronous store closure on the blocking pool. The closure
/// must be short (single statements or the store's own brief
/// transactions); cancellation drops the waiter while the closure runs to
/// completion, which is safe because store operations are atomic and
/// idempotent at the row level.
pub async fn store_op<F, T>(store: &Arc<Store>, operation: F) -> Result<T, StoreError>
where
    F: FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || operation(&store))
        .await
        .map_err(|_| StoreError::Database("store task failed".to_owned()))?
}
