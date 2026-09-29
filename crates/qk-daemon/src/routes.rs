//! Route handlers. Each handler validates input, calls the store through
//! the shared blocking boundary, and maps typed results to the frozen
//! JSON contract. No authorization semantics live here.

pub mod approvals;
pub mod connections;
pub mod health;
pub mod history;
pub mod sessions;
