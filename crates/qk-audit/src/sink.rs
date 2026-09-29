//! Audit sink abstraction: small, sync, side-effect-only. Built-ins
//! are `NoopSink` (no storage) and `MemorySink` (deterministic tests
//! with failure injection). No file sink exists in the frozen product,
//! so none is added. Sink failures are returned for operational
//! visibility and never feed back into authorization.

use std::fmt::{self, Display, Formatter};
use std::sync::Mutex;

use crate::event::AuditEvent;

/// Sink failure handle. Carries the sink name plus a bounded,
/// sink-defined detail. Built-ins use fixed text; custom sinks MUST
/// keep details secret-free (no SQL, credentials, or tokens).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSinkError {
    /// Sink name for diagnostics.
    pub sink: String,
    /// Bounded failure detail (secret-free by contract).
    pub detail: String,
}

impl AuditSinkError {
    /// Build with a truncated detail (bounded diagnostics).
    pub fn new(sink: impl Into<String>, detail: impl Into<String>) -> Self {
        let detail: String = detail.into();
        let detail = if detail.len() > 300 {
            format!("{}…[truncated]", &detail[..300])
        } else {
            detail
        };
        Self {
            sink: sink.into(),
            detail,
        }
    }
}

impl Display for AuditSinkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "audit sink '{}' failed: {}", self.sink, self.detail)
    }
}

impl std::error::Error for AuditSinkError {}

/// Audit event sink: side effects only, never authorization input.
/// Must be `Send + Sync` (shared across workers) and must not panic
/// on untrusted-shaped data (events are already typed by then).
pub trait AuditSink: Send + Sync {
    /// Sink name for diagnostics.
    fn name(&self) -> &'static str;
    /// Record one event. Failures are returned, never thrown into the
    /// enforcement path.
    fn record(&self, event: &AuditEvent) -> Result<(), AuditSinkError>;
}

/// No-op sink: run without configured audit storage.
#[derive(Debug, Default)]
pub struct NoopSink;

impl AuditSink for NoopSink {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn record(&self, _event: &AuditEvent) -> Result<(), AuditSinkError> {
        Ok(())
    }
}

/// Deterministic in-memory sink for tests: counts, contents, and
/// failure injection (fail the next `fail_next` records). No globals.
#[derive(Debug, Default)]
pub struct MemorySink {
    events: Mutex<Vec<AuditEvent>>,
    fail_next: Mutex<usize>,
}

impl MemorySink {
    /// Empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `count` records with a fixed diagnostic.
    pub fn fail_next(&self, count: usize) {
        *self.fail_next.lock().expect("sink lock") = count;
    }

    /// Recorded event count.
    pub fn len(&self) -> usize {
        self.events.lock().expect("sink lock").len()
    }

    /// True when nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot of recorded events.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().expect("sink lock").clone()
    }
}

impl AuditSink for MemorySink {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn record(&self, event: &AuditEvent) -> Result<(), AuditSinkError> {
        let mut fail_next = self.fail_next.lock().expect("sink lock");
        if *fail_next > 0 {
            *fail_next -= 1;
            return Err(AuditSinkError::new(self.name(), "injected sink failure"));
        }
        drop(fail_next);
        self.events.lock().expect("sink lock").push(event.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> AuditEvent {
        crate::observation::test_event()
    }

    #[test]
    fn noop_ok_memory_counts_and_injects() {
        let noop = NoopSink;
        assert!(noop.record(&event()).is_ok());
        let memory = MemorySink::new();
        assert!(memory.is_empty());
        assert!(memory.record(&event()).is_ok());
        assert!(memory.record(&event()).is_ok());
        assert_eq!(memory.len(), 2);
        memory.fail_next(1);
        assert!(memory.record(&event()).is_err());
        assert_eq!(memory.len(), 2);
        assert_eq!(memory.events().len(), 2);
    }
}
