//! Approval providers: who the human decision comes from. Synchronous by
//! design — the providers needed here are in-process; daemon HTTP transport
//! adapts at its own layer later without touching this trait.

use std::cell::Cell;
use std::collections::VecDeque;
use std::fmt::{self, Display, Formatter};

use qk_core::ReasonCode;

use crate::scope::ApprovalScope;

/// What a human/provider is asked to decide. Contains the SQL fingerprint
/// and the evaluation facts, never raw SQL (mirrors the reference provider
/// input, which carries fingerprint plus reason, not statement text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Fingerprint of the exact SQL under evaluation.
    pub fingerprint: String,
    /// Binding scope the grant would carry.
    pub scope: ApprovalScope,
    /// Frozen reason that produced `RequireApproval`.
    pub reason_code: ReasonCode,
    /// Human diagnostic message from evaluation.
    pub message: String,
    /// Decisive policy path, when any.
    pub matched_policy: Option<String>,
    /// Sensitive/unbounded target table, when named.
    pub table: Option<String>,
    /// Sensitive column, when named.
    pub column: Option<String>,
    /// Statement kinds, when present.
    pub operation: Option<String>,
}

/// A provider's verdict on one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderDecision {
    /// Human approved.
    Approved,
    /// Human denied.
    Denied,
    /// Still waiting (async human pending; resolution stays `RequireApproval`).
    Waiting,
}

/// Provider response: verdict plus the approval id it is stored under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderResponse {
    /// Approval id (provider-assigned; opaque to the evaluator).
    pub id: String,
    /// The verdict.
    pub decision: ProviderDecision,
}

/// Provider-level failure. Never exposes transport internals as machine
/// values; human diagnostics keep a bounded detail string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// Provider cannot be reached / is not configured at call time.
    Unavailable,
    /// Provider call failed; detail is bounded at render time.
    Transport(String),
}

impl Display for ProviderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "approval provider unavailable"),
            Self::Transport(detail) => write!(f, "approval provider error: {detail}"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// Human-decision source consulted after `RequireApproval`. Synchronous:
/// in-process providers only.
pub trait ApprovalProvider {
    /// Ask for a decision. Called at most once per resolution, and never
    /// for evaluations that already allowed or denied.
    fn request(&self, request: &ApprovalRequest) -> Result<ProviderResponse, ProviderError>;
}

/// Generates approval ids. Injectable so tests stay deterministic while
/// production uses random ids (daemon port).
pub trait ApprovalIdGenerator {
    /// Mint a fresh id.
    fn generate(&self) -> String;
}

/// Deterministic counter generator (`{prefix}-{n}` from 1). Test and
/// single-process use; the daemon port supplies a random generator.
pub struct CountingIdGenerator {
    prefix: String,
    next: Cell<usize>,
}

impl CountingIdGenerator {
    /// Generator yielding `{prefix}-1`, `{prefix}-2`, ...
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_owned(),
            next: Cell::new(1),
        }
    }
}

impl ApprovalIdGenerator for CountingIdGenerator {
    fn generate(&self) -> String {
        let n = self.next.get();
        self.next.set(n + 1);
        format!("{}-{n}", self.prefix)
    }
}

/// Reference semantics: a default provider never grants. (A *missing*
/// provider maps to `APPROVAL_UNAVAILABLE` without a call; an explicit
/// denial maps to `APPROVAL_DENIED`.)
pub struct DenyByDefaultProvider;

impl ApprovalProvider for DenyByDefaultProvider {
    fn request(&self, _request: &ApprovalRequest) -> Result<ProviderResponse, ProviderError> {
        Ok(ProviderResponse {
            id: "denied-default".to_owned(),
            decision: ProviderDecision::Denied,
        })
    }
}

/// Simulates an unreachable provider.
pub struct UnavailableProvider;

impl ApprovalProvider for UnavailableProvider {
    fn request(&self, _request: &ApprovalRequest) -> Result<ProviderResponse, ProviderError> {
        Err(ProviderError::Unavailable)
    }
}

/// Simulates a failing provider call.
pub struct ErrorProvider {
    detail: String,
}

impl ErrorProvider {
    /// Provider that always fails with `detail`.
    pub fn new(detail: &str) -> Self {
        Self {
            detail: detail.to_owned(),
        }
    }
}

impl ApprovalProvider for ErrorProvider {
    fn request(&self, _request: &ApprovalRequest) -> Result<ProviderResponse, ProviderError> {
        Err(ProviderError::Transport(self.detail.clone()))
    }
}

/// Deterministic scripted provider (mirrors the reference test provider):
/// verdicts come from a queue, ids from the generator. Records requests
/// for assertions (e.g. proving non-approval results never contact it).
pub struct TestProvider {
    queue: std::cell::RefCell<VecDeque<ProviderDecision>>,
    ids: CountingIdGenerator,
    seen: std::cell::RefCell<Vec<ApprovalRequest>>,
    calls: Cell<usize>,
}

impl TestProvider {
    /// Provider replaying `queue` in order; exhausted queue yields Waiting.
    pub fn new(queue: Vec<ProviderDecision>) -> Self {
        Self {
            queue: std::cell::RefCell::new(queue.into()),
            ids: CountingIdGenerator::new("test"),
            seen: std::cell::RefCell::new(Vec::new()),
            calls: Cell::new(0),
        }
    }

    /// How many times `request` ran.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.get()
    }

    /// Requests received, in order.
    pub fn seen(&self) -> Vec<ApprovalRequest> {
        self.seen.borrow().clone()
    }
}

impl ApprovalProvider for TestProvider {
    fn request(&self, request: &ApprovalRequest) -> Result<ProviderResponse, ProviderError> {
        self.calls.set(self.calls.get() + 1);
        self.seen.borrow_mut().push(request.clone());
        let decision = self
            .queue
            .borrow_mut()
            .pop_front()
            .unwrap_or(ProviderDecision::Waiting);
        Ok(ProviderResponse {
            id: self.ids.generate(),
            decision,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ApprovalRequest;
    use super::{
        ApprovalIdGenerator, ApprovalProvider, CountingIdGenerator, ProviderDecision, TestProvider,
    };
    use crate::scope::ApprovalScope;
    use qk_core::ReasonCode;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            fingerprint: "abc".to_owned(),
            scope: ApprovalScope {
                session_id: None,
                integration: "mcp".to_owned(),
                environment: "production".to_owned(),
                database: "main".to_owned(),
                agent_id: String::new(),
                tool: String::new(),
            },
            reason_code: ReasonCode::RequireApproval,
            message: "m".to_owned(),
            matched_policy: None,
            table: None,
            column: None,
            operation: None,
        }
    }

    #[test]
    fn deterministic_ids_and_queue() {
        let provider =
            TestProvider::new(vec![ProviderDecision::Approved, ProviderDecision::Denied]);
        let first = provider.request(&request()).expect("ok");
        let second = provider.request(&request()).expect("ok");
        assert_eq!(first.id, "test-1");
        assert_eq!(second.id, "test-2");
        assert_eq!(first.decision, ProviderDecision::Approved);
        assert_eq!(second.decision, ProviderDecision::Denied);
        // Exhausted queue waits rather than inventing verdicts.
        let third = provider.request(&request()).expect("ok");
        assert_eq!(third.decision, ProviderDecision::Waiting);
        assert_eq!(provider.calls(), 3);
        assert_eq!(provider.seen().len(), 3);
    }

    #[test]
    fn counting_generator() {
        let gen = CountingIdGenerator::new("qka_test");
        assert_eq!(gen.generate(), "qka_test-1");
        assert_eq!(gen.generate(), "qka_test-2");
    }
}
