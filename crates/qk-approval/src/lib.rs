//! Fail-closed approval resolution layered after pure policy evaluation.
//!
//! Pipeline: `qk_core::evaluate()` decides `Allow`, `Deny`, or
//! `RequireApproval`. This crate only ever touches the third case:
//!
//! ```text
//! RequireApproval + valid matching grant/provider approval = executable
//! RequireApproval + anything else                          = NOT executable
//! Allow / Deny                                             = returned untouched
//! ```
//!
//! An approval can never override a `Deny` (INV-024). Matching binds the
//! SQL fingerprint plus every recorded scope dimension (session,
//! integration, environment, database, agent, tool); missing values match
//! only missing values. Time is an explicit `now_ms` parameter, never read
//! inside matching. No IO, no clock, no globals; the provider trait is
//! synchronous by design (in-process providers only — daemon HTTP transport
//! adapts at its own layer later).

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod id;
pub mod provider;
pub mod resolve;
pub mod scope;
pub mod store;

pub use id::ApprovalId;
pub use provider::{
    ApprovalIdGenerator, ApprovalProvider, ApprovalRequest, CountingIdGenerator,
    DenyByDefaultProvider, ErrorProvider, ProviderDecision, ProviderError, ProviderResponse,
    TestProvider, UnavailableProvider,
};
pub use resolve::{
    resolve, ResolutionOutcome, ResolveRequest, ResolvedEvaluation, DEFAULT_APPROVAL_TTL_MS,
};
pub use scope::{ApprovalScope, DecisionSource, Scope};
pub use store::{
    ApprovalBinding, ApprovalStore, DecideError, GrantStatus, InMemoryApprovalStore, StoredGrant,
};
