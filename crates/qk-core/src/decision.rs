//! Decision and reason-code taxonomy. Internal logic uses typed enums;
//! external serialization uses the exact frozen QueryKnight strings.

use std::fmt::{self, Display, Formatter};

/// Policy verdict for one SQL evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The statement may execute.
    Allow,
    /// The statement must not execute.
    Deny,
    /// A human must decide first (resolved by a later approval layer;
    /// this evaluator never resolves approvals itself).
    RequireApproval,
}

impl Decision {
    /// Frozen lowercase serialization (`allow`, `deny`, `require_approval`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
        }
    }
}

impl Display for Decision {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Frozen reason-code set. Every code the reference implementation can emit
/// through policy evaluation or its enforcement envelope is represented;
/// `as_str` preserves the exact external values. The `Approval*` codes are
/// produced by the future approval-resolution layer, not by `evaluate()`,
/// which stops at `RequireApproval`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    /// Unparseable SQL (`on_parse_error` path).
    DenyParseError,
    /// Unsupported/unknown statement shape (`on_unknown` path).
    DenyUnknownStatement,
    /// Sensitive column hit.
    SensitiveColumn,
    /// Explicit deny rule matched.
    DenyRule,
    /// UPDATE without WHERE.
    UnboundedUpdate,
    /// DELETE without WHERE.
    UnboundedDelete,
    /// SELECT without LIMIT against `require_limit`.
    LimitRequired,
    /// LIMIT above `max_limit`.
    LimitExceeded,
    /// Approval rule matched (provider layer resolves from here).
    RequireApproval,
    /// Allow rule matched.
    AllowRule,
    /// Fell through to `defaults.decision: allow`.
    DefaultAllow,
    /// Fell through to `defaults.decision: require_approval`.
    DefaultApproval,
    /// Fell through to `defaults.decision: deny`.
    DefaultDeny,
    /// Empty or whitespace-only SQL.
    EmptyQuery,
    /// SQL exceeds the byte budget.
    QueryTooLarge,
    /// Policy evaluation itself failed (fail-closed envelope).
    PolicyError,
    /// Approval required but no provider configured (provider layer).
    ApprovalUnavailable,
    /// Human approved (provider layer).
    ApprovalGranted,
    /// Human denied (provider layer).
    ApprovalDenied,
    /// Approval provider failed (provider layer).
    ApprovalError,
}

impl ReasonCode {
    /// Exact frozen external value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DenyParseError => "DENY_PARSE_ERROR",
            Self::DenyUnknownStatement => "DENY_UNKNOWN_STATEMENT",
            Self::SensitiveColumn => "SENSITIVE_COLUMN",
            Self::DenyRule => "DENY_RULE",
            Self::UnboundedUpdate => "UNBOUNDED_UPDATE",
            Self::UnboundedDelete => "UNBOUNDED_DELETE",
            Self::LimitRequired => "LIMIT_REQUIRED",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::RequireApproval => "REQUIRE_APPROVAL",
            Self::AllowRule => "ALLOW_RULE",
            Self::DefaultAllow => "DEFAULT_ALLOW",
            Self::DefaultApproval => "DEFAULT_APPROVAL",
            Self::DefaultDeny => "DEFAULT_DENY",
            Self::EmptyQuery => "EMPTY_QUERY",
            Self::QueryTooLarge => "QUERY_TOO_LARGE",
            Self::PolicyError => "POLICY_ERROR",
            Self::ApprovalUnavailable => "APPROVAL_UNAVAILABLE",
            Self::ApprovalGranted => "APPROVAL_GRANTED",
            Self::ApprovalDenied => "APPROVAL_DENIED",
            Self::ApprovalError => "APPROVAL_ERROR",
        }
    }
}

impl Display for ReasonCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Parse a frozen reason-code string. Used when reading persisted rows;
/// unknown values are rejected (never defaulted) by the caller.
pub fn parse_reason_code(name: &str) -> Option<ReasonCode> {
    match name {
        "DENY_PARSE_ERROR" => Some(ReasonCode::DenyParseError),
        "DENY_UNKNOWN_STATEMENT" => Some(ReasonCode::DenyUnknownStatement),
        "SENSITIVE_COLUMN" => Some(ReasonCode::SensitiveColumn),
        "DENY_RULE" => Some(ReasonCode::DenyRule),
        "UNBOUNDED_UPDATE" => Some(ReasonCode::UnboundedUpdate),
        "UNBOUNDED_DELETE" => Some(ReasonCode::UnboundedDelete),
        "LIMIT_REQUIRED" => Some(ReasonCode::LimitRequired),
        "LIMIT_EXCEEDED" => Some(ReasonCode::LimitExceeded),
        "REQUIRE_APPROVAL" => Some(ReasonCode::RequireApproval),
        "ALLOW_RULE" => Some(ReasonCode::AllowRule),
        "DEFAULT_ALLOW" => Some(ReasonCode::DefaultAllow),
        "DEFAULT_APPROVAL" => Some(ReasonCode::DefaultApproval),
        "DEFAULT_DENY" => Some(ReasonCode::DefaultDeny),
        "EMPTY_QUERY" => Some(ReasonCode::EmptyQuery),
        "QUERY_TOO_LARGE" => Some(ReasonCode::QueryTooLarge),
        "POLICY_ERROR" => Some(ReasonCode::PolicyError),
        "APPROVAL_UNAVAILABLE" => Some(ReasonCode::ApprovalUnavailable),
        "APPROVAL_GRANTED" => Some(ReasonCode::ApprovalGranted),
        "APPROVAL_DENIED" => Some(ReasonCode::ApprovalDenied),
        "APPROVAL_ERROR" => Some(ReasonCode::ApprovalError),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::ReasonCode;

    /// Tripwire: the frozen set must survive intact. Adding a code updates
    /// this list deliberately; removing or renaming one fails here.
    #[test]
    fn frozen_reason_code_set() {
        let all = [
            ReasonCode::DenyParseError,
            ReasonCode::DenyUnknownStatement,
            ReasonCode::SensitiveColumn,
            ReasonCode::DenyRule,
            ReasonCode::UnboundedUpdate,
            ReasonCode::UnboundedDelete,
            ReasonCode::LimitRequired,
            ReasonCode::LimitExceeded,
            ReasonCode::RequireApproval,
            ReasonCode::AllowRule,
            ReasonCode::DefaultAllow,
            ReasonCode::DefaultApproval,
            ReasonCode::DefaultDeny,
            ReasonCode::EmptyQuery,
            ReasonCode::QueryTooLarge,
            ReasonCode::PolicyError,
            ReasonCode::ApprovalUnavailable,
            ReasonCode::ApprovalGranted,
            ReasonCode::ApprovalDenied,
            ReasonCode::ApprovalError,
        ];
        let names: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "DENY_PARSE_ERROR",
                "DENY_UNKNOWN_STATEMENT",
                "SENSITIVE_COLUMN",
                "DENY_RULE",
                "UNBOUNDED_UPDATE",
                "UNBOUNDED_DELETE",
                "LIMIT_REQUIRED",
                "LIMIT_EXCEEDED",
                "REQUIRE_APPROVAL",
                "ALLOW_RULE",
                "DEFAULT_ALLOW",
                "DEFAULT_APPROVAL",
                "DEFAULT_DENY",
                "EMPTY_QUERY",
                "QUERY_TOO_LARGE",
                "POLICY_ERROR",
                "APPROVAL_UNAVAILABLE",
                "APPROVAL_GRANTED",
                "APPROVAL_DENIED",
                "APPROVAL_ERROR",
            ]
        );
    }
}
