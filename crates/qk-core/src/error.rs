//! Stable QueryKnight-owned error taxonomy for policy loading.
//!
//! Third-party YAML parser diagnostics are never exposed verbatim: syntax
//! failures normalize to [`PolicyLoadError::InvalidYaml`] carrying only a
//! line/column position. Validation failures keep the `path: message` shape
//! that is part of the CLI contract (`invalid policy <file>: <error>`).

use std::fmt::{self, Display, Formatter};

/// Stable error model for policy v1 loading and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyLoadError {
    /// YAML syntax failure. Carries source position only, never parser prose.
    InvalidYaml {
        /// 1-based line, when the parser reports one.
        line: Option<usize>,
        /// 1-based column, when the parser reports one.
        column: Option<usize>,
    },
    /// `version` field is missing or is not exactly `1`.
    UnsupportedVersion {
        /// Rendered value found in the document.
        found: String,
    },
    /// A mapping contains a field outside its allowlist.
    UnknownField {
        /// Validation path of the containing mapping.
        path: String,
        /// Offending field name.
        field: String,
        /// Comma-separated allowlist, mirrored in the message.
        allowed: String,
    },
    /// A rule names an operation outside the explicit allowlist.
    InvalidOperation {
        /// Validation path, e.g. `policy.environments.prod.databases.main.allow[0].operations`.
        path: String,
        /// Offending operation (already lowercased).
        operation: String,
        /// Comma-separated allowlist, mirrored in the message.
        allowed: String,
    },
    /// A mapping key appears twice. Duplicates are rejected rather than
    /// resolved by first-wins or last-wins, so an ambiguous document can
    /// never silently select the more permissive value.
    DuplicateKey {
        /// Validation path of the offending mapping, e.g. `policy.defaults`.
        path: String,
        /// Offending key name.
        key: String,
        /// 1-based line, when known.
        line: Option<usize>,
        /// 1-based column, when known.
        column: Option<usize>,
    },
    /// A glob pattern cannot be compiled and must never broaden access.
    InvalidGlob {
        /// Validation path of the offending pattern list.
        path: String,
    },
    /// A limit field is not a positive integer.
    InvalidLimit {
        /// Validation path of the offending field.
        path: String,
    },
    /// Any other structural or value violation, with a stable message.
    InvalidConfiguration {
        /// Validation path of the offending node.
        path: String,
        /// Stable QueryKnight-owned detail.
        message: String,
    },
}

impl Display for PolicyLoadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidYaml { line, column } => match (line, column) {
                (Some(l), Some(c)) => write!(f, "invalid YAML at line {l} column {c}"),
                _ => write!(f, "invalid YAML: syntax error"),
            },
            Self::UnsupportedVersion { found } => {
                write!(
                    f,
                    "policy.version: unsupported policy version '{found}' (expected 1)"
                )
            }
            Self::UnknownField {
                path,
                field,
                allowed,
            } => {
                write!(f, "{path}: unknown field '{field}' (allowed: {allowed})")
            }
            Self::InvalidOperation {
                path,
                operation,
                allowed,
            } => {
                write!(
                    f,
                    "{path}: unknown operation '{operation}' (allowed: {allowed})"
                )
            }
            Self::DuplicateKey {
                path,
                key,
                line,
                column,
            } => {
                write!(f, "{path}: duplicate mapping key '{key}'")?;
                match (line, column) {
                    (Some(l), Some(c)) => write!(f, " at line {l} column {c}"),
                    _ => Ok(()),
                }
            }
            Self::InvalidGlob { path } => write!(
                f,
                "{path}: invalid glob pattern (rejected; patterns must never broaden on failure)"
            ),
            Self::InvalidLimit { path } => write!(f, "{path}: expected a positive integer"),
            Self::InvalidConfiguration { path, message } => write!(f, "{path}: {message}"),
        }
    }
}

impl std::error::Error for PolicyLoadError {}

#[cfg(test)]
mod tests {
    use super::PolicyLoadError;

    #[test]
    fn duplicate_message_shape() {
        let e = PolicyLoadError::DuplicateKey {
            path: "policy.defaults".to_owned(),
            key: "decision".to_owned(),
            line: Some(4),
            column: Some(3),
        };
        assert_eq!(
            e.to_string(),
            "policy.defaults: duplicate mapping key 'decision' at line 4 column 3"
        );
        let e = PolicyLoadError::DuplicateKey {
            path: "policy".to_owned(),
            key: "a".to_owned(),
            line: None,
            column: None,
        };
        assert_eq!(e.to_string(), "policy: duplicate mapping key 'a'");
    }

    #[test]
    fn messages_keep_contract_shape() {
        let e = PolicyLoadError::InvalidYaml {
            line: Some(2),
            column: Some(15),
        };
        assert_eq!(e.to_string(), "invalid YAML at line 2 column 15");
        let e = PolicyLoadError::InvalidYaml {
            line: None,
            column: None,
        };
        assert_eq!(e.to_string(), "invalid YAML: syntax error");
        let e = PolicyLoadError::UnsupportedVersion {
            found: "2".to_owned(),
        };
        assert!(e.to_string().contains("unsupported policy version"));
    }
}
