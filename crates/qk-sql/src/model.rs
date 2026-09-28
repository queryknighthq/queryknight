//! Parser-independent normalized analysis model. No `sqlparser-rs` types
//! appear in these definitions.

use std::fmt::{self, Display, Formatter};

use crate::dialect::SqlDialect;

/// An identifier with its quoting preserved. Unquoted identifiers fold
/// per-dialect at match time (a later layer); quoted identifiers never fold.
/// Nothing here lowercases: case information is retained for safe matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identifier {
    /// Identifier text without surrounding quotes.
    pub value: String,
    /// Whether the identifier was quoted (`".."`, `` `..` ``, `[..]`).
    pub quoted: bool,
}

impl Identifier {
    /// Build an unquoted identifier.
    pub fn bare(value: &str) -> Self {
        Self {
            value: value.to_owned(),
            quoted: false,
        }
    }

    /// Comparison key: unquoted identifiers fold to lowercase (PostgreSQL
    /// semantics), quoted identifiers compare exactly.
    pub fn match_key(&self) -> String {
        if self.quoted {
            self.value.clone()
        } else {
            self.value.to_lowercase()
        }
    }
}

/// A table reference: `[database.[schema.]]name`. Syntactic only; no catalog
/// resolution is performed or implied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableRef {
    /// First qualifier for three-part names.
    pub database: Option<Identifier>,
    /// Schema/second qualifier.
    pub schema: Option<Identifier>,
    /// Table name (final part).
    pub name: Identifier,
}

impl Display for TableRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(db) = &self.database {
            write!(f, "{}.", db.value)?;
        }
        if let Some(schema) = &self.schema {
            write!(f, "{}.", schema.value)?;
        }
        write!(f, "{}", self.name.value)
    }
}

/// A column position: either `*` or a concrete name. `SELECT *` is always
/// [`ColumnName::Star`]; concrete columns are never invented.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColumnName {
    /// `*` wildcard.
    Star,
    /// Concrete column identifier.
    Name(Identifier),
}

/// A column reference with its qualifier path preserved.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ColumnRef {
    /// Qualifier path (`[]`, `[table]`, or `[schema, table]`).
    pub qualifier: Vec<Identifier>,
    /// Column position.
    pub name: ColumnName,
}

/// QueryKnight-owned statement operations. Kind-level (what the statement
/// is), never a verdict. `Unsupported` marks parsed-but-unmapped shapes so
/// they can never be mistaken for reads.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Operation {
    /// SELECT / WITH ... SELECT / VALUES / TABLE.
    Select,
    /// INSERT.
    Insert,
    /// UPDATE.
    Update,
    /// DELETE.
    Delete,
    /// MERGE.
    Merge,
    /// CREATE (table, index, view, schema, extension, ...).
    Create,
    /// ALTER.
    Alter,
    /// DROP.
    Drop,
    /// TRUNCATE.
    Truncate,
    /// GRANT.
    Grant,
    /// REVOKE.
    Revoke,
    /// COPY ... FROM/TO.
    Copy,
    /// CALL / procedure execution.
    Call,
    /// SET / configuration assignment.
    Set,
    /// SHOW / DESCRIBE-style inspection.
    Show,
    /// VACUUM and similar maintenance statements.
    Vacuum,
    /// EXPLAIN of another statement. The inner write, when any, is also
    /// recorded in `nested_operations` so it stays visible.
    Explain,
    /// Transaction control (BEGIN / COMMIT / ROLLBACK / ...).
    Transaction,
    /// Parsed but deliberately unmapped: never read, never executed-blind.
    Unsupported,
}

impl Operation {
    /// Stable serialization name, lowercase, matching oracle kind vocabulary.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Merge => "merge",
            Self::Create => "create",
            Self::Alter => "alter",
            Self::Drop => "drop",
            Self::Truncate => "truncate",
            Self::Grant => "grant",
            Self::Revoke => "revoke",
            Self::Copy => "copy",
            Self::Call => "call",
            Self::Set => "set",
            Self::Show => "show",
            Self::Vacuum => "vacuum",
            Self::Explain => "explain",
            Self::Transaction => "transaction",
            Self::Unsupported => "unknown",
        }
    }

    /// Security-relevant category used for `read_only` computation.
    #[must_use]
    pub fn category(&self) -> OpCategory {
        match self {
            Self::Select | Self::Show | Self::Explain => OpCategory::Read,
            Self::Insert | Self::Update | Self::Delete | Self::Merge => OpCategory::Write,
            Self::Create | Self::Alter => OpCategory::Ddl,
            Self::Drop | Self::Truncate => OpCategory::Destructive,
            Self::Grant | Self::Revoke => OpCategory::Privilege,
            Self::Copy | Self::Call | Self::Set | Self::Vacuum => OpCategory::Admin,
            Self::Transaction | Self::Unsupported => OpCategory::Unknown,
        }
    }
}

/// Coarse operation categories for read/write separation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCategory {
    /// Pure reads.
    Read,
    /// Data modifications.
    Write,
    /// Schema definitions.
    Ddl,
    /// Destructive operations.
    Destructive,
    /// Privilege changes.
    Privilege,
    /// Administrative / high-impact operations.
    Admin,
    /// Transaction control or explicitly unsupported shapes.
    Unknown,
}

impl OpCategory {
    /// Stable lowercase name, matching the reference operation vocabulary
    /// used in policy `operations` rules.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Ddl => "ddl",
            Self::Destructive => "destructive",
            Self::Privilege => "privilege",
            Self::Admin => "admin",
            Self::Unknown => "unknown",
        }
    }
}

/// LIMIT representation. Non-literal limits are never coerced to numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitValue {
    /// `LIMIT 10`: known numeric literal.
    Literal(u64),
    /// `LIMIT ?` / `LIMIT $1`: bound at execution time, value unknown here.
    Parameterized,
    /// Any other expression (arithmetic, function call, ...).
    Expression,
}

/// Structural facts derived directly from the AST. Facts, not verdicts: no
/// allow/deny semantics exist in this layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskSignal {
    /// More than one statement in the input.
    MultipleStatements,
    /// Top-level UPDATE/DELETE without a WHERE clause.
    MutationWithoutWhere,
    /// `SELECT *` or `t.*` present.
    SelectStar,
    /// A LIMIT that is not a numeric literal.
    DynamicLimit,
    /// A CREATE/ALTER/DROP/TRUNCATE operation is present.
    DdlOperation,
    /// A COPY/CALL/SET/VACUUM operation is present.
    AdministrativeOperation,
    /// Data-modifying operation nested inside a read (CTE, subquery, ...).
    NestedMutation,
    /// Walk depth was capped; deeper nodes were not visited.
    DepthTruncated,
}

impl RiskSignal {
    /// Stable snake_case name for policy `signals` rule matching.
    /// `multi_statement` mirrors the reference vocabulary; the rest are
    /// QueryKnight-owned names for facts the reference never produced.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::MultipleStatements => "multi_statement",
            Self::MutationWithoutWhere => "mutation_without_where",
            Self::SelectStar => "select_star",
            Self::DynamicLimit => "dynamic_limit",
            Self::DdlOperation => "ddl_operation",
            Self::AdministrativeOperation => "administrative_operation",
            Self::NestedMutation => "nested_mutation",
            Self::DepthTruncated => "depth_truncated",
        }
    }
}

/// Normalized analysis of one statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementAnalysis {
    /// Top-level operation of the statement.
    pub operation: Operation,
    /// Every referenced table, including write targets. Sorted, deduplicated.
    /// CTE names are excluded: they are query-local aliases, not objects.
    pub tables: Vec<TableRef>,
    /// Write targets (UPDATE/DELETE/MERGE/INSERT/DDL targets). Sorted, deduplicated.
    pub mutated_tables: Vec<TableRef>,
    /// Extracted columns. Sorted, deduplicated. Unresolvable positions are
    /// [`ColumnName::Star`], never invented names.
    pub columns: Vec<ColumnRef>,
    /// WHERE presence for UPDATE/DELETE; `None` where not applicable.
    pub has_where: Option<bool>,
    /// LIMIT value where the statement carries one.
    pub limit: Option<LimitValue>,
    /// RETURNING / OUTPUT clause present.
    pub has_returning: bool,
    /// `SELECT *` / `t.*` present.
    pub select_star: bool,
    /// Data-modifying operations found in nested positions (CTEs,
    /// subqueries, MERGE branches, EXPLAIN inner statements). Sorted,
    /// deduplicated, excluding the top-level operation itself.
    pub nested_operations: Vec<Operation>,
    /// Nested UPDATE/DELETE operations lacking a WHERE clause. Sorted,
    /// deduplicated. Lets the evaluator apply unbounded-mutation protection
    /// to nested writes without claiming catalog knowledge.
    pub nested_unbounded: Vec<Operation>,
}

/// Whether the whole AST was visited. A truncated analysis must never be
/// mistaken for a complete inspection: `read_only` is forced to false and
/// [`RiskSignal::DepthTruncated`] is set whenever completeness is not
/// [`AnalysisCompleteness::Complete`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisCompleteness {
    /// Every node visited; `read_only` is a confident claim.
    Complete,
    /// Traversal stopped at [`crate::MAX_WALK_DEPTH`]; unvisited remainder
    /// may contain anything, including mutations.
    DepthTruncated,
}

/// Normalized whole-input analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryAnalysis {
    /// Dialect the input was parsed with.
    pub dialect: SqlDialect,
    /// Inspection completeness (see [`AnalysisCompleteness`]).
    pub completeness: AnalysisCompleteness,
    /// Per-statement analyses in source order.
    pub statements: Vec<StatementAnalysis>,
    /// Union of all statement tables. Sorted, deduplicated.
    pub tables: Vec<TableRef>,
    /// Union of all mutated tables. Sorted, deduplicated.
    pub mutated_tables: Vec<TableRef>,
    /// Union of all columns. Sorted, deduplicated.
    pub columns: Vec<ColumnRef>,
    /// Union of top-level and nested operations. Sorted, deduplicated, so a
    /// dangerous second statement or nested mutation is always visible.
    pub operations: Vec<Operation>,
    /// Structural signals. Sorted, deduplicated.
    pub risk_signals: Vec<RiskSignal>,
    /// True only when every top-level and nested operation is a read.
    /// Unknown/unsupported shapes are never read-only.
    pub read_only: bool,
}
