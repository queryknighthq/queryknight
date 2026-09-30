//! SQL text -> [`QueryAnalysis`]. Synchronous, allocation-bounded, panic-free
//! on untrusted input.
//!
//! The walker is hand-written (not the parser's generic visitor) so every
//! recursion point is explicit and auditable. Extraction is syntactic, never
//! catalog-aware: unqualified columns are never attributed to a table, CTE
//! names never leak into table lists, and exotic expression shapes
//! contribute nothing rather than wrong facts (see limitations below and
//! `docs/sqlparser-differences.md`).

use std::collections::BTreeSet;
use std::ops::ControlFlow;

use sqlparser::ast::{
    AssignmentTarget, CopySource, Delete, Expr, FunctionArg, FunctionArgExpr, GrantObjects, Ident,
    LimitClause, MergeAction, MergeUpdateKind, ObjectName, Query, Select, SelectItem, Set, SetExpr,
    Statement, TableFactor, TableObject, TableWithJoins, Update, UpdateTableFromKind, Value,
    ValueWithSpan, Visit, Visitor,
};
use sqlparser::dialect::{MySqlDialect, PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;

use crate::dialect::SqlDialect;
use crate::error::{truncate_diagnostic, SqlAnalysisError};
use crate::model::{
    ColumnName, ColumnRef, Identifier, LimitValue, OpCategory, Operation, QueryAnalysis,
    RiskSignal, StatementAnalysis, TableRef,
};
use crate::{AnalysisCompleteness, MAX_SQL_BYTES, MAX_WALK_DEPTH, SQL_PARSER_RECURSION_LIMIT};

/// Analysis input bounds. `Default` carries the frozen [`MAX_SQL_BYTES`].
#[derive(Debug, Clone, Copy)]
pub struct AnalyzeOptions {
    /// Maximum accepted UTF-8 byte length.
    pub max_bytes: usize,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            max_bytes: MAX_SQL_BYTES,
        }
    }
}

/// Analyze SQL text in a named dialect (`postgres`, `mysql`, `sqlite`,
/// plus documented aliases).
pub fn analyze(sql: &str, dialect: &str) -> Result<QueryAnalysis, SqlAnalysisError> {
    let parsed = dialect.parse()?;
    analyze_with_options(sql, parsed, AnalyzeOptions::default())
}

/// Analyze SQL text with explicit dialect and options.
pub fn analyze_with_options(
    sql: &str,
    dialect: SqlDialect,
    options: AnalyzeOptions,
) -> Result<QueryAnalysis, SqlAnalysisError> {
    let bytes = sql.len();
    if bytes > options.max_bytes {
        return Err(SqlAnalysisError::InputTooLarge {
            bytes,
            max_bytes: options.max_bytes,
        });
    }
    // Execution guard: the whole pipeline runs on a grown stack segment.
    // `maybe_grow` is insufficient here on purpose: it switches segments at
    // most once, only when the red zone is already tripped, so a deep drop
    // starting with ample stack still overflows mid-destruction. An
    // unconditional `grow` is the honest primitive: sized from measurement
    // (~80-130 bytes per level; 1 MiB worst case ~500k levels needs ~65 MB;
    // 128 MiB carries ~2x margin, freed on return). Panics inside become
    // AnalysisError; the catch sits inside the segment so unwinding never
    // crosses the stack boundary.
    stacker::grow(GROWTH_BYTES, || {
        std::panic::catch_unwind(|| analyze_inline(dialect, sql)).unwrap_or_else(|_| {
            Err(SqlAnalysisError::AnalysisError {
                message: "analysis panicked on input; failing closed".to_owned(),
            })
        })
    })
}

/// Detect whether parsed SQL contains a bind placeholder, using the same
/// dialect parser and recursion guard as query analysis.
///
/// This lets protocol adapters refuse an unbound parameterized request without
/// scanning SQL text or maintaining a second lexer.
pub fn has_parameter_markers(
    sql: &str,
    dialect: SqlDialect,
    options: AnalyzeOptions,
) -> Result<bool, SqlAnalysisError> {
    let bytes = sql.len();
    if bytes > options.max_bytes {
        return Err(SqlAnalysisError::InputTooLarge {
            bytes,
            max_bytes: options.max_bytes,
        });
    }
    stacker::grow(GROWTH_BYTES, || {
        std::panic::catch_unwind(|| {
            let statements = parse_bounded(dialect, sql)?;
            let mut visitor = ParameterMarkerVisitor { found: false };
            for statement in &statements {
                if statement.visit(&mut visitor).is_break() {
                    break;
                }
            }
            Ok(visitor.found)
        })
        .unwrap_or_else(|_| {
            Err(SqlAnalysisError::AnalysisError {
                message: "analysis panicked on input; failing closed".to_owned(),
            })
        })
    })
}

struct ParameterMarkerVisitor {
    found: bool,
}

impl Visitor for ParameterMarkerVisitor {
    type Break = ();

    fn pre_visit_value(&mut self, value: &ValueWithSpan) -> ControlFlow<Self::Break> {
        if matches!(value.value, Value::Placeholder(_)) {
            self.found = true;
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// Inner pipeline: parse, walk, assemble. Runs inside the grown segment.
fn analyze_inline(dialect: SqlDialect, sql: &str) -> Result<QueryAnalysis, SqlAnalysisError> {
    let statements = parse_bounded(dialect, sql)?;
    if statements.is_empty() {
        return Err(SqlAnalysisError::EmptyQuery);
    }
    let mut analyses = Vec::with_capacity(statements.len());
    let mut truncated = false;
    for stmt in &statements {
        let (analysis, was_truncated) = analyze_statement(stmt);
        truncated |= was_truncated;
        analyses.push(analysis);
    }

    let mut tables = BTreeSet::new();
    let mut mutated = BTreeSet::new();
    let mut columns = BTreeSet::new();
    let mut operations = BTreeSet::new();
    let mut signals = BTreeSet::new();
    if analyses.len() > 1 {
        signals.insert(RiskSignal::MultipleStatements);
    }
    if truncated {
        signals.insert(RiskSignal::DepthTruncated);
    }
    for stmt in &analyses {
        tables.extend(stmt.tables.iter().cloned());
        mutated.extend(stmt.mutated_tables.iter().cloned());
        columns.extend(stmt.columns.iter().cloned());
        operations.insert(stmt.operation.clone());
        operations.extend(stmt.nested_operations.iter().cloned());
        if stmt.select_star {
            signals.insert(RiskSignal::SelectStar);
        }
        if matches!(
            stmt.limit,
            Some(LimitValue::Parameterized) | Some(LimitValue::Expression)
        ) {
            signals.insert(RiskSignal::DynamicLimit);
        }
        if matches!(
            stmt.operation.category(),
            OpCategory::Ddl | OpCategory::Destructive
        ) {
            signals.insert(RiskSignal::DdlOperation);
        }
        if matches!(stmt.operation.category(), OpCategory::Admin) {
            signals.insert(RiskSignal::AdministrativeOperation);
        }
        if !stmt.nested_operations.is_empty() {
            signals.insert(RiskSignal::NestedMutation);
        }
        if matches!(stmt.operation, Operation::Update | Operation::Delete)
            && stmt.has_where == Some(false)
        {
            signals.insert(RiskSignal::MutationWithoutWhere);
        }
    }
    // A truncated walk is never confidently read-only: unvisited remainder
    // may contain anything. The evaluator distinguishes via `completeness`.
    let mut read_only = operations
        .iter()
        .all(|op| op.category() == OpCategory::Read);
    let completeness = if truncated {
        read_only = false;
        AnalysisCompleteness::DepthTruncated
    } else {
        AnalysisCompleteness::Complete
    };

    Ok(QueryAnalysis {
        dialect,
        completeness,
        statements: analyses,
        tables: tables.into_iter().collect(),
        mutated_tables: mutated.into_iter().collect(),
        columns: columns.into_iter().collect(),
        operations: operations.into_iter().collect(),
        risk_signals: signals.into_iter().collect(),
        read_only,
    })
}

/// Grown execution segment for the whole pipeline. Sizing: measured
/// ~80-130 bytes per AST level on destruction; the 1 MiB input worst case
/// (~500k levels) needs ~65 MB; 128 MiB carries ~2x margin and is freed on
/// return. Transient per call, not reserved.
const GROWTH_BYTES: usize = 128 * 1024 * 1024;

/// Parse with the explicit QueryKnight recursion limit. Left-associative
/// operator chains bypass this counter (the parser handles them
/// iteratively); their trees are bounded by [`MAX_SQL_BYTES`] and destroyed
/// via the guarded drop above.
fn parse_bounded(dialect: SqlDialect, sql: &str) -> Result<Vec<Statement>, SqlAnalysisError> {
    let mut parser = match dialect {
        SqlDialect::PostgreSql => {
            Parser::new(&PostgreSqlDialect {}).with_recursion_limit(SQL_PARSER_RECURSION_LIMIT)
        }
        SqlDialect::MySql => {
            Parser::new(&MySqlDialect {}).with_recursion_limit(SQL_PARSER_RECURSION_LIMIT)
        }
        SqlDialect::Sqlite => {
            Parser::new(&SQLiteDialect {}).with_recursion_limit(SQL_PARSER_RECURSION_LIMIT)
        }
    }
    .try_with_sql(sql)
    .map_err(|e| SqlAnalysisError::ParseError {
        message: truncate_diagnostic(&e.to_string()),
        line: None,
        column: None,
    })?;
    parser.parse_statements().map_err(|e| match e {
        sqlparser::parser::ParserError::RecursionLimitExceeded => {
            SqlAnalysisError::ComplexityLimitExceeded {
                limit: SQL_PARSER_RECURSION_LIMIT,
            }
        }
        other => SqlAnalysisError::ParseError {
            message: truncate_diagnostic(&other.to_string()),
            line: None,
            column: None,
        },
    })
}

fn analyze_statement(stmt: &Statement) -> (StatementAnalysis, bool) {
    let mut col = Collector::default();
    let operation = walk_statement(stmt, &mut col, true, 0);
    let truncated = col.depth_truncated;
    (col.finish(operation), truncated)
}

/// Per-statement accumulator. Sets keep output deterministic; the walk
/// itself is order-independent.
#[derive(Default)]
struct Collector {
    tables: BTreeSet<TableRef>,
    mutated: BTreeSet<TableRef>,
    columns: BTreeSet<ColumnRef>,
    nested: BTreeSet<Operation>,
    nested_unbounded: BTreeSet<Operation>,
    has_where: Option<bool>,
    limit: Option<LimitValue>,
    has_returning: bool,
    select_star: bool,
    depth_truncated: bool,
    cte_names: Vec<String>,
}

impl Collector {
    fn finish(mut self, operation: Operation) -> StatementAnalysis {
        let mut nested: Vec<Operation> = self
            .nested
            .iter()
            .filter(|op| **op != operation)
            .cloned()
            .collect();
        nested.sort();
        nested.dedup();
        let _ = &mut self;
        let mut unbounded: Vec<Operation> = self.nested_unbounded.iter().cloned().collect();
        unbounded.sort();
        unbounded.dedup();
        StatementAnalysis {
            operation,
            tables: self.tables.into_iter().collect(),
            mutated_tables: self.mutated.into_iter().collect(),
            columns: self.columns.into_iter().collect(),
            has_where: self.has_where,
            limit: self.limit,
            has_returning: self.has_returning,
            select_star: self.select_star,
            nested_operations: nested,
            nested_unbounded: unbounded,
        }
    }

    fn note_depth(&mut self, depth: usize) -> bool {
        if depth > MAX_WALK_DEPTH {
            self.depth_truncated = true;
            return false;
        }
        true
    }
}

fn ident_of(id: &Ident) -> Identifier {
    Identifier {
        value: id.value.clone(),
        quoted: id.quote_style.is_some(),
    }
}

fn part_ident(part: &sqlparser::ast::ObjectNamePart) -> Option<Identifier> {
    part.as_ident().map(ident_of)
}

fn table_ref_of(name: &ObjectName) -> Option<TableRef> {
    let parts: Vec<Identifier> = name.0.iter().filter_map(part_ident).collect();
    match parts.as_slice() {
        [] => None,
        [table] => Some(TableRef {
            database: None,
            schema: None,
            name: table.clone(),
        }),
        [schema, table] => Some(TableRef {
            database: None,
            schema: Some(schema.clone()),
            name: table.clone(),
        }),
        [database, schema, table] => Some(TableRef {
            database: Some(database.clone()),
            schema: Some(schema.clone()),
            name: table.clone(),
        }),
        many => {
            // Longer-than-three paths are not real catalog addresses in our
            // dialects; join the leading parts into one database qualifier
            // deterministically rather than dropping them.
            let (leading, tail) = many.split_at(many.len().saturating_sub(2));
            let (schema, table) = match tail {
                [schema, table] => (schema.clone(), table.clone()),
                _ => return None,
            };
            let joined = leading
                .iter()
                .map(|i| i.value.clone())
                .collect::<Vec<_>>()
                .join(".");
            let quoted = leading.iter().all(|i| i.quoted);
            Some(TableRef {
                database: Some(Identifier {
                    value: joined,
                    quoted,
                }),
                schema: Some(schema),
                name: table,
            })
        }
    }
}

fn column_ref_of(name: &ObjectName) -> Option<ColumnRef> {
    let parts: Vec<Identifier> = name.0.iter().filter_map(part_ident).collect();
    match parts.as_slice() {
        [] => None,
        [single] if single.value == "*" && !single.quoted => Some(ColumnRef {
            qualifier: Vec::new(),
            name: ColumnName::Star,
        }),
        [column] => Some(ColumnRef {
            qualifier: Vec::new(),
            name: ColumnName::Name(column.clone()),
        }),
        many => {
            let (qualifier, last) = many.split_at(many.len().saturating_sub(1));
            let name = match last {
                [star] if star.value == "*" && !star.quoted => ColumnName::Star,
                [column] => ColumnName::Name(column.clone()),
                _ => return None,
            };
            Some(ColumnRef {
                qualifier: qualifier.to_vec(),
                name,
            })
        }
    }
}

fn changes_sql_interpretation(set: &Set) -> bool {
    match set {
        Set::SetNames { .. } | Set::SetNamesDefault {} => true,
        Set::SingleAssignment { variable, .. } => is_sql_interpretation_variable(variable),
        Set::MultipleAssignments { assignments } => assignments
            .iter()
            .any(|assignment| is_sql_interpretation_variable(&assignment.name)),
        _ => false,
    }
}

fn is_sql_interpretation_variable(name: &ObjectName) -> bool {
    let Some(identifier) = name.0.last().and_then(|part| part.as_ident()) else {
        return false;
    };
    [
        "character_set",
        "character_set_client",
        "character_set_connection",
        "character_set_results",
        "character_set_server",
        "character_set_database",
        "collation_connection",
        "collation_server",
        "collation_database",
        "sql_mode",
    ]
    .iter()
    .any(|setting| identifier.value.eq_ignore_ascii_case(setting))
}

// ---------------------------------------------------------------------------
// Statement dispatch
// ---------------------------------------------------------------------------

fn walk_statement(stmt: &Statement, col: &mut Collector, primary: bool, depth: usize) -> Operation {
    let op = match stmt {
        Statement::Query(q) => walk_query(q, col, primary, depth).unwrap_or(Operation::Select),
        Statement::Insert(i) => {
            if let TableObject::TableName(name) = &i.table {
                if let Some(t) = table_ref_of(name) {
                    col.tables.insert(t.clone());
                    col.mutated.insert(t);
                }
            }
            for name in &i.columns {
                if let Some(c) = column_ref_of(name) {
                    col.columns.insert(c);
                }
            }
            if let Some(source) = &i.source {
                walk_query(source, col, false, depth + 1);
            }
            walk_returning(i.returning.as_deref(), col, depth + 1);
            Operation::Insert
        }
        Statement::Update(u) => {
            walk_update(u, col, depth + 1, primary);
            Operation::Update
        }
        Statement::Delete(d) => {
            walk_delete(d, col, depth + 1, primary);
            Operation::Delete
        }
        Statement::Merge(m) => {
            walk_merge(m, col, depth + 1);
            Operation::Merge
        }
        Statement::CreateTable(t) => {
            if let Some(table) = table_ref_of(&t.name) {
                col.tables.insert(table.clone());
                col.mutated.insert(table);
            }
            if let Some(query) = &t.query {
                walk_query(query, col, false, depth + 1);
            }
            Operation::Create
        }
        Statement::CreateIndex(i) => {
            if let Some(table) = table_ref_of(&i.table_name) {
                col.tables.insert(table.clone());
                col.mutated.insert(table);
            }
            Operation::Create
        }
        Statement::CreateView(v) => {
            if let Some(table) = table_ref_of(&v.name) {
                col.tables.insert(table.clone());
                col.mutated.insert(table);
            }
            walk_query(&v.query, col, false, depth + 1);
            Operation::Create
        }
        Statement::AlterTable(a) => {
            if let Some(table) = table_ref_of(&a.name) {
                col.tables.insert(table.clone());
                col.mutated.insert(table);
            }
            Operation::Alter
        }
        Statement::Drop { names, .. } => {
            for name in names {
                if let Some(table) = table_ref_of(name) {
                    col.tables.insert(table.clone());
                    col.mutated.insert(table);
                }
            }
            Operation::Drop
        }
        Statement::Truncate(t) => {
            for target in &t.table_names {
                if let Some(table) = table_ref_of(&target.name) {
                    col.tables.insert(table.clone());
                    col.mutated.insert(table);
                }
            }
            Operation::Truncate
        }
        Statement::Grant(g) => {
            if let Some(GrantObjects::Tables(names)) = &g.objects {
                for name in names {
                    if let Some(table) = table_ref_of(name) {
                        col.tables.insert(table);
                    }
                }
            }
            Operation::Grant
        }
        Statement::Revoke(r) => {
            if let Some(GrantObjects::Tables(names)) = &r.objects {
                for name in names {
                    if let Some(table) = table_ref_of(name) {
                        col.tables.insert(table);
                    }
                }
            }
            Operation::Revoke
        }
        Statement::Copy { source, .. } => {
            match source {
                CopySource::Table {
                    table_name,
                    columns,
                } => {
                    if let Some(table) = table_ref_of(table_name) {
                        col.tables.insert(table);
                    }
                    for id in columns {
                        col.columns.insert(ColumnRef {
                            qualifier: Vec::new(),
                            name: ColumnName::Name(ident_of(id)),
                        });
                    }
                }
                CopySource::Query(q) => {
                    walk_query(q, col, false, depth + 1);
                }
            }
            Operation::Copy
        }
        Statement::Call(f) => {
            walk_function(f, col, depth + 1);
            Operation::Call
        }
        Statement::Set(set) => {
            if changes_sql_interpretation(set) {
                Operation::Unsupported
            } else {
                Operation::Set
            }
        }
        Statement::ShowTables { .. } => Operation::Show,
        // SHOW COLUMNS carries its scope in `show_options`; the table filter
        // forms differ per dialect, so no table identity is claimed here.
        Statement::ShowColumns { .. } => Operation::Show,
        Statement::Explain { statement, .. } => {
            walk_statement(statement, col, false, depth + 1);
            Operation::Explain
        }
        Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. } => Operation::Transaction,
        Statement::Vacuum(v) => {
            if let Some(name) = &v.table_name {
                if let Some(table) = table_ref_of(name) {
                    col.tables.insert(table);
                }
            }
            Operation::Vacuum
        }
        _ => Operation::Unsupported,
    };
    if !primary && op.category() != OpCategory::Read {
        col.nested.insert(op.clone());
    }
    op
}

// ---------------------------------------------------------------------------
// DML walkers
// ---------------------------------------------------------------------------

fn walk_update(u: &Update, col: &mut Collector, depth: usize, primary: bool) {
    if let TableFactor::Table { name, .. } = &u.table.relation {
        if let Some(t) = table_ref_of(name) {
            col.tables.insert(t.clone());
            col.mutated.insert(t);
        }
    } else {
        walk_table_factor(&u.table.relation, col, depth, false);
    }
    for join in &u.table.joins {
        walk_join(join, col, depth);
    }
    for assignment in &u.assignments {
        match &assignment.target {
            AssignmentTarget::ColumnName(name) => {
                if let Some(c) = column_ref_of(name) {
                    col.columns.insert(c);
                }
            }
            AssignmentTarget::Tuple(names) => {
                for name in names {
                    if let Some(c) = column_ref_of(name) {
                        col.columns.insert(c);
                    }
                }
            }
        }
        walk_expr(&assignment.value, col, depth);
    }
    if let Some(from) = &u.from {
        let tables = match from {
            UpdateTableFromKind::BeforeSet(t) | UpdateTableFromKind::AfterSet(t) => t,
        };
        for twj in tables {
            walk_table_with_joins(twj, col, depth, false);
        }
    }
    if primary {
        if col.has_where.is_none() {
            col.has_where = Some(u.selection.is_some());
        }
        if let Some(e) = &u.limit {
            set_limit(limit_of(e), col);
        }
    } else if u.selection.is_none() {
        col.nested_unbounded.insert(Operation::Update);
    }
    if let Some(selection) = &u.selection {
        walk_expr(selection, col, depth);
    }
    walk_returning(u.returning.as_deref(), col, depth);
}

fn walk_delete(d: &Delete, col: &mut Collector, depth: usize, primary: bool) {
    use sqlparser::ast::FromTable;
    let from_tables: Vec<TableWithJoins> = match &d.from {
        FromTable::WithFromKeyword(t) => t.clone(),
        FromTable::WithoutKeyword(t) => t.clone(),
    };
    if d.tables.is_empty() {
        for twj in &from_tables {
            if let TableFactor::Table { name, .. } = &twj.relation {
                if let Some(t) = table_ref_of(name) {
                    col.tables.insert(t.clone());
                    col.mutated.insert(t);
                }
            } else {
                walk_table_factor(&twj.relation, col, depth, false);
            }
            for join in &twj.joins {
                walk_join(join, col, depth);
            }
        }
    } else {
        for name in &d.tables {
            if let Some(t) = table_ref_of(name) {
                col.tables.insert(t.clone());
                col.mutated.insert(t);
            }
        }
        for twj in &from_tables {
            walk_table_with_joins(twj, col, depth, false);
        }
    }
    if let Some(using) = &d.using {
        for twj in using {
            walk_table_with_joins(twj, col, depth, false);
        }
    }
    if primary {
        if col.has_where.is_none() {
            col.has_where = Some(d.selection.is_some());
        }
        if let Some(e) = &d.limit {
            set_limit(limit_of(e), col);
        }
    } else if d.selection.is_none() {
        col.nested_unbounded.insert(Operation::Delete);
    }
    if let Some(selection) = &d.selection {
        walk_expr(selection, col, depth);
    }
    walk_returning(d.returning.as_deref(), col, depth);
}

fn walk_merge(m: &sqlparser::ast::Merge, col: &mut Collector, depth: usize) {
    walk_merge_source(&m.table, col, depth, true);
    walk_merge_source(&m.source, col, depth, false);
    walk_expr(&m.on, col, depth);
    for clause in &m.clauses {
        match &clause.action {
            MergeAction::Insert(expr) => {
                col.nested.insert(Operation::Insert);
                for name in &expr.columns {
                    if let Some(c) = column_ref_of(name) {
                        col.columns.insert(c);
                    }
                }
                if let sqlparser::ast::MergeInsertKind::Values(values) = &expr.kind {
                    for row in &values.rows {
                        for e in &row.content {
                            walk_expr(e, col, depth);
                        }
                    }
                }
            }
            MergeAction::Update(expr) => {
                col.nested.insert(Operation::Update);
                if let MergeUpdateKind::Set(assignments) = &expr.kind {
                    for assignment in assignments {
                        if let AssignmentTarget::ColumnName(name) = &assignment.target {
                            if let Some(c) = column_ref_of(name) {
                                col.columns.insert(c);
                            }
                        }
                        walk_expr(&assignment.value, col, depth);
                    }
                }
                if let Some(pred) = &expr.update_predicate {
                    walk_expr(pred, col, depth);
                }
                if let Some(pred) = &expr.delete_predicate {
                    walk_expr(pred, col, depth);
                }
            }
            MergeAction::Delete { .. } => {
                col.nested.insert(Operation::Delete);
            }
            _ => {}
        }
    }
}

fn walk_merge_source(factor: &TableFactor, col: &mut Collector, depth: usize, target: bool) {
    if target {
        if let TableFactor::Table { name, .. } = factor {
            if let Some(t) = table_ref_of(name) {
                col.tables.insert(t.clone());
                col.mutated.insert(t);
                return;
            }
        }
    }
    walk_table_factor(factor, col, depth, false);
}

// ---------------------------------------------------------------------------
// Query / SELECT walkers. `main` means a DML body here defines the
// statement's own operation; every other position records DML as nested.
// ---------------------------------------------------------------------------

/// Walk a query. Returns the primary operation when `main` and the body is
/// itself data-modifying (e.g. `WITH .. UPDATE ..`).
fn walk_query(q: &Query, col: &mut Collector, main: bool, depth: usize) -> Option<Operation> {
    if !col.note_depth(depth) {
        return None;
    }
    // CTE names stay in scope for the main body, ORDER BY, and LIMIT: the
    // main query observes every CTE defined in its own WITH clause.
    let cte_base = col.cte_names.len();
    if let Some(with) = &q.with {
        for cte in &with.cte_tables {
            col.cte_names.push(ident_of(&cte.alias.name).match_key());
            walk_query(&cte.query, col, false, depth + 1);
        }
    }
    let primary = walk_set_expr(&q.body, col, main, depth + 1);
    if let Some(order_by) = &q.order_by {
        if let sqlparser::ast::OrderByKind::Expressions(exprs) = &order_by.kind {
            for e in exprs {
                walk_order_expr(e, col, depth + 1);
            }
        }
    }
    if let Some(clause) = &q.limit_clause {
        walk_limit_clause(clause, col, depth + 1);
    }
    col.cte_names.truncate(cte_base);
    primary
}

fn walk_set_expr(
    body: &SetExpr,
    col: &mut Collector,
    main: bool,
    depth: usize,
) -> Option<Operation> {
    match body {
        SetExpr::Select(s) => {
            walk_select(s, col, depth);
            if s.into.is_some() {
                if main {
                    Some(Operation::Unsupported)
                } else {
                    col.nested.insert(Operation::Unsupported);
                    None
                }
            } else {
                None
            }
        }
        SetExpr::Query(q) => walk_query(q, col, main, depth),
        SetExpr::SetOperation { left, right, .. } => {
            let first = walk_set_expr(left, col, main, depth + 1);
            let _ = walk_set_expr(right, col, false, depth + 1);
            first
        }
        SetExpr::Values(v) => {
            for row in &v.rows {
                for e in &row.content {
                    walk_expr(e, col, depth + 1);
                }
            }
            None
        }
        SetExpr::Table(t) => {
            // `TABLE name`: a read of a whole table. Names here are plain
            // strings without quoting metadata.
            if let Some(name) = &t.table_name {
                let table = TableRef {
                    database: None,
                    schema: t.schema_name.as_deref().map(Identifier::bare),
                    name: Identifier::bare(name),
                };
                if !is_cte(table_name_key(&table), col) {
                    col.tables.insert(table);
                }
            }
            None
        }
        SetExpr::Insert(s) => {
            let op = walk_statement(s, col, main, depth + 1);
            main.then_some(op)
        }
        SetExpr::Update(s) => {
            let op = walk_statement(s, col, main, depth + 1);
            main.then_some(op)
        }
        SetExpr::Delete(s) => {
            let op = walk_statement(s, col, main, depth + 1);
            main.then_some(op)
        }
        SetExpr::Merge(s) => {
            let op = walk_statement(s, col, main, depth + 1);
            main.then_some(op)
        }
    }
}

fn walk_select(s: &Select, col: &mut Collector, depth: usize) {
    for item in &s.projection {
        walk_select_item(item, col, depth + 1);
    }
    for twj in &s.from {
        walk_table_with_joins(twj, col, depth + 1, false);
    }
    for clause in [&s.selection, &s.having, &s.qualify] {
        if let Some(e) = clause.as_ref() {
            walk_expr(e, col, depth + 1);
        }
    }
    if let sqlparser::ast::GroupByExpr::Expressions(exprs, _) = &s.group_by {
        for e in exprs {
            walk_expr(e, col, depth + 1);
        }
    }
}

fn walk_select_item(item: &SelectItem, col: &mut Collector, depth: usize) {
    match item {
        SelectItem::UnnamedExpr(e)
        | SelectItem::ExprWithAlias { expr: e, .. }
        | SelectItem::ExprWithAliases { expr: e, .. } => {
            walk_expr(e, col, depth);
        }
        SelectItem::Wildcard(_) => {
            col.select_star = true;
            col.columns.insert(ColumnRef {
                qualifier: Vec::new(),
                name: ColumnName::Star,
            });
        }
        SelectItem::QualifiedWildcard(kind, _) => {
            use sqlparser::ast::SelectItemQualifiedWildcardKind as Qw;
            match kind {
                Qw::ObjectName(name) => {
                    col.select_star = true;
                    let parts: Vec<Identifier> = name.0.iter().filter_map(part_ident).collect();
                    col.columns.insert(ColumnRef {
                        qualifier: parts,
                        name: ColumnName::Star,
                    });
                }
                // `expr.*` on an arbitrary expression: star noted, no fake qualifier.
                Qw::Expr(e) => {
                    col.select_star = true;
                    walk_expr(e, col, depth);
                }
            }
        }
    }
}

fn table_name_key(table: &TableRef) -> String {
    table.name.match_key()
}

fn is_cte(key: String, col: &Collector) -> bool {
    col.cte_names.contains(&key)
}

fn walk_table_with_joins(twj: &TableWithJoins, col: &mut Collector, depth: usize, _target: bool) {
    walk_table_factor(&twj.relation, col, depth, false);
    for join in &twj.joins {
        walk_join(join, col, depth);
    }
}

fn walk_join(join: &sqlparser::ast::Join, col: &mut Collector, depth: usize) {
    walk_table_factor(&join.relation, col, depth + 1, false);
    match &join.join_operator {
        sqlparser::ast::JoinOperator::Inner(constraint)
        | sqlparser::ast::JoinOperator::Left(constraint)
        | sqlparser::ast::JoinOperator::Right(constraint)
        | sqlparser::ast::JoinOperator::FullOuter(constraint)
        | sqlparser::ast::JoinOperator::LeftSemi(constraint)
        | sqlparser::ast::JoinOperator::RightSemi(constraint)
        | sqlparser::ast::JoinOperator::LeftAnti(constraint)
        | sqlparser::ast::JoinOperator::RightAnti(constraint) => {
            walk_join_constraint(constraint, col, depth + 1);
        }
        _ => {}
    }
}

fn walk_join_constraint(
    constraint: &sqlparser::ast::JoinConstraint,
    col: &mut Collector,
    depth: usize,
) {
    use sqlparser::ast::JoinConstraint;
    match constraint {
        JoinConstraint::On(e) => walk_expr(e, col, depth),
        JoinConstraint::Using(names) => {
            for name in names {
                if let Some(c) = column_ref_of(name) {
                    col.columns.insert(c);
                }
            }
        }
        JoinConstraint::Natural | JoinConstraint::None => {}
    }
}

fn walk_table_factor(factor: &TableFactor, col: &mut Collector, depth: usize, _nested: bool) {
    if !col.note_depth(depth) {
        return;
    }
    match factor {
        TableFactor::Table { name, args, .. } => {
            if let Some(table) = table_ref_of(name) {
                if !is_cte(table_name_key(&table), col) {
                    col.tables.insert(table);
                }
            }
            if let Some(args) = args {
                for arg in &args.args {
                    walk_function_arg(arg, col, depth + 1);
                }
            }
        }
        TableFactor::Derived { subquery, .. } => {
            walk_query(subquery, col, false, depth + 1);
        }
        TableFactor::TableFunction { expr, .. } => {
            walk_expr(expr, col, depth + 1);
        }
        TableFactor::Function { name, args, .. } => {
            let _ = name;
            for arg in args {
                walk_function_arg(arg, col, depth + 1);
            }
        }
        TableFactor::UNNEST { array_exprs, .. } => {
            for e in array_exprs {
                walk_expr(e, col, depth + 1);
            }
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            walk_table_with_joins(table_with_joins, col, depth + 1, false);
        }
        _ => {}
    }
}

fn walk_function(func: &sqlparser::ast::Function, col: &mut Collector, depth: usize) {
    use sqlparser::ast::FunctionArguments as Args;
    match &func.args {
        Args::None => {}
        Args::Subquery(q) => {
            walk_query(q, col, false, depth);
        }
        Args::List(list) => {
            for arg in &list.args {
                walk_function_arg(arg, col, depth);
            }
        }
    }
}

fn walk_function_arg(arg: &FunctionArg, col: &mut Collector, depth: usize) {
    match arg {
        FunctionArg::Unnamed(FunctionArgExpr::Expr(e))
        | FunctionArg::Named {
            arg: FunctionArgExpr::Expr(e),
            ..
        } => {
            walk_expr(e, col, depth);
        }
        _ => {}
    }
}

fn walk_returning(items: Option<&[SelectItem]>, col: &mut Collector, depth: usize) {
    if let Some(items) = items {
        if !items.is_empty() {
            col.has_returning = true;
        }
        for item in items {
            walk_select_item(item, col, depth);
        }
    }
}

fn walk_order_expr(e: &sqlparser::ast::OrderByExpr, col: &mut Collector, depth: usize) {
    walk_expr(&e.expr, col, depth);
}

fn walk_limit_clause(clause: &LimitClause, col: &mut Collector, _depth: usize) {
    let exprs: Vec<&Expr> = match clause {
        LimitClause::LimitOffset { limit: Some(e), .. } => vec![e],
        LimitClause::LimitOffset { limit: None, .. } => Vec::new(),
        LimitClause::OffsetCommaLimit { limit, .. } => vec![limit],
    };
    for e in exprs {
        set_limit(limit_of(e), col);
    }
}

/// First limit wins; the walker visits outer clauses before inner ones.
fn set_limit(value: Option<LimitValue>, col: &mut Collector) {
    if col.limit.is_none() {
        col.limit = value;
    }
}

fn limit_of(e: &Expr) -> Option<LimitValue> {
    match e {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse::<u64>().ok().map(LimitValue::Literal),
            Value::Placeholder(_) => Some(LimitValue::Parameterized),
            _ => Some(LimitValue::Expression),
        },
        _ => Some(LimitValue::Expression),
    }
}

// ---------------------------------------------------------------------------
// Expression walker. Records identifiers/compound identifiers as columns and
// descends into every query-bearing position. Exotic shapes contribute
// nothing rather than wrong facts.
// ---------------------------------------------------------------------------

fn walk_expr(e: &Expr, col: &mut Collector, depth: usize) {
    if !col.note_depth(depth) {
        return;
    }
    let next = depth + 1;
    match e {
        Expr::Identifier(id) => {
            col.columns.insert(ColumnRef {
                qualifier: Vec::new(),
                name: ColumnName::Name(ident_of(id)),
            });
        }
        Expr::CompoundIdentifier(parts) => {
            let name = ObjectName(
                parts
                    .iter()
                    .map(|id| sqlparser::ast::ObjectNamePart::Identifier(id.clone()))
                    .collect(),
            );
            if let Some(c) = column_ref_of(&name) {
                col.columns.insert(c);
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            walk_expr(left, col, next);
            walk_expr(right, col, next);
        }
        Expr::UnaryOp { expr, .. } => walk_expr(expr, col, next),
        Expr::Cast { expr, .. } => walk_expr(expr, col, next),
        Expr::Nested(e) => walk_expr(e, col, next),
        Expr::IsNull(e)
        | Expr::IsNotNull(e)
        | Expr::IsFalse(e)
        | Expr::IsNotFalse(e)
        | Expr::IsTrue(e)
        | Expr::IsNotTrue(e)
        | Expr::IsUnknown(e)
        | Expr::IsNotUnknown(e) => walk_expr(e, col, next),
        Expr::IsJson { expr, .. } | Expr::IsNormalized { expr, .. } => {
            walk_expr(expr, col, next);
        }
        Expr::IsDistinctFrom(e1, e2) | Expr::IsNotDistinctFrom(e1, e2) => {
            walk_expr(e1, col, next);
            walk_expr(e2, col, next);
        }
        Expr::InList { expr, list, .. } => {
            walk_expr(expr, col, next);
            for e in list {
                walk_expr(e, col, next);
            }
        }
        Expr::InSubquery { expr, subquery, .. } => {
            walk_expr(expr, col, next);
            walk_query(subquery, col, false, next);
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            walk_expr(expr, col, next);
            walk_expr(low, col, next);
            walk_expr(high, col, next);
        }
        Expr::Like { expr, pattern, .. }
        | Expr::ILike { expr, pattern, .. }
        | Expr::RLike { expr, pattern, .. }
        | Expr::SimilarTo { expr, pattern, .. } => {
            walk_expr(expr, col, next);
            walk_expr(pattern, col, next);
        }
        Expr::InUnnest {
            expr, array_expr, ..
        } => {
            walk_expr(expr, col, next);
            walk_expr(array_expr, col, next);
        }
        Expr::MatchAgainst { columns, .. } => {
            for name in columns {
                if let Some(c) = column_ref_of(name) {
                    col.columns.insert(c);
                }
            }
        }
        Expr::Subquery(q) => {
            walk_query(q, col, false, next);
        }
        Expr::Exists { subquery, .. } => {
            walk_query(subquery, col, false, next);
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(e) = operand {
                walk_expr(e, col, next);
            }
            for when in conditions {
                walk_expr(&when.condition, col, next);
                walk_expr(&when.result, col, next);
            }
            if let Some(e) = else_result {
                walk_expr(e, col, next);
            }
        }
        Expr::Tuple(exprs) => {
            for e in exprs {
                walk_expr(e, col, next);
            }
        }
        Expr::Function(f) => walk_function(f, col, next),
        Expr::AnyOp { left, .. } | Expr::AllOp { left, .. } => {
            walk_expr(left, col, next);
        }
        Expr::Trim { expr, .. } => walk_expr(expr, col, next),
        Expr::Substring { expr, .. } => walk_expr(expr, col, next),
        Expr::Collate { expr, .. } => walk_expr(expr, col, next),
        Expr::Extract { expr, .. } => walk_expr(expr, col, next),
        Expr::Ceil { expr, .. } | Expr::Floor { expr, .. } => walk_expr(expr, col, next),
        Expr::AtTimeZone {
            timestamp,
            time_zone,
            ..
        } => {
            walk_expr(timestamp, col, next);
            walk_expr(time_zone, col, next);
        }
        Expr::Position { expr, r#in, .. } => {
            walk_expr(expr, col, next);
            walk_expr(r#in, col, next);
        }
        Expr::Overlay {
            expr,
            overlay_what,
            overlay_from,
            overlay_for,
            ..
        } => {
            walk_expr(expr, col, next);
            walk_expr(overlay_what, col, next);
            walk_expr(overlay_from, col, next);
            if let Some(e) = overlay_for {
                walk_expr(e, col, next);
            }
        }
        Expr::Convert { expr, .. } => walk_expr(expr, col, next),
        Expr::Prefixed { value, .. } => walk_expr(value, col, next),
        Expr::Named { expr, .. } => walk_expr(expr, col, next),
        Expr::CompoundFieldAccess { root, .. } => walk_expr(root, col, next),
        // JsonAccess paths are JSONPath programs, not SQL: only the base
        // value can carry column references.
        Expr::JsonAccess { value, .. } => {
            walk_expr(value, col, next);
        }
        _ => {}
    }
}
