//! Frozen MCP text formatting: `formatQuery` markdown shape,
//! tables/describe/schema overviews, explain wrapper, `Blocked:` and
//! pending-approval templates. Byte-level compatibility surface —
//! replicate, never redesign.

use qk_db::{BudgetedResult, DbValue, TableInfo};

/// `formatQuery`: planner-estimate line, `Showing N rows.`, markdown
/// table (`NULL` renders empty, like `String(value)`), byte/token
/// footers, optional avoided/cursor/affected lines.
pub fn format_query(result: &BudgetedResult) -> String {
    let mut lines = Vec::new();
    if let Some(matched) = result.estimated_rows_matched {
        lines.push(format!("Query matched ~{matched} rows (planner estimate)."));
    }
    lines.push(format!("Showing {} rows.", result.rows_shown));
    if !result.columns.is_empty() {
        lines.push(String::new());
        lines.push(format!("| {} |", result.columns.join(" | ")));
        lines.push(format!(
            "| {} |",
            result
                .columns
                .iter()
                .map(|_| "---")
                .collect::<Vec<_>>()
                .join(" | ")
        ));
        for row in &result.rows {
            lines.push(format!(
                "| {} |",
                row.iter().map(cell_text).collect::<Vec<_>>().join(" | ")
            ));
        }
    }
    lines.push(String::new());
    lines.push(format!(
        "Returned to agent: {} bytes",
        result.bytes_returned
    ));
    lines.push(format!(
        "Estimated tokens returned: ~{}",
        result.estimated_tokens_returned
    ));
    if let Some(avoided) = result.estimated_tokens_avoided {
        lines.push(format!("Estimated context avoided: ~{avoided} tokens"));
    }
    if let Some(cursor) = result.cursor.as_deref() {
        lines.push(format!("Use cursor: {cursor} for the next page."));
    }
    if let Some(affected) = result.rows_affected {
        lines.push(format!("Rows affected: {affected}"));
    }
    lines.join("\n")
}

/// Frozen cell rendering (`value == null ? '' : String(value)`).
fn cell_text(value: &DbValue) -> String {
    match value {
        DbValue::Null => String::new(),
        DbValue::Bool(value) => value.to_string(),
        DbValue::Int(value) => value.to_string(),
        DbValue::UInt(value) => value.to_string(),
        // Rust `{}` matches JS `String(number)` for finite values
        // (`1.0` renders `1` in both).
        DbValue::Float(value) => format!("{value}"),
        DbValue::Decimal(text)
        | DbValue::Text(text)
        | DbValue::DateTime(text)
        | DbValue::JsonText(text) => text.clone(),
        DbValue::Bytes(bytes) => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(bytes)
        }
        DbValue::Json(value) => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// `formatTables`: `schema.name  kind` lines, frozen truncation note.
pub fn format_tables(tables: &[qk_db::TableRef], truncated: bool) -> String {
    if tables.is_empty() {
        return "No tables.".to_owned();
    }
    let mut lines: Vec<String> = tables
        .iter()
        .map(|table| {
            let name = match table.schema.as_deref() {
                Some(schema) => format!("{schema}.{}", table.name),
                None => table.name.clone(),
            };
            let kind = match table.kind {
                qk_db::TableKind::Table => "table",
                qk_db::TableKind::View => "view",
            };
            format!("{name}  {kind}")
        })
        .collect();
    if truncated {
        lines.push("… truncated. Pass a smaller schema or higher limit.".to_owned());
    }
    lines.join("\n")
}

/// `formatTable`: name, pk, columns, indexes, fks.
pub fn format_table(def: &TableInfo) -> String {
    let name = match def.schema.as_deref() {
        Some(schema) => format!("{schema}.{}", def.name),
        None => def.name.clone(),
    };
    let mut lines = vec![
        name,
        format!("pk: {}", def.primary_key.join(", ").if_empty("—")),
        "columns:".to_owned(),
    ];
    for col in &def.columns {
        let nulls = if col.nullable { "null" } else { "not null" };
        let default = col
            .default
            .as_deref()
            .map_or(String::new(), |def| format!(" default {def}"));
        lines.push(format!("  {} {} {nulls}{default}", col.name, col.data_type));
    }
    if !def.indexes.is_empty() {
        lines.push("indexes:".to_owned());
        for index in &def.indexes {
            let uniq = if index.unique { " unique" } else { "" };
            lines.push(format!(
                "  {} ({}){uniq}",
                index.name,
                index.columns.join(", ")
            ));
        }
    }
    if !def.foreign_keys.is_empty() {
        lines.push("fks:".to_owned());
        for fk in &def.foreign_keys {
            let target = match fk.referenced_schema.as_deref() {
                Some(schema) => format!("{schema}.{}", fk.referenced_table),
                None => fk.referenced_table.clone(),
            };
            lines.push(format!(
                "  {} {} -> {}({})",
                fk.name,
                fk.columns.join(", "),
                target,
                fk.referenced_columns.join(", ")
            ));
        }
    }
    lines.join("\n")
}

/// `formatSchemaOverview`: `name: cols` lines, frozen truncation note.
pub fn format_schema_overview(tables: &[TableInfo], truncated: bool) -> String {
    if tables.is_empty() {
        return "No tables.".to_owned();
    }
    let mut lines: Vec<String> = tables
        .iter()
        .map(|def| {
            let name = match def.schema.as_deref() {
                Some(schema) => format!("{schema}.{}", def.name),
                None => def.name.clone(),
            };
            let cols = def
                .columns
                .iter()
                .map(|col| col.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{name}: {cols}")
        })
        .collect();
    if truncated {
        lines.push("… truncated. Narrow schema or raise limit.".to_owned());
    }
    lines.join("\n")
}

/// `formatExplain` wrapper (estimated plan, not measured runtime).
pub fn format_explain(raw: &str) -> String {
    format!("Estimated plan (not measured runtime):\n{raw}")
}

/// Frozen denial/pending prefix (`Blocked:`, exact capital + colon).
pub fn format_blocked(message: &str) -> String {
    format!("Blocked: {message}")
}

/// Frozen pending-approval template, byte-for-byte.
pub fn format_pending_approval(approval_id: &str) -> String {
    [
        format!("Blocked: waiting for approval {approval_id}."),
        "Ask the user to approve or deny, then call:".to_owned(),
        format!("  approvals_decide(\"{approval_id}\", \"approved\")   # or \"denied\""),
        format!("Then retry db_query with the same SQL and approvalId=\"{approval_id}\"."),
    ]
    .join("\n")
}

/// `parseTableRef`: explicit `schema` wins, else split on FIRST dot.
pub fn parse_table_ref(table: &str, schema: Option<&str>) -> (Option<String>, String) {
    if let Some(schema) = schema {
        return (Some(schema.to_owned()), table.to_owned());
    }
    match table.find('.') {
        None => (None, table.to_owned()),
        Some(dot) => (Some(table[..dot].to_owned()), table[dot + 1..].to_owned()),
    }
}

trait IfEmpty {
    fn if_empty(self, fallback: &str) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.to_owned()
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_pending_template() {
        assert_eq!(
            format_pending_approval("qka_4e40db0b"),
            "Blocked: waiting for approval qka_4e40db0b.\n\
             Ask the user to approve or deny, then call:\n\
             \x20 approvals_decide(\"qka_4e40db0b\", \"approved\")   # or \"denied\"\n\
             Then retry db_query with the same SQL and approvalId=\"qka_4e40db0b\"."
        );
    }

    #[test]
    fn frozen_query_shape() {
        let result = BudgetedResult {
            columns: vec!["id".to_owned(), "name".to_owned()],
            rows: vec![
                vec![DbValue::Int(1), DbValue::Text("ann".to_owned())],
                vec![DbValue::Null, DbValue::Text("x".to_owned())],
            ],
            rows_affected: None,
            rows_shown: 2,
            estimated_rows_matched: Some(7),
            truncated: true,
            bytes_returned: 42,
            estimated_tokens_returned: 11,
            estimated_tokens_avoided: Some(100),
            cursor: Some("qk_cur_abc".to_owned()),
        };
        assert_eq!(
            format_query(&result),
            "Query matched ~7 rows (planner estimate).\n\
             Showing 2 rows.\n\
             \n\
             | id | name |\n\
             | --- | --- |\n\
             | 1 | ann |\n\
             |  | x |\n\
             \n\
             Returned to agent: 42 bytes\n\
             Estimated tokens returned: ~11\n\
             Estimated context avoided: ~100 tokens\n\
             Use cursor: qk_cur_abc for the next page."
        );
    }

    #[test]
    fn frozen_table_shapes() {
        assert_eq!(format_tables(&[], false), "No tables.");
        assert_eq!(format_schema_overview(&[], false), "No tables.");
        let (schema, name) = parse_table_ref("public.users", None);
        assert_eq!(
            (schema.as_deref(), name.as_str()),
            (Some("public"), "users")
        );
        assert_eq!(
            parse_table_ref("users", Some("s")),
            (Some("s".to_owned()), "users".to_owned())
        );
        // First dot wins.
        assert_eq!(
            parse_table_ref("a.b.c", None),
            (Some("a".to_owned()), "b.c".to_owned())
        );
    }
}
