use qk_core::ExecutionParam;
use serde_json::Value;

const MAX_CANDIDATES: usize = 8;
const MAX_SQL_BYTES: usize = 200_000;
const MAX_JSON_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) sql: String,
    pub(crate) params: Vec<ExecutionParam>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtractError {
    TooManyCandidates,
    SqlTooLarge,
    UnsupportedParameters,
    TooDeep,
}

pub(crate) fn extract_candidates(text: &str) -> Result<Vec<Candidate>, ExtractError> {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        let mut candidates = Vec::new();
        visit(&value, 0, &mut candidates)?;
        return Ok(candidates);
    }
    if looks_like_raw_sql(text) {
        if text.len() > MAX_SQL_BYTES {
            return Err(ExtractError::SqlTooLarge);
        }
        return Ok(vec![Candidate {
            sql: text.to_owned(),
            params: Vec::new(),
        }]);
    }
    Ok(Vec::new())
}

fn visit(value: &Value, depth: usize, out: &mut Vec<Candidate>) -> Result<(), ExtractError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ExtractError::TooDeep);
    }
    match value {
        Value::Object(object) => {
            for key in ["sql", "query", "statement"] {
                if let Some(Value::String(sql)) = object.get(key) {
                    if object.contains_key("parameters") {
                        return Err(ExtractError::UnsupportedParameters);
                    }
                    let params = match object.get("params") {
                        None => Vec::new(),
                        Some(Value::Array(values)) => values
                            .iter()
                            .map(to_execution_param)
                            .collect::<Result<Vec<_>, _>>()?,
                        Some(_) => return Err(ExtractError::UnsupportedParameters),
                    };
                    push_candidate(sql.clone(), params, out)?;
                }
            }
            for (key, child) in object {
                if key == "arguments" {
                    if let Value::String(arguments) = child {
                        if let Ok(parsed) = serde_json::from_str::<Value>(arguments) {
                            visit(&parsed, depth + 1, out)?;
                            continue;
                        }
                    }
                }
                visit(child, depth + 1, out)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                visit(item, depth + 1, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn push_candidate(
    sql: String,
    params: Vec<ExecutionParam>,
    out: &mut Vec<Candidate>,
) -> Result<(), ExtractError> {
    if sql.len() > MAX_SQL_BYTES {
        return Err(ExtractError::SqlTooLarge);
    }
    if out.len() == MAX_CANDIDATES {
        return Err(ExtractError::TooManyCandidates);
    }
    out.push(Candidate { sql, params });
    Ok(())
}

fn to_execution_param(value: &Value) -> Result<ExecutionParam, ExtractError> {
    Ok(match value {
        Value::Null => ExecutionParam::Null,
        Value::Bool(value) => ExecutionParam::Bool(*value),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                ExecutionParam::Int(value)
            } else if let Some(value) = number.as_u64() {
                ExecutionParam::UInt(value)
            } else if let Some(value) = number.as_f64() {
                ExecutionParam::FloatBits(value.to_bits())
            } else {
                return Err(ExtractError::UnsupportedParameters);
            }
        }
        Value::String(value) => ExecutionParam::Text(value.clone()),
        Value::Array(_) | Value::Object(_) => {
            let encoded =
                serde_json::to_string(value).map_err(|_| ExtractError::UnsupportedParameters)?;
            ExecutionParam::Text(encoded)
        }
    })
}

fn looks_like_raw_sql(text: &str) -> bool {
    let mut rest = text.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("--") {
            rest = after
                .find('\n')
                .map_or("", |newline| &after[newline + 1..])
                .trim_start();
        } else if let Some(after) = rest.strip_prefix("/*") {
            let Some(end) = after.find("*/") else {
                return false;
            };
            rest = after[end + 2..].trim_start();
        } else {
            break;
        }
    }
    let word = rest
        .split(|character: char| !character.is_ascii_alphabetic())
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(
        word.as_str(),
        "SELECT"
            | "WITH"
            | "INSERT"
            | "UPDATE"
            | "DELETE"
            | "MERGE"
            | "CREATE"
            | "ALTER"
            | "DROP"
            | "TRUNCATE"
            | "GRANT"
            | "REVOKE"
            | "CALL"
            | "COPY"
            | "LOAD"
            | "SET"
            | "SHOW"
            | "DESCRIBE"
            | "EXPLAIN"
            | "USE"
            | "BEGIN"
            | "COMMIT"
            | "ROLLBACK"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_json_arguments_and_preserves_parameter_values() {
        let candidates = extract_candidates(
            r#"{"method":"tools/call","params":{"name":"db_query","arguments":{"query":"SELECT * FROM t WHERE id = $1","params":[42,"x",null]}}}"#,
        )
        .expect("extract");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sql, "SELECT * FROM t WHERE id = $1");
        assert_eq!(
            candidates[0].params,
            vec![
                ExecutionParam::Int(42),
                ExecutionParam::Text("x".to_owned()),
                ExecutionParam::Null
            ]
        );
    }

    #[test]
    fn rejects_candidate_truncation_and_parameter_shape_loss() {
        let oversized = format!("{{\"sql\":\"{}\"}}", "x".repeat(MAX_SQL_BYTES + 1));
        assert_eq!(
            extract_candidates(&oversized),
            Err(ExtractError::SqlTooLarge)
        );
        assert_eq!(
            extract_candidates(r#"{"sql":"SELECT 1","params":{"x":1}}"#),
            Err(ExtractError::UnsupportedParameters)
        );
    }
    #[test]
    fn candidate_limit_rejects_the_ninth_instead_of_truncating() {
        let eight = serde_json::Value::Array(
            (0..MAX_CANDIDATES)
                .map(|_| serde_json::json!({ "sql": "SELECT 1" }))
                .collect(),
        );
        assert_eq!(
            extract_candidates(&eight.to_string())
                .expect("eight candidates")
                .len(),
            MAX_CANDIDATES
        );
        let nine = serde_json::Value::Array(
            (0..=MAX_CANDIDATES)
                .map(|_| serde_json::json!({ "sql": "SELECT 1" }))
                .collect(),
        );
        assert_eq!(
            extract_candidates(&nine.to_string()),
            Err(ExtractError::TooManyCandidates)
        );
    }
    #[test]
    fn recognizes_raw_sql_after_comments_and_ignores_non_sql_json() {
        assert_eq!(
            extract_candidates("-- query\nSELECT 1").expect("extract")[0].sql,
            "-- query\nSELECT 1"
        );
        assert!(extract_candidates(r#"{"message":"not sql"}"#)
            .expect("extract")
            .is_empty());
    }
}
