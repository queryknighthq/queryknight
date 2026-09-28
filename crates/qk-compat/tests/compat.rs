//! Compatibility harness: runs `tests/compatibility/*.cases.json` against
//! qk-core. Commit 1 executes validation and glob fixtures; evaluation and
//! contract fixtures unlock with later commits (qk-sql, daemon, MCP).

use std::fs;
use std::path::PathBuf;

use qk_core::{glob_match, parse_policy};

fn compat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/compatibility")
}

fn load_cases(file: &str) -> Vec<serde_json::Value> {
    let text =
        fs::read_to_string(compat_dir().join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {file}: {e}"))
}

fn get<'a>(case: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    case.as_object().and_then(|m| m.get(key))
}

fn str_field(case: &serde_json::Value, key: &str) -> String {
    get(case, key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("case missing string field {key}: {case}"))
        .to_owned()
}

#[test]
fn policy_validation_fixtures() {
    let mut pass = 0u32;
    let mut cases = 0u32;
    for case in load_cases("policy-validation.cases.json") {
        if get(&case, "valid").is_none() {
            continue;
        }
        cases += 1;
        let name = str_field(&case, "name");
        let yaml = str_field(&case, "policy_yaml");
        let want_valid = get(&case, "valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match parse_policy(&yaml) {
            Ok(_) => {
                assert!(want_valid, "case '{name}' expected invalid, parsed valid");
                pass += 1;
            }
            Err(e) => {
                assert!(!want_valid, "case '{name}' expected valid, got: {e}");
                let text = e.to_string();
                if let Some(needle) = get(&case, "error_contains").and_then(|v| v.as_str()) {
                    assert!(
                        text.contains(needle),
                        "case '{name}': error '{text}' missing '{needle}'"
                    );
                }
                pass += 1;
            }
        }
    }
    assert_eq!(cases, 10, "expected 10 validation fixtures");
    assert_eq!(pass, cases, "all validation fixtures must pass");
}

#[test]
fn glob_matching_fixtures() {
    let mut pass = 0u32;
    let mut cases = 0u32;
    for case in load_cases("glob-matching.cases.json") {
        if get(&case, "pattern").is_none() {
            continue;
        }
        cases += 1;
        let name = str_field(&case, "name");
        let pattern = str_field(&case, "pattern");
        let value = str_field(&case, "value");
        let want = get(&case, "expected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let got = glob_match(&pattern, &value);
        assert_eq!(
            got, want,
            "case '{name}': glob_match({pattern:?}, {value:?})"
        );
        pass += 1;
    }
    assert_eq!(cases, 10, "expected 10 glob fixtures");
    assert_eq!(pass, cases, "all glob fixtures must pass");
}
