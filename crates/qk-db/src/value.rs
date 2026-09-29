//! QueryKnight-owned result values. Drivers convert into [`DbValue`]
//! inside adapter internals; nothing driver-specific escapes.
//! Externally visible JSON rules are in `docs/database-execution.md`.

use serde::ser::{Serialize, Serializer};

/// Largest integer exactly representable as JSON/f64 (JavaScript safe
/// range). Larger magnitudes serialize as strings, never via f64.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// A single normalized database value.
#[derive(Debug, Clone, PartialEq)]
pub enum DbValue {
    /// SQL NULL.
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed integer (fits or is stringified on output).
    Int(i64),
    /// Unsigned integer (fits or is stringified on output).
    UInt(u64),
    /// Binary float (finite or null on output).
    Float(f64),
    /// Exact decimal/numeric text (precision preserved, never float).
    Decimal(String),
    /// Text.
    Text(String),
    /// Raw bytes (base64 on output).
    Bytes(Vec<u8>),
    /// Date/time/timestamp as ISO-8601 text (already formatted).
    DateTime(String),
    /// JSON/JSONB document: parsed value when valid, else raw text.
    Json(serde_json::Value),
    /// Raw JSON text that did not parse (preserved verbatim as string).
    JsonText(String),
}

impl DbValue {
    /// True for SQL NULL.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Approximate byte weight for budget accounting. Uses the same
    /// serialized form the output path emits, so budgets and bytes
    /// agree by construction.
    pub fn json_len(&self) -> usize {
        serde_json::to_string(self)
            .map(|text| text.len())
            .unwrap_or(4)
    }
}

fn int_fits(value: i64) -> bool {
    (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value)
}

impl Serialize for DbValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_none(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            // Never route 64-bit IDs through f64: out-of-range
            // magnitudes become strings (JS-safe compat).
            Self::Int(value) if int_fits(*value) => serializer.serialize_i64(*value),
            Self::Int(value) => serializer.serialize_str(&value.to_string()),
            Self::UInt(value) if *value <= MAX_SAFE_INTEGER as u64 => {
                serializer.serialize_u64(*value)
            }
            Self::UInt(value) => serializer.serialize_str(&value.to_string()),
            // JSON has no NaN/Infinity: match `JSON.stringify` (null).
            Self::Float(value) if value.is_finite() => serializer.serialize_f64(*value),
            Self::Float(_) => serializer.serialize_none(),
            Self::Decimal(text) => serializer.serialize_str(text),
            Self::Text(text) => serializer.serialize_str(text),
            Self::Bytes(bytes) => serializer.serialize_str(&base64_encode(bytes)),
            Self::DateTime(text) => serializer.serialize_str(text),
            Self::Json(value) => value.serialize(serializer),
            Self::JsonText(text) => serializer.serialize_str(text),
        }
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Build a JSON value from raw document text: parsed when valid (so
/// objects keep object shape), verbatim string otherwise.
pub fn json_value(raw: &str) -> DbValue {
    match serde_json::from_str(raw) {
        Ok(value) => DbValue::Json(value),
        Err(_) => DbValue::JsonText(raw.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(value: &DbValue) -> String {
        serde_json::to_string(value).expect("json")
    }

    #[test]
    fn normalization_shapes() {
        assert_eq!(json(&DbValue::Null), "null");
        assert_eq!(json(&DbValue::Bool(true)), "true");
        assert_eq!(json(&DbValue::Int(42)), "42");
        assert_eq!(json(&DbValue::UInt(42)), "42");
        // Outside JS-safe range: strings, never f64 approximations.
        assert_eq!(
            json(&DbValue::Int(9_007_199_254_740_992)),
            "\"9007199254740992\""
        );
        assert_eq!(json(&DbValue::Int(i64::MIN)), format!("\"{}\"", i64::MIN));
        assert_eq!(json(&DbValue::UInt(u64::MAX)), format!("\"{}\"", u64::MAX));
        // Boundary values stay numeric.
        assert_eq!(
            json(&DbValue::Int(9_007_199_254_740_991)),
            "9007199254740991"
        );
        assert_eq!(json(&DbValue::Float(1.5)), "1.5");
        assert_eq!(json(&DbValue::Float(f64::NAN)), "null");
        assert_eq!(json(&DbValue::Float(f64::INFINITY)), "null");
        assert_eq!(json(&DbValue::Decimal("19.99".to_owned())), "\"19.99\"");
        assert_eq!(
            json(&DbValue::Decimal("0.30000000000000004".to_owned())),
            "\"0.30000000000000004\""
        );
        assert_eq!(json(&DbValue::Bytes(vec![0, 1, 2])), "\"AAEC\"");
        assert_eq!(
            json(&DbValue::DateTime("2026-09-30T12:00:00Z".to_owned())),
            "\"2026-09-30T12:00:00Z\""
        );
        assert_eq!(json(&json_value("{\"a\":1}")), "{\"a\":1}");
        assert_eq!(json(&json_value("not json")), "\"not json\"");
    }
}
