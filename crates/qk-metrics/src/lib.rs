//! Zero-dependency Prometheus exposition over a QueryKnight-owned
//! registry: counters and one histogram family, incremented from typed
//! observations. Frozen names, labels, buckets, and rendering live
//! here (`docs/metrics.md`).
//!
//! Thread-safe (interior `Mutex`, no globals, no unsafe):
//! concurrent increments from daemon/MCP/proxy workers are safe.
//! Process-lifetime with no reset; tests use isolated registries.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Frozen evaluation-duration buckets, in seconds.
pub const DURATION_BUCKETS: &[f64] = &[0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0];

/// Frozen metric names.
pub const REQUESTS_TOTAL: &str = "queryknight_requests_total";
/// Frozen metric names.
pub const DECISIONS_TOTAL: &str = "queryknight_decisions_total";
/// Frozen metric names.
pub const POLICY_DENIALS_TOTAL: &str = "queryknight_policy_denials_total";
/// Frozen metric names.
pub const PARSE_ERRORS_TOTAL: &str = "queryknight_parse_errors_total";
/// Frozen metric names.
pub const APPROVAL_REQUESTS_TOTAL: &str = "queryknight_approval_requests_total";
/// Frozen metric names.
pub const EVALUATION_DURATION_SECONDS: &str = "queryknight_evaluation_duration_seconds";

#[derive(Debug, Default)]
struct Histogram {
    bounds: Vec<f64>,
    counts: Vec<u64>,
    sum: f64,
    total: u64,
}

impl Histogram {
    fn new(bounds: &[f64]) -> Self {
        Self {
            bounds: bounds.to_vec(),
            counts: vec![0; bounds.len() + 1],
            sum: 0.0,
            total: 0,
        }
    }

    fn observe(&mut self, value: f64) {
        self.sum += value;
        self.total += 1;
        let index = self
            .bounds
            .iter()
            .position(|bound| value <= *bound)
            .unwrap_or(self.counts.len() - 1);
        self.counts[index] += 1;
    }
}

/// QueryKnight-owned metrics registry (isolated instances; no globals).
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    counters: Mutex<BTreeMap<String, BTreeMap<String, u64>>>,
    histograms: Mutex<BTreeMap<String, Histogram>>,
}

impl MetricsRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment a counter series by `value` (default 1). Labels are
    /// `(name, value)` pairs; keys render sorted (deterministic).
    pub fn counter(&self, name: &str, labels: &[(&str, &str)], value: u64) {
        let key = label_key(labels);
        self.counters
            .lock()
            .expect("metrics lock")
            .entry(name.to_owned())
            .or_default()
            .entry(key)
            .and_modify(|count| *count += value)
            .or_insert(value);
    }

    /// Observe a histogram sample (seconds) with explicit bounds.
    pub fn histogram(&self, name: &str, value: f64, bounds: &[f64]) {
        self.histograms
            .lock()
            .expect("metrics lock")
            .entry(name.to_owned())
            .or_insert_with(|| Histogram::new(bounds))
            .observe(value);
    }

    /// Observe with the frozen duration buckets.
    pub fn observe_duration_seconds(&self, name: &str, value: f64) {
        self.histogram(name, value, DURATION_BUCKETS);
    }

    /// Render Prometheus text exposition (frozen shape: `# TYPE`
    /// lines, samples, cumulative buckets + `+Inf`, `_sum`, `_count`;
    /// no HELP lines). Empty registry renders `""`.
    pub fn render(&self) -> String {
        let mut lines = Vec::new();
        for (name, series) in self.counters.lock().expect("metrics lock").iter() {
            lines.push(format!("# TYPE {name} counter"));
            for (labels, value) in series {
                lines.push(format!("{name}{{{labels}}} {value}"));
            }
        }
        for (name, entry) in self.histograms.lock().expect("metrics lock").iter() {
            lines.push(format!("# TYPE {name} histogram"));
            let mut cumulative = 0u64;
            for (index, bound) in entry.bounds.iter().enumerate() {
                cumulative += entry.counts[index];
                lines.push(format!("{name}_bucket{{le=\"{bound}\"}} {cumulative}"));
            }
            cumulative += entry.counts[entry.counts.len() - 1];
            lines.push(format!("{name}_bucket{{le=\"+Inf\"}} {cumulative}"));
            lines.push(format!("{}_sum {}", name, entry.sum));
            lines.push(format!("{}_count {}", name, entry.total));
        }
        if lines.is_empty() {
            String::new()
        } else {
            lines.join("\n") + "\n"
        }
    }
}

/// Frozen label encoding: keys sorted, `\` and `"` escaped (newline
/// is NOT escaped — frozen reference behavior).
pub fn label_key(labels: &[(&str, &str)]) -> String {
    let mut sorted: Vec<(&str, &str)> = labels.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .iter()
        .map(|(key, value)| {
            format!(
                "{key}=\"{}\"",
                value.replace('\\', "\\\\").replace('"', "\\\"")
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_rendering() {
        let registry = MetricsRegistry::new();
        assert_eq!(registry.render(), "");
        registry.counter("queryknight_requests_total", &[("b", "2"), ("a", "1")], 1);
        registry.counter("queryknight_requests_total", &[("a", "1"), ("b", "2")], 2);
        registry.histogram(
            "queryknight_evaluation_duration_seconds",
            0.007,
            DURATION_BUCKETS,
        );
        registry.histogram(
            "queryknight_evaluation_duration_seconds",
            7.0,
            DURATION_BUCKETS,
        );
        assert_eq!(
            registry.render(),
            "# TYPE queryknight_requests_total counter\n\
             queryknight_requests_total{a=\"1\",b=\"2\"} 3\n\
             # TYPE queryknight_evaluation_duration_seconds histogram\n\
             queryknight_evaluation_duration_seconds_bucket{le=\"0.005\"} 0\n\
             queryknight_evaluation_duration_seconds_bucket{le=\"0.01\"} 1\n\
             queryknight_evaluation_duration_seconds_bucket{le=\"0.05\"} 1\n\
             queryknight_evaluation_duration_seconds_bucket{le=\"0.1\"} 1\n\
             queryknight_evaluation_duration_seconds_bucket{le=\"0.5\"} 1\n\
             queryknight_evaluation_duration_seconds_bucket{le=\"1\"} 1\n\
             queryknight_evaluation_duration_seconds_bucket{le=\"5\"} 1\n\
             queryknight_evaluation_duration_seconds_bucket{le=\"+Inf\"} 2\n\
             queryknight_evaluation_duration_seconds_sum 7.007\n\
             queryknight_evaluation_duration_seconds_count 2\n"
        );
    }

    #[test]
    fn frozen_buckets_and_escaping() {
        assert_eq!(DURATION_BUCKETS, &[0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]);
        assert_eq!(
            label_key(&[("q", "a\"b\\c"), ("a", "x")]),
            "a=\"x\",q=\"a\\\"b\\\\c\""
        );
    }

    #[test]
    fn concurrent_increments() {
        let registry = std::sync::Arc::new(MetricsRegistry::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let registry = registry.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    registry.counter("c", &[("t", "x")], 1);
                    registry.observe_duration_seconds("h", 0.001);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread");
        }
        let text = registry.render();
        assert!(text.contains("c{t=\"x\"} 800"));
        assert!(text.contains("h_count 800"));
    }
}
