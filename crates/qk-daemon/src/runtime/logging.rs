//! Operational logging on `tracing` without new dependencies: a minimal
//! `Subscriber` that appends bounded, human-readable lines to
//! `daemon.log` (and mirrors to stderr in foreground mode).
//!
//! This is the operational log, not the QueryKnight audit log. Lifecycle
//! code never handles SQL, tokens, or provider secrets, so redaction here
//! means only ever emitting paths, ports, pids, and counters — enforced
//! by only logging fixed format strings at call sites.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::sync::Mutex;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber};

use super::error::{RuntimeError, RuntimeErrorKind};

/// Maximum single log line length; longer field text is truncated.
const MAX_LINE: usize = 2048;

/// Minimal subscriber: timestamp, level, target, and message/fields.
/// No spans, no ANSI, no JSON — `daemon.log` stays greppable.
pub struct OpLog {
    file: Mutex<std::io::BufWriter<File>>,
    stderr: bool,
    max_level: Level,
}

impl OpLog {
    fn emit(&self, meta: &Metadata<'_>, message: String) {
        if *meta.level() > self.max_level {
            return;
        }
        let level = match *meta.level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };
        let mut line = format!("{} {level} {}: ", unix_secs(), meta.target());
        line.push_str(&message);
        if line.len() > MAX_LINE {
            line.truncate(MAX_LINE);
            line.push_str("…[truncated]");
        }
        line.push('\n');
        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
        if self.stderr {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

struct MessageVisitor {
    text: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            write!(self.text, "{value:?}").ok();
        } else {
            write!(self.text, " {}={value:?}", field.name()).ok();
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.text.push_str(value);
        } else {
            write!(self.text, " {}={value}", field.name()).ok();
        }
    }
}

impl Subscriber for OpLog {
    fn enabled(&self, meta: &Metadata<'_>) -> bool {
        *meta.level() <= self.max_level
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = MessageVisitor {
            text: String::new(),
        };
        event.record(&mut visitor);
        self.emit(event.metadata(), visitor.text);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Initialize the operational log: open (creating) `daemon.log` in
/// append mode — the frozen append-forever semantics, no rotation — and
/// return the subscriber. The lifecycle layer installs it process-wide
/// (first call wins); unit tests scope it with `with_default` around
/// synchronous emits instead.
pub fn init_logging(
    log_path: &std::path::Path,
    mirror_stderr: bool,
) -> Result<OpLog, RuntimeError> {
    let max_level = match std::env::var("QUERYKNIGHT_LOG").as_deref() {
        Ok("debug") => Level::DEBUG,
        Ok("warn") => Level::WARN,
        Ok("error") => Level::ERROR,
        _ => Level::INFO,
    };
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|error| {
            RuntimeError::new(
                RuntimeErrorKind::Logging,
                format!("cannot open log file: {error}"),
            )
        })?;
    Ok(OpLog {
        file: Mutex::new(std::io::BufWriter::new(file)),
        stderr: mirror_stderr,
        max_level,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::dispatcher::Dispatch;

    #[test]
    fn appends_bounded_lines() {
        let path = std::env::temp_dir().join(format!("qk-runtime-log-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let log = init_logging(&path, false).expect("init");
        let dispatch = Dispatch::new(log);
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!("daemon starting");
            tracing::info!(port = 47821, "listening");
        });
        drop(dispatch);
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("daemon starting"));
        assert!(text.contains("port=47821"));
        assert!(text.contains("INFO"));
        // Append-forever: second init keeps the first lines.
        let log = init_logging(&path, false).expect("reinit");
        let dispatch = Dispatch::new(log);
        tracing::dispatcher::with_default(&dispatch, || tracing::warn!("again"));
        drop(dispatch);
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("daemon starting") && text.contains("again"));
        let _ = std::fs::remove_file(&path);
    }
}
