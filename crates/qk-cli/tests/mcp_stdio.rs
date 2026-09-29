//! Real-process MCP stdio tests: spawn `queryknight mcp`, speak
//! JSON-RPC over pipes, and prove stdout is protocol-only. Uses a temp
//! SQLite user DB; no daemon (history-less execution + frozen
//! unavailable texts).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary");
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    path.join(format!("queryknight{}", std::env::consts::EXE_SUFFIX))
}

struct Session {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::io::Lines<BufReader<std::process::ChildStdout>>,
    next_id: u64,
}

impl Session {
    fn start(db_url: &str, home: &std::path::Path) -> Self {
        let mut child = Command::new(binary())
            .arg("mcp")
            .env("DATABASE_URL", db_url)
            .env("QUERYKNIGHT_ENV", "production")
            .env("QUERYKNIGHT_DATABASE", "main")
            .env("QUERYKNIGHT_HOME", home)
            .env_remove("MYSQL_URL")
            .env_remove("QUERYKNIGHT_POLICY_FILE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mcp");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        Session {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
            next_id: 1,
        }
    }

    fn send(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        writeln!(self.stdin, "{}", frame).expect("write");
        self.stdin.flush().expect("flush");
        self.recv()
    }

    fn notify(&mut self, method: &str) {
        let frame = serde_json::json!({"jsonrpc": "2.0", "method": method});
        writeln!(self.stdin, "{}", frame).expect("write");
        self.stdin.flush().expect("flush");
    }

    fn recv(&mut self) -> serde_json::Value {
        let line = self
            .lines
            .next()
            .expect("response line")
            .expect("read line");
        // INV-038: every stdout line is valid protocol JSON.
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("non-JSON stdout: {line}"))
    }

    fn call(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        self.send(
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        )
    }

    fn close(self) -> (bool, String) {
        drop(self.stdin);
        let output = self.child.wait_with_output().expect("wait");
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        (output.status.success(), stderr)
    }
}

fn temp_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "qk-mcp-stdio-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    dir
}

fn seed_db(home: &std::path::Path) -> String {
    let db = home.join("user.db");
    let conn = rusqlite::Connection::open(&db).expect("open");
    conn.execute_batch(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1, 'one');",
    )
    .expect("seed");
    format!("sqlite:{}", db.display())
}

#[test]
fn stdio_initialize_list_call_shutdown() {
    let home = temp_home("full");
    let url = seed_db(&home);
    let mut session = Session::start(&url, &home);
    // initialize → server identity (frozen name/version).
    let init = session.send(
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "queryknight");
    assert_eq!(init["result"]["serverInfo"]["version"], "0.1.0-beta.0");
    session.notify("notifications/initialized");
    // tools/list → the frozen eight.
    let list = session.send("tools/list", serde_json::json!({}));
    let mut names: Vec<String> = list["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|tool| tool.get("name")?.as_str().map(str::to_owned))
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "approvals_decide",
            "approvals_list",
            "db_describe",
            "db_explain",
            "db_query",
            "db_sample",
            "db_schema",
            "db_tables",
        ]
    );
    // tools/call db_query → markdown text result (single text block).
    let called = session.call("db_query", serde_json::json!({"sql": "SELECT * FROM t"}));
    let content = called["result"]["content"].as_array().expect("content");
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], "text");
    assert!(
        called["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("Showing 1 rows.")),
        "got: {called}"
    );
    assert!(called.get("error").is_none());
    // Unknown tool → protocol error (never Blocked: text).
    let unknown = session.call("nope", serde_json::json!({}));
    assert!(unknown.get("error").is_some(), "got: {unknown}");
    assert!(!unknown.to_string().contains("Blocked:"));
    // EOF → clean shutdown.
    let (ok, stderr) = session.close();
    assert!(ok, "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn mcp_requires_connection_url() {
    let home = temp_home("nourl");
    let output = Command::new(binary())
        .arg("mcp")
        .env("QUERYKNIGHT_HOME", &home)
        .env_remove("MYSQL_URL")
        .env_remove("DATABASE_URL")
        .output()
        .expect("run");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("set MYSQL_URL"));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn stdio_denied_and_pending_shapes() {
    let home = temp_home("shapes");
    let url = seed_db(&home);
    let mut session = Session::start(&url, &home);
    session.send(
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        }),
    );
    session.notify("notifications/initialized");
    // Denial is a text result starting with Blocked:.
    let denied = session.call("db_query", serde_json::json!({"sql": "DROP TABLE t"}));
    let text = denied["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(text.starts_with("Blocked: "), "got: {denied}");
    // Daemon-less approval flow degrades to the frozen unavailable text.
    let waiting = session.call(
        "db_query",
        serde_json::json!({"sql": "UPDATE t SET v = 'x' WHERE id = 1"}),
    );
    let text = waiting["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(text.starts_with("Blocked: "), "got: {waiting}");
    let list = session.call("approvals_list", serde_json::json!({}));
    assert_eq!(
        list["result"]["content"][0]["text"].as_str().expect("text"),
        "daemon unavailable; start queryknight"
    );
    let (ok, _) = session.close();
    assert!(ok);
    let _ = std::fs::remove_dir_all(&home);
}
