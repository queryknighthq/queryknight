# Changelog

Notable changes to QueryKnight. This project is an early technical preview; the
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
version is the single workspace product version.

## 0.1.0 - Unreleased

First public source preview. Nothing is tagged, released, or published as a
binary; the repository is licensed under Apache-2.0.

### Added

- **Deterministic policy engine** — versioned policy documents, frozen decision
  precedence, and fail-closed defaults for parse errors and unknown statements.
  `Allow` / `Deny` / `RequireApproval` with stable reason codes.
- **SQL analysis** for PostgreSQL, MySQL, and SQLite dialects, with a
  documented fallback classifier and its known divergences.
- **Approvals** — exact request binding with `ExactV2` identity over dialect,
  SQL, and ordered bound parameter values; `once` and session-shape scopes;
  legacy shape-only rows are quarantined and never authorize.
- **`ExecutionPermit` authorization plane** — a permit is minted only by
  `authorize_guarded` for the current request and is consumed by execution, so
  adapters and proxies can forward only what was already authorized.
- **PostgreSQL direct adapter** — explicit plaintext (`sslmode=disable`) or
  verified TLS (`sslmode=require`, pinned CA, hostname verification).
- **PostgreSQL wire proxy** — guarded Simple Query and Extended Query
  (Parse/Bind/Describe/Execute/Close/Flush/Sync) with per-connection statement
  and portal state, backend session continuity, and verified backend TLS.
- **MySQL wire proxy** — guarded `COM_QUERY` plus an audited prepared-statement
  subset with per-connection state.
- **MCP server** (stdio) exposing the tool surface, and a **daemon/control
  plane** with an embedded browser UI bundle.
- **OpenShell v0.1.2 integration** — authenticated HTTP/WebSocket middleware
  over HTTPS + extension JWT, live-verified against a real sandbox.
- **OpenShell network-gated PostgreSQL** — a real OpenShell sandbox reaches the
  QueryKnight proxy and is denied the database, with SQL enforcement and exact
  approvals proven against real backend state.
- **Observability** — query history, OCSF audit events, and Prometheus metrics,
  with sink failures that never change an authorization decision.

### Known limitations

- **Technical preview.** Not production-ready, not a drop-in PostgreSQL
  gateway, and not endorsed by or affiliated with NVIDIA/OpenShell.
- **The PostgreSQL proxy frontend hop is plaintext.** Frontend TLS is not
  implemented; only the QueryKnight → PostgreSQL hop is verified TLS.
- **The PostgreSQL proxy binds loopback only.** The OpenShell deployment
  currently needs operator-managed forwarding between the sandbox and the
  proxy; the test harness uses a test-only relay.
- **MySQL TLS is not implemented.**
- **Unsupported PostgreSQL operations fail closed**: COPY, FunctionCall,
  replication startup, CancelRequest forwarding, and SQL `SET`.
- **Approvals bind to a per-connection session**, so a retry after approval must
  reuse the connection.
- **OpenShell compatibility targets `v0.1.2` only** (commit
  `6648bd0c290efbc41ba131ee9831ee45cd431f94`); newer releases are added after
  live verification.
- **The live integration suites are validated on macOS / Apple Silicon.** Other
  platforms are unverified.
- **No release packaging.** No binary artifacts, container images, or crates.io
  publication exist yet.
