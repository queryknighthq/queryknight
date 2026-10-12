# Rust migration plan (QueryKnight TS -> Rust)

Goal: same fixtures -> TS oracle + Rust port -> identical `{decision, reason_code}`. No Rust code in this phase.

**Status note:** This is the original implementation plan, not the current
release/support inventory. Several planned crate names and stages changed;
see [`README.md`](../README.md) and
[`release-security.md`](release-security.md) for current status.

## Workspace / crate layout

```
Cargo.toml (workspace, resolver 2)
crates/
  qk-core/        policy-file parse+validate, glob, analysis model, policy-engine, evaluate, approvals trait, audit, fingerprint, redact, cursors, budget, metrics, ocsf, health, paths
  qk-policy/      (optional split later: keep inside qk-core initially; split only if policy-file churn justifies it)
  qk-sql/         dialect analysis: sqlparser-rs wrappers per dialect + fallbackScan port + risk-signal catalog
  qk-daemon/      axum HTTP API + rusqlite store (WAL) + token auth + static UI serving
  qk-mcp/         rmcp-based stdio server, tool schemas mirroring zod bounds
  qk-proxy-mysql/ mysql_proxy-style TCP proxy (COM_QUERY/PREPARE/EXECUTE/CLOSE, template map)
  qk-proxy-pg/    pgwire-based proxy (Q + Parse/Bind/Execute/Sync)
  qk-adapters/    sqlx (mysql/postgres/sqlite) implementing a DatabaseAdapter trait; sqlite via rusqlite/sqlx-sqlite
  qk-cli/         clap CLI (all commands/flags/exit codes) + run confinement + snapshot/restore + init/detect
  qk-openshell/   supervisor-middleware logic (extract + inspect + reason codes) with tonic optional for gRPC transport
  qk-compat/      test-only harness: reads tests/compatibility/*.cases.json, calls qk-core, asserts (mirrors tools/reference-runner)
```

Start with 3 crates (`qk-core` incl. `qk-sql`, `qk-compat`, `qk-cli inspect/policy`) and split outgrowing modules only on second need.

## Chosen dependencies

- SQL: `sqlparser-rs` (multi-dialect: MySQL/PostgreSQL/SQLite) — replaces node-sql-parser. Risk: AST shape differs everywhere (see below).
- Policy YAML: `serde` + `serde_yaml` (validate with explicit structs + `deny_unknown_fields`).
- HTTP daemon: `axum` + `tower-http` (CORS), `tokio` runtime.
- SQLite: `rusqlite` (WAL, migrations) — daemon store.
- DB drivers: `sqlx` (mysql, postgres, sqlite features) for adapters.
- MCP: `rmcp` (Rust MCP SDK, stdio transport).
- CLI: `clap` v4, `dialoguer` (init wizard), `which`, `tokio::process`.
- Proxies: `tokio` + `bytes`; mysql packet handling hand-rolled or `mysql_proxy`-style crate; postgres via `pgwire`.
- gRPC (OpenShell): `tonic` + `prost` (proto vendored), optional until a consumer needs the socket.
- Metrics: hand-rolled registry (port the ~60-line class) or `prometheus` crate; hand-roll first to keep exposition byte-identical.
- Misc: `sha2`+`hex` (fingerprint), `regex` (fallback scan), `uuid`+`chrono` (events), `thiserror`, `tracing` (audit sink).

## TS module -> Rust crate mapping

| TS | Rust |
|---|---|
| core/policy-file.ts + context.ts | qk-core::policy (serde deny_unknown_fields; same error `path: message` strings) |
| core/analysis.ts + adapters/*/analyze.ts | qk-sql (dialect parse, statement detail, signals, fallbackScan) |
| core/policy-engine.ts | qk-core::engine (precedence order + matchers, verbatim) |
| core/evaluate.ts + approval-provider.ts | qk-core::evaluate (shared enforcement envelope/provider; legacy observe downgrade intentionally not ported) |
| core/approvals.ts + safety.ts | qk-core::approvals (status machine, poll->expired, session allows) |
| core/audit.ts + ocsf.ts + metrics.ts + health.ts | qk-core::audit/ocsf/metrics/health |
| core/fingerprint.ts + redact.ts + cursors.ts + budget.ts + diff.ts + query.ts | qk-core::infra (byte-identical algorithms) |
| core/history.ts + paths.ts + version.ts | qk-core::client/paths (Bearer, token file 0600) |
| daemon/app.ts + store.ts + index.ts | qk-daemon (routes/auth/schema/SPA fallback) |
| mcp/* | qk-mcp (8 tools + stdio server + daemon control-plane client) |
| proxies/* | qk-proxy-mysql / qk-proxy-postgres |
| adapters/* | qk-db (PostgreSQL/MySQL/SQLite adapters and guarded execution service) |
| integrations/openshell/* | qk-openshell (authenticated HTTPS middleware; explicit unauthenticated mode is local-only) |
| cli/* | qk-cli (commands, exit codes 0/1/2/3, demoPolicy, redacted logs) |
| apps/ui (Vue) | stays TypeScript (see below) |

## Migration sequence

1. `qk-sql` + `qk-core` policy/evaluate + `qk-compat` harness; gate: `tools/reference-runner` and `cargo test -p qk-compat` agree on all 63 executable fixtures.
2. Policy validation errors byte-compatible (`policy-validation` 10 cases) + `policy validate/test` in `qk-cli`.
3. `inspect --json` text/exit-code parity.
4. Audit/OCSF/metrics/health ports with golden JSON tests.
5. Daemon API + store (schema DDL identical; migration path for existing `queryknight.db` tolerant ADD COLUMNs) + UI serving (unchanged dist).
6. MCP server parity (schemas + pending template + history recording).
7. Adapters (sqlite first, then mysql/postgres against compose) + proxies.
8. OpenShell port + `queryknight_bad_config` + reason-code goldens.
9. CLI remainder (run confinement, snapshot/restore, init, doctor) + Docker (`cargo build --release` multi-stage) + CI matrix (TS fixtures + Rust harness + docker build).

## Compatibility risks

- Parser differences (HIGHEST): sqlparser-rs vs node-sql-parser ASTs differ in kind coverage, `hasWhere`/`hasLimit` representation, column/table extraction, CTE handling, and which statements fail. The `WITH ... DELETE ... RETURNING` corpus case currently pins a TS parse failure; Rust may parse it — then the verdict must still be deny-or-approval via nested-DML signals, never allow, and the corpus expectation needs an explicit dialect-note update (fixture change, not silent drift). Fuzz corpus (`analysis-fuzz.test.ts`) must be re-run to catalog divergences.
- Glob semantics: trivial (`*`->`.*`, case-insensitive, escape rest) but must pin the 10 glob cases byte-identical, incl. regex-char escaping.
- YAML: serde_yaml error strings differ; keep our own `path: message` validation layer so CLI output stays stable.
- Fingerprint/cursor/id formats: sha256/16hex, `qk_cur_*`, `qkc_<12hex>`, `qka_*` must match or cross-version session allows break.
- OpenShell `queryknight_*` reason-code operations must be char-exact (Unicode slicing). Legacy TypeScript `OBSERVED_*` strings are oracle-only and not a Rust port requirement.
- Timeout/poll cadence (50ms) and expiry races are timing-sensitive; test with injected clocks.
- SQLite schema: keep DDL column-for-column; rusqlite WAL behavior + tolerant migrations must open TS-created DBs.

## Parser differences (expected)

node-sql-parser `astify` multi-statement + per-dialect quirks have no 1:1 in sqlparser-rs (which is stricter/more capable). Expect: fewer parse failures in Rust (data-modifying CTEs, MERGE, CALL may parse) — each newly-parsed kind needs an explicit operation mapping + corpus expectation review under INV-003/INV-010 (stricter-only). LIMIT AST differs (LimitClause vs limit.value numerics) — port `limitValue` = first numeric literal. Comment/string stripping in `fallbackScan`/`normalizeSql` must be ported char-for-char (quoted `''`/`""`/backticks, `--`/`/* */`, number regex `\b\d+\b`).

## Persistence migration concerns

Existing `~/.queryknight/queryknight.db` must open read/write in Rust: identical table DDL, tolerant `PRAGMA table_info` migrations, WAL mode, 5000-event cap semantics, ms-epoch timestamps. `connections.json` (contains secrets) and `session.token` formats unchanged; file modes (0600 token) preserved. Snapshot files (mysqldump/pg_dump/sqlite copy naming) must remain restorable across versions.

## MCP compatibility risks

rmcp schema generation must reproduce zod bounds (sql 1..1M chars, params <=1000, maxRows/limit 1..200, defaults 50/20) and tool names/descriptions agents already prompt against. Pending-approval text template is agent-parsed — byte-identical. `destructiveHint`/`readOnlyHint` annotations preserved. History pseudo-SQL for schema tools (`SHOW TABLES`, `DESCRIBE`) preserved.

## OpenShell compatibility risks

Config keys (`policy_yaml`, `dialect`, `database`, `environment`, `approval_action`) + `queryknight_bad_config` + finding types + candidate caps (8/200k) + raw-lead keyword list + MCP/OpenAI extraction paths must match, or supervisor decisions diverge silently. gRPC enum (ALLOW=1/DENY=2) and proto field mapping stay 1:1; keep transport optional until a live gateway test exists.

## What stays TypeScript (Vue UI)

`apps/ui` remains Vue 3 + Vite. The daemon serves its `dist/` output unchanged; UI fetch paths, Bearer scheme, `qk_token` key, and approval JSON shapes are frozen by contract fixtures. Rust must satisfy the UI, not rewrite it.

## What will NOT be ported line-by-line

- node-sql-parser AST walk (`collectDeep`): reimplemented against sqlparser-rs AST with equivalent outputs, not equivalent code.
- Proxy byte-plumbing: reimplemented on tokio/pgwire; only the safety pipeline (classify template -> approve/deny -> pause/reject without corrupting state) is behaviorally pinned.
- TUI/dashboard rendering, init wizard prompts, help-box ASCII art: reimplemented to same commands/exit codes, not same bytes.
- HistoryClient internals: same HTTP contract, idiomatic reqwest retry/timeout behavior except where pinned (Bearer, paths, codes).
- Metrics/OCSF internals: same emitted names/shapes; storage internals free.

## Proposed first Rust commit

`qk-core` skeleton + policy-file validation + glob + `qk-compat` harness wiring: `cargo init` workspace with `crates/qk-core` (policy parse/validate with `deny_unknown_fields`, KNOWN_OPERATIONS/MUTATIONS allowlists, error `path: message` format) + `crates/qk-compat` JSON runner + vendored `tests/compatibility/` (already in repo) proving 10/10 `policy-validation` + 10/10 `glob-matching` green against fixtures before any SQL parsing exists. Parser deliberately excluded so the first diff is small and strictly pinned.
