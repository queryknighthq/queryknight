# Guarded database execution (`qk-db`)

The final security choke point between agent SQL and real databases:
trusted connection + SQL request → QueryKnight evaluation → approval
resolution → explicit executable Allow → adapter → bounded normalized
result. MCP (next commit) will be a thin formatter over this service.
Audited TS behavior is in `docs/reference-implementation.md`
("Database execution audit"); this document is the Rust contract.

## Architecture

Single crate `qk-db` (adapters and service share the result model; a
second crate would be ceremony). Dependency direction:

```text
qk-core / qk-sql / qk-approval
              ↑
     qk-db service (guarded execution)
              ↓
adapters: postgres (tokio-postgres) · mysql (mysql_async) · sqlite (rusqlite)
```

`qk-core` never depends on drivers. The user-database SQLite adapter
never touches `qk-store`'s internal connection object (separate
`rusqlite::Connection` per operation).

## Choke point

```text
execute_guarded(request, auth)
  → evaluate() the EXACT sql that will run (cursor-resolved first)
  → Deny AnythingElseThanAllow ⇒ Blocked (adapter never constructed)
  → RequireApproval ⇒ resolve via qk-approval (store + provider)
  → still not executable ⇒ Blocked / PendingApproval (no DB contact)
  → ONLY explicit executable Allow ⇒ adapter.execute(exact sql, params)
```

`if decision != Deny { execute() }` is structurally impossible: the
execute path requires the positive executable state. DepthTruncated,
parse failures, unavailable/error providers, denied/expired approvals,
and mismatched approval tokens all terminate before any adapter call.

## Trusted derivation (INV-036)

- Dialect comes from the connection, never the request:
  `postgres(ql)://` → PostgreSql, `mysql://`/`mariadb://`/anything
  else → MySql (frozen `createAdapter` default!), `sqlite:` → Sqlite.
- The policy `ExecutionContext` (integration, environment, database
  key, session, tool) is built by the trusted caller from
  configuration, not from agent metadata. The agent supplies only
  SQL text, params, paging, and an optional approval id.

## Connections

- Config is a typed enum (`Postgres/Sqlite/Mysql` URL newtypes);
  required fields validated before connecting. Credentials live in
  the URL (env-provided, as in TS) and are redacted everywhere
  (`SecretUrl`: password → `***`; Display/Debug/errors/logging
  pinned by tests).
- Lifecycle: connect → operate → close per service call (matches the
  reference shape of short-lived adapter use; no pool). Consequence
  (frozen): no cross-request transaction affinity — `BEGIN` in one
  call never scopes the next. Autocommit is never changed silently.
- `test_connection` is connect + `SELECT 1`-class handshake +
  close; it never executes user SQL.
- The `connections` table stays metadata-only (no secrets); the
  service never reads `qk-store` directly. A typed record→config
  mapping is provided for later daemon wiring.

## Budgets (frozen numbers, exact semantics)

- `maxRows = 50`: page size AND preview cap. SELECTs without their
  own `LIMIT` are rewritten `… LIMIT (maxRows+1) OFFSET (offset)`
  (`withPage`; skipped when the text already matches `/\blimit\b/i`
  — frozen regex quirk); fetching `maxRows+1` rows detects the cap.
  `input.maxRows` is clamped into the budget (`min(input, 50)`).
- `maxBytes = 65536`: counts `Buffer.byteLength(JSON.stringify(row))`
  per row-array — i.e. serialized JSON bytes of the value arrays
  (not raw DB bytes, not pretty text).
- `maxEstimatedTokens = 8000`: `ceil(bytes / 4)` heuristic only
  (documented estimate, no tokenizer).
- Precedence: row cap checked first per row, then byte/token caps;
  the FIRST row is exempt from byte/token caps (always shows
  something); any cut sets `truncated: true` with rows kept so far.
  Cuts never drop silently — `truncated` + `rowsShown` always agree.
- Mutation statements bypass paging (`rowsAffected` instead).

## Cursors

In-memory server map (no persistence): id
`qk_cur_<12 base64url chars from 9 random bytes>`, TTL 10 min,
swept on access. Cursor re-resolves stored (sql, params, offset) and
the resolved SQL is EVALUATED again before execution. Unknown/expired
→ typed error; cross-connection use → typed error. Offsets are
validated `u64` (no negative/overflow). Sample queries never issue
cursors (re-randomization would mislead).

## EXPLAIN / impact

- Impact EXPLAIN (UPDATE/DELETE only, planner-only, never ANALYZE)
  runs AFTER evaluation returns non-Deny and only to enrich the
  approval reason (pg: max of `rows=` matches; mysql: max of the
  `rows` column; sqlite: none). The reference runs it pre-decision;
  Rust narrows this to non-denied evaluations (hardening: denied
  queries cause zero DB contact).
- `estimatedRowsMatched` for SELECTs comes from the same EXPLAIN
  regex (`/\brows[=:]?\s*(\d+)/i`) post-execution; `tokensAvoided =
  max(0, est(fullBytes) − returned)`. EXPLAIN failures degrade to
  `None`, never to authorization changes.
- Standalone explain is allow-only: Deny → blocked, RequireApproval
  → pending (plans leak schema names, so no pre-approval EXPLAIN).
  The reference `dbExplain` evaluates nothing — deliberate
  hardening per INV-035.

## Metadata trust boundary

`list_tables` / `describe_table` / `sample` take identifiers, never
SQL, so they cannot smuggle arbitrary statements past policy:

- Sample SQL is server-generated
  (`SELECT * FROM <quoted> ORDER BY RANDOM()/RAND() LIMIT n`,
  limit clamped to 200, default 20) and still EVALUATED; Allow runs
  it, RequireApproval pends, Deny blocks (the reference evaluates
  nothing here — hardening, same rationale as explain).
- Introspection reads (`information_schema`, `PRAGMA`,
  `sqlite_master`, `SHOW CREATE TABLE`) are fixed statements with
  quoted identifiers. They reveal schema names — equivalent to what
  approved queries reveal — and are available to the already-trusted
  local agent caller.
- `dump_schema`: sqlite/mysql implemented; postgres returns
  `Unsupported` (the reference shells to `pg_dump`; no subprocesses
  in the service — documented).

## Values (externally visible JSON)

Rows are positional arrays + `columns` metadata (duplicate column
names are PRESERVED positionally; the TS driver objects collapse
them last-wins — Rust keeps both, same array shape, documented):

| DB value | JSON |
|---|---|
| NULL | `null` |
| bool | bool |
| ints within ±2⁵³ | number |
| ints outside ±2⁵³ | **string** (JS-safe compat; never via f64) |
| float (finite) | number; non-finite → `null` (matches `JSON.stringify`) |
| DECIMAL/NUMERIC | **string** (text precision preserved) |
| text | string |
| bytea/blob | base64 **string** (TS emits Buffer-JSON; Rust uses an explicit encoding — documented) |
| date/time/timestamp | ISO-8601 **string** |
| JSON/JSONB | parsed value when valid, else raw string |

## Statements, params, transactions

- The executed SQL is byte-identical to the evaluated SQL (no
  rewrites except the frozen paging `LIMIT/OFFSET` append on
  limit-less SELECTs, which is part of the evaluated-executed form…
  see below).
- Multi-statement batches are REJECTED with a typed error (the
  reference sends them to the driver, where each driver partially
  copes; silent partial execution is a footgun — hardening).
- Params bind through the driver (never interpolated); `>1000`
  params is a typed error (frozen `MAX_QUERY_PARAMS`).
- No implicit transactions; user `BEGIN/COMMIT/ROLLBACK` evaluate
  and execute like any SQL (no cross-request affinity — see above).

Note on the paging rewrite: the `LIMIT maxRows+1 OFFSET n` form is
what executes AND what the fingerprint/approval binds — cursor pages
re-resolve the stored ORIGINAL sql plus the stored offset, then the
same deterministic rewrite applies. Approval tokens therefore cover
the logical (sql, offset) pair, not the rewritten text.

## Timeout

`QUERYKNIGHT_DB_TIMEOUT_MS`, default 30000, client-side race. Typed
`Timeout` error with the frozen warning semantics: the statement
**may still be running server-side** (documented on the error, never
"rolled back" unless transaction semantics prove it). Best-effort
`cancel_token` is attempted for postgres; nothing is claimed for
mysql/sqlite. No detached tasks outlive the request.

## Errors (QueryKnight-owned, redacted)

`Connection | Authentication | Timeout | Query | Constraint |
Unsupported | Protocol | Internal` + separate `Blocked` /
`PendingApproval` outcomes (never flattened into strings). Useful
bounded driver messages are preserved (truncated); credentials never
appear. A DB syntax error after authorization is a `Query` error,
never a policy parse error (syntax-vs-semantic boundary pinned by
test: `SELECT ... TYPO` allowed by policy executes and fails at the
DB).

## MCP mapping (no MCP in this commit)

| Tool | Execution-service operation |
|---|---|
| `db_query` | `execute_guarded` |
| `db_explain` | `explain_guarded` |
| `db_sample` | `sample_guarded` |
| `db_tables`, `db_describe`, `db_schema` | metadata ops (ungated identifiers) |
| `approvals_list`, `approvals_decide` | control-plane only (qk-daemon client) |
| cursor continuation | `execute_guarded` with `cursor` |

## Intentional divergences from TS

1. Impact/explain/sample paths evaluate first (TS: no/early DB
   contact); denied evaluations cause zero DB roundtrips.
2. Multi-statement batches rejected instead of driver-dependent
   partial execution.
3. Duplicate columns preserved positionally (TS collapses last-wins
   in driver objects).
4. `rowsAffected` reported for pg/mysql too (TS: sqlite only).
5. Binary → base64 string (TS: Buffer-JSON).
6. `dump_schema` postgres → `Unsupported` (TS: `pg_dump` subprocess).
7. Per-operation connections, no pooling (matches reference
   short-lived use; explicit).

## Live verification

Both ignored contract suites were executed against real servers
during development (not in CI): PostgreSQL 17 (value decoding incl.
NUMERIC precision, bigint, bytea, timestamptz, JSONB version-byte
strip, EXPLAIN estimates, introspection, guarded end-to-end) and
MySQL 8.4 (DECIMAL text, bigint, blob-vs-text via binary shapes,
DATETIME(6), JSON, `SHOW CREATE TABLE`, introspection). Live runs
caught and fixed: temporal `try_get` accepts-gating (raw-bytes
wrapper), a timestamp hour/modulo bug, JSONB version prefix, and
BLOB-vs-binary-collation detection.

## Approval-binding gap (hardening phase, traced 2026-09-30, fixed in-code)

Current Rust flow for `MCP db_query -> qk-db -> qk-approval ->
daemon provider -> qk-daemon/qk-store -> approvals_decide -> retry`:

1. `ExactRequestDigest` is created in `qk-approval::resolve` from
   `(dialect, sql)` ONLY (`exact_request_digest`, v1 domain
   `queryknight:approval-request:v1`). `ResolveRequest` has no
   params field, so `DELETE ... WHERE id = ?` + `[42]` and `+ [999]`
   share one digest.
2. It is persisted two places: local `ApprovalStore` rows
   (`exact_digest` 32-byte column, `binding_kind = exact_v1`) and
   NOT AT ALL in daemon rows (MCP-created rows are `shape_v1` with
   only the 16-hex shape fingerprint; the daemon create DTO has no
   digest/binding fields).
3. It disappears at three boundaries: (a) `qk-db` never forwards
   bound params to `resolve`; (b) the daemon API cannot store or
   return a digest; (c) the provider retry verdict is
   `id + approved + shape-fingerprint` only.
4. A changed literal reuses an approval ID because the provider
   returns `Approved` on shape match and `resolve` then mints a
   brand-new local `ExactV1` grant for the CURRENT sql — laundering
   a shape approval into exact authority (§17 pattern, now
   forbidden).
5. Retry is therefore authorized by daemon status + shape
   fingerprint, NOT by exact digest. Session vs Once differ only in
   daemon `scope` param and the `/allows` pre-check; neither binds
   params.
6. Fix: versioned digests (V1 SQL-only preserved, V2
   dialect+sql+params), digest + binding persisted through the
   daemon DTO, provider-side verify against the daemon row
   (internal `POST .../verify`, digest in body never URL/logs),
   scope comparison from new view fields, and resolve-side
   version-aware matching. Session scope remains intentionally
   shape-wide; Once becomes exact-request-strict (deliberate TS
   divergence, INV-041).
