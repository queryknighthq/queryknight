# QueryKnight Reference Implementation (TypeScript/Bun)

Source: `../queryknight-ts` (READ-ONLY oracle). Version `0.1.0-beta.0`.
Runtime: Bun workspaces (`apps/*`, `packages/*`, `packages/adapters/*`, `packages/proxies/*`, `packages/integrations/*`).
Measured: 218 tests across 39 files; 207 pass locally, 11 fail without live MySQL/Postgres (CI sets `QK_LIVE_DB=0` so they self-skip via `test.skipIf(!LIVE)`).

## 1. Repository architecture

```
packages/core/                  Policy, analysis, evaluation, audit, metrics, OCSF, approvals, query budget, cursors, history client, health, paths, redact, fingerprint, diff, safety (legacy env-preset gate)
packages/core/src/
  index.ts                      Re-exports everything (single import surface)
  types.ts                      Domain types: engines, envs, QueryClass/Risk/Decision, QueryEvent, ApprovalRequest, ResultBudget
  adapter.ts                    DatabaseAdapter + DatabaseCapabilities interface (engines implement; core never branches on engine)
  analysis.ts                   node-sql-parser based analyzer -> RichQueryAnalysis (THE parser oracle)
  classify.ts                   Legacy first-keyword classifier (read/write/ddl/destructive/privilege/unknown)
  policy-file.ts                Policy v1 YAML parse + strict validation + globMatch + defaultPolicy
  policy-engine.ts              evaluatePolicy: precedence + all rule matching
  evaluate.ts                   evaluate(): THE authorization entry point (size/empty checks, policy eval, observe mode, approval provider, audit sink)
  approval-provider.ts          ApprovalProvider, DenyByDefaultProvider, TestApprovalProvider
  approvals.ts                  ApprovalPort, ApprovalView, InMemoryApprovals, waitForApproval (poll 50ms until timeoutMs -> expired)
  safety.ts                     Legacy env-preset gate (decidePolicy) + enforcePolicy + runSafeQuery (used when QUERYKNIGHT_POLICY_FILE unset)
  policy.ts                     decidePolicy (legacy env presets) + approvalTimeoutMs
  context.ts                    AgentContext (trusted identity fields vs untrusted metadata)
  audit.ts                      AuditEvent + buildAuditEvent + SqlLogLevel
  ocsf.ts                       toOcsf (OCSF 1.5.0, API Activity 6003)
  metrics.ts                    MetricsRegistry + recordEvaluation + Prometheus exposition
  query.ts                      runQuery (single/multi statement, SELECT paging LIMIT/OFFSET, budget clip, cursor), assertSingleStatement, withPage
  budget.ts                     DEFAULT_BUDGET {maxRows 50, maxBytes 65536, maxEstimatedTokens 8000}, estimateTokens = ceil(bytes/4), clipRows
  cursors.ts                    Opaque cursor store (TTL 10min, bound to connectionKey), connectionKeyFromUrl (password-stripped), connectionIdFromKey (qkc_<12hex>), connectionIdCandidates
  fingerprint.ts                normalizeSql (literals->?, numbers->?, collapse ws, lowercase) + sqlFingerprint (sha256 hex slice 0,16)
  redact.ts                     redact(): replaces `//user:password@` with `//user:***@`
  history.ts                    HistoryClient (HTTP to daemon, Bearer token) implements ApprovalPort; SessionSummary
  health.ts                     checkHealth probes -> {status ok|degraded, checks[]}
  paths.ts                      queryknightHome (~/.queryknight or QUERYKNIGHT_HOME), daemonUrl, daemonPort (47821), session token (0600, 24 random bytes base64url)
  diff.ts                       unifiedDiff for schema before/after
  version.ts                    QUERYKNIGHT_VERSION = '0.1.0-beta.0'

packages/mcp/                    MCP stdio server (@modelcontextprotocol/server v2, zod/v4 schemas)
  engine.ts                     createAdapter(url): sqlite: -> SqliteAdapter, postgres: -> PostgresAdapter, else MysqlAdapter
  tools.ts                      db_tables/db_describe/db_schema/db_query/db_explain/db_sample/approvals_list/approvals_decide + withTimeout + formatPendingApproval
  policy-bridge.ts              getFilePolicy (QUERYKNIGHT_POLICY_FILE, cached by path, fail-fast on invalid), databaseKeyFor, DaemonApprovalProvider
  format.ts                     Compact text formatters (no raw information_schema dumps)
  index.ts                      createMcpServer, startMcpStdio, mcpInstructions

packages/daemon/                 Bun.serve on 127.0.0.1:47821 + Hono API; HistoryStore (bun:sqlite, WAL, ~/.queryknight/queryknight.db)
  index.ts                      Daemon boot, daemon.pid write, autostart proxy if QUERYKNIGHT_AUTOSTART_PROXY_URL, static UI serving
  app.ts                        createApi, Host/Origin localhost checks, CORS, auth, routes, redacted connections
  store.ts                      SQLite schema + session/event/approval CRUD + session_allows + tolerant migrations

packages/cli/                    Compiled binary entry (`bun build ... --compile --outfile queryknight`)
  index.ts                      Command dispatch: version/help/mcp/start/stop/status/sessions/session/approvals/approve/deny/backup-allow/init/connections/ui/web/proxy/run/snapshot/restore/snapshots/doctor/inspect/policy
  run.ts                        Proxy-confined child spawn (STRIP_RE credential vars, repoint non-loopback mysql:/postgres: URLs to proxy, DATABASE_URL override, .env warning)
  policy-cmd.ts                 inspect/policy validate/policy test (+ demoPolicy, baseContext defaults --env production --db main --integration cli)
  connections.ts                connections list|add|test|remove (connections.json)
  init.ts / detect.ts           Project init wizard, .env/DATABASE_URL detection, agent config writers (Claude, Cursor, Codex, OpenCode, Pi, OMP, Windsurf/Gemini/VS Code)
  agents.ts                     AgentConfigurator interface
  snapshot.ts                   snapshot/restore via mysqldump/pg_dump (sqlite file copy); snapshotsDir
  backup-allow.ts               Backup then approve flow
  doctor.ts                     Diagnostics
  ui.ts                         Terminal dashboard

packages/adapters/{mysql,postgres,sqlite}/
## PostgreSQL proxy audit (source-verified)

The exact TypeScript proxy behavior, limitations, frozen error framing, and
pre-implementation Rust protocol-state table are documented in
[`proxy-postgres.md`](proxy-postgres.md). In particular, the reference's
extended-protocol handling authorizes Parse rather than bound Execute values,
does not track transaction status, and relays GSS/COPY/FunctionCall/replication
without a request-bound authorization gate. The Rust proxy is a hardening
port, not a byte-for-byte reproduction of those unsafe paths.

The PostgreSQL Rust ingress uses `proxy_pg` as trusted integration identity,
one backend session per frontend, and a fresh `ExecutionPermit` before every
executable Q/Execute. It is not a generic proxy framework. The MySQL Rust
ingress is a separate classic-protocol COM_QUERY proxy; prepared execution is
deferred to a later reviewed commit, and OpenShell remains deferred.
## MySQL proxy audit (source-verified)

The TypeScript MySQL proxy's exact behavior, security gaps, and the hardened
Rust COM_QUERY protocol-state table are documented in [`proxy-mysql.md`](proxy-mysql.md).
MySQL has its own protocol crate and state machine; it does not share a generic
wire-proxy engine with PostgreSQL.
packages/integrations/openshell/  NVIDIA OpenShell supervisor-middleware (dependency-free, gRPC optional peer dep)
  inspector.ts                  parseInspectorConfig, baseContext, inspectHttpRequest/inspectWebSocketMessage, WaitingProvider (approvals always waiting), approvalAction deny|allow_with_findings, toReasonCode
  sql-extract.ts                SQL extraction: raw-SQL lead regex, MCP JSON-RPC tools/call, OpenAI tool_calls, generic sql/query/statement fields; caps 8 candidates / 200k chars; strips leading -- and /* */ comments
  service.ts                    Describe/ValidateConfig/EvaluateHttpRequest/EvaluateWebSocketSession + buildGrpcImplementation (Decision ALLOW=1/DENY=2, proto field 1:1) + serveGrpc wiring notes
  index.ts                      Re-exports

apps/ui/                        Vue 3 + Vite, built to apps/ui/dist, served by daemon for GET non-API paths (SPA fallback to index.html). NOT a query editor: Activity, Sessions, Connections, Approvals tabs. Poll-based refresh. Token from ?token= stored to localStorage qk_token, then Bearer header.
```

## 2. MCP tools and schemas

Server: `queryknight` v`QUERYKNIGHT_VERSION`, stdio via `serveStdio`. Instructions string steers agents to these tools over `mysql`/`psql`/`sqlite3`/`docker exec`/bash and defines the approval retry loop.

| Tool | Input schema | Semantics |
|---|---|---|
| `db_tables` | `{schema?: string, includeViews?: boolean, limit?: int 1..200 (default 50)}` | listTables, filter views unless includeViews, slice to limit, `formatTables`; history recorded as `SHOW TABLES` pseudo-SQL |
| `db_describe` | `{table: string (schema.table ok), schema?: string}` | describeTable -> columns/PK/indexes/FKs text; history as `DESCRIBE <name>` |
| `db_schema` | `{schema?: string, limit?: int 1..200 (default 50)}` | table+column names only, bounded; history as `SHOW TABLES -- schema` |
| `db_query` | `{sql: string 1..1_000_000 chars, params?: unknown[0..1000], maxRows?: int 1..200, cursor?: string, approvalId?: string}` `destructiveHint:true` | Policy-file mode if `QUERYKNIGHT_POLICY_FILE` set: `evaluate()` with `{integration:'mcp', environment: env-from-env, database: databaseKeyFor(connectionKey), tool:'db_query'}`, dialect = adapter.engine, DaemonApprovalProvider; deny -> `Blocked: <msg> [<code>]`; require_approval -> `formatPendingApproval` text; allow -> `runQuery` + history. Legacy mode: `runSafeQuery` + `forceConfirmDeletes:true, wait:false`; ApprovalPendingError -> same pending text; QueryDeniedError -> `Blocked: <msg>`. Timeout `QUERYKNIGHT_DB_TIMEOUT_MS` default 30000 races driver; timed-out statement may still run server-side. `>1000` params -> `Blocked: too many query parameters (max 1000)`. Cursor paging reuses stored SQL; evaluates the text that will run. |
| `db_explain` | `{sql: string, params?: unknown[]}` | Prefixes `EXPLAIN` unless present; `runExplain`; returns estimated plan text only |
| `db_sample` | `{table: string, schema?: string, limit?: int 1..200 (default 20, cap 200)}` | `adapter.sample` + `runSample` (ORDER BY RAND()/random); budgeted like query |
| `approvals_list` | `{}` | Waiting approvals `id risk operationSummary + reason + schemaDdl`; `daemon unavailable; start queryknight` when no history |
| `approvals_decide` | `{id: string (e.g. qka_4e40db0b), status: approved\|denied}` `destructiveHint:true` | `history.client.decide(id, status, 'mcp')` -> `approval <id>: <status>` |

Pending-approval text (exact contract, agents parse it):
```
Blocked: waiting for approval <id>.
Ask the user to approve or deny, then call:
  approvals_decide("<id>", "approved")   # or "denied"
Then retry db_query with the same SQL and approvalId="<id>".
```

## 3. CLI commands and flags

`queryknight <cmd>` (Bun binary). Value flags: `--dialect --policy --env --db --agent --integration --tool --listen --connection`.

| Command | Behavior |
|---|---|
| `version` / `--version` / `-v` | prints `QueryKnight 0.1.0-beta.0` |
| `help` / `--help` / `-h` | boxed help listing all commands |
| `mcp` | stdio server; needs `MYSQL_URL` or `DATABASE_URL`, else `set MYSQL_URL` exit 1 |
| `start` | spawn detached daemon (`packages/daemon/src/index.ts` via `process.execPath`), wait 20x50ms on `/status`, else dump last 15 daemon.log lines |
| `stop` | SIGTERM pid from `daemon.pid`, unlink pid file |
| `status` | `daemon up pid=<pid>` or `daemon down` exit 1 |
| `sessions` | `<id> <date> queries= reads= writes=` lines or `no sessions` |
| `session <id>` | `formatSessionSummary` |
| `approvals` | waiting `<id> <risk> <summary> <reason>` + schemaDdl blocks, or `no waiting approvals` |
| `approve <id> [session]` | decide approved, scope once|session -> `<id> <status> <scope>` |
| `deny <id>` | decide denied |
| `backup-allow <id>` | snapshot then approve (needs MYSQL/POSTGRES/DATABASE_URL) |
| `init` | wizard: detect URL, confirm env (never auto-labels production), backup/diff agent configs before write |
| `connections <list\|add\|test\|remove>` | manages `connections.json` |
| `ui` | terminal dashboard |
| `web` | requires daemon + token; builds UI if dist missing; `open http://127.0.0.1:47821/?token=<token>` |
| `proxy [--listen <port>]` | MySQL default 3308 / Postgres 5434 on 127.0.0.1; logs `proxy 127.0.0.1:<p> -> <redacted> (local plaintext)` |
| `run [--connection <id>] [--listen <port>] <binary> [args...]` | proxy-confined spawn (see §23) |
| `snapshot` / `restore --id <id>` / `snapshots` | mysqldump/pg_dump/sqlite copy under snapshotsDir; list `<path> <engine> <db> <size> <iso>` |
| `doctor` | diagnostics, exit code = result |
| `inspect [--dialect mysql] [--policy p.yaml] [--env production] [--db main] [--json] "<SQL>"` | `evaluate()` with demoPolicy default; text or JSON `{decision UPPER, reason_code, message, matched_policy, table, column, operation, risk_signals, fingerprint}`; exit 3 when decision != allow |
| `policy validate <policy.yaml>` | `policy <path>: valid (version 1, <n> database scope(s), <m> embedded test(s))`, exit 2 on invalid |
| `policy test <policy.yaml> [cases.yaml]` | runs embedded `tests:` or cases file; defaults `--dialect postgres --env production --db main`; `TestApprovalProvider(['waiting'])` so approval verdicts surface; `PASS <name> (<code>)` / `FAIL ...`; summary `<p>/<n> passed`; exit 1 on failure, 2 on usage/invalid |

## 4. Environment variables

| Var | Default | Used in |
|---|---|---|
| `QUERYKNIGHT_ENV` | `development` | legacy `environmentFromEnv` (only production/staging/development honored) |
| `QUERYKNIGHT_POLICY_FILE` | unset (legacy mode) | `getFilePolicy`; set-but-invalid fails fast at startup; cache keyed by path |
| `QUERYKNIGHT_DATABASE` | connectionKey | `databaseKeyFor` (policy scope key; passwords never enter matching) |
| `QUERYKNIGHT_APPROVAL_TIMEOUT_MS` | 60000 | `approvalTimeoutMs` (positive finite else default) |
| `QUERYKNIGHT_DB_TIMEOUT_MS` | 30000 | MCP `dbTimeoutMs` |
| `QUERYKNIGHT_HOME` | `~/.queryknight` | state dir |
| `QUERYKNIGHT_DAEMON_URL` | `http://127.0.0.1:47821` | HistoryClient base |
| `QUERYKNIGHT_PORT` | 47821 | daemon listen |
| `QUERYKNIGHT_AUTOSTART_PROXY_URL` | unset | daemon autostart proxy |
| `MYSQL_URL` / `POSTGRES_URL` / `DATABASE_URL` | — | connection resolution order MYSQL > POSTGRES > DATABASE; `mcp`/`proxy`/`run`/`backup-allow`/`snapshot` |
| `QK_LIVE_DB` | live (`!== '0'`) | `0` skips live adapter/proxy tests (CI) |

## 5. Policy v1 schema

Top level (strict, unknown fields rejected at every level): `version: 1` (only 1 accepted), `defaults: {decision: allow|deny|require_approval (required), on_parse_error?: deny|require_approval, on_unknown?: deny|require_approval, require_limit?: boolean, max_limit?: positive int}`, `environments?: {<env>: {databases?: {<db>: DatabasePolicy}}}` (env/db names free-form; `*` db key = wildcard fallback), `tests?: PolicyTestCase[]`.

DatabasePolicy: `allow?/deny?/approval_required?: PolicyRule[]`, `sensitive?: {columns?: string[] (glob), action?: deny|require_approval (default deny)}`, `mutations?: {deny_without_where?: subset of [update,delete,insert] (lowercased)}`, `row_safety?: {require_limit?: boolean, max_limit?: positive int}`.

PolicyRule (all fields optional AND-combined; empty `{}` = match-all; unknown fields rejected): `operations?` (lowercased, must be in allowlist: select/insert/update/delete/merge/create/alter/drop/truncate/rename/grant/revoke/call/copy/load/set/show/describe/explain/use/transaction/unknown/read/write/ddl/destructive/privilege/admin/administrative — typo can never silently disable a rule), `schemas?/tables?/columns?/agents?/integrations?/tools?/signals?: string[]` (non-empty strings; glob matched).

PolicyTestCase: `{name, sql (non-empty), expect: allow|deny|require_approval, dialect?, database?, environment?, agent_id?, integration?, reason? (exact reason_code match)}`. Standalone cases file: bare list or `{tests: [...]}`.

Invalid policy never replaces active policy: `loadPolicy`/`getFilePolicy` exit 2 / throw; daemon keeps last good.

## 6. Decision model

`evaluate()` returns `decision: allow|deny|require_approval` + `reason_code` + `message` + `matched_policy?` + `table?/column?/operation?` + `analysis` + `fingerprint(16hex)` + `durationMs` + `eventId(uuid)` + `timestamp(iso)` + `enforced(bool)` + `approvalId?`.

Legacy `decidePolicy` (no policy file) returns `allow|confirm|deny` with env presets; `confirm` = interactive approval (MCP non-blocking variant throws ApprovalPendingError).

OpenShell collapses to `allow|deny` (require_approval -> deny, or finding when `allow_with_findings`).

## 7. All reason codes

Policy engine: `DENY_PARSE_ERROR`, `DENY_UNKNOWN_STATEMENT`, `SENSITIVE_COLUMN`, `DENY_RULE`, `UNBOUNDED_UPDATE`, `UNBOUNDED_DELETE`, `LIMIT_REQUIRED`, `LIMIT_EXCEEDED`, `REQUIRE_APPROVAL`, `ALLOW_RULE`, `DEFAULT_ALLOW`, `DEFAULT_APPROVAL`, `DEFAULT_DENY`.
`evaluate()` envelope: `EMPTY_QUERY`, `QUERY_TOO_LARGE`, `POLICY_ERROR` (eval threw), `APPROVAL_UNAVAILABLE` (require_approval, no provider), `APPROVAL_GRANTED`, `APPROVAL_DENIED`, `APPROVAL_ERROR` (provider threw), `OBSERVED_<CODE>` (observe mode; e.g. `OBSERVED_DENY_RULE`).
Legacy safety errors: `QueryDeniedError(decision deny|expired)`, `ApprovalPendingError` (not a code; MCP renders pending text).
OpenShell wire codes: `queryknight_<lowercased reason, non-[a-z0-9_] -> _, max 56 chars>` + `queryknight_bad_config`, findings types `queryknight_denial` / `queryknight_approval_required`.

## 8. Decision precedence

`evaluatePolicy` order (first match wins): 1) `!parsed` -> `defaults.on_parse_error` (default deny) `DENY_PARSE_ERROR`; 2) `operation unknown` or kinds include `unknown` -> `defaults.on_unknown` (default deny) `DENY_UNKNOWN_STATEMENT`; 3) sensitive columns -> deny|require_approval `SENSITIVE_COLUMN`; 4) explicit `deny[]` (first matching rule) `DENY_RULE`; 5) `mutations.deny_without_where` (default `[update,delete]`) per-statement no-WHERE check `UNBOUNDED_*`; 6) row safety: `require_limit` (db > defaults) on any LIMIT-less select -> `LIMIT_REQUIRED`; `max_limit` (db > defaults) vs top-level `limitValue` -> `LIMIT_EXCEEDED`; 7) `approval_required[]` (first match) `REQUIRE_APPROVAL`; 8) `allow[]` (first match) `ALLOW_RULE`; 9) `defaults.decision` -> `DEFAULT_*`.

Rule match = AND over present fields; operations tested against per-statement kinds + operation categories (+`administrative` alias for `admin`); schemas vs `table.schema`; tables vs bare + `schema.name`; columns vs bare + `table.col` + `schema.table.col` cross-product; agents/integrations/tools exact-glob on ctx; signals glob vs `riskSignals`.

DB scope: exact `ctx.database` match, else `*`, else defaults-only (`defaults` dbPath).

## 9. Fail-closed rules

Empty/whitespace -> `deny EMPTY_QUERY` (no parse). Over `maxSqlBytes` (default 1,000,000, `Buffer.byteLength`) -> `deny QUERY_TOO_LARGE` fingerprint `oversize`. Parse failure/unsupported -> policy `on_parse_error`/`on_unknown` (default deny). Policy eval throw -> `deny POLICY_ERROR` (msg truncated 300). REQUIRE_APPROVAL with no provider -> `deny APPROVAL_UNAVAILABLE` (DenyByDefaultProvider exists but `evaluate` only uses it internally as unused default; explicit `undefined` fails). Provider throw -> `deny APPROVAL_ERROR`. Approval timeout -> `expired` -> deny. Daemon/store errors in audit sink never break enforcement (try/catch). `defaultPolicy()` = deny/deny/deny. Legacy unknown SQL: production deny, development confirm; never read.

## 10. Supported SQL dialects

`analyzeSql(sql, dialect)`: `mysql|mariadb -> MySQL`, `postgres|postgresql -> Postgresql`, `sqlite -> sqlite` (node-sql-parser option); unknown dialect string falls back to MySQL options but `analysis.dialect` keeps the lowercased input. Adapters pin: mysql/mariadb, postgres, sqlite. CLI `inspect` default `mysql`; `policy test` default `postgres`; `evaluate` default `mysql` unless `ctx.metadata.dialect` set. Case-insensitive dialect keys.

## 11. Known unsupported SQL

Anything node-sql-parser cannot `astify`: classified `unknown/unknown`, `parsed:false`, `parseError` (300 chars), `fallbackKinds` from regex scan, `riskSignals = [unparseable, possible_<kind>...]`. Observed: `WITH deleted AS (DELETE ... RETURNING *) SELECT ...` (data-modifying CTE in Postgres dialect) fails to parse in the pinned parser version. Fallback regex covers drop db/schema|table/index/view, truncate, delete-from, update-set, insert-into, alter-table, create user/role|table/index/db/schema/extension/view, grant, revoke, copy-from, vacuum(->unknown), call, load-data, merge(->unknown), select. `call`/`transaction` parse to `unknown` operation -> `DENY_UNKNOWN_STATEMENT` in enforce mode. `VACUUM`, `MERGE INTO` never allow in enforce mode.

## 12. Sensitive-data matching semantics

`findSensitiveColumn` over `analysis.columns`; unqualified column fans out to every `analysis.tables` name (and `''` when no tables). Candidates per column: `<table>.<col>`, bare `<col>`, `<schema>.<table>.<col>`. Any glob hit (case-insensitive, `*` = `.*` incl. dots) triggers; `*.api_key` matches `users.api_key` and `public.users.api_key`. Returns first hit `{qualified, table, column}`. Action default `deny`; applies to reads AND writes (column presence, not operation). Checked before deny/allow rules (only parse/unknown beat it).

## 13. Row-limit semantics

Applies to `select` statements only. `require_limit`: any LIMIT-less select -> deny `LIMIT_REQUIRED` (db-level else `defaults.require_limit` else false). `max_limit`: top-level `analysis.limitValue` (first numeric LIMIT found) > max -> deny `LIMIT_EXCEEDED` (db-level else defaults). LIMIT detection reads AST `limit.value[]` numeric entries. Execution budget is separate: `DEFAULT_BUDGET {50 rows, 64KiB, 8000 tokens}`; SELECTs get `LIMIT maxRows+1 OFFSET cursor.offset` injected only when no LIMIT present; over-fetch -> truncate + `truncated:true` + cursor; byte/token caps clip mid-page (keeps >=1 row). `maxRows` input capped by budget.

## 14. Approval semantics

`REQUIRE_APPROVAL` never executes by itself. `evaluate` needs an `ApprovalProvider`: `TestApprovalProvider(queue)` (deterministic), `DenyByDefaultProvider` (returns denied, but missing provider is a harder deny `APPROVAL_UNAVAILABLE`), `DaemonApprovalProvider` (MCP: creates daemon approval, fingerprint-matched retry on `approvalId`), OpenShell `WaitingProvider` (always waiting). Outcomes: approved -> `allow APPROVAL_GRANTED` (+approvalId); denied -> `deny APPROVAL_DENIED`; waiting -> pass through `require_approval` + approvalId. Daemon objects: `qka_<seq>` (memory) / uuid-ish persisted; `status waiting|approved|denied|expired|cancelled`; `expiresAt = now + timeoutMs`; `scope once|session` (session allow stores fingerprint per session, checked pre-decision in legacy path); `decisionSource cli|ui|mcp|tui|policy`; `schemaDdl` (before image) + `schemaDiff` (unified after). `waitForApproval` polls every 50ms; timeout flips to `expired`. Daemon `POST /approvals/:id/decide {status, source, scope}`; deciding non-waiting returns current (idempotent); unknown id throws/400.

## 15. Daemon API routes

Base `http://127.0.0.1:47821` (PORT override). All JSON. Auth: `Authorization: Bearer <session.token>` OR `?token=` OR `x-qk-token`; missing/mismatch -> 401. Host must be localhost (`127.0.0.1|localhost|::1`, brackets tolerated) else 403; non-localhost Origin -> 403; CORS allows localhost origins, headers Authorization/Content-Type, methods GET/POST/OPTIONS. Unauth paths: `GET /status /health /ready` + any non-API GET (static UI). Everything else requires token.

| Method Path | Auth | I/O |
|---|---|---|
| `GET /status` | no | `{ok:true, pid}` |
| `GET /health` | no | `{ok:true, version}` |
| `GET /ready` | no | `checkHealth({store, state_dir})` -> 200 `{status:'ok'}` or 503 degraded |
| `GET /activity` | yes | all query events desc |
| `GET /sessions` | yes | session summaries |
| `GET /sessions/:id` | yes | one summary or 404 |
| `GET /sessions/:id/events` | yes | session events |
| `POST /sessions {connectionKey, source, agent?}` | yes | `{id}` |
| `POST /events` | yes | `{id}` (history record incl. classification) |
| `GET /allows?sessionId=&fingerprint=` | yes | `{allowed: bool}` |
| `GET /connections` | yes | `connections.json` minus secrets (`redact(url)`) |
| `GET /approvals` | yes | all approvals |
| `GET /approvals/:id` | yes | one or 404 |
| `POST /approvals` | yes | create (raw passthrough to store) |
| `POST /approvals/:id/decide {status, source?, scope?}` | yes | decided view or 400 |
| `POST /approvals/:id/schema-diff {schemaDiff?}` | yes | stores diff, returns approval or 404 |
| `GET /*` (non-API) | no | daemon `fetch` falls through to `apps/ui/dist` SPA file or index.html |

## 16. Auth/token behavior

`ensureSessionToken`: reuse or `randomBytes(24).base64url`, write `0600 ~/.queryknight/session.token`. Clients: HistoryClient sends `authorization: Bearer <token>`; UI takes `?token=` once into `localStorage qk_token` then Bearer. Daemon compares exact string; no expiry/rotation endpoint; delete file + restart rotates. PID file `daemon.pid` (`<pid>\n<port>\n`). No TLS (loopback only); Host/Origin pinning is the SSRF guard.

## 17. Audit event structure

`AuditEvent {timestamp(iso), event_id(uuid), request_id?, agent_id?, session_id?, integration, environment, database?, user?, tool?, dialect, statements, operation, kinds[], tables[] (schema.name), columns? (table.col), fingerprint(16hex), normalized_sql?, sql?, decision, reason_code, matched_policy?, approval_id?, duration_ms, parser_ok, enforced}`. `buildAuditEvent` + `SqlLogLevel`: `none` (ids+fingerprint only), `fingerprint` (default), `metadata` (+ normalized literal-stripped SQL <=20000 chars + columns), `full_sql` (+ raw SQL <=20000 chars, secrets possible, opt-in). `evaluate({auditSink, sqlLogLevel, requestId})` invokes sink post-decision in try/catch. OpenShell collects one event per SQL candidate.

## 18. SQL logging levels

See §17. Production default `fingerprint`. QueryEvents table stores fingerprint always, raw `sql` column only when history path records it (tolerant migration adds it). `redact()` covers `user:password@` in URLs/logs; result rows never persisted (counts/bytes/tokens only).

## 19. OCSF behavior

`toOcsf(event, productVersion='0.1.0')`: OCSF 1.5.0, category 6 Application Activity, class 6003 API Activity. deny -> activity 7 Deny / High(4) / Failure(2); require_approval -> 0 Unknown / Low(2) / Unknown(0); else -> 6 Allow / Informational(1) / Success(1). `time = Date.parse(timestamp)`, `metadata.product={QueryKnight, version}`, `actor.user.name = agent_id ?? user`, `api.operation = <integration>:<operation>`, full decision preserved under `unmapped{qk_event_id, qk_reason_code, qk_matched_policy, qk_fingerprint, qk_tables, qk_kinds, qk_database, qk_environment, qk_enforced, qk_approval_id}`. Best-effort exporter; AuditEvent stays source of truth.

## 20. Prometheus metrics

`MetricsRegistry` (in-process, no deps): `counter(name, labels, v=1)`, `histogram(name, seconds, buckets=[0.005,0.01,0.05,0.1,0.5,1,5])`, `renderPrometheus()` (`# TYPE` + series; histograms with `_bucket{le}` +Inf, `_sum`, `_count`). `recordEvaluation(registry, ctx, result)` emits: `queryknight_requests_total{integration,environment,database,operation}`, `queryknight_decisions_total{+decision,reason_code}`, `queryknight_policy_denials_total` (deny only), `queryknight_parse_errors_total{integration,dialect}` (parsed=false), `queryknight_approval_requests_total{+result approved|denied|waiting}` (approvalId or APPROVAL_* or require_approval), `queryknight_evaluation_duration_seconds` histogram. No endpoint in daemon yet — registry is library-level (OpenShell service state carries one).

## 21. Health/readiness endpoints

`GET /health` = static `{ok, version}`. `GET /ready` = `checkHealth({store: listSessions ok?, state_dir: queryknightHome() writable?})` -> `{status:'ok'|'degraded', checks:[{name, ok, detail?}]}` with 200/503. Library `checkHealth` catches probe throws into `{ok:false, detail}`. No destructive probes. Daemon `/status` is liveness (no auth).

## 22. Database execution paths

Common: `runQuery(adapter, {sql, params, cursor, maxRows}, connectionKey, budget)`: cursor replays stored SQL/params/offset; trailing `;` trimmed; `;` inside => multi (no paging); single SELECT without LIMIT gets `LIMIT maxRows+1 OFFSET offset`; `adapter.execute`; row-cap slice; `clipRows` byte/token clip; SELECT matched-rows estimate via cheap path only (never auto-COUNT(*) large tables); returns `{columns, rows, rowsShown, rowsAffected?, truncated, bytesReturned, estimatedTokensReturned, estimatedTokensAvoided?, cursor?}`. `assertSingleStatement` throws on interior `;`. `withPage` is string-level. `isSelect` = `^\s*select`. MySQL/Postgres/SQLite adapters: `Bun.SQL` / `postgres` driver / `bun:sqlite`; introspection from information_schema normalized to `{schema, name, kind, columns, pk, indexes, fks}`; `estimateImpact` EXPLAIN UPDATE/DELETE only. Timeouts race client-side only. Errors propagate (MCP rethrows non-denial).

## 23. MCP execution path

`queryknight mcp` (MYSQL_URL/DATABASE_URL) -> `startMcpStdio`: `createAdapter` + connect, `HistoryClient.startSession({connectionKey: password-stripped key, source:'mcp'})` (undefined-tolerant), `serveStdio(createMcpServer(adapter, connectionKey, {client, sessionId}?))`. Per `db_query`: policy-file branch (`evaluate` + DaemonApprovalProvider) or legacy (`runSafeQuery` + forceConfirmDeletes + wait:false). Every outcome recorded via `history.client.record` (rows/bytes/tokens or decision/errorCode). Schema tools record pseudo-SQL. No policy => legacy env presets; policy file => core single auth point before `runQuery`.

## 24. OpenShell execution path

`parseInspectorConfig({policy_yaml (required string), dialect? default postgres, database? default main, environment? default production, approval_action? deny|allow_with_findings})` (bad -> `queryknight_bad_config` deny). `extractSqlFromHttpBody/WebSocketText` -> up to 8 candidates. Per candidate: `evaluate({integration:'openshell', environment, database, session_id: sandboxId}, sql, {policy, dialect, maxSqlBytes, approvalProvider: WaitingProvider, auditSink: collect})` + `recordEvaluation`. allow -> continue; require_approval + allow_with_findings -> finding, continue; else deny + `queryknight_denial` finding + `toReasonCode` code, stop at first blocking candidate. No-SQL traffic -> allow (not a firewall). gRPC: `Describe/ValidateConfig/EvaluateHttpRequest(/WebSocketSession)` over injected loader; throwing handler = supervisor fail_closed. Service `queryknight 0.1.0`, protocol `openshell.middleware.v1/1`, bindings HTTP_REQUEST + WEBSOCKET_MESSAGE @ PRE_CREDENTIALS, default 1MiB payload cap.

## 25. Persisted SQLite state/schema

`~/.queryknight/queryknight.db` (WAL). Tables: `connections(id PK, name, engine, environment default 'unknown', source, database, host_label)`, `sessions(id PK, connection_id, agent, started_at ms, ended_at, source)`, `query_events(id PK, session_id, connection_id, source, sql_fingerprint, sql NULL (migrated), query_class, risk, decision, started_at ms, duration_ms, rows_returned, rows_affected, bytes_returned, estimated_tokens_returned, estimated_tokens_avoided, error_code)`, `settings(key PK, value)`, `approvals(id PK, session_id, connection_id, fingerprint, status, reason, risk, operation_summary, created_at ms, expires_at ms, decided_at, decision_source, scope, schema_ddl JSON, schema_diff JSON)` (+ tolerant ADD COLUMN migrations), `session_allows(session_id, fingerprint PK)`. Event cap 5000 (trim). Siblings: `connections.json` (secrets at rest!), `session.token` (0600), `daemon.pid`, `daemon.log`, snapshots dir. Credentials/result rows stay off disk by default (URLs in connections.json are the exception).

## 26. Vue frontend API expectations

Polls (no SSE) `GET /activity /sessions /connections /approvals` + `GET /sessions/:id/events` with `Bearer` header; `POST /approvals/:id/decide {status, source:'ui', scope:'once'}`; renders `schemaDdl[]` and `schemaDiff[]`. Token bootstrap from `?token=`. Tabs: approvals (default), activity, sessions, connections. Expects daemon shape `{id, status, reason, risk, operationSummary, fingerprint, schemaDdl?, schemaDiff?}` and session summaries. Unauthenticated localhost -> error banner. No query editor; same approval objects as CLI.

## 27. Docker behavior

Multi-stage: `oven/bun:1` build (`bun install --frozen-lockfile`, `bun build packages/cli/src/index.ts --compile -> /out/queryknight`), `debian:12-slim` runtime (+ca-certificates, user `queryknight`, binary + `/etc/queryknight/policy.yaml policy-cases.yaml`), `ENTRYPOINT [queryknight] CMD [version]`. No source/toolchain/secrets in final image. CI builds `queryknight:ci`.

## 28. CI behavior

`.github/workflows/ci.yml` (ubuntu-latest, Bun latest): install --frozen-lockfile -> `typecheck (tsc --noEmit)` -> `biome check` -> UI build -> `bun test` with `QK_LIVE_DB=0` -> `policy test examples/policy.yaml examples/policy-cases.yaml` -> OpenShell demo (`bun --filter @queryknight/integration-openshell demo`) -> `docker build`. PLAN.md defers live-DB CI (11 live tests exercised locally via compose) and OS network sandbox, MariaDB/SQL Server, provider recovery.

## 29. All existing test suites

39 files: core(13): analysis, analysis-fuzz, budget, classify, cursors, diff, evaluate, observability, policy-engine, policy-file, query, redact, safety, version(14 with policy.test); cli(6): detect, doctor, init, policy-cmd, run, snapshot; daemon(3): app, http, store; mcp(4): format, index, policy-tools, tools; adapters(6): mysql analyze + live, postgres analyze + live, sqlite analyze + live-sqlite; proxies(4): mysql packets + live-proxy, postgres messages + live-proxy; openshell(1): inspector. Plus `examples/policy.yaml + policy-cases.yaml` as CI policy fixtures and the openshell demo script.

## 30. All currently skipped tests

No `describe.skip/it.skip/todo/xfail` literals. Gating is `test.skipIf(!LIVE)` with `LIVE = QK_LIVE_DB !== '0'`: mysql-adapter (6: ping, introspect, missing-table, budgeted SELECT, estimateImpact skip-path, dumpSchema), postgres-adapter (4: ping+introspect, estimateImpact skip-path, dumpSchema + one more), mysql proxy (2: SELECT-allow/DROP-block, mysql2 driver COM_QUERY/prepared/write/block), postgres proxy (2: same pair). Locally without DB servers these 11 fail with connection errors instead of skipping; with `QK_LIVE_DB=0` they skip (CI green).

## Re-audit notes (evaluator phase, 2026-09-28, verified against source)

- Observe mode (`evaluate(..., {mode: 'observe'})` -> `OBSERVED_*` allow) has
  no product caller: MCP, CLI `inspect`/`policy test`, daemon, proxies, and
  OpenShell never set it. It is a library option exercised by one unit test
  and one corpus fixture. Not a frozen product surface.
- Approval codes (`APPROVAL_UNAVAILABLE/GRANTED/DENIED/ERROR`) are produced
  only by the `evaluate()` envelope around approval providers, never by
  `evaluatePolicy()` itself, which stops at `require_approval`.
- `SELECT *` receives no special sensitive handling: `*` is an ordinary
  column string, so `users.password_hash` and `*.api_key` patterns do not
  match it (verified: all star selects allow under a sensitive policy
  unless another rule fires).
- Result field rules: `table`/`column` appear only on sensitive hits
  (bare names) and `table` on unbounded mutations (qualified); `operation`
  is kinds-joined (duplicates kept) on rule/default/unknown paths and the
  single kind on unbounded paths; empty/oversized results carry no
  `matched_policy`, `table`, `column`, or `operation`.
- `possible_*` fallback signals are verdict-dead by structure: failure
  paths return before signals rules are consulted, and successful parses
  never carry them. They enrich deny messages only.
- `CALL` reaches `DENY_UNKNOWN_STATEMENT` via unknown operation (kind
  `call` is known); `GRANT` under the standard policy reaches
  `DEFAULT_DENY` (no rule names it).

## CLI re-audit (CLI-parity phase, verified against source and live runs)

- Exit codes: `0` success (valid policy, all tests pass, inspect ALLOW);
  `1` policy-test failures, unknown subcommand, or bare `policy`;
  `2` usage errors (bad CLI shape, missing file/SQL), invalid policy or
  cases files; `3` inspect evaluated but decision is not allow (deny or
  require-approval). TS `policy` bare prints usage to stderr with exit 1;
  unknown commands print full help to stdout with exit 1.
- `inspect` defaults: `--dialect mysql` (differs from `policy test`
  default `postgres`), demo policy when `--policy` is absent, `--env
  production`, `--db main`, `--integration cli`. Demo policy: allow
  `select|show|describe|explain`, deny `drop|truncate|grant|revoke`,
  approval `insert|update|delete|create|alter`, sensitive columns,
  `deny_without_where: [update, delete]`, `max_limit: 1000`.
- `inspect` reads piped stdin when no positional SQL is given; text output
  lines are `Decision` (uppercase), `Reason`, `Message`, optional
  `Table`/`Column`/`Matched policy`/`Risk signals`; `--json` emits the
  9-key shape (decision uppercase, reason_code, message, matched_policy,
  table, column, operation, risk_signals, fingerprint; absent keys
  omitted). Non-allow exits 3.
- `policy validate` prints `policy <path>: valid (version 1, <dbs>
  database scope(s), <tests> embedded test(s))`; invalid/missing files go
  to stderr with exit 2 (`invalid policy <path>: ...` vs `cannot read
  policy <path>: ...`).
- `policy test <policy> [cases]` runs embedded `tests:` or a standalone
  cases file (bare list or `{tests: [...]}`), defaults
  `--dialect postgres --env production --db main`, per-case context
  overrides, `TestApprovalProvider(['waiting'])` so approval verdicts
  surface; lines `PASS <name> (<code>)` /
  `FAIL <name>: expected <exp>[/<reason>], got <dec>/<code> (<message>)`
  plus `<p>/<n> passed`; exit 1 on failures, 2 on usage/invalid.
- `version`, `--version`, `-v` print `QueryKnight 0.1.0-beta.0`;
  `help`, `--help`, `-h` print help (exit 0). Unknown flags are silently
  ignored by positional parsing; unknown dialects fall back to MySQL
  options silently. CLI `inspect` wires no approval provider, so
  approval-gated SQL reports `APPROVAL_UNAVAILABLE`/deny.

## SQLite layer audit (persistence phase, read from source DDL)

- Path `~/.queryknight/queryknight.db`; `new Database(path)` with no
  flags; exactly one PRAGMA (`journal_mode = WAL`); no `synchronous`,
  `busy_timeout`, `foreign_keys`, `user_version`, transactions, busy
  handling, or corruption handling anywhere.
- Six tables, no indexes, no foreign keys: `connections`, `sessions`,
  `query_events`, `settings` (created but never read or written),
  `approvals`, `session_allows`. Tolerant upgrades only via `PRAGMA
  table_info` checks adding `approvals.schema_ddl`, `approvals.schema_diff`,
  and `query_events.sql`.
- IDs: sessions `qks_<4B hex>`, events `qke_<6B hex>`, approvals
  `qka_<4B hex>`; connections `qkc_<sha256(key)[..12]>` (pure function).
- Connections upsert via SELECT-then-INSERT (race-prone, throws on
  conflict); URL parsing derives engine/database/host label, unknown
  environment/source defaults.
- Events insert then trim to 5000 by oldest `rowid` (no other cleanup;
  cap<=0 disables). Listings: events newest-first (limit 100), session
  events newest-first reversed to chronological (limit 500), sessions
  newest-first with live-computed summaries (`summarizeEvents` counts
  reads/writes/schema-changes/rows/bytes/tokens by class).
- Session summaries are computed on read from events, never stored.

## Fingerprint audit (identity-hardening phase, probed 2026-09-28)

`normalizeSql`/`sqlFingerprint` (`packages/core/src/fingerprint.ts`) are a
single global algorithm with no dialect input: single-quoted spans collapse
(only `''` escapes; backslash is literal), double-quoted spans collapse
(treated as strings, never identifiers), ASCII bare numbers collapse
(`$1` -> `$?`, `1.5` -> `?.?`, `-3` -> `-?`, while `0x10` survives),
whitespace runs collapse with trim and lowercase. Comments, `?`
placeholders, backticks, and `$n` prefixes are NOT special. The
fingerprint is the first 16 hex characters of SHA-256 over the normalized
form (64-bit truncation). It appears in `QueryEvent.sqlFingerprint`,
approval rows (`fingerprint` column), the session-allow key
`(session_id, fingerprint)`, the `/allows` check, MCP approval retry
matching, and audit/OCSF (`qk_fingerprint`) output. Literal-only variants
(`id = 42` vs `id = 43`) intentionally share identity: session-shape
grants approve a statement shape once per session.

## Approval lifecycle re-audit (approval-layer phase, verified)

- `RequireApproval` is produced only by `evaluatePolicy()` (sensitive
  action, approval rules, `on_parse_error`/`on_unknown` set to
  `require_approval`, `defaults.decision`). Envelope codes
  (`APPROVAL_*`) come from `evaluate()` around providers, never the
  policy engine.
- Provider input: `{eventId, context, fingerprint, reasonCode, message,
  matchedPolicy, table, column, operation}` — fingerprint plus facts,
  never raw SQL. Outcomes: `{id, status: approved|denied|waiting}`;
  throws map to `APPROVAL_ERROR` (message bounded to 300 chars).
- Fingerprint: literal/number-stripped, lowercased SHA-256, first 16 hex
  (`sqlFingerprint`). Session grants and approval retries bind on it, so
  literal-only variants (`id=42` vs `id=43`) intentionally share identity.
- Daemon IDs: `qka_<4 random bytes hex>`; in-memory test IDs `qka_<seq>`;
  test-provider IDs `test-<n>`.
- Expiry: `expiresAt = createdAt + timeoutMs` (default 60s); reads lazily
  flip `waiting` to `expired` at `expires_at <= now` (boundary inclusive).
  `waitForApproval` polls every 50ms, then marks expired.
- `decideApproval` only transitions `waiting` (else throws `approval not
  waiting`); `scope: once|session` (default `once`); approved + session +
  sessionId writes an unbounded-lifetime `(session_id, fingerprint)` row
  (no TTL, no revocation path).
- Session-allow matches `(session_id, fingerprint)` only — no
  environment/database/agent comparison (sessions are per-connection).
- Retry (`approvalId`): approved fingerprint-match executes without a new
  row; denied/expired deny; waiting + non-blocking rethrows pending;
  unknown/mismatched id mints a fresh approval. "Single-approval retry"
  is mechanism C: re-invoke evaluation carrying the approval token.
- `cancelled` exists in the status union but has no producer in any flow.
- Envelope field rules: granted/denied/error drop `table`/`column`/
  `operation`; unavailable preserves them; waiting passes the policy
  result through with `approvalId` added.

## Daemon runtime audit (lifecycle phase, verified against source 2026-09-29)

Source: `packages/daemon/src/index.ts`, `packages/cli/src/index.ts`
(`start`/`stop`/`status`), `packages/core/src/paths.ts`,
`packages/core/src/history.ts` (`HistoryClient::status`), `packages/daemon/src/store.ts`.

1. CLI commands: top-level `start`, `stop`, `status` (no `daemon`
   subgroup, no `restart`, no foreground flag).
2. Foreground/background: no foreground mode. `start` spawns the daemon
   detached (`spawn(process.execPath, [daemon/index.ts], {detached: true,
   stdio: ['ignore', logFd, logFd]})`, `child.unref()`), then polls
   `history.status()` 20x50ms; success prints
   `daemon started (log: <home>/daemon.log)`, failure prints
   `daemon failed to start; last log lines from <log>:` + last 15 lines,
   exit 1.
3. Default host/port: `127.0.0.1:47821` (`QUERYKNIGHT_PORT`).
4. State dir: `QUERYKNIGHT_HOME ?? ~/.queryknight` (`queryknightHome()`).
5. SQLite path: `<home>/queryknight.db` (WAL: `PRAGMA journal_mode = WAL`).
6. Token file: `<home>/session.token`.
7. Token format: `randomBytes(24).toString('base64url')` + `"\n"`
   (32 base64url chars, no padding).
8. Generation: `node:crypto randomBytes` (CSPRNG).
9. Reuse/rotation: reuse if `readFileSync(...).trim()` is non-empty (any
   content, no validation); generate only when absent/empty; no rotation
   endpoint (delete file + restart rotates).
10. Token-file permissions: `writeFileSync(path, token, {mode: 0o600})`
    on creation only; no directory permission handling, no chmod of
    existing files.
11. PID file: `<home>/daemon.pid`, format `<pid>\n<port>\n`, written
    after `Bun.serve` succeeds (port-in-use throws first, leaving no pid).
12. Stale PID: no detection. `start` ignores the pid file (HTTP probe
    only); `stop` with a stale file calls `process.kill(deadPid)`
    which throws, and the stale file is NOT unlinked on that path
    (unlink is in a try/catch but the throw happens before it).
13. Already-running: HTTP `GET /status` probe only (`daemon already
    running`, exit 0). No lock file, no pid check.
14. Daemon log: `<home>/daemon.log`, opened `'a'` (append forever, no
    rotation/truncation).
15. stdout/stderr: child stdout+stderr both redirect to the log fd;
    the daemon itself logs via `console.error` (startup line
    `queryknight daemon 127.0.0.1:<port>`, proxy line with redacted URL).
16. Append always; never truncated.
17. Signal handling: none in the daemon. SIGTERM/SIGINT default-kill
    (Bun). No graceful drain, no pid-file removal on exit.
18. Shutdown: abrupt. In-flight requests are dropped; no connection
    draining.
19. SQLite close/checkpoint: `HistoryStore.close()` exists but is never
    called on the daemon path; close relies on process exit. No
    checkpoint call (WAL files persist; replay on next open).
20. Startup failure cleanup: none beyond pid-after-serve ordering.
    A bound-but-crashed-later daemon leaves a stale pid file.
21. Port-in-use: `Bun.serve` throws (EADDRINUSE); the CLI reports the
    log tail. No occupant identification, no state mutations.
22. Status: `GET /status` -> `{ok:true, pid}` over HTTP; CLI prints
    `daemon up pid=<pid>` or `daemon down` (exit 1). No pid-file read.
23. Stop: read first pid-file line, `process.kill(pid, 'SIGTERM')`,
    best-effort unlink, print `daemon stopped`. No ownership check, no
    wait, no escalation. Missing pid file -> `daemon not running`
    (exit 0).
24. Restart: absent (compose `stop` + `start` manually).
25. Autostart: `QUERYKNIGHT_AUTOSTART_PROXY_URL` autostarts a MySQL
    (127.0.0.1:3308) or Postgres (127.0.0.1:5434) *query proxy* inside
    the daemon process -- it is NOT OS service autostart (no
    launchd/systemd/Scheduled-Tasks integration anywhere).
26. Platform differences: none (homedir/path join only; `process.kill`
    SIGTERM is POSIX-meaningful, best-effort elsewhere).
27. Env overrides: `QUERYKNIGHT_HOME`, `QUERYKNIGHT_PORT`,
    `QUERYKNIGHT_DAEMON_URL` (client base, default
    `http://127.0.0.1:47821`), `QUERYKNIGHT_AUTOSTART_PROXY_URL`.
    No CLI flags for the daemon path; no stored settings.
28. Filenames: `queryknight.db` (+ `-wal`/`-shm`), `session.token`,
    `daemon.pid`, `daemon.log`.
29. UI/token bootstrap: UI takes `?token=` once into
    `localStorage qk_token`, then Bearer; `HistoryClient` reads
    `session.token` per request. (UI serving itself is deferred in Rust.)

## Static UI serving audit (browser-surface phase, verified against source and built dist 2026-09-29)

Source: `apps/ui/src/{App.vue (434 lines), main.ts, logo.svg}`,
`apps/ui/{package.json, vite.config.ts, dist/}`,
`packages/daemon/src/{index.ts, app.ts}` (`staticFile`, `isApiPath`,
`uiDistDir`).

1. Frontend source: `apps/ui/src/` (`App.vue` tab SPA, `main.ts`
   mounts `#app`, `logo.svg` inlined as data URI, no vue-router).
2. Build: `vite build` (vite 8 + @vitejs/plugin-vue 6 + vue 3; the
   `build` script does NOT typecheck).
3. Output: `apps/ui/dist/{index.html, assets/index-<8base62>.js,
   assets/index-<8base62>.css}` (80K total; verified byte-identical
   rebuild offline to a temp outDir).
4. TS serves disk files per request: `staticFile()` + `new
   Response(Bun.file(file))` in the `index.ts` fetch fallback.
5. Disk reads, never embedded (`existsSync` on every miss).
6. `GET /` -> `dist/index.html`.
7. Fallback: any GET whose API response is 404 serves the exact disk
   file if present, else `dist/index.html` (200) — INCLUDING missing
   `/assets/*` paths and API-shaped unknown paths.
8. Excluded from fallback: non-GET methods (API 404 returned as-is)
   and any API response != 404.
9. API shape list (`isApiPath`): `/activity`, `/sessions`,
   `/sessions/*`, `/events`, `/allows`, `/connections`, `/approvals`,
   `/approvals/*`. (Auth-skip list: `GET` + non-API skips auth; also
   `/status /health /ready` always skip.)
10. Unknown API route: Hono 404 -> GET falls into static/index.html
    (e.g. `GET /approvals/x/y` -> 200 index.html when dist exists).
    The Rust port deliberately diverges here (frozen 1631702 JSON 404
    for API-shaped unknowns).
11. Bootstrap: `new URLSearchParams(location.search).get('token')`.
12-14. Storage: `localStorage` key `qk_token`, raw token value; no
    sessionStorage/cookie/memory-only mode.
15-17. Removal: `history.replaceState({}, '', location.pathname)` in
    the same `token()` call that stores it, before the first fetch;
    no redirect/navigation.
18. Precedence: `?token=` unconditionally OVERWRITES any stored value
    (no comparison, no validation).
19-20. Invalid `?token=wrong`: stored blindly; every API call then
    401s and the page shows the `401 unauthorized` text. No logout or
    clear-token control exists.
21. Transport after bootstrap: `authorization: Bearer <token>` header
    on every `fetch` (plus `content-type: application/json`); the
    query transport is never reused by the UI.
22. Same-origin relative paths (`/activity`, `/sessions`, ...): no
    port/host assumptions, no CORS needed in production.
23-25. No CSP, no Referrer-Policy, no X-Frame-Options/frame-ancestors
    anywhere (server or bundle). Rust adds these as hardening.
26. No Cache-Control/ETag logic in TS (Bun.file defaults only). Rust
    sets `no-store` (index/bootstrap) vs `immutable` (hashed assets).
27. Hashed names: `index-<8 chars base62>.js/.css`.
28. `index.html` cached like any other file in TS (no special rule).
29. No `.map` files in dist (vite default `sourcemap: false`).
30. Dev: `vite dev` standalone; the daemon never proxies to it.
31. Deep links: no router — every path renders the same SPA (default
    tab `approvals`, 2s poll); session selection is JS state, not URL.
32. Malformed/nonexistent asset: TS serves index.html 200 (Rust
    diverges to 404 for recognizable asset paths).
33. No favicon/manifest/link icons (`/favicon.ico` -> index.html).
34. The token never enters logs: the bundle has zero `console.*`
    calls and no error reporting.
35. Browser contract relied upon: same-origin relative fetch, Bearer
    `qk_token` from localStorage, `?token=` one-shot bootstrap with
    immediate `replaceState` cleanup.

## Database execution audit (db-layer phase, verified against source 2026-09-30)

Source: `packages/adapters/{mysql,postgres,sqlite}/src/index.ts`,
`packages/core/src/{adapter.ts,query.ts,budget.ts,cursors.ts,safety.ts}`,
`packages/mcp/src/{engine.ts,tools.ts}` (`dbQuery`, `dbExplain`,
`dbSample`, `dbTables`, `dbDescribe`, `dbSchema`, `withTimeout`).

- Adapter selection (`engine.ts createAdapter`): `sqlite:` ->
  SqliteAdapter, `^postgres(ql)?:` -> PostgresAdapter, EVERYTHING ELSE
  -> MysqlAdapter (mysql is the default). All three wrap `Bun.SQL`
  (`bun:sqlite` for sqlite); `sql.unsafe(sql, params)` binds params
  safely. No pools configured; adapter objects hold one client.
- `DatabaseAdapter` surface: connect/disconnect/ping/listSchemas/
  listTables/describeTable/dumpSchema?/execute/explain/analyze/
  sample/estimateImpact?/getCapabilities. Capabilities: sqlite
  {explain, sampling}, pg {explain, explainWrites, sampling},
  mysql {schemas, explain, explainWrites, protocolProxy, sampling}.
- `runSafeQuery`: analyze -> estimateImpact (unbounded writes only,
  EXPLAIN pre-decision) -> enforcePolicy (deny/confirm/allow,
  session-allow, approval create-or-retry, waitForApproval unless
  `wait:false` -> ApprovalPendingError) -> runQuery -> after-diff
  record. Legacy env-preset path and policy-file path (`evaluate` +
  DaemonApprovalProvider) coexist in `dbQuery`.
- `runQuery`: cursor resolves stored (sql,params,offset) FIRST (and the
  policy-file path re-evaluates the resolved text); trailing `;`
  trimmed; `multi = includes(';')`; SELECT without `/\blimit\b/i`
  gets `LIMIT maxRows+1 OFFSET offset`; `maxRows =
  min(input.maxRows ?? 50, 50)`; `clipRows` (row cap first, then byte
  `Buffer.byteLength(JSON.stringify(row))` / token `ceil(bytes/4)`
  caps vs 65536/8000, first row exempt); `hitRowCap` (fetched >
  maxRows) also marks truncated; `estimatedRowsMatched` via EXPLAIN
  regex `/\brows[=:]?\s*(\d+)/i` post-execution; `tokensAvoided =
  max(0, est(avg*matched) - returned)`; cursor issued iff truncated
  && SELECT && `opts.cursor !== false`, `offset + shown`.
- `DEFAULT_BUDGET = {maxRows: 50, maxBytes: 64*1024,
  maxEstimatedTokens: 8000}`; `DEFAULT_LIMIT = 50` (list caps),
  `DEFAULT_SAMPLE_LIMIT = 20`, sample clamp 200, `MAX_QUERY_PARAMS =
  1000` (-> `Blocked:` text), `dbTimeoutMs =
  QUERYKNIGHT_DB_TIMEOUT_MS ?? 30000`, `withTimeout` races the driver
  with `may still be running server-side` semantics (no cancellation
  claim).
- Cursors: in-memory Map, `qk_cur_<9 random bytes base64url>` (12
  chars), TTL 10min, sweep on access, connectionKey-bound, unknown /
  cross-connection -> throw. `connectionKeyFromUrl` strips passwords;
  `connectionIdFromKey` = `qkc_<sha256hex[0..12]>`.
- Values: driver rows are JS objects passed through verbatim
  (`columns = Object.keys(first)`, duplicate columns collapse
  last-wins at the driver); mutations return `rowsAffected` ONLY for
  sqlite (`changes`); pg/mysql mutations return no count.
- `execute` sends multi-statement batches to the driver as-is (only
  `runExplain` asserts single-statement); params via driver binding.
- `estimateImpact`: UPDATE/DELETE only, `EXPLAIN` (never ANALYZE),
  pg takes max of `rows=` matches, mysql max of the `rows` column,
  failures -> `{}`.
- Introspection SQL: pg `information_schema` (+current_schema,
  BASE TABLE/VIEW filter), mysql `information_schema` (+DATABASE(),
  BASE TABLE/VIEW filter), sqlite `sqlite_master` + PRAGMAs +
  `ORDER BY RANDOM()/RAND()/random()` sampling; `dumpSchema` =
  sqlite_master DDL / `SHOW CREATE TABLE` / `pg_dump` subprocess.
- `dbExplain` and `runSample` evaluate NO policy (direct
  adapter calls); metadata tools (`dbTables`/`dbDescribe`/`dbSchema`)
  take identifiers only. History `track()` records every tool call
  (decision/errorCode on failure).
- Errors: raw driver messages propagate (`throw error` after
  tracking); URLs redacted only via `redact()` (password -> `***`)
  at display edges.
- No implicit transactions anywhere; per-request adapter use means
  no cross-request transaction affinity.

## MCP contract audit (mcp phase, verified against source 2026-09-30)

Source: `packages/mcp/src/{index.ts, tools.ts, format.ts, engine.ts}`,
`@modelcontextprotocol/server` (stdio), `packages/cli/src/index.ts`
(`mcp` command).

- Exactly 8 tools: `db_tables`, `db_describe`, `db_schema`,
  `db_query`, `db_explain`, `db_sample`, `approvals_list`,
  `approvals_decide`. No aliases.
- Server identity: name `queryknight`, version `QUERYKNIGHT_VERSION`
  (`0.1.0-beta.0`), frozen `mcpInstructions(connectionKey)` text
  (bound-connection preamble + tool summary + approval-retry
  instructions + no-fallback warning).
- Schemas (zod; unknown keys stripped, not rejected):
  `db_tables {schema?, includeViews?, limit? int 1-200}`,
  `db_describe {table, schema?}`, `db_schema {schema?, limit? int
  1-200}`, `db_query {sql string 1-1_000_000, params? array max
  1000, maxRows? int 1-200, cursor?, approvalId?}`,
  `db_explain {sql, params?}`, `db_sample {table, schema?, limit?
  int 1-200}`, `approvals_list {}`, `approvals_decide {id, status:
  approved|denied}`. Annotations: `destructiveHint: true` only on
  `db_query`/`approvals_decide`, else read-only.
- Output: `{content: [{type: 'text', text}]}` single text block
  always. `formatQuery`: optional `Query matched ~N rows (planner
  estimate).`, `Showing N rows.`, markdown table (`NULL` -> ``),
  blank, `Returned to agent: N bytes`, `Estimated tokens returned:
  ~N`, optional avoided/cursor/`Rows affected:` lines.
- `Blocked:` prefix (exact capital + colon) for denials, pending,
  and param overflow; pending template byte-exact
  (`Blocked: waiting for approval <id>.` / ask-user line /
  `approvals_decide("<id>", "approved")   # or "denied"` / `Then
  retry db_query with the same SQL and approvalId="<id>".`).
  Denied/pending are TEXT RESULTS, not protocol errors; DB/daemon
  failures throw (protocol errors).
- Retry is an explicit `approvalId` tool argument; cursor paging
  reuses stored SQL (policy-file path re-evaluates it).
- One bound connection per server (`createAdapter(url)` at
  startup; `connectionKeyFromUrl` password-stripped key);
  `db_query` uses `databaseKeyFor(connectionKey)`
  (`QUERYKNIGHT_DATABASE` ?? key), `environmentFromEnv()`,
  hardcoded `integration: 'mcp'`, `tool: 'db_query'`.
- `dbTables` default limit 50, views filtered unless
  `includeViews`; `dbSchema` tables-only default 50 with `…
  truncated. Narrow schema or raise limit.`; `dbSample` default 20,
  clamp 200, cursor disabled; `parseTableRef` splits on FIRST dot
  (`schema.table`), explicit `schema` wins.
- `dbExplain`/`runSample` evaluate NO policy (direct adapter calls);
  metadata tools take identifiers only.
- History: `track()` records EVERY tool call (`sessionId`,
  `connectionKey`, `source: 'mcp'`, SQL text, durationMs,
  rows/bytes/tokens or decision/errorCode) via `POST /events`
  (best-effort catch); `dbQuery` success records full counters.
  Daemon down at startup -> `sessionId` undefined -> history
  undefined -> tools run history-less; approvals tools return
  `daemon unavailable; start queryknight`.
- `queryknight mcp` requires `MYSQL_URL`/`DATABASE_URL` else
  `set MYSQL_URL` stderr exit 1; `adapter.connect()` at startup;
  SIGTERM/SIGINT -> disconnect; `serveStdio` (stdout protocol-only,
  no other stdout writes in mcp sources).
- `withTimeout`: `QUERYKNIGHT_DB_TIMEOUT_MS ?? 30000`, race with
  `may still be running server-side` text, AbortSignal support.

## Observability audit (observability phase, verified against source 2026-09-30)

Source: `packages/core/src/{audit.ts, ocsf.ts, metrics.ts,
fingerprint.ts, redact.ts, evaluate.ts}`, OpenShell
`inspector.ts`/`service.ts` (only non-core consumers).

- Levels: `SqlLogLevel = none|fingerprint|metadata|full_sql`;
  default `fingerprint` (safe); `MAX_SQL_LOG_CHARS = 20000`.
  `none` = ids+fingerprint only; `metadata` adds literal-stripped
  `normalizeSql` + tables + columns; `full_sql` adds raw SQL
  (secrets possible, opt-in).
- `normalizeSql`: single/double-quoted literals -> `?`, bare
  numbers -> `?`, whitespace collapsed, lowercased;
  `sqlFingerprint` = sha256 hex sliced to 16.
- `AuditEvent` JSON names: timestamp, event_id, request_id?,
  agent_id?, session_id?, integration, environment, database?,
  user?, tool?, dialect, statements, operation, kinds, tables,
  columns?, fingerprint, normalized_sql?, sql?, decision,
  reason_code, matched_policy?, approval_id?, duration_ms,
  parser_ok, enforced.
- `buildAuditEvent(ctx, sql, result, {level, requestId})` reads the
  TS `Evaluation` (eventId = `crypto.randomUUID()`, ISO timestamp,
  `enforced = mode !== 'observe'`).
- `evaluate({auditSink})` calls the sink post-evaluation inside
  try/catch (sink failures swallowed — enforcement never breaks).
  Only OpenShell wires `auditSink` (array push) and
  `recordEvaluation`; MCP/daemon/proxies emit nothing.
- Observe mode: `mode === 'observe'` turns non-allow into `allow`
  with `OBSERVED_<code>` + `enforced: false` — Deny→Allow security
  semantics, NOT ported (stop-and-report; fixture stays deferred).
- OCSF 1.5.0, Application Activity / API Activity, class 6003:
  deny 7/Deny/High(4)/Failure(2); require_approval
  0/Unknown/Low(2)/Unknown(0); allow 6/Allow/Informational(1)/
  Success(1). `metadata.product` QueryKnight+version;
  `actor.user.name` from agent_id ?? user; `api.operation =
  "<integration>:<operation>"`; full decision under `unmapped.qk_*`;
  `undefined` fields omitted. Emitted for decisions (including
  deny/pending), never labeled as successful DB activity.
- Metrics (`MetricsRegistry`, zero-dep, insertion-order maps):
  `queryknight_requests_total{integration,environment,database,
  operation}`, `queryknight_decisions_total{+decision,reason_code}`,
  `queryknight_policy_denials_total{+reason_code}` (deny only),
  `queryknight_parse_errors_total{integration,dialect}`,
  `queryknight_approval_requests_total{+result
  approved|denied|waiting}` (waiting covers pending/unavailable/
  error), `queryknight_evaluation_duration_seconds` histogram
  buckets `[0.005,0.01,0.05,0.1,0.5,1,5]` over `durationMs/1000`.
  Render: `# TYPE <name> counter|histogram` (NO HELP), samples,
  cumulative buckets + `+Inf`, `_sum`, `_count`; labels sorted,
  escaping `\` and `"` only; empty renders `""`. No gauges, no
  reset, no `/metrics` endpoint anywhere.
- `redact()`: `//user:password@` -> `//user:***@` (display edges
  only).
- Daemon `query_events` history (raw SQL, per-session log) is a
  separate record from security audit; nothing links them.

## External compatibility surfaces (freeze list)

1. `evaluate(ctx, sql, opts)` signature + Evaluation JSON shape + all reason codes.
2. Policy v1 YAML schema + strict validation messages (`path: message`) + `parsePolicyFile/parseTestCasesFile` + `policy validate/test` CLI I/O.
3. `inspect [--json]` stdout + exit codes (0 allow, 3 non-allow, 2 usage/invalid).
4. MCP tool names + zod schemas + text responses (incl. exact pending-approval template + `Blocked:` prefix + `daemon unavailable` fallback).
5. Daemon REST paths/methods/auth/JSON shapes + status codes (401/403/404/400/503).
6. Approval object shape + retry-with-approvalId flow + scope once|session + expiry/timeout default 60s.
7. AuditEvent JSON + SqlLogLevel set + OCSF mapping (class 6003, activity mapping, unmapped.* keys).
8. Prometheus metric names + label keys + histogram buckets.
9. Fingerprint/normalize algorithm (sha256/16hex, literal rules) + cursor id format (`qk_cur_*`, TTL 10min, connection binding) + connection key/id formats (`protocol//user@host/path`, `qkc_<12hex>`).
10. Result budget defaults (50/64KiB/8000) + truncation/cursor contract + token heuristic (bytes/4).
11. `redact()` behavior + redacted `/connections` output.
12. Proxy wire behavior (MySQL COM_*, Postgres Q/Parse-Bind-Execute-Sync, prepared-template classification, 127.0.0.1 plaintext local leg).
13. OpenShell config keys + verdict/findings/reason_code format + gRPC method/enum mapping.
14. SQLite schema DDL + token/pid/log/connections.json/snapshot file layouts.
15. UI fetch paths + Bearer scheme + localStorage key `qk_token`.
16. Env var names/defaults (§4) + `run` child-env rewrite rules + `.env` warning.
17. Docker image layout/entrypoint + CI steps order.
18. `QUERYKNIGHT_VERSION` string + `/health` version field + MCP server name/version.
