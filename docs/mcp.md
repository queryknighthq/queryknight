# MCP server (`qk-mcp`)

Thin protocol adapter over the finished services: stdio in, frozen
tool schemas, `qk-db` guarded execution or the daemon control plane,
frozen text results out. No SQL analysis, policy, approval matching,
or driver logic lives here — if it does, that is an architectural
bug. Audited TS behavior is in `docs/reference-implementation.md`
("MCP contract audit"); this document is the Rust contract.

## Identity and transport

- Server name `queryknight`, version from package metadata
  (`0.1.0-beta.0`), frozen instructions text (interpolated with the
  bound connection key).
- stdio transport (rmcp); **stdout is protocol-only** — no banners,
  no `println!`, no tracing-to-stdout (INV-038). Diagnostics go to
  stderr. EOF shuts down cleanly; SIGTERM/SIGINT disconnect.
- CLI: `queryknight mcp` (frozen spelling) reads `MYSQL_URL` then
  `DATABASE_URL`; missing both prints `set MYSQL_URL` to stderr and
  exits 1. One server instance serves ONE bound connection (frozen:
  adapter + connectionKey fixed at startup).

## Tools (frozen eight)

| Tool | Input | Maps to |
|---|---|---|
| `db_tables` | `{schema?, includeViews?, limit? (1–200)}` | qk-db `list_tables` (default limit 50, views excluded unless asked) |
| `db_describe` | `{table, schema?}` (`schema.table` split like the reference) | qk-db `describe_table` |
| `db_schema` | `{schema?, limit? (1–200)}` | list + describe each (tables only, default 50) |
| `db_query` | `{sql (1–1M chars), params? (≤1000), maxRows? (1–200), cursor?, approvalId?}` | qk-db `execute_guarded` |
| `db_explain` | `{sql, params?}` | qk-db `explain_guarded` (allow-only hardening) |
| `db_sample` | `{table, schema?, limit? (1–200, default 20)}` | qk-db `sample_guarded` |
| `approvals_list` | `{}` | daemon `GET /approvals`, waiting rows |
| `approvals_decide` | `{id, status: approved\|denied}` | daemon `POST /approvals/{id}/decide` (source `mcp`) |

Unknown JSON fields are ignored (frozen zod strip behavior), never
rejected. Schema bounds reject before any service contact (0 adapter
calls, pinned). Tool annotations mirror the reference
(`destructiveHint: true` only on `db_query`/`approvals_decide`).

## Trusted context (INV-037)

Tool arguments are untrusted agent input. The server assigns
`integration: "mcp"`; environment/database/session come from the
bound connection configuration; the dialect comes from the
connection (`DbConfig`), never from an argument (there is no
`dialect` argument). Arguments select only: SQL text, params, paging,
approval id, table identifiers.

## Results (frozen text)

- Single `{content: [{type: "text", text}]}` block, never structured
  content. `formatQuery` markdown shape preserved byte-for-byte
  (estimate line, `Showing N rows.`, markdown table with `NULL`→``,
  byte/token footers, `Use cursor:`, `Rows affected:`).
- Denials and approval waits are **successful tool results** starting
  with `Blocked:` — never JSON-RPC protocol errors. DB failures,
  daemon failures, and schema violations are protocol errors.
- Pending template (byte-exact):
  `Blocked: waiting for approval <id>.` + ask-user line +
  `approvals_decide("<id>", "approved")   # or "denied"` +
  `Then retry db_query with the same SQL and approvalId="<id>".`
- Retry re-runs the full guarded path (evaluate → store/session
  checks → provider re-verification against the live daemon row →
  execute). The daemon row must prove the FULL exact identity
  (approved/live status, binding version, digest bytes via the
  opaque `POST .../verify`, full scope, expiry) — id + fingerprint
  alone never authorize (INV-041). Changed literals or params fail
  verification and pend for a fresh approval; only explicit Session
  grants stay shape-wide (via `/allows`), and legacy rows read as
  waiting (INV-027).
- `approvals_list` without daemon: `daemon unavailable; start
  queryknight`. Decide result: `approval <id>: <status>`.

## Approvals via daemon

`qk-mcp` never opens the state DB. A sync daemon provider maps
`ApprovalRequest` → daemon `POST /approvals` (new row, always
waiting — the `wait:false` flow) and retry ids → `GET
/approvals/{id}` verdicts (approved only with matching shape
fingerprint; exact binding still enforced locally by
`qk-approval`). A pre-check of `GET /allows` reuses daemon session
grants without minting duplicate rows (mirrors
`hasSessionAllow`). Session history: `POST /sessions` at startup
(source `mcp`), `POST /events` per tool call (best-effort; failures
never change outcomes, never re-execute).

Daemon discovery reuses `qk-daemon` runtime paths/token semantics
(`QUERYKNIGHT_HOME`, `session.token`, pid-file port); Bearer header
transport; bounded timeouts; redacted errors. Daemon down →
history-less execution still works; approval tools degrade to the
frozen unavailable text (never authorization success).

## Intentional divergences from TS

1. `db_explain`/`db_sample` evaluate first (allow-only/approved-only
   execution; denied causes zero DB contact) — INV-035 hardening.
2. Multi-statement rejected (qk-db rule, not driver-dependent).
3. Duplicate columns preserved positionally in markdown tables.
4. `rowsAffected` on pg/mysql mutations too; binary as base64.
5. `dump_schema` on postgres → normalized unsupported error (no
   `pg_dump` subprocess).
6. Session-grant reuse via `/allows` pre-check instead of
   `hasSessionAllow` (same observable: no duplicate approvals).

## Legacy quarantine at the boundary

Migrated `legacy_shape` daemon rows never authorize via MCP (7th
divergence): the provider reads them as waiting so the agent seeks a
fresh approval, even when approved and fingerprint-matching. INV-027
holds at every layer.

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
