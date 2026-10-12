# MCP server (`qk-mcp`)

Thin protocol adapter over the finished services: stdio in, frozen
tool schemas, `qk-db` guarded execution or the daemon control plane,
frozen text results out. No SQL analysis, policy, approval matching,
or driver logic lives here — if it does, that is an architectural
bug. Audited TS behavior is in `docs/reference-implementation.md`
("MCP contract audit"); this document is the Rust contract.

## Identity and transport

- Server name `queryknight`, version from package metadata
  (`0.1.0`), frozen instructions text (interpolated with the
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

## Daemon control-plane client and approval provider

### Audited pre-extraction implementation

Before extraction, daemon HTTP logic lived in `qk-mcp/src/daemon.rs`;
session/history payload assembly lived in `history.rs`; discovery and
approval-provider construction lived in `server.rs`. Runtime files and port
records are owned by `qk-daemon::runtime`; MCP did not parse pid-file
contents itself. Approval decisions and storage remain in
`qk-approval`/`qk-daemon`/`qk-store`.

- Discovery called `RuntimeSource { home, port: None }` and centralized
  `runtime::paths::resolve`; explicit `home` won, else `QUERYKNIGHT_HOME`,
  else `~/.queryknight`. It read `session.token` through
  `runtime::token::read_token_raw`, UTF-8 decoded and trimmed it; empty,
  unreadable, or non-UTF8 token disabled the endpoint.
- URL precedence was `QUERYKNIGHT_DAEMON_URL` over pid-file port over the
  resolved `QUERYKNIGHT_PORT`/default. A configured invalid URL failed
  discovery with no fallback. The private parser accepted only the literal
  `http://` prefix and loopback host names; because it splits on the first
  colon, the effective accepted hosts were `127.0.0.1` and `localhost`
  (neither raw nor bracketed IPv6 parsed successfully). It then connected to
  `127.0.0.1` regardless of hostname. Without an override, `daemon.pid` port
  was preferred; pid read/parse errors fell back to the resolved port.
- HTTP was hand-written over `std::net::TcpStream`; no client library.
  Connect, read, and write timeouts were each set to 5 seconds. These are
  per-blocking-operation socket timeouts, not a guaranteed total request
  deadline (a slow stream could extend `read_to_end`). Requests used
  `Host: 127.0.0.1`, `Connection: close`, JSON content headers, and
  `Authorization: Bearer …`; the token was not put in URL/path/query.
  Response reads used unbounded `read_to_end`; `Content-Length` was parsed
  when present, defaulted to zero when absent, and body bytes were required
  to contain at least that length. No chunked-transfer parser existed.
  JSON was decoded with `serde_json::from_slice`; response bodies were not
  copied into errors. `DaemonFailure` was a content-free unit type. The old
  `DaemonEndpoint` derived `Debug` and exposed its token; the shared client
  redacts it. The shared client also reads at most the centralized 4 KiB
  runtime token bound and caps HTTP headers at 32 KiB and responses at 1 MiB.
- Status handling varied by operation: JSON POST accepted any 2xx; list and
  GET approval/session-allow required 200. Missing/malformed fields became
  generic failure, `None`, or `false`; approval lookups/verification and
  session checks failed closed as waiting/false. MCP mapped list/decide
  failures to fixed protocol errors, never daemon body text.
- Generic operations were `POST /sessions`, `POST /events`, `GET /approvals`,
  `GET /approvals/:id`, `POST /approvals`, `POST /approvals/:id/verify`,
  `POST /approvals/:id/decide`, and `GET /allows`. Session creation used
  `{connectionKey, source:"mcp"}`. `/events` carried the existing full-SQL
  history payload and was best effort. Approvals-list JSON was formatted by
  MCP. Decide used `{status, source:"mcp"}`.
- Exact retries first checked fetched status, shape fingerprint, and binding
  kind, then used POST verify with digest/version/full scope; only an approved
  row plus a successful verify could return Approved. Digest traveled in the
  POST body only; raw SQL/parameters never crossed this HTTP boundary.
  Exact V1/V2 versions were checked by the daemon against stored typed
  bindings; ShapeV1 could not satisfy exact verification; LegacyShape was
  explicitly quarantined. The daemon verify route checked approved status,
  `now < expires_at`, binding version, all 32 digest bytes, and full scope.
- Explicit Session reuse used `/allows` with session, fingerprint, and all
  trusted scope dimensions. The daemon store returned only live,
  fully-bound session grants. The provider supplied a local-only approval id
  so qk-approval could mint a new request-specific permit. Once retry with a
  changed exact digest returned Waiting (fresh approval required), not
  Approved. Denied approvals returned Denied; expired/unknown/malformed/
  invalid-token responses never became Approved.
- Provider-specific functions mapped risk/operation summary and created exact
  bound waiting approvals. These, exact verification sequencing, and binding
  interpretation are reusable control-plane/approval responsibilities.
  MCP-specific responsibilities are history SQL classification/payload,
  startup source `"mcp"`, approval-list presentation, and user-facing fixed
  protocol error text.

### Shared extraction boundary

`qk-control-plane` owns `ControlPlaneClient`, typed daemon approval DTOs,
runtime-based discovery, authenticated loopback HTTP, and the single
`DaemonApprovalProvider` implementation. `qk-mcp` consumes that client for
approval tools, session bootstrap, and event recording; it retains only MCP
history shaping/classification and formatting. The provider remains
synchronous; a future async wire proxy must schedule it off Tokio core workers.
The client reuses `qk-daemon::runtime::{paths, token, singleton}` for home,
token, and pid/port discovery; `QUERYKNIGHT_DAEMON_URL` remains highest
precedence and an invalid override never falls back. `ControlPlaneClient`
exposes only typed session/event/approval operations
(`create_session`, `record_event`, `list_approvals`, `approval`,
`verify_approval`, `decide_approval`, `session_allows`, `create_approval`),
not arbitrary method/path requests. It uses the existing 5-second
connect/read/write socket timeouts (per blocking operation, not an absolute
deadline) and newly caps headers at 32 KiB and responses at 1 MiB. Token-file
decoding/trim and the 4 KiB bound come from the existing runtime token reader.
Control-plane errors are typed and content-free; MCP maps list/decide failures
to the same frozen fixed protocol messages.

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
