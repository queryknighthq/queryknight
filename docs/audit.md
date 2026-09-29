# Security audit (`qk-audit`)

Observation-only security decision records. Audit observes typed
outcomes; it never authorizes, never retries, never panics the
enforcement path. Audited TS behavior is in
`docs/reference-implementation.md` ("Observability audit"); this
document is the Rust contract.

## Model

One guarded execution attempt → one `Observation` → one `AuditEvent`
(+ metrics). The observation is derived from already-existing typed
outcomes (`Decision`, `ReasonCode`, approval resolution,
`ExecutionOutcome`) plus structural facts re-read from `qk-sql`
analysis (operation, tables, columns, statement count, parser status
— deterministic, side-effect-free, never a second policy
evaluation). Decisions are never reconstructed from message strings.

Trusted identity (integration/environment/database/agent/tool/
session) comes from the caller's trusted context, never from agent
metadata. Connection keys are password-stripped upstream.

## Event

Frozen `AuditEvent` JSON shape (absent optionals omitted, never
`null`): `timestamp` (ISO-8601), `event_id` (UUID v4, CSPRNG;
caller-supplied in tests), `request_id?`, `agent_id?`,
`session_id?`, `integration`, `environment`, `database?`, `user?`,
`tool?`, `dialect`, `statements`, `operation`, `kinds`, `tables`,
`columns?` (metadata level+), `fingerprint` (16-hex shape, always),
`normalized_sql?` (metadata level+, ≤20000 chars), `sql?`
(full_sql only, ≤20000 chars), `decision`, `reason_code`,
`matched_policy?`, `approval_id?` (opaque public id only — never
digests), `duration_ms`, `parser_ok`, `enforced: true`, plus
execution facts (`outcome`: executed/blocked/pending/failed with
`error_kind?`, `error_message?` (bounded), `rows_affected?`,
`rows_shown?`, `truncated?`, `timeout_may_still_run?`).

Timestamps and event ids are supplied at the observation boundary
(no hidden clocks inside formatters; deterministic tests).

## SQL levels (frozen)

- `none`: no SQL text at all (ids + fingerprint only).
- `fingerprint`: default, safe (stable sha256 of literal-stripped SQL).
- `metadata`: + literal-stripped normalized SQL (existing
  `normalize_sql` — no third normalizer), tables, columns.
- `full_sql`: + raw SQL text (may contain secrets; opt-in only).

Default is `fingerprint`. Raw SQL appears only at `full_sql`, and
only from the observed request — never reconstructed elsewhere.
Truncation is UTF-8-safe (char boundaries) at 20000 chars.

## Redaction

Frozen `redact()`: `//user:password@` → `//user:***@`. Credentials
(passwords, tokens, `Authorization` headers, connection URLs) never
appear in audit output; only redacted placeholders or stripped keys.
Exact digests never appear (internal authorization material).
Sentinel-secret tests pin every surface (event JSON, OCSF JSON,
sink diagnostics, Debug).

## Approvals

Pending attempts carry the opaque approval id; granted/denied carry
id + source + scope facts from the typed resolution (no
state-machine duplication). Approval ids are public handles, never
secrets.

## Outcomes

- Executed: result summary only (rows affected/shown, truncated,
  estimates, bytes/tokens, duration) — never the result set.
- Blocked: decision + reason + operation facts; `rows_affected`
  never implies execution.
- Failed: typed DB kind + bounded message; timeouts preserve the
  may-still-run uncertainty (never "rolled back").
- Parse failures and metadata operations observe like any other
  attempt (parser_ok/distinct operation).

## Sinks

`AuditSink::record(&AuditEvent) -> Result<(), AuditSinkError>`
(sync; no Tokio required). Built-ins: `NoopSink`, `MemorySink`
(count/contents/failure-injection for tests; no globals).
No file sink exists in the frozen product — none is added.
Sink failures are returned for operational visibility (bounded,
secret-free) and never feed back into authorization: Allow stays
executed-once, Deny stays denied, no retries, no panics.

## History vs audit

Daemon `query_events` history (raw SQL, operational per-session log)
is a different record from security audit (leveled decisions, OCSF
export). MCP maintains both independently; neither duplicates the
other.

## OCSF

Deterministic `AuditEvent → OcsfEvent` conversion (OCSF 1.5.0,
Application Activity / API Activity, class 6003): deny →
7/Deny/High/Failure(4/2), require_approval → 0/Unknown/Low/Unknown
(2/0), allow → 6/Allow/Informational/Success(1/1); product
QueryKnight+version; actor from agent/user; `api.operation =
"<integration>:<operation>"`; the full decision preserved under
`unmapped.qk_*`. `undefined` stays omitted. Non-executed attempts
still emit (never labeled successful DB activity).

## Observe mode (NOT implemented — stop-and-report finding)

The reference `evaluate({mode: 'observe'})` turns non-allow
decisions into `allow` with `OBSERVED_<code>` reasons and
`enforced: false`. That is Deny→Allow security semantics, so per
the integration contract it is NOT ported: `evaluate()` is
untouched, `enforced` is always `true`, and the last deferred
fixture remains deferred pending an explicit security decision.
