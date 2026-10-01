# Security audit (`qk-audit`)

Observation-only security decision records. Audit observes typed
outcomes; it never authorizes, never retries, never panics the
enforcement path. Audited TS behavior is in
`docs/reference-implementation.md` ("Observability audit"); this
document is the Rust contract.

## Model

One guarded execution or authorization attempt → one `Observation`
→ one `AuditEvent` (+ metrics). Execution observations derive from
`ExecutionOutcome`; authorization-only observations derive from
`AuthorizationOutcome`. Both add structural facts re-read from `qk-sql`
analysis (operation, tables, columns, statement count, parser status —
deterministic and side-effect-free, never a second policy evaluation).
Decisions are never reconstructed from message strings.

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
`outcome`: `authorized`/`executed`/`blocked`/`pending`/`failed`.
Execution detail fields (`error_kind?`, `error_message?`, `rows_affected?`,
`rows_shown?`, `truncated?`, `timeout_may_still_run?`) are omitted for
authorization-only `authorized` outcomes.

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

- Authorized: a QueryKnight authorization-only Allow; no external execution
  is asserted. `rows_affected`, `rows_shown`, and `truncated` are absent.
- Executed: result summary only (rows affected/shown, truncated,
  estimates, bytes/tokens, duration) — never the result set.
- Blocked: decision + reason + operation facts; `rows_affected`
  never implies execution.
- Pending: approval-required decision plus opaque approval id; no execution.
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
secret-free) and never feed back into authorization: execution results
remain unchanged, and authorization-only `Authorized` is never promoted
to an execution success. No retries or panics.

## History vs audit

Daemon `query_events` history (raw SQL, operational per-session log)
is a different record from security audit (leveled decisions, OCSF
export). MCP maintains both independently; neither duplicates the
other.

## OCSF

Deterministic `AuditEvent → OcsfEvent` conversion (OCSF 1.5.0,
Application Activity / API Activity, class 6003): deny →
7/Deny/High/Failure; require_approval → 0/Unknown/Low/Unknown;
executed allow → 6/Allow/Informational/Success; authorization-only
allow → 6/Allow/Informational/Unknown; failed execution → Allow/
Informational/Failure. `unmapped.qk_outcome` preserves the typed
authorization/execution outcome, and the full decision remains under
`unmapped.qk_*`. `undefined` stays omitted.

Hardening divergence: the prior Rust OCSF mapper used `decision` alone and
reported every Allow as Success. It now uses the typed outcome: DB execution
failure maps to Failure, while authorization-only `authorized` maps to Unknown.
Existing execution `AuditEvent` facts are unchanged. The TypeScript converter
still maps Allow to Success, but OpenShell never called that converter.

## Observe mode (NOT implemented — stop-and-report finding)

The reference `evaluate({mode: 'observe'})` turns non-allow
decisions into `allow` with `OBSERVED_<code>` reasons and
`enforced: false`. That is Deny→Allow security semantics, so per
the integration contract it is NOT ported: `evaluate()` is
untouched, `enforced` is always `true`, and the last deferred
fixture remains deferred pending an explicit security decision.
