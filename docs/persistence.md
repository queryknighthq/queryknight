# QueryKnight persistence (`qk-store`)

SQLite state for the future daemon: approvals, sessions, query events,
connections. No HTTP, no auth, no background tasks here.

## Database location

The reference daemon opens `~/.queryknight/queryknight.db`
(`QUERYKNIGHT_HOME` override). `Store::open` takes an explicit path and
creates parent directories; file placement stays a daemon concern.

## Schema versions

Single mechanism: `PRAGMA user_version`. Current version: **2**.

- Version 1 is the TypeScript schema verbatim: `connections`, `sessions`,
  `query_events`, `settings`, `approvals`, `session_allows`. No indexes,
  no foreign keys, no version tracking (the reference never sets
  `user_version`, so legacy databases read as 0).
- Version 2 adds approval columns (`exact_digest BLOB`, `integration`,
  `environment`, `database_name`, `agent_id`, `tool`, `reason_code`,
  `matched_policy`, `decided_by`) and two indexes (see below).
- Fresh files are created at version 2 in one transaction. Legacy
  databases (version 0 *with* tables) migrate 0 -> 2 directly. A version
  above 2 is refused with `SchemaMismatch`.

The `settings` table is created for schema compatibility but has no API:
nothing in the reference reads or writes it.

## Tables and indexes

All six reference tables with identical columns and constraints, plus the
v2 approval columns above. Indexes (the reference has none; these two are
driven by actual lookups, nothing speculative):

- `approvals_session_fingerprint (session_id, fingerprint)` — session-grant scans.
- `query_events_session_started (session_id, started_at)` — per-session listings.

## PRAGMAs

- `journal_mode = WAL`: reference parity; daemon read concurrency.
- `busy_timeout = 5000 ms`: deliberate addition (the reference sets no
  timeout and fails fast). Contention surfaces as typed `Busy`, never
  hangs. Tunable via `set_busy_timeout` (tests use 50 ms).
- Nothing else is tuned: `synchronous`, `foreign_keys` (no FKs exist),
  and cache settings stay at SQLite defaults for lack of evidence.

## Migration strategy

One transaction: v1 DDL (`IF NOT EXISTS`), tolerant column repair via
`PRAGMA table_info` (mirrors the reference checks, and also backfills the
historically added `schema_ddl`, `schema_diff`, `sql` columns), v2
columns, indexes, orphan session-grant adoption, then the version stamp.
A crash can never leave a half-applied schema behind the stamp, and
re-running is a no-op. No `DROP TABLE`, no rebuilds, no data deletion.

Legacy approval migration:

- Rows without `exact_digest` (or without any scope dimension) validate
  with `legacy_shape_only`: they keep frozen session+shape matching but
  can never satisfy strict scope comparison or exact-token replay (a
  synthesized digest can never equal a real request digest).
- Orphaned `session_allows` rows (no matching approved session approval)
  are adopted as synthetic approved session grants with deterministic
  `qkam-<session>-<fingerprint>` ids (idempotent by existence check,
  unbounded expiry like the reference rows they mirror).
- `session_id` is required for session matching; scope dimensions compare
  exactly otherwise.

## Shape vs exact identity persistence

- `fingerprint TEXT`: frozen 16-hex shape identity (compat display,
  session-shape binding, `/allows`-style lookups).
- `exact_digest BLOB`: 32 raw bytes, strict length check on read.
  Anything else (wrong length, and any use of the shape value as an
  exact digest) is `InvalidRow`.
- Scope dimensions are explicit nullable columns (`integration`,
  `environment`, `database_name`, `agent_id`, `tool`); `NULL` means
  legacy-unknown and never wildcards for new rows.

## Expiry semantics

Milliseconds since epoch everywhere (frozen unit). Live means
`now_ms < expires_at_ms`; equality is expired (reference boundary).
Reads never consult a clock: `get_grant` returns rows as stored,
`find_session_grant` takes `now_ms`, `decide_grant` enforces liveness in
the conditional update, `expire_due(now_ms)` persists the waiting->expired
flip explicitly, and `list_grants(now_ms)` applies the reference lazy flip.

## Invalid-row behavior

Point lookups (`get_grant`, `get_session`) return `InvalidRow` on bad
digests, unknown status/scope/source/reason values, negative timestamps,
or short fingerprints. Scans (`list_grants`, session lookup, event and
session listings) skip invalid rows: skipped rows can never authorize
anything. Unknown persisted enums are never defaulted.

## Concurrency model

One connection behind a `Mutex` (`Send`+`Sync`); short critical sections
(single statements or the record+trim transaction). Decisions use an
atomic conditional update (`WHERE status='waiting' AND expires_at > ?`),
so exactly one concurrent decider wins and losers observe
`NotWaiting`/`Expired`/`NotFound` deterministically — no timing
assumptions. Connection inserts use `INSERT OR IGNORE` (deterministic
under races, unlike the reference SELECT-then-INSERT).

## State transitions

`waiting -> approved`, `waiting -> denied` (via `decide_grant` with an
explicit reuse mode and source), and `waiting -> expired` (via
`expire_due` or the conditional-update guard). Decided rows reject further
decisions; transitioning *to* waiting is refused. Terminal states are
terminal.

## Filesystem state (deferred to the daemon commit)

Session tokens, `daemon.pid`, `daemon.log`, and DB file permissions: the
reference owns token-file modes only; nothing here manages filesystem
policy. SQLite files remain backup-compatible (single-file database, no
external blobs).
