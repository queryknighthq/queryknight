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
columns, indexes, v3 `binding_kind` column plus completeness promotion,
then the version stamp. A crash can never leave a half-applied schema
behind the stamp, and re-running is a no-op. No `DROP TABLE`, no rebuilds,
no data deletion. Converges: fresh files, TS `user_version` 0 (with or
without tables), and Rust v2 databases all end at version 3.

## Legacy field matrix (what can and cannot be reconstructed)

Per legacy row type, as the reference leaves it:

| Field | Legacy `approvals` row | Legacy `session_allows` row |
|---|---|---|
| shape fingerprint | present (16-hex) | present (16-hex) |
| exact request digest | **absent** — underivable from a 64-bit shape | **absent** |
| session_id | present or NULL | present (PK part) |
| integration | **absent** | **absent** |
| environment | **absent** | **absent** |
| database | **absent** | **absent** |
| agent_id | **absent** | **absent** |
| tool | **absent** | **absent** |
| expiry | present (`expires_at`) | **absent** (upstream rows never expire) |
| decision source | present or NULL | **absent** (a session approval existed) |

Nothing is inferred: no defaults, no wildcards, no current-context
fill-in. No legacy row is fully reconstructable, so **all** migrated
grants require reapproval for active use. (The v2->v3 promotion of
actually-complete rows exists only for databases already written by Rust
versions, never for TypeScript rows.)

Legacy approval migration:

- Rows are preserved verbatim and marked `binding_kind = 'legacy_shape'`
  (the default for every pre-existing row; complete rows are promoted to
  `exact_v1` by column-presence check).
- Legacy rows validate for history (`get_grant`, `list_grants`,
  `list_legacy_grants`) but can never satisfy authorization lookups:
  `find_session_grant` filters `binding_kind = 'exact_v1'` in SQL and
  re-checks in Rust; exact-token retry additionally requires digest
  equality against a real request digest.
- `session_allows` rows are never converted into grants (that would
  require inventing the missing scope dimensions). The table is preserved
  untouched for history; orphan rows authorize nothing.
- `decide_grant` still records human decisions on legacy waiting rows
  (mechanics work), but deciding does not upgrade binding: the row stays
  `legacy_shape` and authorizes nothing until a new fully-bound approval
  exists.

## Intentional divergence from the TypeScript runtime

Old QueryKnight: session + shape could authorize (session-allow rows, and
approval retry on fingerprint match).

Rust QueryKnight after migration: legacy session + shape grants remain
visible as history but require reapproval, because the old database lacks
the identity dimensions of the new security model. This is a deliberate
fail-closed hardening (INV-027), not exact persistence parity: migration
is non-destructive, but ambiguous authorization is disabled.

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

## ApprovalStore trait (qk-approval)

One fallible owned-value abstraction serves both backends:
`insert_grant` / `get_grant` / `find_session_grant` / `decide_grant`,
all returning `Result<_, ApprovalStoreError>` (`Unavailable`, `Conflict`,
`NotFound`, `InvalidState`, `CorruptState`, `Internal`) over owned
`StoredGrant` values — no borrowed rows, no infallible writes. Both
`InMemoryApprovalStore` and `qk_store::Store` implement it; `resolve()`
calls it identically either way, re-verifying binding, status, scope,
and liveness on every returned candidate (defense in depth: backends
narrow, qk-approval authorizes). Store failures during resolution map to
deny-side codes (`APPROVAL_ERROR`, or `APPROVAL_UNAVAILABLE` when no
provider could be consulted); a provider verdict that cannot be durably
recorded fails closed instead of executing. The trait requires
`Send + Sync` (both implementations hold it via short mutex sections)
so the future daemon can share one store across requests; no Tokio or
async runtime is involved at this layer.

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
