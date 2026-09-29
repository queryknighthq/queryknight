# Daemon HTTP API (`qk-daemon`)

Control-plane HTTP surface. This is a port of `packages/daemon/src/app.ts`
(Hono on `Bun.serve`); behavior below is frozen against the reference,
quirks included. Anything not listed here does not exist: query execution,
cursor paging, token files, pid files, autostart, and static UI serving are
deferred to the runtime-lifecycle commit (tracked in
`docs/rust-migration-plan.md`).

## Transport

- Bind: `127.0.0.1:47821` by default. Non-loopback bind is refused unless
  explicitly opted in (`DaemonConfig::allow_remote`); the listener address is
  asserted loopback at serve time (fail closed).
- `Host` must be loopback or `localhost`, else `403 invalid host` (text).
- `Origin`, when present, must be loopback/`localhost`/`null`/absent, else
  `403 invalid origin` (text). Valid localhost origins get CORS
  `Access-Control-Allow-Origin` echo; `OPTIONS` preflight answers `204`
  without authentication (browsers never send credentials on preflight).
- Auth (constant-time compare, argon of the reference `timingSafeEqual`):
  `Authorization: Bearer`, `?token=`, or `x-qk-token`. Failures are
  `401 unauthorized` (text), byte-identical shape to the reference.
  Unauthenticated: `GET /status`, `/health`, `/ready` only.
- Limits: request bodies over 1 MiB are `413`; requests over 30s are `408`.
- Method mismatch on a known path is `404` (Hono default), not `405`.

## Errors (frozen)

- Unknown API row (approval/session/event lookup): text `not found`, 404 —
  the reference answers `c.text('not found', 404)`.
- Unknown path: JSON `{"error": "not found"}`, 404. The reference serves its
  SPA bundle here when a UI build exists; without static serving the
  contract is a plain 404 (documented deviation).
- Decide on an unknown, decided, or expired approval: `400` with the exact
  text `Error: approval not waiting` (the reference collapses all three;
  its `decide` path throws `Error: approval not waiting` for any
  non-`waiting` row, and unknown ids flow through the same branch).
- Malformed JSON / failed validation: `400` (or `422` from the JSON
  extractor on type errors), never a store-shaped 500. The reference hits
  SQLite `NOT NULL` violations as 500s on missing fields; this port
  validates first and answers `400`.
- Store failures map fail-closed: busy → `503`, conflict → `409`,
  unknown row → `404`, corrupt row → `400`, everything else → `500
  internal error`. No rusqlite/engine text ever leaves the process.
- The token never appears in logs, `Debug`, or `Display` output
  (redaction wrapper; pinned by test).

## Browser/static surface

The embedded Vue SPA shell and assets (full contract:
`docs/browser-ui.md`). Delivery rules affecting API clients:

- `GET`/`HEAD` of non-API paths need no token (SPA shell, static
  assets); every API-shaped path still requires it. (`HEAD` is
  included though the reference only exempts `GET`: HEAD is bodyless
  GET and browsers/CDNs rely on it.)
- Precedence: exact API routes > embedded files > SPA fallback for
  browser-owned `GET`/`HEAD` > frozen JSON 404 for API-shaped
  unknowns (`/approvals/...`, `/sessions/...`, `/activity`,
  `/events`, `/allows`, `/connections`) > plain 404 for `/assets/*`
  misses and non-GET/HEAD misses.
- `index.html` and any `?token=` response: `Cache-Control: no-store`.
  Hashed `/assets/*`: `public, max-age=31536000, immutable`.
- HTML carries restrictive CSP, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, `nosniff`; assets carry `nosniff`.

## Endpoints

| Method + path | Auth | Body / params | Success | Notes |
|---|---|---|---|---|
| `GET /status` | no | — | `{ok, pid}` | Liveness, no store contact. |
| `GET /health` | no | — | `{ok, version}` | Static version marker. |
| `GET /ready` | no | — | `{status: "ok", checks: [{name: "store", ok}]}` | Non-destructive schema probe; degraded answers `503` with `status: "degraded"`. |
| `GET /activity` | yes | — | newest-first event views (cap 100) | Frozen event view shape below. |
| `POST /events` | yes | `{sessionId, connectionKey, source, sqlFingerprint, sql?, classification: {class, risk}, decision?}` | created event view | Mints `qke_<12hex>`; upserts the connection; `decision` defaults to `executed` (reference client default). |
| `GET /sessions` | yes | — | newest-first session summaries | |
| `POST /sessions` | yes | `{connectionKey, source}` | session summary | Mints `qks_<12hex>`; upserts the connection. |
| `GET /sessions/{id}` | yes | — | session summary | Unknown id: text `not found`. |
| `GET /sessions/{id}/events` | yes | — | chronological event views | |
| `GET /connections` | yes | — | `{id, name, engine, environment, source, database?, hostLabel?, lastUsedAt?}` | No URL/secret fields on the wire (reference `ConnectionMetadata` shape). |
| `GET /approvals` | yes | — | newest-first approval views incl. legacy rows | |
| `POST /approvals` | yes | `{connectionKey?, sessionId?, fingerprint (16hex, required), reason, risk, operationSummary, timeoutMs? (=60000), integration?, environment?, database?, agentId?, tool?, schemaDdl? (array)}` | approval view, `status: waiting`, `bindingKind: shape_v1` | Server mints `qka_<8hex>`; HTTP creation never sees SQL so the binding is always shape. `schemaDdl` round-trips opaquely; non-array is `400`. |
| `GET /approvals/{id}` | yes | — | approval view | Unknown id: text `not found`. |
| `POST /approvals/{id}/decide` | yes | `{status: approved\|denied, source?: tui\|cli\|ui\|mcp (=ui), scope?: once\|session (=once)}` | decided approval view | Unknown/decided/expired → frozen `400` text (see above). Invalid enum → `400`/`422`, nothing stored. |
| `POST /approvals/{id}/schema-diff` | yes | `{schemaDiff: [...]}` | approval view with `schemaDiff` | Unknown id: text `not found`; non-array: `400`. |
| `GET /allows?sessionId=&fingerprint=` | yes | — | `{allowed: bool}` | Session-shape check for legacy enforcement paths; missing params answer `false`; only fully-bound session grants count. |

## Frozen view shapes

- Approval: `{id, fingerprint, database?, reason, risk, operationSummary,
  timeoutMs?, status, scope ("once"\|"session"\|null), integration?,
  environment?, agent?, tool?, bindingKind ("exact_v1"\|"shape_v1"\|"legacy_shape"),
  schemaDdl?, schemaDiff?, decidedAt?, decidedBy?, createdAt, expiresAt}`.
  Legacy history rows surface with `bindingKind: legacy_shape` and can never
  authorize (INV-027).
- Session summary: `{id, name, connectionId, engine, agent?, source,
  queries, reads, writes, highRisk, sensitiveTables, startedAt, lastActivityAt,
  endedAt?}`. Counts derive from recorded events; the `main` session only
  exists in-memory in the reference and is not a stored row here.
- Event: `{id, sessionId, fingerprint, operation, risk, decision,
  startedAt, endedAt?}`.
- `operation` derives from the stored query class (`read`→`select`,
  `write`→`write`, `schema`→`schema`, else `query`) and `risk` from the
  class/risk pair (`high`+`ddl`→`schema_change`, matching the reference
  `operationFor`/`riskFor` mapping).

## Concurrency

Exactly one concurrent decider wins: the conditional `UPDATE ...
WHERE status='waiting' AND expires_at > now` is atomic under SQLite
write serialization; losers deterministically observe the frozen `400`
text. Covered by an integration test that races two decisions.
