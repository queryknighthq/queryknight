# Browser UI serving (`qk-daemon` static surface)

The existing Vue SPA (`apps/ui`, served from its production `dist/`)
as delivered by the Rust daemon. The daemon owns delivery only —
asset bytes, fallback rules, and browser security headers. It never
owns Vue logic, approval semantics, or SQL evaluation. Audited TS
behavior is in `docs/reference-implementation.md` ("Static UI serving
audit"); this document is the Rust contract.

## Source/build/packaging

- Source: the TS-repo Vue app, used as-is (no rewrite, no visual
  changes). Production bundle: `dist/{index.html,
  assets/index-<hash>.js, assets/index-<hash>.css}` (~80K).
- Node/Vite are build-time only. The daemon never runs npm/vite at
  startup; missing assets are a build/packaging error.
- Strategy: **embedded** (`include_bytes!` over a vendored
  `crates/qk-daemon/ui/` copy of `dist/`). One-binary deployment, no
  asset-path discovery, no version skew, no traversal class, no extra
  dependency. Rebuild procedure: `vite build --outDir <tmp>` in
  `apps/ui` (works offline from checked-in `node_modules`), then
  byte-compare against the vendored copy; CI fails on mismatch so Rust
  tests can never pass against a stale/broken bundle.
- Version match: UI package version equals daemon version
  (`0.1.0-beta.0`); the bundle IS the version — no network version
  check. No source maps ship (vite default off; none in dist).

## Route precedence

1. Exact API routes (frozen 1631702 behavior, unchanged).
2. Embedded static files by path (`/assets/*`, `/index.html`).
3. SPA fallback: `GET`/`HEAD` non-API paths without a file match
   serve `index.html` (deep links render the tab SPA; there is no
   Vue router — session/tab state lives in JS).
4. API-shaped unknown paths (`/approvals/...`, `/sessions/...`,
   `/activity`, `/events`, `/allows`, `/connections` — the frozen
   `isApiPath` shape list) answer the frozen JSON
   `{"error": "not found"}` 404, never `index.html`.
5. Recognizable asset misses (`/assets/*` with no such file) answer
   plain 404, never HTML (prevents HTML-with-JS-expectations; the TS
   serves index.html here — deliberate divergence).
6. Non-GET/HEAD on non-API paths: 404 (no SPA fallback for writes).

## Token bootstrap (frozen UI contract)

- `GET /?token=SECRET` serves `index.html`; the bundle stores
  `localStorage.qk_token = SECRET` (unconditionally overwriting any
  stored value, no validation) and immediately strips the query via
  `history.replaceState` — no redirect, no navigation, before the
  first API call.
- After bootstrap every API call uses `Authorization: Bearer`
  (same-origin relative paths, port-agnostic). `?token=` is never
  reused by the UI; the server keeps accepting it as
  compatibility-only transport.
- Invalid tokens are stored blindly; the UI then shows API 401s.
  There is no logout/clear control (out of scope).
- Static assets never require auth; API data always does.

## Response headers

- `Referrer-Policy: no-referrer` on HTML/bootstrap responses (the
  bootstrap query is credential-bearing; referrers must never carry
  it). TS sends none — hardening.
- `Content-Security-Policy` on HTML: `default-src 'self'; script-src
  'self'; style-src 'self'; img-src 'self' data:; font-src 'self';
  connect-src 'self'; object-src 'none'; base-uri 'none';
  form-action 'self'; frame-ancestors 'none'`. Verified against the
  actual bundle: hashed external JS/CSS only, no inline
  scripts/styles, logo inlined as data URI (hence `data:` for img),
  same-origin fetch only. No `unsafe-eval`, no `*`, no `https:`.
- `X-Frame-Options: DENY` alongside `frame-ancestors 'none'`
  (defense in depth for older browsers).
- `X-Content-Type-Options: nosniff` on HTML and assets (MIME types
  are exact first: html/js/css/json/svg/png/jpeg/webp/ico/woff/woff2).
- CORS unchanged (frozen localhost echo + preflight); same-origin UI
  needs nothing new, and no `*` is added.
- Host/Origin gates unchanged (1631702).

## Caching

- `index.html` + SPA fallback: `Cache-Control: no-store` (always
  fresh shell; doubles as the bootstrap rule below).
- Hashed assets (`/assets/index-<hash>.js/css`): `Cache-Control:
  public, max-age=31536000, immutable`.
- Any response to a request carrying `?token=`: `Cache-Control:
  no-store`, overriding the hashed-asset rule (credential-bearing
  URLs must never sit in caches).
- No compression (not in TS; correctness/security first).

## Log hygiene

`GET /?token=SECRET` must never land SECRET in `daemon.log`. The
operational logger only emits fixed lifecycle strings, and no request
logger exists; pinned by an integration test asserting the log file
contains no token after bootstrapped requests.

## Non-default ports

The bundle uses relative API paths, so an ephemeral-port daemon just
works: open `http://127.0.0.1:<port>/?token=...` and every call stays
same-origin. Covered by test.

## Intentional divergences from TS

1. Embedded (not disk-read-per-request) assets.
2. API-shaped unknown GETs stay JSON 404 (frozen 1631702) instead of
   falling into `index.html`.
3. `/assets/*` misses are 404 instead of 200 `index.html`.
4. Added: CSP, `no-referrer`, `DENY` framing, `nosniff`, and the
   no-store/immutable cache split (TS sends none of these).
