# V1 release security contract

## Scope and maturity

The existing direct database and proxy paths remain a **local / trusted-host**
technical preview. Separately, OpenShell v0.1.2 supervisor middleware is
supported over authenticated HTTPS with strict OpenShell extension JWT checks.
That integration does not add MySQL TLS or make the database paths
production-ready.

The source repository is public-ready under Apache-2.0, but it is **not yet
release-ready**: every QueryKnight crate and every product version surface
reports `0.1.0` from one workspace package declaration, and there is still no
Dockerfile, release artifact workflow, or published binary. Nothing has been
tagged, released, or published to crates.io. See
[the release checklist](release-checklist.md).

## Canonical execution guarantee

> For QueryKnight-owned execution paths, an executable database operation is
> forwarded or executed only after the current request receives a positive
> `ExecutionPermit`. Unsupported or unverifiable operations fail closed.

`authorize_guarded` has no adapter handle and is the permit-issuing boundary.
Permits are process-local, non-cloneable, and bind the current request. A Deny,
unsupported analysis, or unresolved approval does not authorize QueryKnight-
owned database execution.

**OpenShell is authorization-only and has an external-executor trust boundary.**
Its `ALLOW` means QueryKnight authorized the candidate observed at its boundary;
it does not prove a downstream executor ran it, used the same SQL/parameters,
or succeeded.

## Enforcement, evaluation-only, and legacy observe

- **Enforcement** is the current Rust execution model: a QueryKnight-owned
  database operation needs a positive current permit. Deny does not execute.
- **Evaluation-only/shadow** is a possible future diagnostic feature. It may
  report `would_allow`, `would_deny`, and `would_require_approval`, but must
  not issue a permit, execute SQL, consume Once approvals, create Session
  grants, or mutate approval state.
- **Legacy observe/bypass** is TypeScript-only: ordinary non-Allow outcomes can
  become `Allow` with `enforced=false`. It is not evaluation-only and is not
  shipped in Rust v1; see [the ADR](adr/observe-mode.md).

## Current transport matrix

| Surface | Client → QueryKnight | QueryKnight → database/backend | Current trust boundary |
|---|---|---|---|
| qk-db PostgreSQL direct | In-process API; MCP is a local stdio caller | Explicit `sslmode=disable` (plaintext through `NoTls`) or `sslmode=require` (verified TLS). Omitted `sslmode` parses as `prefer`; `prefer`/`allow` fail with typed `Unsupported` before network access, and `verify-ca`/`verify-full` are parser errors. `QUERYKNIGHT_PG_SSLROOTCERT` (trusted startup config) is the only trust anchor under `require`; an absent bundle uses the platform roots. A refusing, untrusted, or hostname-mismatched backend fails closed with no plaintext retry. | Direct adapter; MCP rejects unsupported transport during connection binding, and guarded direct execution validates before approval resolution. |
| qk-db MySQL direct | In-process API; MCP is a local stdio caller | Plaintext only. Parsed `SslOpts` are rejected as typed `Unsupported` before `Conn::new`; `require_ssl=false` is valid plaintext. Native TLS is not implemented and there is no downgrade. | Direct adapter; guarded execution blocks unsupported transport before approval resolution. |
| PostgreSQL wire proxy | Plaintext PostgreSQL wire protocol on loopback only. SSL/GSS encryption requests receive `N` (up to two refusals, then close); no frontend TLS termination. | One raw TCP backend session per frontend; backend config must explicitly use `sslmode=disable` (trusted plaintext) or `sslmode=require` (verified TLS, hostname checked against the certificate SAN). `prefer`/`allow` fail configuration; no fallback and no plaintext retry after a TLS failure. | SQL remains visible to the proxy for authorization. COPY, FunctionCall, replication startup, and CancelRequest forwarding fail closed. |
| MySQL wire proxy | Plaintext classic protocol on loopback only. `CLIENT_SSL` is filtered/rejected; compression/zstd and `CLIENT_LOCAL_FILES` are disabled. | One raw TCP backend session per frontend; TLS/socket/compression modes are rejected during proxy config validation. | Inspected COM_QUERY and supported prepared execution are authorized before forwarding. Unsupported commands are rejected rather than default-forwarded. |
| MCP | stdio only; local process integration; no HTTP/SSE/network listener | Uses the configured qk-db adapter. A PostgreSQL URL must explicitly specify `sslmode=disable` or `sslmode=require`; MySQL TLS requests fail during connection binding. | Tool arguments cannot choose the trusted dialect or connection. Protocol errors use the existing MCP error mapping. |
| OpenShell | Authenticated HTTPS + OpenShell extension JWT for v0.1.2 network middleware. Explicit `OpenShellInsecureLocal` stays loopback-only; Unix sockets are owner-only local test/integration paths. | No database connection or SQL execution by QueryKnight. Native DB TLS is unchanged. | Authorization-only middleware; OpenShell's `on_error` policy controls transport failure behavior. |
| Daemon/control plane | Loopback HTTP with a bearer token on protected routes; runtime token file is `session.token`. | No database protocol connection; it stores/resolves approvals and history. | Managed runtime binds loopback. The shared client rejects non-loopback daemon URLs and HTTPS. This is not a public remote API. |

OpenShell `ValidateConfig` has a strict allowlist. Defaults for optional
`database`, `environment`, and `dialect` apply only when a field is absent;
explicit null/wrong types and unknown fields fail validation. Failed
revalidation does not replace the prior validated registration. Rust
intentionally hardens the TypeScript parser's non-string `database`/`dialect`
fallback.

OpenShell records authorization-only outcomes (`AttemptOutcome::Authorized` /
`ObservedExecution::Authorized`). OCSF status is `Unknown` for that Allow;
only `AttemptOutcome::Executed` maps to Success. QueryKnight cannot prove what
the external gateway executes after the authorization RPC.

PostgreSQL backends support native verified TLS (`sslmode=require`), so the
inspected PostgreSQL hop can be encrypted in-band. MySQL backend TLS and both
frontend proxy legs remain plaintext; where encryption is required for those,
an operator may use an independently managed SSH tunnel, stunnel, service-mesh
sidecar, or private encrypted network. **QueryKnight does not provision,
authenticate, validate, or manage such a tunnel and does not provide end-to-end
TLS through it.**

## Supported deployment profile: OpenShell-gated PostgreSQL

One composition is live-verified end to end
(`scripts/test-openshell-postgres-v0.1.2.sh`):

```
OpenShell-controlled local/trusted frontend path
        +
QueryKnight verified PostgreSQL backend TLS
```

- the agent runs in an OpenShell v0.1.2 sandbox whose egress policy admits only
  the QueryKnight PostgreSQL proxy; a direct connection to the database is
  denied by OpenShell, so valid database credentials alone are not enough to
  bypass the architecture;
- QueryKnight terminates the PostgreSQL wire protocol, authorizes each
  statement, and forwards on the same backend session;
- the QueryKnight → PostgreSQL hop is verified TLS (`sslmode=require`, pinned
  CA, hostname checked against the certificate SAN).

This profile does **not** establish, and must not be read as:

- PostgreSQL frontend TLS — the sandbox → proxy leg is plaintext and local;
- a publicly reachable QueryKnight PostgreSQL listener — the proxy binds
  loopback only;
- MySQL TLS — not implemented;
- general production readiness — the maturity items in this document still
  apply.

The two OpenShell integration mechanisms are distinct: the HTTP middleware path
runs QueryKnight *inside* OpenShell for admitted egress and never sees
PostgreSQL traffic, while this profile uses OpenShell for network gating only
and QueryKnight for SQL enforcement. See
[`openshell-postgres-demo.md`](openshell-postgres-demo.md).

## Protocol support matrix

### PostgreSQL proxy

| Area | Supported behavior | Unsupported / fail-closed behavior |
|---|---|---|
| Startup and auth | Bounded protocol-v3 startup; configured user and effective database must match; supported auth frames are relayed; one backend TCP session per frontend. If frontend database is omitted it defaults to the requested user; backend URL database also defaults to user if omitted. | One backend TCP host only; unsupported startup parameters/non-empty `options` or `replication` rejected. SSLRequest/GSSENCRequest receive `N` at most twice; another request closes the connection. |
| Simple Query | Complete nonempty `Q` SQL is authorized with a fresh permit before the original frame is forwarded once. | Frontend TLS, COPY streaming, SQL SET passthrough, FunctionCall, replication, and CancelRequest forwarding are unsupported. Backend TLS is explicit `sslmode=disable` or `sslmode=require`. Empty `Q` is handled locally. |
| Extended Query | Parse/Bind/Describe/Close/Flush are setup only; Execute resolves the current per-frontend portal, authorizes exact SQL and ordered wire parameters (ExactV2), then forwards once. Prepared statements, portals, transaction state, and approvals remain per frontend. | Execute without a permit, malformed/unverifiable setup, COPY, FunctionCall, replication, CancelRequest, and frontend TLS fail closed; an unverifiable backend TLS mode also fails closed. No permit cache or reconnect/replay path. |

This is a guarded local PostgreSQL proxy for the implemented Simple and
Extended Query paths, **not** a fully transparent PostgreSQL gateway.

### MySQL proxy

| Area | Supported behavior | Unsupported / fail-closed behavior |
|---|---|---|
| Handshake/auth | Classic handshake relay with configured user/database identity checks; supported native-password and caching-SHA2 fast-auth exchanges are relayed. One backend session per frontend preserves transaction/session continuity. | TLS, `CLIENT_SSL`, cleartext/unknown/full-auth modes, compression/zstd, local files, and unmodeled capabilities are rejected/disabled. |
| COM_QUERY | Complete strict-decoded SQL is authorized with a fresh permit before one backend write; no SQL splitting or proxy-local grant cache. | `LOCAL INFILE`, unsupported admin/session-switch commands, and unknown commands are rejected. `CLIENT_MULTI_STATEMENTS` is cleared; batches are not forwarded as negotiated multi-statements. |
| Prepared statements | PREPARE is setup only. Each EXECUTE is authorized against statement SQL and ordered typed ExactV2 parameters. SEND_LONG_DATA is bounded and buffered until its matching permit; RESET/CLOSE follow the audited state machine. Transactions and prepared state are per frontend. | TLS, compression, query attributes, cursors/FETCH, `LOCAL INFILE`, unsupported admin/session changes, and prepared execution without a permit are rejected. |

The proxy supports COM_QUERY and the documented prepared-statement subset; it
is **not** full MySQL wire-protocol compatibility. MariaDB server compatibility
has not been live-validated. The `mariadb://` URL scheme is not accepted by the
resolved `mysql_async` URL parser; do not claim MariaDB support without separate
validation and live tests.

## Release/security readiness matrix

Classification meanings:

- **V1 BLOCKER** — must remain correct for any public technical-preview
  release; the current implementation is present, but a regression or missing
  release gate blocks publication.
- **PRODUCTION-MATURITY BLOCKER** — acceptable only under the explicitly local /
  trusted-host preview profile; required before a broader production/network
  claim that depends on it.
- **POST-V1 FEATURE** — intentionally not supported now and fail-closed where
  applicable; not required unless a later product claim includes it.

| Area | Current state | Security consequence | Classification | Required before broader production claim? |
|---|---|---|---|---|
| Policy enforcement | Deny-by-default evaluation and approval resolution; direct execution uses the guarded service. | Deny and unresolved approval do not authorize qk-owned execution. | V1 BLOCKER | Yes |
| SQL analysis | Multi-dialect AST analysis; incomplete, unknown, unsupported, or unverifiable analysis is refused on guarded paths. | Conservative failures reduce compatibility rather than create an allow path. | V1 BLOCKER | Yes |
| ExecutionPermit | Positive, request-specific, process-local capability; only the guarded authorization plane issues permits. | SQL/parameters/scope cannot be substituted after authorization. | V1 BLOCKER | Yes |
| ExactV1 | SQL-only identity for requests without bound parameters; retained for compatibility. | Once retries bind the exact SQL request. | V1 BLOCKER | Yes |
| ExactV2 | Shared canonical identity for parameterized requests, including dialect, SQL, ordered values, and wire metadata when present. | Prepared values cannot be changed while reusing an exact approval. | V1 BLOCKER | Yes |
| Once approvals | Exact, live, fully-bound approval; mismatch requires a fresh decision. | No changed request inherits a Once approval. | V1 BLOCKER | Yes |
| Session approvals | Live Session grant may authorize a same-shape request, but issuance still creates a new request-bound permit and checks full scope. | Session reuse does not reuse a prior executable capability. | V1 BLOCKER | Yes |
| LegacyShape | Persisted for history/migration but quarantined from authorization. | Historical incomplete bindings cannot execute. | V1 BLOCKER | Yes |
| Audit | Typed outcomes; sink failure is observational and cannot authorize, retry, or repeat execution. Durable external sink is optional. | Local preview may lack centralized durable audit retention. | PRODUCTION-MATURITY BLOCKER | Yes, for operationally auditable production deployments |
| Metrics | In-process counters/durations; no default public exporter or DB-success claim. | Operators need their own supported collection/alerting path. | PRODUCTION-MATURITY BLOCKER | Yes, where production operations require monitoring |
| MCP | stdio-only local process integration; no network listener. | Local process and configured DB endpoint are trusted inputs. | V1 BLOCKER | Yes |
| PostgreSQL Simple Query | Full SQL guarded before one original `Q` forward. | No partial forwarding on policy refusal. | V1 BLOCKER | Yes |
| PostgreSQL Extended Query | Parse/Bind are setup; every Execute is authorized against current portal SQL/parameters with a fresh permit. | Prepared identifiers cannot bypass per-Execute authorization. | V1 BLOCKER | Yes |
| MySQL COM_QUERY | Strict complete payload analysis and one permit-gated backend write. | Unsupported/oversized SQL is not default-forwarded. | V1 BLOCKER | Yes |
| MySQL prepared statements | Supported audited PREPARE/EXECUTE/SEND_LONG_DATA/RESET/CLOSE subset with ExactV2 and per-frontend state. | Prepared values and buffered long data cannot reach MySQL before a permit. | V1 BLOCKER | Yes |
| OpenShell | Authenticated HTTPS middleware for v0.1.2; local insecure mode is loopback-only. | Authorization Allow is not evidence of downstream execution or success. | PRODUCTION-MATURITY BLOCKER | Yes, before any claim of end-to-end external execution security |
| Direct PostgreSQL native TLS | Implemented as verified TLS (`sslmode=require`): hostname checked against the certificate SAN, `QUERYKNIGHT_PG_SSLROOTCERT` as the only trust anchor. Explicit `sslmode=disable` stays trusted plaintext; omitted/`prefer`/`allow` fail before network; `verify-ca`/`verify-full` remain parser errors. Live evidence: `scripts/test-postgres-tls.sh`. | No silent Prefer-to-plaintext downgrade and no retry after a failed handshake; trusted plaintext is explicit. | Resolved for PostgreSQL; MySQL native TLS remains a PRODUCTION-MATURITY BLOCKER | Yes |
| Direct MySQL native TLS | Not implemented. Parsed `SslOpts` fail with typed Unsupported before `Conn::new`; `require_ssl=false` is plaintext. Malformed/unknown URL options remain parser errors. | No TLS-to-plaintext downgrade. | PRODUCTION-MATURITY BLOCKER | Yes |
| PostgreSQL proxy frontend TLS | SSL/GSS requests receive `N`; no termination. | Clients must use plaintext on the local proxy leg. | PRODUCTION-MATURITY BLOCKER | Before recommending remotely exposed proxy listeners |
| PostgreSQL proxy backend TLS | TLS-required (`sslmode=require`) or explicit plaintext (`sslmode=disable`). TLS-required sends SSLRequest on the same socket before StartupMessage and requires `S`; `N`, handshake failure, untrusted certificate, and hostname mismatch all fail closed. Live evidence: `scripts/test-postgres-tls.sh` and the composed `scripts/test-openshell-postgres-v0.1.2.sh` run. | No fallback to plaintext and no verification bypass. | Resolved for PostgreSQL; frontend proxy TLS remains a PRODUCTION-MATURITY BLOCKER | Yes |
| MySQL proxy frontend TLS | `CLIENT_SSL` is filtered/rejected; no termination. | Frontend leg is plaintext and intended only for loopback. | PRODUCTION-MATURITY BLOCKER | Before recommending remotely exposed proxy listeners |
| MySQL proxy backend TLS | Native TLS is unsupported; TLS-required URL options fail proxy config. | No silent backend downgrade. | PRODUCTION-MATURITY BLOCKER | Yes |
| Remote OpenShell middleware | Authenticated HTTPS, strict EdDSA extension JWT, exact audience/issuer/caller/sandbox binding, local trusted JWKS, and fail-closed version negotiation are implemented for OpenShell v0.1.2. Unauthenticated remote, plaintext non-loopback, and unsupported mTLS remain rejected. | No token enters SQL/audit/control-plane state; the returned Allow is not proof of downstream execution. | Supported for v0.1.2; exact live-E2E evidence is recorded in the OpenShell compatibility matrix. | Yes, before any claim of end-to-end external execution security |
| Daemon remote exposure | Managed runtime is loopback HTTP with bearer token; shared client rejects non-loopback/HTTPS. A low-level explicit `allow_remote` option is not a recommended public mode. | No encrypted remote control-plane contract exists. | PRODUCTION-MATURITY BLOCKER | Yes, if remote daemon use is claimed |
| Legacy observe mode | Not present in Rust; legacy TypeScript Deny-to-Allow behavior is not shipped for security. | No compatibility bypass weakens permit enforcement. | V1 BLOCKER | Yes; keep it absent |
| PostgreSQL COPY | Unsupported and not forwarded. | Streaming data never bypasses SQL authorization. | POST-V1 FEATURE | No, while explicitly excluded |
| PostgreSQL FunctionCall | Unsupported and not forwarded. | Opaque function execution cannot bypass the SQL gate. | POST-V1 FEATURE | No, while explicitly excluded |
| PostgreSQL replication | Replication startup is rejected. | No replication stream bypass. | POST-V1 FEATURE | No, while explicitly excluded |
| PostgreSQL CancelRequest | Not forwarded; request closes locally. | Cancellation is not an unauthenticated side channel. | POST-V1 FEATURE | No, while explicitly excluded |
| MySQL LOCAL INFILE | Capability disabled; backend request is refused and file bytes are never relayed. | No client-file transfer through the proxy. | POST-V1 FEATURE | No, while explicitly excluded |
| MySQL cursors/FETCH | Cursor Execute flags and `COM_STMT_FETCH` are rejected. | No unmodeled fetch path. | POST-V1 FEATURE | No, while explicitly excluded |
| MySQL query attributes | Capability disabled and layouts are rejected. | Attributes cannot hide SQL semantics from inspection. | POST-V1 FEATURE | No, while explicitly excluded |
| MySQL compression | Compression and zstd are disabled/rejected. | No opaque compressed command path. | POST-V1 FEATURE | No, while explicitly excluded |
| MySQL admin/session switching | Unsupported commands are rejected; modeled SQL session changes follow policy and additional semantics fail closed. | No unmodeled database/user/session switch. | POST-V1 FEATURE | No, while explicitly excluded |
| MySQL multi-statements | `CLIENT_MULTI_STATEMENTS` is cleared; a complete COM_QUERY payload is authorized and is not split. | The server cannot execute a negotiated multi-statement batch; no safe-half forwarding. | POST-V1 FEATURE | No, while explicitly excluded |
| MariaDB validation | `mariadb://` is rejected by the MySQL URL parser; MariaDB server behavior has not been live-validated. | Do not claim MariaDB compatibility based on the MySQL protocol implementation. | PRODUCTION-MATURITY BLOCKER | Yes, if MariaDB support is claimed |
| Docker | No Rust Dockerfile/image is present, deliberately deferred: the proxy is loopback-only and the OpenShell PostgreSQL path needs operator-managed forwarding, so a container image would imply a deployment contract that does not exist yet. | No container installation or update contract. | POST-V1 FEATURE | Only if a Docker distribution is claimed |
| CI | No Rust CI workflow is present. | No automated clean-room gate for PRs/releases. | V1 BLOCKER | Yes |
| Release binaries | No versioned Rust release artifacts/checksums are present. | Users cannot verify a canonical published binary. | V1 BLOCKER | Yes |
| Clean-install verification | No release clean-install smoke is recorded. | Installation/startup assumptions remain unverified. | V1 BLOCKER | Yes |
| Version consistency | All workspace crates inherit one `[workspace.package] version = "0.1.0"`; CLI, daemon health, MCP `serverInfo`, and the OpenShell `Describe` implementation metadata all report `0.1.0`. | Protocol and format versions (policy schema, approval digest, OCSF, OpenShell extension) are separate and unchanged. | Resolved for source publication; binary release packaging remains open | Yes, for a binary release |

## Deployment assumptions and failure semantics

The first profile is **local / trusted-host technical preview**:

```text
local agent/client
    ├── stdio ───────────────> MCP ──────> qk-db direct adapter
    ├── loopback DB protocol ─> PostgreSQL/MySQL proxy
    └── Unix socket or loopback gRPC ────> OpenShell authorization
                                             └─> external gateway/executor

MCP / proxies ── loopback HTTP + bearer ──> daemon control plane

qk-db direct ── local SQLite file
qk-db or proxy ── explicit trusted plaintext link ──> database
          OR operator-managed tunnel ────────────────> database
```

QueryKnight provides no native PostgreSQL/MySQL TLS and does not verify an
operator tunnel. Never bind the DB proxies or OpenShell publicly as a workaround
for missing TLS. The daemon is a separate loopback HTTP control plane, not a
remote gateway.

QueryKnight avoids automatic replay and forwards/executes an authorized wire
operation at most once per received executable request where implemented. It
does not promise exactly-once database execution: after bytes reach a database,
a timeout, disconnect, cancellation, or transport error can leave the final
server-side outcome ambiguous. A client timeout/cancellation is not proof of
rollback or non-execution.

Use observability terms precisely: `Authorized` means authorization only;
`Executed` means qk-owned database execution returned; `Failed` is an execution
failure; `Blocked` is refusal without execution; `Pending` awaits approval.
OpenShell `Authorized` is never `Executed`. Audit/metrics sinks observe outcomes
and cannot change decisions or trigger retries.

## TypeScript compatibility classification

| Surface | Classification | Rust v1 disposition |
|---|---|---|
| Core policy and ordinary evaluation | PORTED | Compatibility-tested where security semantics agree. |
| Legacy observe/Deny-to-Allow | NOT SHIPPED FOR SECURITY | No Rust mode or compatibility switch; see [ADR](adr/observe-mode.md). |
| OpenShell `allow_with_findings` | NOT SHIPPED FOR SECURITY | Rust rejects the setting; it is separate from core observe. |
| Unsafe PostgreSQL/MySQL proxy default forwarding | INTENTIONALLY HARDENED | Unsupported/unverifiable protocol paths fail closed. |
| Parameterized approval identity | INTENTIONALLY HARDENED | Shared ExactV2 binds ordered parameter values and wire metadata. |
| LegacyShape approval rows | INTENTIONALLY HARDENED | Rows remain available as history/migration data but never authorize. |
| PostgreSQL/MySQL TLS preferences | INTENTIONALLY HARDENED | Native TLS is absent; supported plaintext must be explicit and unsupported TLS fails closed. |
| Vue UI port | DEFERRED | The Vue package remains TypeScript; the Rust daemon embeds the existing vendored distribution rather than implementing a Rust UI. |

Parity with the TypeScript oracle is not a reason to restore a less restrictive
security behavior.

## Release recommendation

**V1 blockers before publishing even a technical preview:** add a Rust CI gate,
synchronize package/runtime versions, produce reproducible release artifacts,
run clean-install/CLI/daemon/MCP/proxy smoke tests, and keep the README and
support matrices exact. There is no evidence of a remaining permit bypass or
silent TLS downgrade after the reviewed fixes, but live direct PostgreSQL and
MySQL evidence was unavailable in this environment (`PG_URL`/`MYSQL_URL` were
not configured).

**Production-maturity blockers:** native encrypted backend DB transport for
network deployments; authenticated encrypted remote daemon/control-plane
design if remote daemon use is desired; durable audit/metrics operational
integration; broader protocol/deployment validation; and MariaDB live
validation before claiming MariaDB compatibility. OpenShell remote middleware
support is limited to the verified v0.1.2 extension contract and does not
remove the separate database TLS blocker.

**Post-v1 features:** the explicitly rejected COPY/replication/FunctionCall/
CancelRequest, MySQL LOCAL INFILE/cursors/query attributes/compression, and other
unmodeled protocol commands may remain excluded unless broader compatibility is
claimed.

**TLS remains three separate projects:** (1) qk-db PostgreSQL backend TLS;
(2) qk-db and/or MySQL proxy backend TLS; (3) optional PostgreSQL/MySQL proxy
frontend TLS termination. OpenShell's authenticated HTTPS transport is a
separate middleware boundary already implemented; it does not provide native
database TLS.

**Next engineering phase: RELEASE PACKAGING NEXT.** For the explicitly local /
trusted-host preview, transport limitations are documented and fail closed;
packaging, CI, version synchronization, artifacts, and clean-install evidence
are the blockers. Proposed task: `build(release): establish reproducible 0.1.0 technical-preview artifacts`.
