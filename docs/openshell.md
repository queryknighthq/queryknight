# OpenShell integration audit and Rust contract

This document records the historical TypeScript adapter audit and the current Rust integration contract. OpenShell v0.1.2 at commit `6648bd0c290efbc41ba131ee9831ee45cd431f94` is the protocol and runtime compatibility source of truth; its imported `extension.proto` and `supervisor_middleware.proto` are byte-for-byte retained under `crates/qk-openshell/proto/` with provenance and SHA-256 values in [`third_party/openshell/README.md`](../third_party/openshell/README.md). The sibling TypeScript adapter remains a historical source audit only; it is not the authenticated Rust server contract.

The historical TypeScript package uses `@grpc/grpc-js` and `@grpc/proto-loader` as peer dependencies. `service.ts` accepts a caller-supplied proto-loader/runtime; it does not load or vendor generated stubs. The adapter is authorization middleware for traffic executed by OpenShell or another upstream service. It does **not** open a database driver or execute SQL itself. A returned `Allow` is therefore a synchronous decision to a trusted external gateway, not a serializable QueryKnight `ExecutionPermit` and not a cryptographic guarantee that a later external executor will run identical bytes. The Rust port retains that trust boundary rather than claiming QK owns the external side effect.

## Fifty-point TypeScript audit

| # | Audited behavior | Source evidence |
|---:|---|---|
| 1 | OpenShell is the network/sandbox gate; QueryKnight classifies SQL found in HTTP/WebSocket traffic. | `examples/openshell/README.md`; `src/service.ts` comments |
| 2 | The adapter protocol is gRPC supervisor middleware. | `src/service.ts`; `proto/supervisor_middleware.proto` |
| 3 | Main protobuf package is `openshell.middleware.v1`; the imported peer-metadata package is `openshell.extension.v1`. | Local proto and upstream `extension.proto` |
| 4 | Supervisor schema is `packages/integrations/openshell/proto/supervisor_middleware.proto`; its imported `extension.proto` is not locally vendored. | OpenShell proto directory listing |
| 5 | Declared RPCs: `SupervisorMiddleware.Describe`, `ValidateConfig`, `EvaluateHttpRequest`, `EvaluateWebSocketSession`; `HttpResponsePreReturn.Evaluate`. | Proto services |
| 6 | Describe/ValidateConfig/HTTP evaluation are unary; WebSocket and HTTP response evaluation are bidirectional streams. The TypeScript gRPC implementation registers only the three unary SupervisorMiddleware handlers; it has no `EvaluateWebSocketSession` or `HttpResponsePreReturn.Evaluate` handler. | Proto; `src/service.ts:210-265` |
| 7 | Requests are `MiddlewareDescribeRequest`, `ValidateConfigRequest`, `HttpRequestEvaluation`, and the WebSocket/response event oneofs. | Proto message declarations |
| 8 | Responses are `MiddlewareManifest`, `ValidateConfigResponse`, `HttpRequestResult`, and the WebSocket/response result oneofs. | Proto message declarations |
| 9 | Decision enum numeric values are unspecified `0`, allow `1`, deny `2`; no pending value exists. Validation returns `valid` plus a reason string. | Proto `Decision`, `ValidateConfigResponse`; `service.ts` constants |
| 10 | `Describe` advertises operation/phase bindings, `max_payload_bytes`, `expected_audience`, and peer extension metadata. Request-context, header, target, body and metadata limits are in proto comments. Current handler sets `expected_audience` to empty and `extension` to `{}`. | Proto; `describe()` and `buildGrpcImplementation()` |
| 11 | Intended gateway lifecycle: Describe at registration/startup, ValidateConfig before accepting a binding, then per-request evaluation. | Proto comments; `examples/openshell/README.md`; TOML comments |
| 12 | Runtime startup is a library call: `serveGrpc({address, loadPackage})` loads a runtime, creates a server, registers a caller-loaded service definition and binds it. | `src/service.ts:267-298` |
| 13 | OpenShell discovers/registers a service through the gateway manifest; QueryKnight does not discover a DB from the HTTP request. | Proto; gateway TOML/example |
| 14 | TypeScript accepts an explicit address; the checked-in gateway example uses `unix:///run/queryknight/middleware.sock`. No default listen address exists. | `serveGrpc`; `supervisor-middleware.toml` |
| 15 | OpenShell’s admitted target is selected by its network policy and carried in `HttpRequestTarget`; QueryKnight’s handler ignores target/headers and the external gateway performs the upstream connection. | Proto; `buildGrpcImplementation()` |
| 16 | The OpenShell package defines no environment variables. The root README’s `QUERYKNIGHT_POLICY_FILE` example is for MCP, not OpenShell. | package manifest; CLI grep; README |
| 17 | There is no `queryknight openshell` CLI command. The package scripts are `build` and `demo`; `serveGrpc` is a library helper. | Package manifest; `packages/cli` search |
| 18 | Gateway registration config includes `database`, `dialect`, `environment`, `approval_action`, and `policy_yaml`; the inspector requires `policy_yaml`, defaults dialect to `postgres`, database to `main`, environment to `production`, and approval action to `deny`. Unknown config fields are ignored. | `parseInspectorConfig`; example TOML |
| 19 | The package does not autostart a service or daemon. A host must call `serveGrpc`; no server stop handle is returned. | `package.json`; `serveGrpc` |
| 20 | Integration identity is the literal `openshell`, assigned in `baseContext`, not read from request metadata. | `src/inspector.ts:93-103` |
| 21 | No DB URL, saved connection name, host, credentials, or connection key is selected by this integration. It uses a policy `database` label and configured dialect; OpenShell owns the external target. | `InspectorConfig`; example TOML; no DB adapter dependency |
| 22 | HTTP bodies are decoded as UTF-8 text, JSON-inspected for MCP/OpenAI/generic `sql`/`query`/`statement` fields, or sniffed as raw SQL after leading comments. WebSocket text uses the same extractor. | `src/service.ts:205-208`; `src/sql-extract.ts` |
| 23 | Dialect is a string in service config, defaulting to PostgreSQL; it is not derived from a QueryKnight saved connection and current parser does not validate it in `parseInspectorConfig`. | `InspectorConfig`; `parseInspectorConfig` |
| 24 | The proto carries an opaque HTTP body, not a typed SQL parameter list. The TypeScript extractor returns SQL/source only and drops JSON `params`/bind values; Rust preserves an adjacent JSON `params` array as ordered `ExecutionParam`s and rejects unsupported encodings or placeholders without explicit values. | Proto `HttpRequestEvaluation`; TypeScript `ExtractedSql`; Rust extractor and shared AST marker helper |
| 25 | Policy YAML is parsed from the gateway-supplied registration config; `ValidateConfig` calls the same parser. | `validateConfig`; `parseInspectorConfig` |
| 26 | Approval is non-interactive: a singleton `WaitingProvider` returns a synthetic `openshell-<eventId>` waiting result. No daemon provider is used. | `WaitingProvider` |
| 27 | Proto has no pending decision/status or approval-ID response field. With default config, `require_approval` becomes deny with `queryknight_require_approval`; no ID is returned. | `Decision`; `evaluateHttpRequest`; inspector tests |
| 28 | There is no approval-ID retry path in the gRPC request. Repeated calls re-evaluate independently. | `HttpRequestEvaluation`; handler |
| 29 | Deny is `Decision.DENY` plus `queryknight_<normalized reason>` and findings; free-form reason is returned as empty by the handler. | `toReasonCode`; `buildGrpcImplementation` |
| 30 | No DB execution or driver call occurs in the OpenShell package; it only returns a verdict. | Imports and handlers in `src/service.ts`/`src/inspector.ts` |
| 31 | OpenShell/gateway or another downstream tool executes the allowed HTTP operation. QueryKnight cannot prove that a later external executor uses the same operation after the RPC returns. | README architecture; no DB driver or execution call |
| 32 | The integration defines no RPC/deadline timeout. Example gateway config sets 500ms; individual proto binding request timeouts are optional and the server does not enforce them. | TOML; proto; `serveGrpc` |
| 33 | gRPC cancellation is not propagated to `evaluate`; no cancellation/rollback promise exists. | `buildGrpcImplementation`/inspector signatures |
| 34 | Policy session identity is `RequestContext.sandbox_id`; missing IDs remain absent. WebSocket proto has a separate stream `session_id`, but the current gRPC adapter does not use it. | `baseContext`; proto |
| 35 | No authenticated agent ID is assigned. `RequestContext.originating_process` is ignored. | `baseContext`; `RequestContext` |
| 36 | No tool identity is assigned by `baseContext`; extraction source labels are audit-only strings. | `baseContext`; extractor |
| 37 | Environment and database policy identity come from service config, not the request’s destination host. | `baseContext`; `parseInspectorConfig` |
| 38 | Caller identity/authentication is not verified by the historical TypeScript server: `serveGrpc` uses insecure credentials and ignores peer metadata. Its checked-in example uses a Unix socket. The Rust server now supports authenticated HTTPS/JWT network mode and keeps explicit local Unix/loopback development modes; see the Rust implementation below. | `serveGrpc`; `supervisor-middleware.toml`; `OpenShellServer`; `docs/openshell-compatibility.md` |
| 39 | The OpenShell package does not record QueryKnight daemon query history or call `qk-control-plane`. | Imports and package dependencies |
| 40 | `inspectCandidates` supplies `auditSink` to each core `evaluate`; the callback appends to `InspectionResult.audit`, and core `evaluate` swallows sink exceptions. The gRPC handler returns only decision/reason/findings, so this collected audit array is discarded and there is no configured sink. | `src/inspector.ts:143-150`; `packages/core/src/evaluate.ts:53-65`; `src/service.ts:240-258` |
| 41 | Core exposes an `AuditEvent → OcsfEvent` converter, but OpenShell neither imports/calls it nor gives the in-memory audit array to an external sink. | `packages/core/src/ocsf.ts`; OpenShell imports and response mapping |
| 42 | Metrics are optional on low-level handlers; `createServiceState()` creates a registry, but `serveGrpc()` calls `buildGrpcImplementation()` without passing it. The actual gRPC path records no metrics. | `src/service.ts:86-142,210-298`; `src/inspector.ts:143-152` |
| 43 | Package load/bind errors reject `serveGrpc`; there is no supervisor/retry/autostart wrapper. | `serveGrpc` |
| 44 | If policy requires approval, default behavior denies. No daemon is contacted; runtime unavailability is left to gateway `failure_policy = "fail_closed"`. | `WaitingProvider`; TOML |
| 45 | Invalid config returns `valid=false` from ValidateConfig; Evaluate returns deny `queryknight_bad_config`. Invalid JSON falls through to raw-SQL sniffing; malformed UTF-8 bytes are replacement-decoded. | Inspector/service/extractor |
| 46 | Unrecognized or non-SQL traffic is left alone (Allow); SQL candidates are evaluated sequentially and processing stops on first non-Allow unless the explicit `allow_with_findings` setting is used. | `inspectCandidates`; `sql-extract.ts` |
| 47 | Extractor silently truncates bodies to 200,000 characters and candidates to 8. Proto comments cap body at 4 MiB, config example caps binding at 1 MiB, context 4 KiB, config 64 KiB, and headers 64 KiB/128 lines. | Extractor; proto; TOML |
| 48 | HTTP handlers are request-local and await the core evaluator; no mutable per-request global state. WebSocket stream concurrency semantics are specified by proto but not implemented in the TS gRPC adapter. | `service.ts`; proto |
| 49 | `serveGrpc` returns only address/port and never calls `tryShutdown`/`forceShutdown`; lifecycle ownership is external. | `serveGrpc` |
| 50 | Frozen common outputs include `queryknight_bad_config`, `queryknight_require_approval`, `queryknight_unbounded_delete`, numeric allow/deny `1/2`, and empty free-form reason. `toReasonCode` takes a 56-character suffix plus `queryknight_`, potentially exceeding the proto’s 64-byte code limit; Rust caps the complete value to 64. | `inspector.test.ts`; proto; TypeScript `toReasonCode`; Rust `reason_code` |

## Confirmed TypeScript observability path

1. `inspectCandidates` passes `auditSink: event => audit.push(event)` to `@queryknight/core.evaluate` for every extracted SQL candidate. Core `evaluate` calls that hook after `evaluateInner` completes and before returning its evaluation result; the gRPC handler later discards `InspectionResult.audit`.
2. For every returned core evaluation the hook sees its final `allow`, `deny`, or `require_approval` decision. In the actual OpenShell path the injected provider always returns `waiting`, so approval-required SQL remains `require_approval`; it never produces a provider-granted/denied result. Default OpenShell behavior denies that result. With explicit `approval_action=allow_with_findings`, the wrapper may return allow while the captured core event still says `require_approval` and `enforced=true`.
3. A thrown audit callback is caught and swallowed by core `evaluate`, so it cannot alter the returned evaluation. The OpenShell callback itself only appends to a request-local array; OpenShell has no configurable audit sink.
4. Event creation follows policy evaluation and approval-provider resolution, before `evaluate` returns to the inspector. Evaluation duration includes the provider call; the inspector then continues or stops on the first non-allow candidate.
5. OpenShell does not pass `sqlLogLevel`; the core default `fingerprint` applies. OpenShell configuration has no SQL logging-level setting.
6. OpenShell does not call `recordQuery`, use `qk-control-plane`, or record query history.
7. Core exposes `toOcsf`, but OpenShell does not import or call it. The handler drops the in-memory audit array; no OCSF event/export or configured external sink exists in the OpenShell path.
8. Low-level handlers record metrics only if a `MetricsRegistry` is passed. `createServiceState()` creates a registry, but `serveGrpc()` calls `buildGrpcImplementation()` without one, so the actual gRPC service records no metrics.
9. Low-level HTTP and WebSocket-text helpers share `inspectCandidates` and the same core audit path. The TypeScript gRPC server implements HTTP only; its declared WebSocket stream has no handler and performs no gRPC message audits.
10. `Describe` and `ValidateConfig` do not call `evaluate`; they create no SQL audit event or decision metric.
11. There is no standalone OpenShell CLI or autostart. Package scripts are only `build` and `demo`; `serveGrpc` is an explicit library function taking an address and a caller-supplied runtime loader. No `openshell` command exists under `packages/cli`.
12. Invalid configuration and payloads yielding no SQL candidate do not reach core `evaluate`. Invalid JSON falls back to raw-SQL detection; malformed UTF-8 is replacement-decoded.

## RPC classification

| RPC | Type | Classification | Current TS status / Rust disposition |
|---|---|---|---|
| `SupervisorMiddleware.Describe` | Unary | Control-plane | Authenticated gateway caller; validate `MiddlewareDescribeRequest.gateway` protocol/capabilities and return v0.1.2 metadata, HTTP/WebSocket bindings, and exact configured audience. |
| `SupervisorMiddleware.ValidateConfig` | Unary | Control-plane | Validate the gateway registration config; invalid config is reported through `valid=false`. |
| `SupervisorMiddleware.EvaluateHttpRequest` | Unary | Authorization-only | Evaluate extracted SQL, return frozen allow/deny result; do not execute through a DB driver. |
| `SupervisorMiddleware.EvaluateWebSocketSession` | Bidirectional stream | Authorization-only | Declared but missing from TS `buildGrpcImplementation`; Rust binds one authenticated supervisor token to the stream, binds the sandbox on preflight, accepts strictly increasing sequence numbers with gaps, inspects text only, and denies binary messages. |
| `HttpResponsePreReturn.Evaluate` | Bidirectional stream | Pass-through / not registered | Defined by the tagged proto but not implemented, advertised, or bound by QueryKnight Rust. Response denial cannot undo a completed database operation. |

For every SQL candidate Rust calls `authorize_guarded`, observes the typed outcome, then drops any permitted process-local capability before returning a decision. `authorized_external` means QueryKnight authorized a request; it does not mean the external executor ran or succeeded. This is **not** a QueryKnight-owned execution guarantee.

## Rust implementation

- The protocol inputs are the official NVIDIA/OpenShell v0.1.2 `extension.proto` and `supervisor_middleware.proto`; SHA-256 and deterministic generation instructions are recorded in `third_party/openshell/README.md`. The v0.1.2 descriptor uses package `openshell.middleware.v1`, `MiddlewareDescribeRequest` for Describe, protocol major/minor `1.0`, and the `openshell.supervisor-middleware.contract` capability. QueryKnight advertises only HTTP request and WebSocket message at `PRE_CREDENTIALS`; the v0.1.2 `HTTP_RESPONSE/PRE_RETURN` service is present in the descriptor but is not bound or advertised.
- Authenticated deployment is `OpenShellServerConfig::authenticated`: HTTPS server certificate/key, operator-provisioned gateway ID, exact audience, and a bounded local Ed25519 JWKS. Tonic validates the PEM identity and certificate/key pairing before binding. TLS hostname/SAN verification remains the OpenShell client's responsibility; `tls_ca_cert_path` belongs to the OpenShell registration. A configured `--advertised-host` is checked by doctor/startup. No certificate reload is performed; restart QueryKnight after rotation.
- The authenticated listener may bind a non-loopback address only with successful TLS and JWT configuration. `OpenShellInsecureLocal` is explicit plaintext loopback-only development mode with an obvious warning. Unix sockets remain owner-only local testing/integration; v0.1.2 supervisor middleware must be reachable from both gateway and sandboxes, so Unix socket mode is not the normal authenticated registration path.
- The Tower request layer authenticates before Tonic decodes protobuf bodies. `Describe` accepts `caller_kind=gateway` (gateway startup) or `caller_kind=supervisor` (supervisor middleware bootstrap); `ValidateConfig` requires `caller_kind=gateway`; `EvaluateHttpRequest` and the complete `EvaluateWebSocketSession` RPC require `caller_kind=supervisor`. A missing/bad token returns gRPC `UNAUTHENTICATED`; a valid token used for the wrong RPC returns `PERMISSION_DENIED`. Authentication failures never become SQL Deny responses.
- JWT validation pins `alg=EdDSA`, requires `typ=openshell-ext+jwt`, verifies Ed25519 signature using the configured local JWKS `kid`, and checks exact `iss=openshell-gateway:<gateway_id>`, exact string `aud`, `sub`, `iat`, `exp`, `jti`, and caller kind. `sandbox_id` is required for supervisor calls and the SPIFFE-shaped `sub` must agree. Expiry is checked with five seconds of skew and a maximum one-hour lifetime; `nbf` is not issued by v0.1.2 but is validated if present. Repeated `jti` is accepted. Unknown `kid`, duplicate key IDs, non-OKP/Ed25519/signature keys, unsupported `alg`, or malformed JWKS fail closed. No token-driven refresh or discovery fetch occurs.
- The returned `expected_audience` is the configured audience, not a value learned from Describe. Config/manifest disagreement therefore fails OpenShell startup. The product release (`v0.1.2`) and extension protocol (`1.0`) are separate values.
- `OpenShellServiceConfig::new(DbConfig)` uses a trusted database URL only to choose dialect and derive a password-redacted approval identity; it never opens a DB connection. Validated registration config supplies policy/database/environment. `ValidateConfig` strictly accepts the existing fields `policy_yaml`, `dialect`, `database`, `environment`, `approval_action`, and `maxSqlBytes`; absent optional fields may default, malformed explicit values and unknown fields fail, and invalid replacement preserves the last good config.
- After authentication, evaluation binds verified token `sandbox_id` to `RequestContext.sandbox_id` before config lookup, SQL extraction, policy evaluation, approval resolution, or SQL audit. `sandbox` name, workspace, process metadata, target, headers, and body are never used as security identity. Display values do not override the signed sandbox ID.
- The service advertises a 1 MiB payload limit (below OpenShell's 4 MiB platform maximum) and enforces bounded config/context/target/header sizes plus the existing SQL/candidate limits. HTTP preserves upstream header order by inspecting only needed values; it does not reconstruct headers. QueryKnight does not require managed provider credentials to be present because middleware runs before OpenShell injects them.
- The QueryKnight binding timeout defaults to 400 ms, below OpenShell v0.1.2's 500 ms default. OpenShell v0.1.2 accepts 10 ms–30 s operator timeouts and uses a binding timeout only to shorten the service timeout. The tagged external middleware client wraps calls in internal timers but does not send `grpc-timeout`; QueryKnight honors a received gRPC timeout when present and uses its advertised internal budget otherwise. Approval daemon connect/read/write operations share the remaining absolute budget, poll cancellation, leave an internal safety margin, and never retry after expiry. A timed-out or canceled blocking authorization drops any local permit and cannot return Allow. Approval errors use gRPC service failure; `on_error: fail_closed` is required for enforcement.
- QueryKnight preserves ExactV2 and Session approval scope. Pending approval maps to a normal middleware DENY because the protocol has no pending state; audit remains `Pending`. `LegacyShape` is never authoritative. QueryKnight never executes SQL, serializes an `ExecutionPermit`, or claims that an external Allow reached the target.
- WebSocket uses one authenticated supervisor credential for the complete gRPC stream, binds sandbox identity on preflight, requires session start, accepts strictly increasing stage sequence numbers with gaps, and checks each text message independently. Binary messages are denied; server-to-client messages are not advertised. HTTP response middleware is not implemented.
- Findings and metadata remain empty; outward `queryknight_*` reason codes are sanitized to the v0.1.2 lowercase/digit/underscore grammar and 64-byte maximum. Auth diagnostics are separate `openshell_auth_success` / `openshell_auth_failure` / authorization decision stderr records; they omit JWTs, signatures, keys, SQL, and parameters. No Prometheus metric names or high-cardinality labels are added.
- The standalone `queryknight openshell serve` and `queryknight openshell doctor` commands expose typed TLS/JWT listener configuration, local trust checks, and no database connectivity check. Authenticated mode is the default; `--insecure-local` is explicit, loopback-only, and development-only.
- The same shared `Observer` records typed authorization outcomes and frozen metrics. These describe QueryKnight's authorization decision only, not downstream execution. No OCSF exporter or query-history call is added.

## Observability boundaries

Query history is not audit; audit is not metrics; metrics are not OCSF. OpenShell records no daemon `query_events` history. `Observer` emits the canonical `AuditEvent` and metrics from typed `AuthorizationOutcome`s; a configured host sink may convert an event with the shared `to_ocsf`, but this service adds no OCSF transport. An `authorized` audit/OCSF outcome means only “authorized for an external executor”; it does not mean “executed” or “succeeded.”

## Product boundary and database path

OpenShell controls which network/service destinations an agent can reach. QueryKnight controls SQL/database actions after database access is intentionally granted. OpenShell's HTTP/WebSocket middleware does not inspect native PostgreSQL/MySQL protocols.

That is a separate integration mode from the native database path, which is implemented and live verified: OpenShell sandbox policy admits the QueryKnight PostgreSQL proxy and denies the database destination directly, with the application pointed at QueryKnight. QueryKnight then enforces SQL on the proxied session and reaches PostgreSQL over verified backend TLS. Evidence and the exact policy shape are in [`openshell-postgres-demo.md`](openshell-postgres-demo.md) and [`openshell-compatibility.md`](openshell-compatibility.md).

Still not implemented: PostgreSQL frontend TLS and MySQL TLS. This OpenShell integration does not make either database path production-ready.

## Standalone and embedded deployment

The supported standalone entrypoint is `queryknight openshell serve`; it requires `DATABASE_URL`/`MYSQL_URL` only for dialect/approval identity, and starts authenticated HTTPS by default. `queryknight openshell doctor` validates local TLS/JWKS/policy configuration without opening a database connection. See [`examples/openshell/README.md`](../examples/openshell/README.md) for the complete OpenShell v0.1.2 registration, CA, policy, and target-service flow.

Embedding remains available when the host owns process lifecycle:

```rust
let database_url = std::env::var("DATABASE_URL")?;
let db = qk_db::DbConfig::from_url(&database_url)?;
let audience = "urn:openshell:extension:middleware:queryknight";
let jwt = qk_openshell::OpenShellJwtConfig::new(
    "queryknight-demo",
    audience,
    "/etc/queryknight/openshell-jwks.json",
)?;
let control_plane = qk_control_plane::ControlPlaneClient::discover(None)?;
let service = qk_openshell::OpenShellService::new(
    qk_openshell::OpenShellServiceConfig::new(db)
        .with_expected_audience(audience)
        .with_control_plane(control_plane),
);
let config = qk_openshell::OpenShellServerConfig::authenticated(
    "0.0.0.0:50051".parse()?,
    "/etc/queryknight/tls/server.pem",
    "/etc/queryknight/tls/server-key.pem",
    jwt,
);
let server = qk_openshell::OpenShellServer::bind(config, service).await?;
server.stop().await?;
```

## External schema note

Both vendored inputs are official NVIDIA/OpenShell Apache-2.0 protocol files, byte-for-byte equal to the v0.1.2 tag; their upstream commit, SHA-256 values, and binding regeneration command are recorded in [`third_party/openshell/README.md`](../third_party/openshell/README.md). No upstream implementation code or QueryKnight project-license changes are included. The sibling TypeScript adapter remains an unauthenticated historical implementation; QueryKnight's Rust network path follows the tagged v0.1.2 authenticated contract.
