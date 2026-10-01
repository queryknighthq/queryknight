# OpenShell integration audit and Rust contract

This document records the completed source audit and the Rust integration contract. The source of truth for the current QueryKnight adapter is `../queryknight-ts/packages/integrations/openshell/`; the OpenShell wire contract is vendored in `crates/qk-openshell/proto/supervisor_middleware.proto` (NVIDIA Apache-2.0). That file imports `extension.proto`, which was absent from the TypeScript vendor directory; the matching upstream schema is vendored unchanged at `crates/qk-openshell/proto/extension.proto`. Rust generation uses both complete schemas and does not reconstruct field numbers from this summary.

The current TypeScript package uses `@grpc/grpc-js` and `@grpc/proto-loader` as peer dependencies. `service.ts` accepts a caller-supplied proto-loader/runtime; it does not load or vendor generated stubs. The adapter is authorization middleware for traffic executed by OpenShell or another upstream service. It does **not** open a database driver or execute SQL itself. A returned `Allow` is therefore a synchronous decision to a trusted external gateway, not a serializable QueryKnight `ExecutionPermit` and not a cryptographic guarantee that a later external executor will run identical bytes. The Rust port retains that trust boundary rather than claiming QK owns the external side effect.

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
| 38 | Caller identity/authentication is not verified by the TypeScript server: `serveGrpc` uses insecure credentials; peer metadata is ignored. The checked-in example uses a Unix socket. Rust restricts TCP to loopback and sets Unix socket permissions to `0600`; it does not verify JWTs or authenticate local gRPC peers. Unix sockets rely on filesystem permissions; loopback TCP is safe only in a trusted local process environment. Remote HTTPS/JWT service deployment is unsupported. | `serveGrpc`; TOML; Rust `OpenShellServer`; [OpenShell middleware auth contract](https://docs.nvidia.com/openshell/extensibility/supervisor-middleware) |
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
| `SupervisorMiddleware.Describe` | Unary | Control-plane | Implement manifest and bindings. Complete peer metadata for the vendored extension contract; no caller-supplied identity. |
| `SupervisorMiddleware.ValidateConfig` | Unary | Control-plane | Validate the gateway registration config; invalid config is reported through `valid=false`. |
| `SupervisorMiddleware.EvaluateHttpRequest` | Unary | Authorization-only | Evaluate extracted SQL, return frozen allow/deny result; do not execute through a DB driver. |
| `SupervisorMiddleware.EvaluateWebSocketSession` | Bidirectional stream | Authorization-only | Declared but missing from TS `buildGrpcImplementation`; Rust processes preflight, one session start and strictly increasing text messages. Binary payloads fail closed; stream IDs are not trusted sandbox identities. |
| `HttpResponsePreReturn.Evaluate` | Bidirectional stream | Pass-through / not registered | Proto-only, not advertised by Describe or bound by the TS service. Deliberately not exposed: response denial cannot undo a completed DB operation. |

For every SQL candidate Rust calls `authorize_guarded`, observes the typed outcome, then drops any permitted process-local capability before returning a decision. `authorized_external` means QueryKnight authorized a request; it does not mean the external executor ran or succeeded. This is **not** a QueryKnight-owned execution guarantee.

## Rust implementation

- `qk-openshell` generates Tonic/Prost types from both vendored NVIDIA schemas. `Describe` accepts protocol major version 1, emits peer metadata version 1.2 and advertises HTTP request plus WebSocket message bindings at `PRE_CREDENTIALS`, each capped at 1 MiB. `expected_audience` remains empty: the service does not verify JWTs.
- `OpenShellServiceConfig::new(DbConfig)` receives a trusted connection URL only to select dialect and derive the password-redacted approval connection key. It never opens a DB connection. Validated registration config supplies policy database/environment; its dialect must match the trusted `DbConfig`.
- `ValidateConfig` strictly accepts `policy_yaml`, `dialect`, `database`, `environment`, `approval_action`, and `maxSqlBytes`; malformed values, unknown fields and `allow_with_findings` are rejected. A bounded in-process registry requires each evaluation config to match the exact validated registration.
- `OpenShellServer` binds only a Unix socket or loopback TCP. Unix sockets are owner-only (`0600`) and require an existing trusted parent directory. Loopback TCP has no peer authentication and is suitable only when local processes are trusted. The returned handle supports graceful shutdown. Non-loopback TCP is refused; remote HTTPS/JWT deployments remain unsupported until their gateway audience and verification keys are configured.
- Every recognized SQL candidate uses `authorize_guarded` and `DaemonApprovalProvider::with_exact_lookup_retry` when a daemon client is supplied. The connection key is password-redacted. `RequestContext.sandbox_id` is the only session identity; missing IDs remain absent, and the separate WebSocket stream ID, process fields, headers and target are not trusted policy identity. Without a daemon client, approval-required requests fail closed.
- The body extractor accepts the audited JSON/raw-SQL shapes, strictly requires UTF-8 for HTTP bodies, preserves adjacent JSON `params` arrays as ordered `ExecutionParam`s (ExactV2), rejects unsupported parameter encodings, and uses the shared `qk-sql` AST to reject placeholders without explicit values. Candidate/body limits fail closed instead of truncating an authorized prefix. No parameter interpolation occurs; non-SQL/unrecognized traffic remains pass-through as in TypeScript.
- Deny results use bounded `queryknight_*` reason codes and an empty free-form reason; successful results contain no reason code, body/header mutations, serialized permit, or approval ID. A pending approval is represented as DENY because the proto has no pending response field; exact daemon retry re-evaluates the current request.
- WebSocket is implemented for ordered text messages: preflight is required, session start precedes messages, sequence numbers must strictly increase, and each text message is evaluated independently. Binary messages fail closed; no replacement is returned. The proto-only HTTP response service remains unregistered.
- The TypeScript gRPC handler drops its in-memory audit array, records no history, and does not call OCSF conversion. Rust emits one shared `qk-audit::Observation` per recognized SQL candidate after authorization; `AttemptOutcome::Authorized` means permitted by QueryKnight but not executed by it. Deny and pending remain blocked/pending, and `Describe`, `ValidateConfig`, malformed bodies rejected before SQL extraction, and non-SQL traffic create no SQL activity event.
- Typed mapping preserves the authorization phase: `Permitted` records Allow/Authorized (and shared approval facts when present), `Blocked` records Deny/Blocked, `PendingApproval` records RequireApproval/Pending, and daemon unavailable/error remains a fail-closed Deny. None is converted to `ExecutionOutcome::Executed`.
- The service calls the shared `Observer` once per recognized SQL candidate. Its default has no configured audit sink and includes the shared metrics registry; an embedding can inject `NoopSink`, `MemorySink`/test, or a configured sink and retrieve metrics through `OpenShellService::observer()`. Fingerprint logging is default; another `SqlLogLevel` (including `full_sql`) requires an explicit builder choice. Sink errors are best-effort diagnostics and never change decisions or retry authorization.
- Shared metrics count authorization requests/decisions, denials, approvals, parse errors, and measured `authorize_guarded` duration only. They never claim DB success, rows, or downstream duration. The canonical `AuditEvent → OcsfEvent` mapping gives authorization-only Allow status Unknown, executed Allow Success, and DB-failed Allow Failure; no OpenShell OCSF exporter or query-history call is added. Bound parameters and ExactV2 digests are not included in observations.
- No CLI, environment-variable contract, autostart, direct daemon HTTP client, TLS, retry wrapper, or custom timeout is added. Tonic honors client deadlines, but the adapter does not enforce the proto binding timeout; an already-running blocking authorization/approval call is not interrupted by RPC cancellation.

## Observability boundaries

Query history is not audit; audit is not metrics; metrics are not OCSF. OpenShell records no daemon `query_events` history. `Observer` emits the canonical `AuditEvent` and metrics from typed `AuthorizationOutcome`s; a configured host sink may convert an event with the shared `to_ocsf`, but this service adds no OCSF transport. An `authorized` audit/OCSF outcome means only “authorized for an external executor”; it does not mean “executed” or “succeeded.”

Example embedding (the host owns daemon and listener lifecycle):

```rust
let db = qk_db::DbConfig::from_url("postgresql://user:password@127.0.0.1/app")?;
let control_plane = qk_control_plane::ControlPlaneClient::discover(None)?;
let service = qk_openshell::OpenShellService::new(
    qk_openshell::OpenShellServiceConfig::new(db).with_control_plane(control_plane),
);
let server =
    qk_openshell::OpenShellServer::bind_unix("/run/queryknight/middleware.sock", service)
        .await?;
server.stop().await?;
```

## External schema note

`supervisor_middleware.proto` is the NVIDIA Apache-2.0 schema vendored in the TypeScript tree. It references `extension.proto`, which is missing from that tree; the matching official peer-metadata schema is vendored unchanged in `crates/qk-openshell/proto/extension.proto`. The TypeScript handler emits an empty `extension` message and does not implement the advertised WebSocket stream; those protocol gaps are documented compatibility differences, not reasons to hand-roll a new protocol. The checked-in deployment uses a Unix-domain socket and insecure gRPC credentials. Current [OpenShell supervisor-middleware guidance](https://docs.nvidia.com/openshell/extensibility/supervisor-middleware) requires HTTPS/JWT for remote services and describes insecure transport as a trusted-network development option. Rust supports only local Unix-domain/loopback transports; it does not expose insecure remote gRPC or invent JWT key provisioning. Remote deployment remains unsupported until the gateway audience/public-key trust material is configured.
