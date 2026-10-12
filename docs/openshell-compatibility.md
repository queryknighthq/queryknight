# OpenShell compatibility matrix

OpenShell product releases and the extension protocol version are separate. This matrix records the OpenShell product tag and the `PeerMetadata.protocol_version` implemented by the tagged protocol. QueryKnight advertises extension protocol **1.0**; the protocol is not an OpenShell product version.

| OpenShell product release | Tag commit | Supervisor/extension proto SHA-256 | Protocol metadata | Status |
|---|---|---|---|---|
| `v0.1.0` | `496ebba293f5cc2bb2753444dddd534f0b4aeb6a` | `supervisor_middleware.proto`: `bee96ac940303d8a7530e6e2283a98077bb428a05ef610b51d018ea18377bebd`; `extension.proto`: `60f28ee9dc846d41152f4db7e82a439c78d024786efaceb464900d1d1ad129ad` | `1.0`, supervisor-middleware contract capability | **COMPATIBLE / NOT LIVE-VERIFIED** |
| `v0.1.1` | `4ce767fc0cadad773c398e15109c0286f4b7aa30` | Same exact two inputs as `v0.1.0` | `1.0`, supervisor-middleware contract capability | **COMPATIBLE / NOT LIVE-VERIFIED** |
| `v0.1.2` | `6648bd0c290efbc41ba131ee9831ee45cd431f94` | Same exact two inputs as `v0.1.0` | `1.0`, supervisor-middleware contract capability | **LIVE VERIFIED** (real sandbox E2E; see below) |

`COMPATIBLE / NOT LIVE-VERIFIED` means the tagged descriptor inputs and the protocol metadata/auth contract inspected from that release are compatible, but QueryKnight has not run a live gateway/sandbox test against that product tag. It is not a support claim based on semver. `v0.1.2` is the required implementation and E2E target for this milestone.

## Live verification record (v0.1.2)

`scripts/test-openshell-v0.1.2.sh` runs the real path end to end and exits `0`:

| Area | Status |
|---|---|
| descriptor / protocol | LIVE VERIFIED |
| TLS / JWT auth | LIVE VERIFIED |
| gateway lifecycle | LIVE VERIFIED |
| supervisor bootstrap | LIVE VERIFIED |
| HTTP sandbox middleware | LIVE VERIFIED |
| Allow enforcement | LIVE VERIFIED |
| Deny enforcement | LIVE VERIFIED |
| Exact approval retry | LIVE VERIFIED |
| changed-request rejection | LIVE VERIFIED |
| PostgreSQL network gating | LIVE VERIFIED |
| WebSocket | generated-client verified; not live sandbox verified |

Evidence from the passing run:

- upstream `ghcr.io/nvidia/openshell/supervisor:0.1.2` (`sha256:d7b5264b…`) and
  `…/sandbox:0.1.2` (`sha256:bf4797b6…`) pulled;
- gateway + CLI built from commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`
  (`openshell 0.1.2`);
- custom `debian:bookworm-slim` + `curl` + `ca-certificates` workload image
  (`queryknight-openshell-e2e:v0.1.2`, non-root UID 65534) created via
  `openshell sandbox create --from …`;
- middleware log shows `openshell_auth_success rpc=Describe caller_kind=gateway`,
  `rpc=ValidateConfig caller_kind=gateway`, `rpc=Describe caller_kind=supervisor`,
  and `rpc=EvaluateHttpRequest caller_kind=supervisor`;
- target request counter: Allow `1`, Deny `1` (unchanged), Pending `1`
  (unchanged), exact approved retry `2`, changed request `2` (unchanged);
- audit counters: `allow=2 deny=3 pending=2`;
- sandbox identity bound through the supervisor-issued token (ExactV2 approval
  bound to the signed sandbox id, not the display name).

The custom workload image exists only to give the sandbox a `curl` binary; the
upstream sandbox runtime image is distroless. It is not a QueryKnight product
image and not required for real deployments.

## PostgreSQL network-gated deployment (v0.1.2) — LIVE VERIFIED

`scripts/test-openshell-postgres-v0.1.2.sh` composes the OpenShell sandbox with
the QueryKnight PostgreSQL wire proxy and PostgreSQL 17, and exits `0`.

This is a **different integration mechanism** from the HTTP middleware above,
and the two must not be conflated:

| | HTTP middleware | Native PostgreSQL |
|---|---|---|
| OpenShell role | Runs QueryKnight as an in-sandbox middleware for admitted egress; `Describe`/`ValidateConfig`/`EvaluateHttpRequest` over HTTPS + JWT | Enforces the network destination only. No middleware is registered and OpenShell never sees SQL |
| QueryKnight role | Returns an authorization decision to the supervisor | Terminates the PostgreSQL wire protocol, authorizes the statement, and forwards on the same backend session |
| Where SQL is inspected | Supervisor → middleware RPC | Inside the proxy, not OpenShell |
| Credential/approval binding | Supervisor-issued token bound to the signed sandbox id | QueryKnight proxy session scope; ExactV2 over SQL plus bound wire parameters |

Verified in the passing run:

- OpenShell denied the sandbox's direct connection to the PostgreSQL backend
  port: `NET:OPEN [MED] DENIED /usr/lib/postgresql/15/bin/psql(0) ->
  198.18.0.2:<backend port> [reason:transparent_tcp_mapping_denied]`, while the
  same address, port, and credentials were proven reachable from a plain
  container context;
- the same `psql` binary reached the QueryKnight proxy, which OpenShell admitted
  with `NET:OPEN [INFO] ALLOWED … -> host.docker.internal:<proxy port>
  [policy:queryknight-postgres engine:opa]`;
- the QueryKnight → PostgreSQL hop was TLS: the proxied session reported
  `pg_stat_ssl.ssl = t` with `TLSv1.3`;
- an untrusted CA made the same sandbox path fail closed at the proxy with no
  SQL executed;
- `SELECT` allowed, unbounded `DELETE` denied with SQLSTATE `42501`, bound
  `DELETE` pending as `exact_v2`, exact retry executed once, and a changed bound
  value did not reuse the `once` grant.

OpenShell's policy here is a `network_policies` rule for
`host.docker.internal:<proxy port>` with `protocol: tcp` and the kernel-resolved
`psql`/`python3` binary paths; the PostgreSQL backend port is deliberately absent,
and OpenShell denies any connection that no rule allows.

## Contract implemented

- Protobuf package: `openshell.middleware.v1`; extension metadata package: `openshell.extension.v1`.
- `SupervisorMiddleware.Describe` is unary and receives `MiddlewareDescribeRequest`; `ValidateConfig` and `EvaluateHttpRequest` are unary; `EvaluateWebSocketSession` is bidirectional streaming.
- `Describe` negotiates protocol major `1`, advertises version `1.0`, supports and requires only `openshell.supervisor-middleware.contract`, and returns the configured exact `expected_audience` in authenticated mode.
- QueryKnight advertises `HTTP_REQUEST/PRE_CREDENTIALS` and `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`. It does not implement or advertise `HTTP_RESPONSE/PRE_RETURN`; the tagged proto does define `HttpResponsePreReturn.Evaluate`.
- The gateway authenticates `Describe` and `ValidateConfig` with `caller_kind=gateway`. The supervisor also calls `Describe` during middleware bootstrap with `caller_kind=supervisor`; QueryKnight accepts both callers for `Describe`. `ValidateConfig` remains gateway-only, and the runtime evaluation RPCs (`EvaluateHttpRequest`, `EvaluateWebSocketSession`) remain supervisor-only and carry a sandbox ID. QueryKnight verifies the signed token sandbox ID against `RequestContext.sandbox_id` before config lookup or SQL processing.
- OpenShell v0.1.2 product defaults are 500 ms for service RPCs; configured service and binding timeouts are bounded to 10 ms–30 s. QueryKnight advertises a 400 ms binding timeout by default and bounds its approval-provider socket operations by the remaining budget, leaving an internal safety margin. The gateway's internal call timeout is not encoded as `grpc-timeout` in its external middleware call; QueryKnight also honors a received `grpc-timeout` when present and cancels blocking approval work when the RPC future is dropped.

## Explicitly unsupported bindings and boundaries

- `HTTP_RESPONSE/PRE_RETURN` is unsupported and absent from the manifest. QueryKnight authorizes outbound SQL candidates; it does not inspect arbitrary response content, and a response-stage denial cannot roll back an already completed database operation.
- `WebSocket` inspection is limited to ordered client-to-upstream text messages. Binary payloads fail closed; server-to-client messages are not advertised. OpenShell sequence numbers are strictly increasing per stage but may contain gaps, which QueryKnight accepts.
- QueryKnight returns authorization-only `ALLOW`/`DENY`; it does not execute SQL or return a serialized `ExecutionPermit`. A returned allow does not prove that a downstream HTTP service executed the same bytes.
- OpenShell's `on_error` controls transport/timeout/malformed-result behavior. Use `on_error: fail_closed` for database safety enforcement. An explicit middleware denial remains a denial, but fail-open operator configuration can bypass a middleware service failure.
- OpenShell middleware runs before OpenShell injects managed provider credentials. QueryKnight does not require a provider `Authorization` header in the inspected request.
- HTTPS server mode uses QueryKnight server-authenticated TLS plus OpenShell EdDSA bearer-JWT authentication. It does not implement mTLS, remote JWKS discovery, or key refresh. Unknown `kid` values fail closed; update the trusted local JWKS file and restart QueryKnight during key rotation.
- Unix sockets and unauthenticated loopback TCP are local development/integration modes, not the normal OpenShell v0.1.2 middleware path. An authenticated non-loopback listener is permitted only with valid TLS and trusted JWT configuration. Plaintext non-loopback is rejected.
- This integration adds no PostgreSQL/MySQL frontend TLS or backend database TLS. OpenShell governs network destinations; QueryKnight governs SQL candidates after database access is intentionally routed through a QueryKnight proxy. OpenShell does not generically inspect native PostgreSQL/MySQL SQL traffic.

## Upstream provenance

The imported files remain byte-for-byte equal to the official `NVIDIA/OpenShell` `v0.1.2` protocol inputs at commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`. Their SHA-256 values and deterministic regeneration instructions are recorded in [`third_party/openshell/README.md`](../third_party/openshell/README.md). The generated descriptor-set golden test catches changes to the complete compiled contract.

## Resolved compatibility bug (qkes-d-001, qk-openshell)

A real OpenShell v0.1.2 sandbox middleware E2E was run from inside a custom
workload container (debian:bookworm-slim + curl + ca-certificates, non-root)
via `openshell sandbox create --from <workload>`. The first run failed every
HTTP request with:

```http
HTTP/1.1 403 Forbidden
X-OpenShell-Policy: <rule>
{
  "error":"middleware_failed",
  "detail":"Request could not be processed by configured middleware",
  "policy":"<rule>"
}
```

The qk-openshell middleware log showed `openshell_auth_success
rpc=Describe/ValidateConfig caller_kind=gateway` (from the gateway at
startup) and then a continuous stream of
`openshell_auth_failure rpc=Describe class=caller_kind_rejected` from the
supervisor's bootstrap. The supervisor never reached
`openshell_auth_success rpc=EvaluateHttpRequest` and no
`openshell_authorization` audit record was produced.

**Root cause** (in qk-openshell, not in the harness): the
`fn rpc_contract(path: &str) -> Option<(CallerKind, bool)>` mapping in
`crates/qk-openshell/src/auth.rs` required `CallerKind::Gateway` for
`/openshell.middleware.v1.SupervisorMiddleware/Describe` and `/ValidateConfig`.
The supervisor's bootstrap calls `Describe` first
(`openshell-supervisor-middleware::GrpcMiddlewareService::describe`), but its
token is `caller_kind=supervisor`; the auth check rejected the call. Without a
successful `Describe`, the supervisor's `ChainRunner` never constructs a
working chain for the middleware, and every request returned the
`middleware_failed` 403 above. `EvaluateHttpRequest` was never invoked, so
`http_request` audit records were never written.

**Fix (commit `5bacd8c`):** `rpc_contract` now returns a bounded caller set
derived from the tagged v0.1.2 source:

| RPC | Allowed callers |
|---|---|
| `Describe` | `Gateway`, `Supervisor` |
| `ValidateConfig` | `Gateway` |
| `EvaluateHttpRequest` | `Supervisor` |
| `EvaluateWebSocketSession` | `Supervisor` |

Least privilege is preserved: the supervisor never calls `ValidateConfig` in
any v0.1.2 code path, and the gateway never calls the evaluation RPCs. Both
checks that enforce the contract (the Tower auth layer in `auth.rs` and the
per-RPC handler in `service.rs`) consult the same shared constants, so they
cannot drift. The JWT trust model is unchanged.

The E2E now passes end to end (`scripts/test-openshell-v0.1.2.sh`, exit `0`);
see the live verification record above.

## Related fix (qk-daemon, not an OpenShell compatibility issue)

The first E2E run that reached the approval phase also exposed a separate
QueryKnight daemon bug: `qk-daemon::server::serve_listener` wrapped the entire
serve future in `timeout(SHUTDOWN_GRACE, server)`, so the daemon stopped after
exactly 5 seconds regardless of the shutdown signal. The grace bound now
applies only to the post-shutdown drain (commit `8abb17d`), with a regression
test that outlives `SHUTDOWN_GRACE`.

## Current-main audit (future-only)

Audited upstream `main` at [`76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2`](https://github.com/NVIDIA/OpenShell/commit/76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2) (2026-10-01). Both current-main protocol files, [`extension.proto`](https://github.com/NVIDIA/OpenShell/blob/76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2/proto/extension.proto) and [`supervisor_middleware.proto`](https://github.com/NVIDIA/OpenShell/blob/76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2/proto/supervisor_middleware.proto), are byte-identical to the vendored v0.1.2 inputs. The extension-core [`auth.rs`](https://github.com/NVIDIA/OpenShell/blob/76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2/crates/openshell-extension-core/src/auth.rs) is also unchanged from v0.1.2. No newer extension protocol or JWT-auth contract was observed, so no main-only behavior is included here. The audited main commit changes a Python sandbox API test to wait for a complete TTY readiness marker; that test-only change is unrelated to middleware. Recheck the pinned upstream revision before any later protocol upgrade.
