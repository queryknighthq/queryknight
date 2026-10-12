# OpenShell compatibility matrix

OpenShell product releases and the extension protocol version are separate. This matrix records the OpenShell product tag and the `PeerMetadata.protocol_version` implemented by the tagged protocol. QueryKnight advertises extension protocol **1.0**; the protocol is not an OpenShell product version.

| OpenShell product release | Tag commit | Supervisor/extension proto SHA-256 | Protocol metadata | Status |
|---|---|---|---|---|
| `v0.1.0` | `496ebba293f5cc2bb2753444dddd534f0b4aeb6a` | `supervisor_middleware.proto`: `bee96ac940303d8a7530e6e2283a98077bb428a05ef610b51d018ea18377bebd`; `extension.proto`: `60f28ee9dc846d41152f4db7e82a439c78d024786efaceb464900d1d1ad129ad` | `1.0`, supervisor-middleware contract capability | **COMPATIBLE / NOT LIVE-VERIFIED** |
| `v0.1.1` | `4ce767fc0cadad773c398e15109c0286f4b7aa30` | Same exact two inputs as `v0.1.0` | `1.0`, supervisor-middleware contract capability | **COMPATIBLE / NOT LIVE-VERIFIED** |
| `v0.1.2` | `6648bd0c290efbc41ba131ee9831ee45cd431f94` | Same exact two inputs as `v0.1.0` | `1.0`, supervisor-middleware contract capability | **REQUIRED**; real tagged E2E result is reported by the harness and final verification record |

`COMPATIBLE / NOT LIVE-VERIFIED` means the tagged descriptor inputs and the protocol metadata/auth contract inspected from that release are compatible, but QueryKnight has not run a live gateway/sandbox test against that product tag. It is not a support claim based on semver. `v0.1.2` is the required implementation and E2E target for this milestone.

## Contract implemented

- Protobuf package: `openshell.middleware.v1`; extension metadata package: `openshell.extension.v1`.
- `SupervisorMiddleware.Describe` is unary and receives `MiddlewareDescribeRequest`; `ValidateConfig` and `EvaluateHttpRequest` are unary; `EvaluateWebSocketSession` is bidirectional streaming.
- `Describe` negotiates protocol major `1`, advertises version `1.0`, supports and requires only `openshell.supervisor-middleware.contract`, and returns the configured exact `expected_audience` in authenticated mode.
- QueryKnight advertises `HTTP_REQUEST/PRE_CREDENTIALS` and `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`. It does not implement or advertise `HTTP_RESPONSE/PRE_RETURN`; the tagged proto does define `HttpResponsePreReturn.Evaluate`.
- The gateway authenticates `Describe` and `ValidateConfig` with `caller_kind=gateway`. Supervisor HTTP and WebSocket evaluation calls use `caller_kind=supervisor` and carry a sandbox ID. QueryKnight verifies the signed token sandbox ID against `RequestContext.sandbox_id` before config lookup or SQL processing.
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

## Discovered compatibility bug (qkes-d-001, qk-openshell)

A real OpenShell v0.1.2 sandbox middleware E2E was run from inside a custom
workload container (debian:bookworm-slim + curl + ca-certificates, non-root)
via `openshell sandbox create --from <workload>`. The supervisor connected
to the gateway, fetched its bootstrap config, opened a relay, and the
in-sandbox `curl` reached the supervisor's HTTP forward proxy. The supervisor
then **failed every HTTP request** with:

```http
HTTP/1.1 403 Forbidden
X-OpenShell-Policy: <rule>
{
  "error":"middleware_failed",
  "detail":"Request could not be processed by configured middleware",
  "policy":"<rule>"
}
```

The qk-openshell middleware log showed only `openshell_auth_success
rpc=Describe/ValidateConfig caller_kind=gateway` (from the gateway at
startup) and then a continuous stream of
`openshell_auth_failure rpc=Describe class=caller_kind_rejected` from the
supervisor's bootstrap. The supervisor never reached
`openshell_auth_success rpc=EvaluateHttpRequest` and no
`openshell_authorization` audit record was produced.

**Root cause** (in qk-openshell, not in the harness): the
`fn rpc_contract(path: &str) -> Option<(CallerKind, bool)>` mapping in
`crates/qk-openshell/src/auth.rs` requires `CallerKind::Gateway` for
`/openshell.middleware.v1.SupervisorMiddleware/Describe` and `/ValidateConfig`.
The supervisor's bootstrap calls `Describe` first, but its token is
`caller_kind=supervisor`; the auth check rejects the call. Without a
successful `Describe`, the supervisor's `ChainRunner` never constructs a
working chain for the middleware, and every request returns the
`middleware_failed` 403 above. `EvaluateHttpRequest` is never invoked, so
`http_request` audit records are never written.

**Recommended fix (separate change, do NOT bundle with the test harness):**
the `Describe` and `ValidateConfig` contract entries in
`crates/qk-openshell/src/auth.rs` should accept either `CallerKind::Gateway`
or `CallerKind::Supervisor`. Both roles legitimately need protocol/capability
discovery; only operation RPCs (`EvaluateHttpRequest`,
`EvaluateWebSocketSession`) should remain `Supervisor`-only.

Until that change lands, the v0.1.2 sandbox middleware E2E in
`scripts/test-openshell-v0.1.2.sh` cannot reach a passing
`openshell_authorization decision=allow/deny` audit; it stops at the
Describe auth rejection. The harness up to that point proves:

- upstream `ghcr.io/nvidia/openshell/supervisor:0.1.2` and `…/sandbox:0.1.2`
  images pull and start;
- the v0.1.2 gateway+CLI builds from the pinned commit
  `6648bd0c290efbc41ba131ee9831ee45cd431f94` and listens on `0.0.0.0`;
- a custom debian+curl workload image can be passed via
  `sandbox create --from <image>` and the supervisor accepts it
  (a custom `--from` workload image is the correct way to give the sandbox
  a `curl` binary because the upstream sandbox image is distroless with no
  userland tools);
- the supervisor authenticates to the gateway and opens a relay; the
  in-sandbox `curl` reaches the supervisor's forward proxy;
- the supervisor's `openshell_auth_success` is observable for gateway
  `Describe` and `ValidateConfig`;
- the supervisor enforces the operator-supplied network policy and blocks
  requests that do not match (verified separately).

The probe does **not** prove Allow/Deny/Approval semantics; that requires
the qk-openshell Describe-auth fix above.

## Current-main audit (future-only)

Audited upstream `main` at [`76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2`](https://github.com/NVIDIA/OpenShell/commit/76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2) (2026-10-01). Both current-main protocol files, [`extension.proto`](https://github.com/NVIDIA/OpenShell/blob/76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2/proto/extension.proto) and [`supervisor_middleware.proto`](https://github.com/NVIDIA/OpenShell/blob/76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2/proto/supervisor_middleware.proto), are byte-identical to the vendored v0.1.2 inputs. The extension-core [`auth.rs`](https://github.com/NVIDIA/OpenShell/blob/76cfd0e31d5e1633db7ccd86ad9023ef7a2461b2/crates/openshell-extension-core/src/auth.rs) is also unchanged from v0.1.2. No newer extension protocol or JWT-auth contract was observed, so no main-only behavior is included here. The audited main commit changes a Python sandbox API test to wait for a complete TTY readiness marker; that test-only change is unrelated to middleware. Recheck the pinned upstream revision before any later protocol upgrade.
