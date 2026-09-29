# PostgreSQL proxy: frozen TypeScript reference and Rust security contract

## Audited TypeScript surface (`../queryknight-ts`, read-only)

Audited source: `packages/proxies/postgres/src/{proxy.ts,messages.ts,reader.ts,proxy.test.ts}`, `packages/cli/src/index.ts`. The CLI is `queryknight proxy [--listen <port>]`; PostgreSQL is selected when `MYSQL_URL ?? DATABASE_URL` has a postgres scheme. `POSTGRES_URL` is used by tests but is not in CLI resolution. It listens on `127.0.0.1`, default port `5434`; upstream host/port come from the URL (port defaults to 5432). `connectionKey` defaults to upstream URL. Relevant shared env includes `QUERYKNIGHT_ENV`, `QUERYKNIGHT_POLICY_FILE`, `QUERYKNIGHT_DATABASE`, `QUERYKNIGHT_DAEMON_URL`, `QUERYKNIGHT_HOME`; proxy options also include `timeoutMs`. No per-proxy host option exists in CLI.

### Audited behavior (numbering matches request)

1. `proxy` subcommand, `--listen`. 2. `127.0.0.1`. 3. URL-derived hostname/port, default 5432. 4. URL precedence `MYSQL_URL` then `DATABASE_URL`; tests additionally use `POSTGRES_URL`; default connection key raw URL. 5. Shared environment/policy/daemon/history config above. 6. First startup packet relayed. 7. Exact 8-byte SSLRequest gets `N`, then another startup is relayed. 8. GSSENCRequest has no special handling and is relayed upstream (unsafe gap). 9. Startup fields are not filtered: user/database/options/replication pass through. 10. Backend auth is relayed; client responses read for auth codes 3,5,10,11; authentication ends at ReadyForQuery. 11–12. Client credentials/proofs pass through; configured credentials are not substituted. 13–14. All auth-phase messages including ParameterStatus and BackendKeyData relay unchanged. 15. CancelRequest is not specially recognized. 16. Q SQL is decoded as a C string, passed to shared policy, then original bytes forwarded. 17. Partial extended handling only. 18. Parse stores name→SQL and authorizes SQL immediately. 19. Bind stores portal→statement SQL; ignores values/formats. 20. Describe forwarded. 21. Execute maps portal to SQL (unknown uses `/* unknown portal */`), authorizes SQL without params, then forwards. 22. Close forwarded without map cleanup. 23. Flush forwarded. 24. Sync forwarded; responses drained through ReadyForQuery. 25–28. Names are plain string map keys; no correct prepared statement/portal lifecycle. 29–32. Binary/text/NULL/OID data ignored by policy identity. 33. Policy exceptions produce structured ErrorResponse; other handler errors destroy sockets. 34. Drains until `Z`. 35. No status tracking; synthetic `Z` is always `I`. 36–39. QueryKnight ErrorResponse uses Severity `ERROR`, SQLSTATE `42501`, message from `QueryDeniedError.message` or `String(error)`, no Detail/Hint; pending text comes from shared approval path, not a proxy-specific formatter. 40. Backend protocol message payloads relay unchanged. 41. TLS refused (`N`). 42. GSS is not refused explicitly. 43. Upstream is plain `node:net`; no TLS negotiation or TLS-required validation. 44. Authentication is byte-relay, including passwords/proofs. 45. BackendKeyData relayed; no cancellation validation. 46. FunctionCall blindly forwarded. 47–48. COPY blindly forwarded; no SQL/payload gate. 49. Replication not rejected. 50. SQL PREPARE/EXECUTE relies on shared evaluator. 51–52. Reader buffer grows unbounded; no explicit framing/state bounds. 53. Shared policy layer limit only. 54. No Bind payload cap. 55. Sequential loop; Q/S drain to Z, no explicit pipeline support. 56–57. Per-handler maps; finally destroys both sockets. 58. `timeoutMs` is enforcement timeout, not frame/idle timeout. 59–60. Optional history records after enforcement and before forwarding; no explicit observer hook. 61. No parameter data is decoded/logged. 62. History is awaited before forwarding. 63. CLI loopback. 64. No TS subprocess. 65. Shared HistoryClient handles approvals/session. 66. Shared core policy behavior. 67. One URL per listener. 68. CLI prints redacted URL and `(local plaintext)`; caught handler errors destroy sockets. 69. Error encoder structures fields but does not guard embedded NUL in message. 70. No explicit validation before policy. 71. Tests are live driver smoke, not message recorder. 72. No malformed codec matrix. 73. Existing live tests: allowed SELECT, parameterized extended SELECT/write, blocked DDL. 74–79. No real approval retries, transaction state, cross-client name state, or no-replay failure tests found. 80. Backend wire responses not decoded/re-encoded beyond message framing relay. 81. No clipping/result budget. 82. No qk-db cursor. 83. No PostgreSQL-specific invariants in TS audited source. 84–86. TS CLI routes MySQL too; out of scope for this commit. 87. No Rust quality gates apply to TS. 88–89. This document is the Rust-side audit contract.

## Rust Simple Query implementation

Rust adds `queryknight proxy [--listen <port>]`, bound only to `127.0.0.1`
(default `5434`). `MYSQL_URL` takes precedence over `DATABASE_URL`, and the
selected URL must be PostgreSQL. Backend selection is fixed at startup and
supports one TCP host. The configured user/database are trusted startup
identity; frontend startup must match both. Set `sslmode=disable` explicitly:
the proxy does not implement backend TLS and rejects every TLS-enabled or
default-`prefer` configuration rather than downgrading. Frontend TLS/GSS
requests receive `N`; traffic after that is plaintext, including authentication
responses. Keep the listener loopback-only.

Each frontend receives a separate backend TCP session. The proxy relays
supported PostgreSQL authentication (AuthenticationOk, cleartext, MD5, and
SCRAM messages) without logging passwords/proofs. The backend URL password is
not substituted for the frontend credential. Startup permits only the
configured user/database plus `application_name`, UTF8 `client_encoding`,
empty options and empty replication values; other startup parameters and
nonempty options/replication are rejected.

| State | Frontend input | Proxy behavior | Backend behavior |
|---|---|---|---|
| Startup | SSLRequest / GSSENCRequest | Reply `N`, continue startup | None |
| Startup | CancelRequest | Close without forwarding | None |
| Startup | StartupMessage | Validate identity and allowed parameters | Forward validated startup unchanged to the fixed target |
| Authentication | Supported auth response | Relay bounded frame without logging | Relay to same backend session |
| Ready | Empty `Q` | Synthesize EmptyQueryResponse and ReadyForQuery using actual status | None |
| Ready | Nonempty `Q` | Decode bounded complete UTF-8 C string; authorize all statements | On a permit, forward the original `Q` frame once |
| Ready | Parse/Bind/Describe/Execute/Close/Flush/Sync | Fail closed; discard until Sync where applicable | Never forward |
| Ready | FunctionCall or COPY data stream | Fail closed and close unsupported COPY streams | Never forward |
| Ready | Unknown/malformed frame | Error or close before execution | Never forward |
| Any | Disconnect | Drop frontend state | Close its backend session |

The complete SQL in each `Q` is evaluated through `qk-db::authorize_guarded`.
No partial statement forwarding or permit cache exists. The original frame
passes only after consuming its request-specific `ExecutionPermit`, on the
same backend session used for authentication and subsequent responses. Simple
Query carries no bind values; parameterized execution therefore is not
supported. Empty queries do not invoke policy. COPY/SET operations are
explicitly rejected by the adapter even if a policy rule would otherwise
allow them. Local policy/approval responses preserve the last backend
ReadyForQuery `I`/`T`/`E` status; they do not synthesize transaction changes.

Approvals use the shared daemon provider and record activity in the same
control-plane path as MCP. Simple Query has no approval-id field, so a retry
may scan same-shape exact-bound candidates, each of which must pass the
daemon's exact digest, version, scope, status, and expiry verification. No
local approval cache or SQL/parameter logging is introduced. With no reachable
daemon, approval-required execution fails closed.

## Scope boundary

The protocol is PostgreSQL Simple Query only. Extended Query, COPY streaming,
FunctionCall, replication startup, and CancelRequest forwarding are
intentionally unsupported. This implementation does not change MySQL,
OpenShell, `observe`, or TypeScript proxy behavior.
