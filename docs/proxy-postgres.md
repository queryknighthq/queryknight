# PostgreSQL proxy: frozen TypeScript reference and Rust security contract

## Audited TypeScript surface (`../queryknight-ts`, read-only)

Audited source: `packages/proxies/postgres/src/{proxy.ts,messages.ts,reader.ts,proxy.test.ts}`, `packages/cli/src/index.ts`. The CLI is `queryknight proxy [--listen <port>]`; PostgreSQL is selected when `MYSQL_URL ?? DATABASE_URL` has a postgres scheme. `POSTGRES_URL` is used by tests but is not in CLI resolution. It listens on `127.0.0.1`, default port `5434`; upstream host/port come from the URL (port defaults to 5432). `connectionKey` defaults to upstream URL. Relevant shared env includes `QUERYKNIGHT_ENV`, `QUERYKNIGHT_POLICY_FILE`, `QUERYKNIGHT_DATABASE`, `QUERYKNIGHT_DAEMON_URL`, `QUERYKNIGHT_HOME`; proxy options also include `timeoutMs`. No per-proxy host option exists in CLI.

### Audited behavior (numbering matches request)

1. `proxy` subcommand, `--listen`. 2. `127.0.0.1`. 3. URL-derived hostname/port, default 5432. 4. URL precedence `MYSQL_URL` then `DATABASE_URL`; tests additionally use `POSTGRES_URL`; default connection key raw URL. 5. Shared environment/policy/daemon/history config above. 6. First startup packet relayed. 7. Exact 8-byte SSLRequest gets `N`, then another startup is relayed. 8. GSSENCRequest has no special handling and is relayed upstream (unsafe gap). 9. Startup fields are not filtered: user/database/options/replication pass through. 10. Backend auth is relayed; client responses read for auth codes 3,5,10,11; authentication ends at ReadyForQuery. 11–12. Client credentials/proofs pass through; configured credentials are not substituted. 13–14. All auth-phase messages including ParameterStatus and BackendKeyData relay unchanged. 15. CancelRequest is not specially recognized. 16. Q SQL is decoded as a C string, passed to shared policy, then original bytes forwarded. 17. Partial extended handling only. 18. Parse stores name→SQL and authorizes SQL immediately. 19. Bind stores portal→statement SQL; ignores values/formats. 20. Describe forwarded. 21. Execute maps portal to SQL (unknown uses `/* unknown portal */`), authorizes SQL without params, then forwards. 22. Close forwarded without map cleanup. 23. Flush forwarded. 24. Sync forwarded; responses drained through ReadyForQuery. 25–28. Names are plain string map keys; no correct prepared statement/portal lifecycle. 29–32. Binary/text/NULL/OID data ignored by policy identity. 33. Policy exceptions produce structured ErrorResponse; other handler errors destroy sockets. 34. Drains until `Z`. 35. No status tracking; synthetic `Z` is always `I`. 36–39. QueryKnight ErrorResponse uses Severity `ERROR`, SQLSTATE `42501`, message from `QueryDeniedError.message` or `String(error)`, no Detail/Hint; pending text comes from shared approval path, not a proxy-specific formatter. 40. Backend protocol message payloads relay unchanged. 41. TLS refused (`N`). 42. GSS is not refused explicitly. 43. Upstream is plain `node:net`; no TLS negotiation or TLS-required validation. 44. Authentication is byte-relay, including passwords/proofs. 45. BackendKeyData relayed; no cancellation validation. 46. FunctionCall blindly forwarded. 47–48. COPY blindly forwarded; no SQL/payload gate. 49. Replication not rejected. 50. SQL PREPARE/EXECUTE relies on shared evaluator. 51–52. Reader buffer grows unbounded; no explicit framing/state bounds. 53. Shared policy layer limit only. 54. No Bind payload cap. 55. Sequential loop; Q/S drain to Z, no explicit pipeline support. 56–57. Per-handler maps; finally destroys both sockets. 58. `timeoutMs` is enforcement timeout, not frame/idle timeout. 59–60. Optional history records after enforcement and before forwarding; no explicit observer hook. 61. No parameter data is decoded/logged. 62. History is awaited before forwarding. 63. CLI loopback. 64. No TS subprocess. 65. Shared HistoryClient handles approvals/session. 66. Shared core policy behavior. 67. One URL per listener. 68. CLI prints redacted URL and `(local plaintext)`; caught handler errors destroy sockets. 69. Error encoder structures fields but does not guard embedded NUL in message. 70. No explicit validation before policy. 71. Tests are live driver smoke, not message recorder. 72. No malformed codec matrix. 73. Existing live tests: allowed SELECT, parameterized extended SELECT/write, blocked DDL. 74–79. No real approval retries, transaction state, cross-client name state, or no-replay failure tests found. 80. Backend wire responses not decoded/re-encoded beyond message framing relay. 81. No clipping/result budget. 82. No qk-db cursor. 83. No PostgreSQL-specific invariants in TS audited source. 84–86. TS CLI routes MySQL too; out of scope for this commit. 87. No Rust quality gates apply to TS. 88–89. This document is the Rust-side audit contract.

## Rust implementation contract and protocol state table

Rust intentionally hardens unsafe/missing reference behavior: exact permit for executable requests; sanitized startup context; fail-closed modes; one backend TCP session per frontend. No opaque frontend encryption or streaming mode is tunneled. Structured local errors use frozen severity/code (`ERROR`/`42501`) without raw SQL/params. The Rust approval text will use the established daemon provider identity and opaque ID only. Reference raw message text is not reliably frozen because it is exception/provider-derived.

| Client state | Incoming frontend message | Proxy action | Backend action | Authorization required? | State transition |
|---|---|---|---|---|---|
| Startup | SSLRequest | Reply `N` | None | No | Startup |
| Startup | GSSENCRequest | Reject | None | No | Close |
| Startup | CancelRequest | Reject (reference has no safe mapping) | None | No | Close |
| Startup | StartupMessage | Validate fields, strip client security-context overrides; bind configured target | Connect fixed backend and send sanitized startup | No | Authentication |
| Authentication | auth response | Relay supported auth bytes without logging | Relay response | No | Authentication |
| Ready | Q nonempty | Decode complete C string; authorize entire SQL | On permit, consume and forward original Q exactly once | Yes | AwaitingReady |
| Ready | Q empty | Synthesize EmptyQueryResponse + actual-status ReadyForQuery | None | No | Ready |
| Ready | P Parse | Validate/store typed statement; protocol parse metadata only | Forward P as needed for backend statement identity | No execution permit (not execution) | Ready/statement tracked |
| Ready | B Bind | Parse formats/OIDs/values with bounds; resolve current statement; track typed portal | Forward original B | No execution permit (binding only) | Ready/portal tracked |
| Ready | D Describe | Validate statement/portal identity; backend metadata may be exposed (documented) | Forward D | No; does not execute SQL | AwaitingResponse |
| Ready | C Close | Validate object; forward and update only when backend confirms | Forward C | No | AwaitingResponse |
| Ready | H Flush | Flush buffered backend traffic | Forward H | No | Ready |
| Ready | E Execute | Resolve live portal + SQL + bound values; authorize exact current values | Permit required, consume permit, forward original E once | **Yes** | AwaitingResponse |
| Ready | S Sync | Synchronize backend; for local extended error, do not send stale queued E; return actual backend transaction status | Forward S only when safe | No | Ready at Z |
| Ready | F FunctionCall | Reject fail-closed | None | Not modeled; never forward | ExtendedErrorUntilSync/close |
| Ready | COPY FROM STDIN candidate | Reject before backend enters CopyIn | None | SQL authorization cannot bind future stream | ExtendedErrorUntilSync |
| Ready | permitted COPY TO STDOUT query | Permit Q/E then relay CopyOut stream unchanged | Forward executable request | Yes for originating SQL | Streaming until Ready |
| Ready | unknown/malformed executable frame | Structured protocol error or close before auth | None | No | Error/close |
| ExtendedErrorUntilSync | non-Sync message | Discard; never forward queued executable operations | None | No | ExtendedErrorUntilSync |
| ExtendedErrorUntilSync | Sync | Restore coherent boundary using actual backend status; never fabricate `E` | Sync only if backend state requires it | No | Ready |
| Any | frontend disconnect | Drop state | Close backend | No | Closed |

### Specific semantic decisions

- PostgreSQL Parse performs syntax analysis and parse analysis, may resolve names/types and access catalogs; planning/execution generally occurs later. It is not SQL execution, but Parse/Describe can disclose metadata and should not be treated as execution permit-bearing operations. Rust documents this deliberate metadata exposure and never allows Parse to authorize an Execute.
- Bind captures actual parameter values and format codes; future proxy state must keep secret bytes bounded and unformatted. It will map text/binary values to shared `ExecutionParam::Wire` with optional generic `type_hint`; NULL remains `ExecutionParam::Null` (never inferred from empty bytes). This identity type and the canonical Exact V2 encoder are now available in qk-core; no protocol-specific digest extension is needed.
- Simple Query authorizes the entire decoded SQL request, including all statements; no partial forwarding. The forwarded frame is the original Q frame whose C-string SQL is the exact bytes analyzed. Empty Q is synthesized per PostgreSQL (`I`/empty response) and does not invoke authorization.
- No persistent permit cache. Every Execute attempt, including a portal resumed after PortalSuspended, authorizes again.
- Startup user/database/options cannot redirect backend target or change trusted role/search path/options. Configured backend host/database identity is the security context. Frontend authentication remains relayed only where compatible with the trusted backend startup identity.
- Backend TLS: TS reference does not implement it. Rust must reject a TLS-required configuration unless clean maintained TLS transport is available; never silently downgrade.
- COPY FROM STDIN, FunctionCall, replication, GSSENC, unvalidated CancelRequest are rejected rather than passed through.

## Future shared-identity boundary

A future PostgreSQL adapter must:

```text
Parse: retain statement SQL and optional generic parameter type hints
Bind: validate each value and format; create ordered ExecutionParam::Wire
      { Text|Binary, type_hint, exact bytes }; represent NULL distinctly
Execute: resolve current portal SQL + values → authorize_guarded
         → shared Exact V2 → consume ExecutionPermit → forward original
         Execute on the same backend session
```

Wire text and binary bytes are hashed exactly as represented, without UTF-8,
base64, or hex conversion. The shared encoder owns representation/type framing;
the future proxy MUST NOT implement another digest. MySQL
`COM_STMT_EXECUTE` will use the same protocol-neutral identity type. No proxy
protocol code is included in this prerequisite.
