# PostgreSQL proxy: frozen TypeScript reference and Rust security contract

## Audited TypeScript surface (`../queryknight-ts`, read-only)

Audited source: `packages/proxies/postgres/src/{proxy.ts,messages.ts,reader.ts,proxy.test.ts}`, `packages/cli/src/index.ts`. The CLI is `queryknight proxy [--listen <port>]`; PostgreSQL is selected when `MYSQL_URL ?? DATABASE_URL` has a postgres scheme. `POSTGRES_URL` is used by tests but is not in CLI resolution. It listens on `127.0.0.1`, default port `5434`; upstream host/port come from the URL (port defaults to 5432). `connectionKey` defaults to upstream URL. Relevant shared env includes `QUERYKNIGHT_ENV`, `QUERYKNIGHT_POLICY_FILE`, `QUERYKNIGHT_DATABASE`, `QUERYKNIGHT_DAEMON_URL`, `QUERYKNIGHT_HOME`; proxy options also include `timeoutMs`. No per-proxy host option exists in CLI.

### Audited behavior (numbering matches request)

1. `proxy` subcommand, `--listen`. 2. `127.0.0.1`. 3. URL-derived hostname/port, default 5432. 4. URL precedence `MYSQL_URL` then `DATABASE_URL`; tests additionally use `POSTGRES_URL`; default connection key raw URL. 5. Shared environment/policy/daemon/history config above. 6. First startup packet relayed. 7. Exact 8-byte SSLRequest gets `N`, then another startup is relayed. 8. GSSENCRequest has no special handling and is relayed upstream (unsafe gap). 9. Startup fields are not filtered: user/database/options/replication pass through. 10. Backend auth is relayed; client responses read for auth codes 3,5,10,11; authentication ends at ReadyForQuery. 11–12. Client credentials/proofs pass through; configured credentials are not substituted. 13–14. All auth-phase messages including ParameterStatus and BackendKeyData relay unchanged. 15. CancelRequest is not specially recognized. 16. Q SQL is decoded as a C string, passed to shared policy, then original bytes forwarded. 17. Partial extended handling only. 18. Parse stores name→SQL and authorizes SQL immediately. 19. Bind stores portal→statement SQL; ignores values/formats. 20. Describe forwarded. 21. Execute maps portal to SQL (unknown uses `/* unknown portal */`), authorizes SQL without params, then forwards. 22. Close forwarded without map cleanup. 23. Flush forwarded. 24. Sync forwarded; responses drained through ReadyForQuery. 25–28. Names are plain string map keys; no correct prepared statement/portal lifecycle. 29–32. Binary/text/NULL/OID data ignored by policy identity. 33. Policy exceptions produce structured ErrorResponse; other handler errors destroy sockets. 34. Drains until `Z`. 35. No status tracking; synthetic `Z` is always `I`. 36–39. QueryKnight ErrorResponse uses Severity `ERROR`, SQLSTATE `42501`, message from `QueryDeniedError.message` or `String(error)`, no Detail/Hint; pending text comes from shared approval path, not a proxy-specific formatter. 40. Backend protocol message payloads relay unchanged. 41. TLS refused (`N`). 42. GSS is not refused explicitly. 43. Upstream is plain `node:net`; no TLS negotiation or TLS-required validation. 44. Authentication is byte-relay, including passwords/proofs. 45. BackendKeyData relayed; no cancellation validation. 46. FunctionCall blindly forwarded. 47–48. COPY blindly forwarded; no SQL/payload gate. 49. Replication not rejected. 50. SQL PREPARE/EXECUTE relies on shared evaluator. 51–52. Reader buffer grows unbounded; no explicit framing/state bounds. 53. Shared policy layer limit only. 54. No Bind payload cap. 55. Sequential loop; Q/S drain to Z, no explicit pipeline support. 56–57. Per-handler maps; finally destroys both sockets. 58. `timeoutMs` is enforcement timeout, not frame/idle timeout. 59–60. Optional history records after enforcement and before forwarding; no explicit observer hook. 61. No parameter data is decoded/logged. 62. History is awaited before forwarding. 63. CLI loopback. 64. No TS subprocess. 65. Shared HistoryClient handles approvals/session. 66. Shared core policy behavior. 67. One URL per listener. 68. CLI prints redacted URL and `(local plaintext)`; caught handler errors destroy sockets. 69. Error encoder structures fields but does not guard embedded NUL in message. 70. No explicit validation before policy. 71. Tests are live driver smoke, not message recorder. 72. No malformed codec matrix. 73. Existing live tests: allowed SELECT, parameterized extended SELECT/write, blocked DDL. 74–79. No real approval retries, transaction state, cross-client name state, or no-replay failure tests found. 80. Backend wire responses not decoded/re-encoded beyond message framing relay. 81. No clipping/result budget. 82. No qk-db cursor. 83. No PostgreSQL-specific invariants in TS audited source. 84–86. TS CLI routes MySQL too; out of scope for this commit. 87. No Rust quality gates apply to TS. 88–89. This document is the Rust-side audit contract.

## Rust Simple Query and Extended Query implementation

Rust adds `queryknight proxy [--listen <port>]`, bound only to `127.0.0.1`
(default `5434`). `MYSQL_URL` takes precedence over `DATABASE_URL`, and the
selected URL must be PostgreSQL. Backend selection is fixed at startup and
supports one TCP host. Explicit `sslmode=disable` is required: backend TLS is
not implemented and TLS-enabled or default-`prefer` configurations are rejected
rather than downgraded. Frontend SSL/GSS requests receive `N`; following
protocol and authentication traffic is plaintext. Keep the listener loopback-
only.

Each frontend owns one backend TCP session, a prepared-statement map, a portal
map, and extended error state. The proxy relays supported PostgreSQL
authentication (AuthenticationOk, cleartext, MD5, and SCRAM messages) without
logging passwords/proofs. The backend URL password is not substituted for the
frontend credential. Configured backend user/database are trusted identity;
the frontend user must match, and an omitted frontend database defaults to
that user. An omitted backend URL database defaults to the configured user.
Only `application_name`, `client_encoding=UTF8`, and empty `options`/`replication`
values are permitted; other startup parameters and non-empty values are
rejected.

| Frontend message/state | Proxy behavior | Backend behavior |
|---|---|---|
| SSLRequest / GSSENCRequest | Reply `N` to at most two requests, then close | None |
| CancelRequest | Close without forwarding | None |
| StartupMessage | Validate identity and allowed parameters | Forward validated startup unchanged to fixed target |
| Authentication | Relay supported bounded auth frames | Same backend session |
| Empty `Q` | Synthesize EmptyQueryResponse + ReadyForQuery with last backend status | None |
| Nonempty `Q` | Authorize complete SQL; consume one permit before forwarding | Original `Q` frame once |
| `P` Parse | Validate UTF8 SQL/OIDs; track only after ParseComplete; never authorize | Forward unchanged as non-executing preparation |
| `B` Bind | Decode formats/lengths/NULL; attach only declared OIDs; retain portal snapshot; never authorize | Forward unchanged as non-executing binding/planning |
| `D` Describe | Require a locally known statement/portal; no authorization | Forward unchanged; relay native metadata responses |
| `C` Close | Remove matching state only after CloseComplete; closing a statement drops dependent portals | Forward unchanged |
| `H` Flush | Validate empty payload; no authorization | Forward and flush |
| `E` Execute | Resolve exact portal snapshot; authorize current SQL and ordered wire params; consume a fresh permit | Forward the original `E` exactly once only on permit |
| `S` Sync | End extended cycle; leave actual transaction status authoritative | Forward and relay ReadyForQuery |
| FunctionCall / COPY frame | Fail closed | Never forward |
| Disconnect/backend failure | Drop all connection-local state; never reconnect/replay | Close session |

### Parse, Bind, and Execute security boundary

Parse and Bind are protocol preparation only, not QueryKnight execution
authorization. PostgreSQL 17's [extended-query flow
specification](https://www.postgresql.org/docs/17/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY)
defines Parse as creating a prepared statement, Bind as creating a portal and
performing query planning, and Execute as running that portal. The proxy
forwards valid Parse and Bind setup messages so PostgreSQL retains its native
statement/portal semantics, but creates no permit and no approval request for
either. A backend Parse/Bind error is relayed and enters error-until-Sync; a
successful BindComplete is not authorization.

For pipelined clients, the proxy issues an internal backend Flush after each
response-bearing setup/execution message so it can correlate ParseComplete,
BindComplete, Describe/Close responses, and Execute completion before applying
the next frontend message. Frontend Flush is still forwarded as requested.

Prepared statements and portals are keyed per frontend. Named Parse/Bind
duplicates retain PostgreSQL's error behavior; unnamed Parse replaces the
unnamed statement, and unnamed Bind replaces the unnamed portal. A portal
holds the exact statement version and decoded parameter identity to which it
was bound, even if the unnamed statement is later replaced. Closing a
statement invalidates its dependent portals. Client names are identifiers,
never authorization capabilities. Per-frontend state is capped at 1024
statement entries, 1024 portals, and 4 MiB of retained SQL/portal parameter state.

Every frontend Execute reconstructs an `AuthorizationRequest` from the
portal's exact SQL and ordered `ExecutionParam` values, then calls
`qk-db::authorize_guarded`. Text/binary representations, exact bytes, and
declared nonzero Parse OIDs flow to the shared Exact V2 encoder; NULL remains
the shared NULL value. Server-inferred OIDs are not invented. Bind result
formats are forwarded and retained for protocol state but are excluded from
approval identity. Execute `max_rows` is preserved in the original frame and
is not added to identity: it controls result flow, not SQL/parameter meaning.

There is no permit cache on statements or portals. Each Execute, including a
resume after PortalSuspended, re-enters authorization and consumes its own
permit immediately before forwarding. A Once grant can reauthorize the same
exact request while live; a changed parameter or wire representation does not
match. Session scope may authorize a new permit for a different request with
the same shape only on the same trusted frontend session. PostgreSQL resumes
a suspended portal rather than replaying its SQL; repeated Execute messages
are still individually gated.

Blocked, pending, and malformed extended messages return ErrorResponse and
enter PostgreSQL error-until-Sync handling. Later messages are not forwarded;
Sync is forwarded to the existing backend session and only its ReadyForQuery
`I`/`T`/`E` state is reported. Backend ErrorResponses after forwarded Execute
are never retried. They are relayed unchanged unless a field contains exact
bound parameter bytes; only matching fields are scrubbed to protect Bind
secrets (large/high-arity error frames conservatively omit dynamic details).
History records executable SQL at an allowed Execute, not at Parse/Bind, and
never includes Bind bytes. The daemon provider receives only the shared exact
digest and trusted scope.

Simple Query remains unchanged: complete `Q` SQL is authorized as one request,
no partial forwarding or permit cache exists, and the original `Q` is sent
only after consuming its permit. Empty `Q` skips policy. COPY and SQL SET
remain explicitly unsupported.

## PostgreSQL 17 live test

The real-client integration matrix uses `tokio-postgres` and a disposable
PostgreSQL 17 database. Provide a URL with an explicit `sslmode=disable` and a
role allowed to create/drop tables:

```sh
QUERYKNIGHT_POSTGRES_TEST_URL='postgres://user:password@127.0.0.1:5432/testdb?sslmode=disable' \
  cargo test -p qk-proxy-postgres --test live_postgres -- --nocapture
```

The test creates a uniquely named table, proves prepared statements and
blocked side effects against an independent direct connection, then removes
the table. Without the environment variable it returns immediately; set it to
collect live evidence.

## Scope boundary

Supported: PostgreSQL Simple Query plus guarded Extended Query prepared
statements and portals. Unsupported/fail-closed: COPY streaming, FunctionCall,
replication startup, CancelRequest forwarding, frontend TLS, and backend TLS.
This feature does not change MySQL or OpenShell. Legacy observe remains
unimplemented and is not shipped in Rust; `../queryknight-ts` remains the
read-only reference oracle.
