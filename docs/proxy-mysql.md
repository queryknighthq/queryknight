# MySQL COM_QUERY proxy: reference audit and Rust contract

This document records the pre-implementation audit of the read-only TypeScript reference at `../queryknight-ts` and the contract implemented by the first Rust MySQL proxy. It is intentionally MySQL-specific; it does not generalize or refactor the PostgreSQL state machine. No TypeScript files are changed.

## Audited TypeScript reference

Audited files:

- `packages/cli/src/index.ts`
- `packages/proxies/mysql/src/{proxy.ts,packets.ts,reader.ts,index.ts}`
- `packages/proxies/mysql/src/{proxy.test.ts,packets.test.ts}`

The TypeScript behavior below describes the current source, not behavior carried forward uncritically.

### 46-point frozen behavior checklist

1. **CLI:** `queryknight proxy [--listen <port>]`.
2. **Default listener:** CLI binds `127.0.0.1`; MySQL proxy default is port `3308`.
3. **Backend configuration:** `MYSQL_URL ?? DATABASE_URL`; backend hostname/port come from URL, default `3306`; library `connectionKey` defaults to the raw URL.
4. **Initial handshake:** one upstream TCP connection is opened; the backend greeting and frontend login are relayed.
5. **Capabilities:** only frontend `CLIENT_DEPRECATE_EOF` is read; capability sets are otherwise relayed unchanged.
6. **Client capabilities:** not filtered, intersected, or validated by the TypeScript proxy.
7. **`CLIENT_SSL`:** not explicitly handled; TLS upgrade bytes are not decrypted.
8. **Authentication plugins:** plugin names are not inspected; auth packets are relayed.
9. **`mysql_native_password`:** relayed opaquely; no hash logic.
10. **`caching_sha2_password`:** relayed opaquely; no fast/full-auth distinction.
11. **Auth switch:** `0xfe` is treated as a request to read and relay a frontend auth packet.
12. **AuthMoreData:** `0x01 0x04` is also treated as requiring a frontend packet; other states are not modeled.
13. **TLS:** no frontend termination or backend TLS validation.
14. **Compression:** not decompressed or rejected.
15. **Sequence IDs:** copied but not validated.
16. **Fragmentation:** TCP chunks are joined into individual physical packets; logical multi-packet messages are not reassembled.
17. **Packet maximum:** three-byte packet length is used, but no aggregate/frame memory bound is imposed.
18. **`COM_QUERY`:** SQL bytes are decoded and passed to `analyzeMysql`/`enforcePolicy`.
19. **Multi-statement text:** not split in the proxy; complete decoded text is analyzed as one policy request.
20. **`CLIENT_MULTI_STATEMENTS`:** not cleared or validated.
21. **`COM_INIT_DB`:** converted to `USE <payload>` for authorization, then original command forwarded.
22. **`COM_CHANGE_USER`:** falls through to backend forwarding without policy or trusted identity update.
23. **`COM_RESET_CONNECTION`:** constant exists but command loop does not handle it; it falls through to forwarding.
24. **`COM_PING`:** forwarded and its response relayed.
25. **`COM_QUIT`:** forwarded and the loop returns.
26. **`COM_FIELD_LIST`:** not explicitly handled; default-forwarded.
27. **`COM_PROCESS_INFO`:** not explicitly handled; default-forwarded.
28. **`COM_PROCESS_KILL`:** not explicitly handled; default-forwarded.
29. **`COM_SET_OPTION`:** not explicitly handled; default-forwarded.
30. **`COM_REFRESH`:** not explicitly handled; default-forwarded.
31. **`COM_STATISTICS`:** not explicitly handled; default-forwarded.
32. **Prepared commands:** PREPARE and EXECUTE are gated by SQL text only; EXECUTE bind values are omitted; CLOSE is default-forwarded; other prepared commands are unmodeled and default-forwarded.
33. **LOCAL INFILE:** capability is not disabled and local-file response flow is not modeled.
34. **`LOAD DATA LOCAL INFILE`:** no explicit pre-backend gate.
35. **Server-side `LOAD DATA`:** delegated to `analyzeMysql` and policy; no additional unknown-operation gate exists in the proxy.
36. **Transaction state:** one backend connection per frontend preserves server state, but transaction/status flags are not tracked.
37. **Session variables:** SQL such as `SET` is handled through policy and executes on the persistent backend session.
38. **Database/schema switching:** `COM_INIT_DB` maps to `USE`; no policy database/session identity update occurs.
39. **Approval:** SQL branches call `enforcePolicy` with the passed `ApprovalPort`; there is no proxy-local approval cache.
40. **Generated ERR:** `encodeErr` defaults to error number `1227` and SQLSTATE `HY000`; message text is passed through.
41. **SQLSTATE:** generated QueryKnight errors use `HY000`.
42. **History/audit:** starts a `proxy` session; records full SQL after policy approval and before backend write; history errors suppress forwarding; raw default connection key may include password.
43. **Timeouts:** `timeoutMs` is used by policy enforcement; explicit socket I/O/connect timeouts are not present in this module.
44. **Disconnect/reconnect:** both sockets are destroyed on completion/failure; no reconnect or replay.
45. **Protocol limits:** one physical packet is read at a time; no explicit total query, buffer, command, or packet-sequence limits.
46. **Unsupported commands:** no fail-closed default; unrecognized commands are forwarded.


### Detail behind the numbered audit

1. **CLI and selection.** `queryknight proxy [--listen <port>]` selects `MYSQL_URL ?? DATABASE_URL`; PostgreSQL schemes route to the PostgreSQL proxy and every other scheme routes to MySQL. `--listen` is parsed as a numeric port. It passes the history client as both approvals and history.
2. **Listener.** The MySQL library default is `127.0.0.1:3308`. URL host and port select the upstream; port defaults to 3306. The proxy library permits overriding listener host, while the CLI binds only loopback. CLI output redacts the displayed URL.
3. **Trusted upstream.** The proxy connects to the configured URL host/port. `connectionKey` defaults to the raw URL (unlike the Rust shared password-stripped connection key). The TypeScript handshake does not bind the login username/database to configured URL identity; all client handshake bytes are relayed.
4. **Handshake model.** It opens one upstream TCP connection per frontend, forwards the backend greeting, forwards the frontend handshake response, then relays backend authentication packets. This is transparent authentication relay, not frontend termination/backend re-authentication.
5. **Capabilities.** Only `CLIENT_DEPRECATE_EOF` is parsed, solely to choose response terminator handling. Capability bits are otherwise neither filtered nor validated. The server greeting and frontend response are passed through.
6. **TLS and compression.** `CLIENT_SSL` is not specially accepted or rejected, backend URL TLS options are not validated, and compression is not decoded. The byte reader continues to expect classic unencrypted packets; these modes are not safely implemented.
7. **Authentication.** Plugin names, credentials, and responses are not interpreted. Auth-switch packets (`0xfe`) and one `AuthMoreData` pattern (`0x01 0x04`) cause the proxy to read and relay one client response. It does not distinguish supported plugins or reject full-auth/cleartext modes. It implements no password cryptography.
8. **Packet framing.** `packets.ts` reads/writes the 3-byte little-endian physical payload length and sequence byte. `PacketReader` waits for one complete physical packet across arbitrary TCP chunks, but has no packet/aggregate size cap and does not validate sequence IDs. A MySQL logical message split into `0xFFFFFF`-byte physical packets is not reassembled as one command; only the first physical packet is interpreted as a command. This is an authorization bypass risk and is not copied.
9. **SQL decoding.** `COM_QUERY` payload bytes after the command byte are decoded with the default non-fatal `TextDecoder`, which can replace invalid input. A heuristic strips a query-attributes prefix when bytes 1–2 are `00 01`. It does not bind decoding to the negotiated character set. Rust will not use this lossy or heuristic behavior.
10. **`COM_QUERY` and batches.** The complete remaining physical payload is passed to `analyzeMysql`/`enforcePolicy`; there is no deliberate statement splitting. `CLIENT_MULTI_STATEMENTS` is not negotiated or constrained, so batch behavior is inherited from the frontend/backend capabilities and parser. Rust will inspect the whole command and clear multi-statements at negotiation.
11. **Database changes.** `COM_INIT_DB` is rewritten into SQL text `USE …`, policy-checked, then the original binary command is forwarded. `USE` inside `COM_QUERY` also reaches normal SQL analysis. There is no trusted-scope update. `COM_CHANGE_USER` and `COM_RESET_CONNECTION` fall through to backend forwarding without updating proxy identity/state.
12. **Simple protocol commands.** `COM_PING` is forwarded and its response relayed. `COM_QUIT` is forwarded then the connection closes. `COM_FIELD_LIST`, process/admin commands, and unknown commands reach the default forwarding path.
13. **Prepared commands.** `COM_STMT_PREPARE` SQL is policy checked and stored by returned statement id. `COM_STMT_EXECUTE` authorizes only the remembered SQL; its binary parameter values are not part of authorization identity. `COM_STMT_CLOSE` deletes local tracking then forwards. Other prepared commands fall through and are forwarded. This path is intentionally excluded from Rust's first MySQL commit.
14. **LOCAL INFILE and LOAD DATA.** Capabilities are not filtered, and there is no explicit LOAD DATA or local-file gate. The result parser does not implement a dedicated LOCAL INFILE state. Rust will not negotiate client local-file support, will reject a backend local-file request without relaying file bytes, and will rely on the shared MySQL evaluator to fail closed for LOAD DATA whose semantics are unknown.
15. **Response protocol.** The response reader forwards packet bytes unchanged. It handles one OK/ERR or a result set with column definitions and EOF/OK terminators according to the parsed `CLIENT_DEPRECATE_EOF` flag. It does not maintain transaction/session status from status flags; a locally generated error cannot report backend status. Rust will relay backend response packets byte-faithfully and track only status actually observed in backend OK/EOF packets.
16. **Transactions and session SQL.** Each frontend owns one backend TCP connection, so backend transactions, variables, current schema, and temporary objects naturally persist. SQL such as `SET` is otherwise handled through ordinary policy. `COM_INIT_DB` can diverge from fixed policy scope. Rust preserves one backend connection per frontend, authorizes session-changing SQL as ordinary SQL, and rejects out-of-band database/user/reset commands.
17. **Approvals and errors.** SQL commands that the TypeScript switch recognizes call `enforcePolicy`; approvals are provided through its `ApprovalPort`. On failure, an ERR is locally encoded with default numeric code `1227` and SQLSTATE `HY000`; denial text comes from the policy error, other errors are stringified. Prepared setup/close and default-forward commands are exceptions to this gating.
18. **History.** A session is started with source `proxy`. After policy allows, full SQL is recorded before forwarding. History failure is inside the policy try/catch, so it can become a local ERR and suppress execution. The default raw-URL `connectionKey` may include the upstream password. Rust uses the shared password-stripped key, records best-effort through `qk-control-plane`, and history failure never replays or changes a permit.
19. **Timeouts and lifecycle.** `timeoutMs` is passed to policy enforcement; there is no explicit socket connect/read/write timeout in this module. Backend loss or frontend disconnect destroys both sockets. There is no reconnect/replay path.
20. **Tests.** The live tests use Bun SQL and mysql2, cover ordinary query and prepared execution, and are gated by `QK_LIVE_DB`. Packet tests cover encoding, ERR shape, and little-endian prepared id. The checked-in tests do not prove packet sequence validation, reassembly, TLS/capability restrictions, command fail-closed behavior, authorization non-forwarding, backend session isolation, or approval scope.

## Rust implementation boundary

### Trusted endpoint and CLI

The Rust command remains `queryknight proxy [--listen <port>]`, selecting `MYSQL_URL ?? DATABASE_URL` as the existing CLI does. PostgreSQL URLs continue to the existing PostgreSQL implementation; MySQL URLs use `qk-proxy-mysql`. MySQL listens only on `127.0.0.1`, default port `3308`. `--listen` changes only the local port.

The configured MySQL URL fixes backend host, port, username, database, SQL dialect, password-stripped connection key, policy database scope, and environment. One backend socket is opened per frontend connection. The initial frontend username/database must exactly match the configured username/database; missing configured identity/database is a configuration error. Frontend fields never choose a host or schema. The URL password is retained only in redacted `SecretUrl` config and is not substituted into the transparent client authentication exchange.

### Handshake, capabilities, TLS, and authentication

Use the reference's transparent handshake/authentication-relay model, hardened at the inspection boundary: relay the backend's classic-protocol greeting and authentication challenge/response bytes without implementing password hashes, while validating the client identity and negotiated flags. Support only `mysql_native_password` and `caching_sha2_password` fast-auth relay; reject unknown/cleartext plugins and `caching_sha2_password` full-auth requests. Authentication payloads are never logged or copied into SQL/history/diagnostics.

The proxy does not terminate frontend TLS or implement MySQL TLS. Strip `CLIENT_SSL` from the greeting before the client selects capabilities; if an SSL upgrade is nevertheless offered, reject/close before forwarding it. Parse backend URL options and fail configuration if TLS is required/enabled, rather than silently connecting in plaintext. Client/backend compression and zstd are not implemented: clear their bits in the advertised greeting and reject a client response that selects them.

Track backend-advertised, proxy-supported, and frontend-selected capability sets separately. Preserve protocol 4.1, secure connection, plugin authentication, configured database, and `CLIENT_MULTI_RESULTS` only for result-set interoperability. Clear `CLIENT_SSL`, `CLIENT_COMPRESS`, `CLIENT_LOCAL_FILES`, `CLIENT_MULTI_STATEMENTS`, `CLIENT_PS_MULTI_RESULTS`, `CLIENT_CONNECT_ATTRS`, `CLIENT_SESSION_TRACK`, `CLIENT_DEPRECATE_EOF`, `CLIENT_QUERY_ATTRIBUTES`, zstd, multifactor auth, expired-password handling, ODBC, `CLIENT_IGNORE_SPACE`, `CLIENT_NO_SCHEMA`, `CLIENT_SSL_VERIFY_SERVER_CERT`, and `CLIENT_REMEMBER_OPTIONS`. Require `CLIENT_PROTOCOL_41`, `CLIENT_SECURE_CONNECTION`, `CLIENT_PLUGIN_AUTH`, and `CLIENT_CONNECT_WITH_DB`; reject unsupported/inconsistent selections. The proxy uses classic EOF terminators.

Only UTF-8-compatible `utf8mb4` collation IDs representable by MySQL's one-byte handshake field are accepted: 45, 46, 224–247, and 255. This includes the `mysql_async` default and MySQL 8.4's common `utf8mb4_0900_ai_ci` (255). Decode COM_QUERY bytes with strict UTF-8; unsupported collation IDs, invalid byte sequences, unnegotiated query-attribute layouts, and malformed handshake fields fail closed. The exact validated bytes are relayed under the same selected collation.

### Packet and query bounds

Validate classic MySQL frame headers before allocation: three-byte little-endian physical length plus sequence id. Check sequence IDs through handshake/auth and every command/response exchange; reject truncated headers/payloads, malformed commands, arithmetic overflow, and oversized frames without panic. The shared `qk_sql::MAX_SQL_BYTES` ceiling is 1,000,000 SQL bytes (excluding the command byte), below MySQL's `0xFFFFFF` physical-fragment boundary. Any COM_QUERY exceeding that ceiling, including a fragmented query, is rejected before SQL decoding or backend write; the proxy drains only bounded oversized input with a fixed-size buffer to send the correctly sequenced local ERR, and closes sessions exceeding that drain bound. It never authorizes a first fragment. Backend response messages are reassembled only for bounded protocol parsing, then re-encoded with unchanged payload bytes and sequence IDs; results are never row/byte clipped.

### Authorization and forwarding

For each non-empty COM_QUERY, strictly decode the entire logical SQL payload and construct `AuthorizationRequest::new(sql, vec![])`; no query is split and no parameters are inferred. Invoke `qk_db::authorize_guarded` with trusted `DbConfig::Mysql`, `TrustedContext { integration: "proxy_mysql", tool: "proxy_query", … }`, the password-stripped key, and a fresh per-attempt approval setup. Set the shared request's `require_supported_analysis` guard so parse-error/unknown fallback decisions cannot be turned into executable approvals; reject parsed `Operation::Unsupported` as well. Use `DaemonApprovalProvider::with_exact_lookup_retry()` because COM_QUERY has no approval-id field. Run this synchronous path in `spawn_blocking`, not on a Tokio core worker. A new `ExecutionPermit` is required for every executable COM_QUERY; there is no proxy-local cache. `Blocked`, `PendingApproval`, malformed SQL, unknown/unsupported operation, or missing approval wiring never writes the command to the backend.

Immediately before the one backend write, validate permit dialect/scope as appropriate, move and consume the permit, then write the original validated logical COM_QUERY exactly once on that frontend's existing backend session. Never call `execute_guarded`; never reconnect or replay after backend write, timeout, disconnect, history, or observer failure. The backend's original OK/ERR/result metadata/row/terminator packets are relayed unchanged.

Session-changing SQL including `SET`, transaction control, and `USE` is sent through ordinary `qk-sql`/policy analysis. `SET NAMES`, `sql_mode`, and AST-recognized `character_set_*`/`collation_*` assignments remain in that path but are classified `Unsupported` because the proxy does not track SQL-interpretation-changing session state; the MySQL request's strict-analysis guard refuses them even if a policy would request approval. Other `SET` operations such as `time_zone`, `ROLE`, and `autocommit` remain ordinary `Operation::Set` requests and follow policy. `SELECT INTO` file/session targets are marked `Unsupported` when represented in the AST; MySQL OUTFILE forms the parser cannot represent (including executable-comment forms) fail the strict parse guard. There is no proxy regex allow-list. If analysis returns `Unsupported`, parse fails, or the evaluator cannot establish safe semantics, fail closed. Since the trusted scope is bound to one configured database, `USE`/schema switching must not be allowed to move execution to a different database. `COM_INIT_DB`, `COM_CHANGE_USER`, and `COM_RESET_CONNECTION` are rejected; no state is silently reset or rebound.

### Commands, approvals, error packets, and state

- `COM_PING` is forwarded to the same backend session and the backend response is relayed; it does not create a SQL permit.
- `COM_QUIT` is handled locally by closing the frontend/backend pair and dropping session state; no response or replay.
- `COM_QUERY` is authorized as described above. Empty/malformed SQL is not an authorization bypass; the implementation returns a local protocol ERR rather than forwarding an uninspected executable request.
- `COM_INIT_DB`, `COM_CHANGE_USER`, `COM_RESET_CONNECTION`, `COM_FIELD_LIST`, process/admin commands, all prepared-statement commands (`PREPARE`, `EXECUTE`, `SEND_LONG_DATA`, `RESET`, `CLOSE`, `FETCH`), LOCAL INFILE continuations, and unknown command bytes are explicitly rejected/closed, never passed through a permissive default branch.
- `COM_CHANGE_USER` closes the frontend/backend pair instead of returning an ERR: clients may update local credentials before its response, so keeping the old authenticated session alive would leave identity state ambiguous.
- An upstream LOCAL INFILE request is a protocol violation for this proxy mode: do not send it to the client or relay client file bytes; close the backend session and fail the frontend.
- `CLIENT_MULTI_STATEMENTS` is cleared. If a client still sends a multi-statement batch, the entire payload is authorized first; backend capability negotiation prevents execution as a batch. A policy-blocked batch produces zero backend query writes.
- Transaction/autocommit/session state belongs to MySQL. Track status bits only from actual backend OK/EOF packets (including `SERVER_STATUS_IN_TRANS` and `SERVER_STATUS_AUTOCOMMIT`) and relay those packets unchanged. A local authorization ERR never mutates or fabricates backend state; the same backend connection remains usable. If an authorization failure is returned while a transaction is active, the local error format does not claim a new backend status.
- QueryKnight ERR packets use a stable MySQL protocol-4.1 ERR layout with a policy/approval code and SQLSTATE `HY000` (no backend constraint-error impersonation), bounded safe text, no digest/token/password/auth bytes, and no raw query literals. Backend errors remain byte-identical. Secret-free diagnostics avoid upstream URL, frontend auth data, and daemon token.
- Once approvals are resolved by a fresh shared-provider authorization on the exact retry; changed SQL does not reuse Once. Session scope can authorize a new request-specific permit for the same normalized shape only on the same frontend session. `LegacyShape` never authorizes. There is no local approval cache. The daemon session is created per frontend connection when available; provider/session failure cannot become Allow.
- History is best-effort through `ControlPlaneClient` using the redacted connection key and frontend session id, and records only authorized SQL at the established proxy boundary. History failure cannot suppress an otherwise permitted query, cause a retry, or change forwarding.

## Protocol-state/action/authorization matrix

| Frontend state | Incoming command/packet | Authorization required? | Backend action | Local state change | Failure behavior |
|---|---|---:|---|---|---|
| Await backend greeting | Backend greeting | No | Validate sequence/capabilities/plugin; send filtered greeting | Record negotiated safe capabilities | Malformed/unsupported greeting: close both sides |
| Await client login | Handshake response / SSLRequest | No SQL | Validate protocol flags, UTF-8 collation, exact configured user/database; relay valid response | Establish auth sequence state | SSL/compression/unsupported flag, identity mismatch, malformed login: reject/close; never tunnel TLS |
| Authenticating | AuthSwitch/AuthMoreData/client auth reply | No SQL | Relay only supported plugin challenge/reply bytes with sequence checks | Advance auth phase | Unknown plugin or caching SHA2 full-auth/TLS requirement: fail safely; no secret logging |
| Ready | `COM_QUERY` | Yes for nonempty SQL | Only write original complete command after consumed permit; then relay full backend response | Update status only from backend response | Denied/pending/unknown/oversized/invalid encoding: local ERR, zero query writes; backend loss closes without replay |
| Ready | Multi-statement text in `COM_QUERY` | Yes, whole SQL text | Same permit gate; server multi-statement capability is off | No partial batch state | Blocked batch writes nothing; backend cannot execute negotiated multi-statements |
| Ready | Empty `COM_QUERY` | No executable SQL | No backend command | None | Local ERR; no bypass/no synthetic success |
| Ready | `COM_PING` | No | Forward once; relay matching backend response | None | Backend failure closes session; no replay |
| Ready | `COM_QUIT` | No | Close backend; do not forward/replay | Drop frontend/session state | Close both sides |
| Ready | `COM_INIT_DB` / `COM_RESET_CONNECTION` | Not modeled | Never forward | No schema/session reset | Local ERR |
| Ready | `COM_CHANGE_USER` | Not modeled | Never forward | Drop frontend/backend and identity state | Close; do not retain a client whose local identity may have changed |
| Ready | Prepared commands, field-list, process/admin, unknown opcode | Not modeled | Never forward | No prepared/admin state | Explicit error where command expects a response; close for no-response/unknown commands |
| Awaiting query response | Backend OK/ERR/result metadata/rows/EOF | Already authorized (or maintenance command) | Relay original bytes and validate response sequence/shape | Track real status flags; return to Ready only at complete response boundary | Malformed/truncated/LOCAL INFILE/unexpected command boundary: close both sides, no reconnect/replay |
| Any | Frontend EOF / backend EOF / malformed packet | No | Drop backend connection | Drop all per-client state | Close; never reconnect or replay |

## Acceptance coverage required for this commit

The deterministic fake backend must prove zero COM_QUERY writes for blocked/pending/changed-Once/unsupported commands; exactly one for a valid permit; one-session transaction and variable continuity; frontend isolation; command/sequence/fragment/size/charset failures; no LOCAL INFILE bytes; and secret-sentinel redaction. Approval coverage must exercise Once exact retry, changed literal rejection, Session same-shape/new permit behavior, different-session isolation, and LegacyShape rejection through the shared provider. Live MySQL 8.4 tests must include real `mysql_async` connections, SELECT/result sets, DML, policy blocks and independent side-effect checks, multi-statement denial, syntax ERR relay, transactions/autocommit/session variables, concurrent clients, disconnect behavior, approvals, and prepared/LOCAL INFILE rejection. Run the `mysql` CLI smoke only if installed; do not claim MariaDB support without testing it.

## Explicit first-commit exclusions

Only ordinary classic-protocol COM_QUERY plus safe COM_PING/COM_QUIT maintenance is supported. Prepared execution, TLS termination, backend TLS, compression, query attributes, local file transfer, arbitrary schema/user switching, admin commands, and generic MySQL protocol compatibility are not implemented. The next feature commit may add prepared statements only after review of this commit; this document does not begin that work.
