# QueryKnight (Rust)

Local SQL authorization/execution toolkit for trusted local workflows.
QueryKnight-owned execution paths evaluate the current request and require a
positive permit before database execution. OpenShell is authorization-only;
it does not execute SQL or verify what an external executor later does.

This Rust workspace is an early technical preview, not a production-ready
database gateway. `../queryknight-ts` remains the read-only behavioral oracle.

## Status

The workspace contains the policy engine, SQL analysis, approvals, direct
database adapters, PostgreSQL and MySQL proxies, MCP, OpenShell, persistence,
daemon/control plane, audit, and metrics crates. Packaging/CI readiness and
transport limits are documented in [`docs/release-security.md`](docs/release-security.md).

## Supported local protocol profile

| Surface | Supported profile | Explicit limitation |
|---|---|---|
| Direct PostgreSQL | Explicit `sslmode=disable` (trusted plaintext) or `sslmode=require` (verified TLS, `QUERYKNIGHT_PG_SSLROOTCERT` as the only trust anchor) | Omitted/`prefer`/`allow` fail closed; no plaintext retry after a TLS failure. |
| Direct MySQL | Plaintext `mysql_async` connection | Parsed TLS requests fail closed; native TLS is not implemented. |
| PostgreSQL proxy | Guarded Simple and supported Extended Query on loopback; backend hop explicitly plaintext (`sslmode=disable`) or verified TLS (`sslmode=require`) | Frontend TLS, COPY, FunctionCall, replication, and CancelRequest are unsupported/fail closed. |
| MySQL proxy | Guarded COM_QUERY and supported prepared statements on loopback | TLS, compression, LOCAL INFILE, cursors/FETCH, query attributes, and unmodeled commands are unsupported/fail closed. |
| MCP | Local stdio process transport | No network listener. |
| OpenShell | Authenticated HTTPS with strict OpenShell extension JWT verification for v0.1.2; explicit insecure mode is loopback-only, and Unix sockets are local integration/test paths. | Authorization-only; unauthenticated remote and plaintext non-loopback are rejected. See the [integration guide](docs/openshell.md). |
| Daemon/control plane | Loopback HTTP with bearer token on protected routes | Not a public remote API; shared client rejects non-loopback targets. |

## OpenShell + PostgreSQL

OpenShell controls where the agent can connect. QueryKnight controls what SQL it
can execute inside PostgreSQL.

```
OpenShell sandbox ──X── direct PostgreSQL          (denied by OpenShell)
        │
        │ PostgreSQL protocol
        ▼
QueryKnight PostgreSQL proxy
        │
        │ verified TLS
        ▼
PostgreSQL 17
```

`scripts/test-openshell-postgres-v0.1.2.sh` runs this composition end to end on
real components — a real OpenShell v0.1.2 sandbox, the real PostgreSQL proxy,
and PostgreSQL 17 over verified TLS — and exits `0` only when every assertion
passes. OpenShell enforces the network destination and never sees SQL;
QueryKnight enforces SQL authorization and does not decide reachability. See
[the demo](docs/openshell-postgres-demo.md).

See [release security and deployment scope](docs/release-security.md) for the complete matrix and trust assumptions.

## Smoke examples

```sh
cargo build --release

# Validate a policy file.
./target/release/queryknight policy validate tests/compatibility/policies/standard.yaml
# policy .../standard.yaml: valid (version 1, 1 database scope(s), 0 embedded test(s))

# Evaluate SQL (default demo policy; exit 0 allow, 3 deny/approval).
./target/release/queryknight inspect --dialect postgres "SELECT 1"
./target/release/queryknight inspect --dialect postgres \
  --policy tests/compatibility/policies/standard.yaml \
  "UPDATE customers SET active = false"
# Decision: DENY / Reason: UNBOUNDED_UPDATE (exit 3)

# Machine-readable output.
./target/release/queryknight inspect --dialect postgres \
  --policy tests/compatibility/policies/standard.yaml \
  --json "DELETE FROM customers WHERE id = 1"

# Piped SQL.
echo "SELECT id FROM public.customers LIMIT 5" | \
  ./target/release/queryknight inspect --dialect postgres \
  --policy tests/compatibility/policies/standard.yaml
```

## Compatibility

`tests/compatibility/` holds language-neutral fixtures proven against both
implementations (`bun tools/reference-runner/run.ts` for TypeScript,
`cargo test -p qk-compat` for Rust, including a direct differential test).
Documentation: [`docs/release-security.md`](docs/release-security.md)
summarizes support/deployment assumptions; [`docs/adr/observe-mode.md`](docs/adr/observe-mode.md)
records why legacy observe is not shipped; [`docs/release-checklist.md`](docs/release-checklist.md)
lists release gates. See [`docs/security-invariants.md`](docs/security-invariants.md)
for INV-001..INV-056, plus [`docs/evaluator.md`](docs/evaluator.md),
[`docs/fallback-analysis.md`](docs/fallback-analysis.md), and
[`docs/sqlparser-differences.md`](docs/sqlparser-differences.md).
Security assumptions and the absence of a private disclosure contact are stated in [`SECURITY.md`](SECURITY.md).
