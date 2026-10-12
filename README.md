# QueryKnight (Rust)

A deterministic database safety layer for AI agents.

**OpenShell controls where agents can connect. QueryKnight controls what SQL
they can execute.**

QueryKnight evaluates the current request against a versioned policy and
requires a positive, request-bound permit before any database execution, so an
adapter or wire proxy can forward only what was already authorized. Approvals
are exact: a `once` grant authorizes one request and a changed bound value
cannot reuse it.

QueryKnight is not a database driver replacement, not a drop-in PostgreSQL
gateway, and not affiliated with or endorsed by NVIDIA/OpenShell.

## Status

**QueryKnight 0.1.0 technical preview.** The source repository is public-ready
under Apache-2.0.

| | |
|---|---|
| Source | public-ready |
| Binary release | not published |
| crates.io | not published |
| Container image | not published |
| GitHub Release / tag | none |

Build from source. Do not expect downloadable artifacts yet.

## Build from source

```sh
git clone https://github.com/queryknighthq/queryknight.git
cd queryknight
cargo build --release --locked
./target/release/queryknight --version    # QueryKnight 0.1.0
```

Requires a stable Rust toolchain (developed and validated with 1.94.1; no
minimum supported version is declared yet). The daemon's browser UI is a
committed bundle, so no frontend toolchain is needed to build.

Validate a policy and evaluate SQL without touching a database:

```sh
./target/release/queryknight policy validate tests/compatibility/policies/standard.yaml
./target/release/queryknight inspect --dialect postgres "SELECT 1"
./target/release/queryknight inspect --dialect postgres \
  --policy tests/compatibility/policies/standard.yaml \
  "UPDATE customers SET active = false"
# Decision: DENY / Reason: UNBOUNDED_UPDATE (exit 3)
```

For a guarded local database path, point the proxy at an explicitly trusted
connection and keep it on loopback — see
[`docs/proxy-postgres.md`](docs/proxy-postgres.md) and
[`docs/release-security.md`](docs/release-security.md). There is no supported
remote-bind configuration.

## Support matrix

| Surface | Status |
|---|---|
| PostgreSQL direct (explicit `sslmode=disable`) | supported |
| PostgreSQL direct verified TLS (`sslmode=require`) | supported, live-tested |
| PostgreSQL proxy Simple Query | supported |
| PostgreSQL proxy Extended Query (Parse/Bind/Describe/Execute/Close/Flush/Sync) | supported |
| PostgreSQL proxy frontend TLS | **not implemented** |
| MySQL proxy `COM_QUERY` + audited prepared statements | supported |
| MySQL TLS | **not implemented** |
| MCP (stdio) | supported |
| Daemon/control plane (loopback HTTP + bearer token) | supported |
| OpenShell v0.1.2 HTTP/WebSocket middleware | live verified |
| OpenShell v0.1.2 native PostgreSQL network gating | live verified |
| OpenShell WebSocket in a real sandbox | generated-client verified only |
| OpenShell `HTTP_RESPONSE/PRE_RETURN` | unsupported |

Unsupported operations fail closed rather than degrading. No MariaDB version is
claimed or tested.

## Known limitations

- **Technical preview.** Not production-ready, and no remote or multi-tenant
  deployment is supported.
- **The PostgreSQL proxy frontend hop is plaintext.** Frontend TLS is not
  implemented; only the QueryKnight → PostgreSQL hop is verified TLS. The
  frontend hop must stay inside a trusted, controlled boundary.
- **The PostgreSQL proxy binds loopback only.** The OpenShell deployment
  currently needs operator-managed forwarding between the sandbox and the
  proxy; the test harness uses a test-only relay, which is not a product
  feature.
- **Unsupported PostgreSQL operations fail closed**: COPY, FunctionCall,
  replication startup, CancelRequest forwarding, and SQL `SET`.
- **MySQL TLS is not implemented.**
- **Approvals bind to a per-connection session**, so a retry after approval must
  reuse the connection.
- **OpenShell compatibility targets `v0.1.2` only** (commit
  `6648bd0c290efbc41ba131ee9831ee45cd431f94`). Newer releases are added after
  live verification; `main` is not tracked.
- **Live integration suites are validated on macOS / Apple Silicon.** Other
  platforms are unverified.
- **No release packaging** exists: no binary artifacts, container images, or
  package publication.

Security limitations and the full transport matrix are kept in
[`docs/release-security.md`](docs/release-security.md) and
[`SECURITY.md`](SECURITY.md).

## OpenShell + PostgreSQL

OpenShell enforces the network destination and never parses PostgreSQL SQL;
QueryKnight terminates the wire protocol and enforces the SQL. Both are live
verified against a real OpenShell v0.1.2 sandbox:

```
OpenShell sandbox ──X── direct PostgreSQL      (denied by OpenShell)
        │
        │ PostgreSQL protocol (plaintext frontend hop)
        ▼
QueryKnight PostgreSQL proxy
        │
        │ verified TLS (sslmode=require, pinned CA)
        ▼
PostgreSQL 17
```

`SELECT` is allowed, an unbounded `DELETE` is denied with SQLSTATE 42501, and a
bound `DELETE` needs an ExactV2 `once` approval that a changed value cannot
reuse. Reproduce it with `scripts/test-openshell-postgres-v0.1.2.sh`; see
[the demo](docs/openshell-postgres-demo.md) and
[the compatibility matrix](docs/openshell-compatibility.md).

## Compatibility

`tests/compatibility/` holds language-neutral fixtures. `cargo test -p qk-compat`
runs them against the Rust evaluator; an optional developer-only runner
(`tools/reference-runner/`, Bun) diffs the same fixtures against the historical
TypeScript implementation. That sibling checkout is not needed to build, test,
or run QueryKnight, and it is not part of this repository.

Documentation: [`docs/release-security.md`](docs/release-security.md) for
support and deployment assumptions, [`docs/security-invariants.md`](docs/security-invariants.md)
for the invariant list, [`docs/evaluator.md`](docs/evaluator.md),
[`docs/fallback-analysis.md`](docs/fallback-analysis.md),
[`docs/sqlparser-differences.md`](docs/sqlparser-differences.md),
[`docs/release-checklist.md`](docs/release-checklist.md), and
[`docs/third-party-licenses.md`](docs/third-party-licenses.md).

## Security

Read [`SECURITY.md`](SECURITY.md) before relying on any deployment, and
[`docs/release-security.md`](docs/release-security.md) for the trust boundaries
this project does and does not provide.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security-semantic changes require
tests that fail before the change.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

Third-party and vendored material keeps its own attribution; see
[`docs/third-party-licenses.md`](docs/third-party-licenses.md).
