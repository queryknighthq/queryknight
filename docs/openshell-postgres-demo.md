# OpenShell + QueryKnight + PostgreSQL demo

A short, runnable demonstration of two independent controls composed:

- **OpenShell controls where the agent can connect.**
- **QueryKnight controls what SQL it can execute inside PostgreSQL.**

Both run as real components: a real OpenShell v0.1.2 sandbox, the real
QueryKnight PostgreSQL wire proxy, and a real PostgreSQL 17 with TLS.

## What each layer proves

| Layer | Mechanism | What it proves |
|---|---|---|
| OpenShell | `network_policies` egress rules (`protocol: tcp`, exact host/port, kernel-resolved binary path) | The sandbox may reach the QueryKnight proxy and **cannot** reach the PostgreSQL backend directly — even with valid database credentials |
| QueryKnight | PostgreSQL wire proxy + policy evaluation + `ExecutionPermit` | Each statement is authorized before it is forwarded: `SELECT` allowed, unbounded `DELETE` denied, a bound `DELETE` requires an approval, and a changed bound value does not reuse a `once` grant |
| QueryKnight → PostgreSQL | `sslmode=require` with a pinned CA and hostname verification | The database hop is encrypted and the certificate chain and hostname are verified; an untrusted CA fails closed |

OpenShell does **not** inspect the PostgreSQL SQL. It enforces the network
destination. QueryKnight does not decide where the agent may connect; it decides
what may run.

### Three distinct failure classes

Keep these separate when reading logs; they have different causes and different
fixes.

| Class | Example from the run | Signal |
|---|---|---|
| Network-policy failure | sandbox → PostgreSQL backend | `NET:OPEN [MED] DENIED … -> <backend>:<port> [reason:transparent_tcp_mapping_denied]`; the client sees `Permission denied` before any PostgreSQL handshake |
| Authorization failure | QueryKnight blocks a statement | a PostgreSQL `ErrorResponse` with SQLSTATE `42501` (`insufficient_privilege`), or `waiting for approval: <id>` |
| Transport failure | QueryKnight → PostgreSQL TLS | a `FATAL` from the proxy: `PostgreSQL backend TLS handshake failed` / `refused the required TLS connection`; no SQL is sent |

## Architecture

```
                     ┌───────────────────────────────┐
                     │ OpenShell sandbox / agent     │
                     └───────┬───────────────┬───────┘
                             │               │
         direct PostgreSQL   │               │  PostgreSQL protocol
                             │               │  (plaintext, local/
                             │               │   trusted frontend hop)
                             X               ▼
                    DENIED by        ┌───────────────────────────┐
                    OpenShell        │ QueryKnight PostgreSQL    │
                    network policy   │ proxy (authorizes SQL)    │
                                     └─────────────┬─────────────┘
                                                   │
                                                   │ verified TLS
                                                   │ (sslmode=require,
                                                   │  pinned CA)
                                                   ▼
                                     ┌───────────────────────────┐
                                     │ PostgreSQL 17             │
                                     └───────────────────────────┘
```

> OpenShell controls where the agent can connect.
> QueryKnight controls what SQL it can execute.

The inspected hop is the frontend one. Frontend PostgreSQL TLS is intentionally
not implemented, so the sandbox → proxy leg is plaintext and local; the
proxy → PostgreSQL leg is verified TLS.

## Prerequisites

- macOS or Linux with Docker (Docker Desktop on macOS) and a Docker socket the
  gateway can reach;
- `cargo`, `git`, `jq`, `openssl`, `curl`, `python3`, `nc`;
- **z3** on `PATH` (`brew install z3`). The OpenShell gateway links the system
  z3; the multi-GB bundled build is not used;
- a non-loopback IPv4 address of this machine that the sandbox can reach
  (autodetected; override with `OPENSHELL_QUERYKNIGHT_HOST`).

No QueryKnight or OpenShell secrets are needed. The PostgreSQL credentials are
ephemeral and generated per run.

## Run it

```sh
scripts/test-openshell-postgres-v0.1.2.sh
```

It exits `0` only when every assertion passes. It provisions an ephemeral PKI,
a TLS-enabled PostgreSQL 17 container, a QueryKnight daemon and two PostgreSQL
proxies (one with the trusted CA, one deliberately with an untrusted CA), an
OpenShell v0.1.2 gateway, and one sandbox. Everything is removed on exit; logs
are retained only on failure.

The OpenShell gateway and CLI are built from the pinned commit on each run,
which takes several minutes. To reuse a build directory between runs:

```sh
OPENSHELL_PERSISTENT_TARGET=/path/to/reusable/target \
  scripts/test-openshell-postgres-v0.1.2.sh
```

## Expected phases

| Phase | Assertion |
|---|---|
| 1 | OpenShell v0.1.2 artifacts and pinned commit |
| 2 | PostgreSQL 17 with `ssl=on`; backend reachable from a plain container context with the same credentials |
| 3 | QueryKnight daemon, verified-TLS proxy, and untrusted-CA proxy up |
| 4 | Sandbox created from the workload image with the egress policy |
| 5 | `psql` → PostgreSQL backend **denied by OpenShell** (with the denial reason from the supervisor log) |
| 6 | `psql` → QueryKnight proxy **allowed**, returns `1` |
| 7 | `SELECT 1` allowed; the proxied backend session reports TLS |
| 8 | Unbounded `DELETE` denied with SQLSTATE `42501`; backend rows unchanged |
| 9 | Bound `DELETE` requires approval; pending as `exact_v2`; backend unchanged |
| 10 | Approval granted through the daemon control plane with `scope=once` |
| 11 | Exact retry on the same connection executes once |
| 12 | Changed bound value is blocked and does not reuse the grant |
| 13 | Untrusted backend CA fails closed with no SQL executed |
| 14 | History contains only executed statements; no credential in any artifact |

## Notes on the harness

- The workload image (`tests/openshell-v0.1.2-workload/`) exists only to give
  the sandbox a real `psql`, a parameterized client, and a `curl`. Real users
  bring their own agent image.
- The QueryKnight PostgreSQL proxy binds loopback only, by design. OpenShell
  resolves `host.docker.internal` to this host's routable address, so the harness
  bridges that one hop with a small local TCP relay
  (`examples/openshell/tcp-relay.py`). The relay is test plumbing, not a
  QueryKnight component.
- The database password is written into the sandbox through stdin (a `.pgpass`
  file), never as a command argument, and the script asserts that the sentinel
  never appears in the retained logs or artifacts.

## Session identity

Approvals are bound to QueryKnight's own trusted session scope, not to anything
the sandbox or the harness chooses. The harness does not construct approval
identity from the OpenShell sandbox display name, the frontend TCP port, or a
`psql` process id; the proxy mints one session per frontend connection and the
daemon verifies the digest, version, and complete scope.

That has a visible consequence in the demo: because the session is per
connection, the retry after approval must be issued on the **same** connection,
exactly as an interactive client would. The demo drives all three approval
attempts from one long-lived client session for this reason.
