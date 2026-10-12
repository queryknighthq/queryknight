# OpenShell + QueryKnight + PostgreSQL demo

Two independent controls composed on real components: an OpenShell v0.1.2
sandbox, the QueryKnight PostgreSQL wire proxy, and PostgreSQL 17 over verified
TLS.

## 1. What this demonstrates

- **OpenShell controls network destination reachability.** The sandbox is
  admitted to the QueryKnight proxy and denied the PostgreSQL backend, even
  though it holds valid database credentials.
- **QueryKnight controls SQL-level authorization and approval.** `SELECT` is
  allowed, an unbounded `DELETE` is denied, and a bound `DELETE` is gated behind
  an exact approval that a changed value cannot reuse.
- **PostgreSQL TLS protects the QueryKnight → database transport** with
  `sslmode=require`, a pinned CA, and hostname verification.

It is a security-integration demonstration, not a benchmark or a deployment
guide. See [Known limitations](#7-known-limitations).

## 2. Architecture

```
        OpenShell sandbox / agent
              │
              │ direct DB      X  DENIED by OpenShell network policy
              │
              │ PostgreSQL protocol (plaintext, local/trusted frontend hop)
              ▼
        QueryKnight PostgreSQL proxy
              │
              │ verified TLS (sslmode=require, pinned CA)
              ▼
        PostgreSQL 17
```

| Component | Responsibility |
|---|---|
| OpenShell | controls network destination reachability |
| QueryKnight | controls SQL-level authorization and approval |
| PostgreSQL TLS | protects the QueryKnight → database transport |

This is **not** an end-to-end encrypted path. The sandbox → QueryKnight frontend
hop is plaintext and must stay inside the documented trusted boundary. OpenShell
never parses PostgreSQL SQL; QueryKnight never decides where the agent may
connect.

## 3. Prerequisites

Docker (Docker Desktop on macOS, with a socket the gateway can reach);
`cargo`/`rustc`; **z3** on `PATH` (`brew install z3` — the gateway links the
system z3 rather than the multi-GB bundled build); `git`, `curl`, `jq`,
`openssl`, `nc`, `python3`; and a non-loopback IPv4 address of this machine that
the sandbox can reach (autodetected; override with `OPENSHELL_QUERYKNIGHT_HOST`).
No secrets are required — PostgreSQL credentials are ephemeral per run.

**Tested platform.** Validated on macOS / Apple Silicon. The harness derives the
sandbox build platform from `uname -m`, so the workload image follows the host
architecture, but only the Apple Silicon path has been executed. Linux and
x86_64 are expected to work and are not claimed as validated.

**Pinned.** OpenShell `v0.1.2`
(`6648bd0c290efbc41ba131ee9831ee45cd431f94`); PostgreSQL 17 (the run prints the
exact server release). No other OpenShell release or PostgreSQL major version is
validated.

## 4. One command to run

```sh
scripts/test-openshell-postgres-v0.1.2.sh          # full diagnostics
QK_DEMO=1 scripts/test-openshell-postgres-v0.1.2.sh  # compact walkthrough
```

Exits `0` only when every assertion passes. It provisions an ephemeral PKI, a
TLS-enabled PostgreSQL container, a QueryKnight daemon and two proxies (trusted
CA and a deliberate untrusted CA), an OpenShell gateway, and one sandbox, then
removes everything. Logs are retained only on failure. The gateway and CLI are
built from the pinned commit each run; reuse that work between runs with
`OPENSHELL_PERSISTENT_TARGET=/path/to/reusable/target`.

Build from source only — there are no published binaries to download.

## 5. Expected phases

| Phase | Step |
|---|---|
| 1 | OpenShell v0.1.2 artifacts and pinned commit |
| 2 | PostgreSQL 17 with `ssl=on`, **reachable outside the sandbox** — the same address, port, and credentials are used from a plain container context, so a later sandbox failure is attributable to policy rather than connectivity |
| 3 | QueryKnight daemon, verified-TLS proxy, untrusted-CA proxy |
| 4 | Sandbox created from the workload image with the egress policy |
| 5 | Sandbox → PostgreSQL backend: **denied by OpenShell**, before any PostgreSQL handshake |
| 6 | Sandbox → QueryKnight proxy: **allowed** |
| 7 | `SELECT 1` allowed; backend session reports TLS |
| 8 | Unbounded `DELETE` denied; backend rows unchanged |
| 9 | Bound `DELETE … id = 42` requires approval; pending as `exact_v2`; row intact |
| 10 | Approval granted with `scope=once` through the daemon control plane |
| 11 | Exact retry on the same connection executes once |
| 12 | Changed bound value `id = 43` is blocked; the prior grant does not apply |
| 13 | Untrusted backend CA fails closed with no SQL executed |
| 14 | History contains only executed statements; no credential in artifacts |

## 6. What each assertion proves

Representative output from a successful run; run-specific values are replaced
by placeholders.

```text
NET:OPEN [MED] DENIED  /usr/lib/postgresql/15/bin/psql(0) -> <backend ip>:<backend port> [reason:transparent_tcp_mapping_denied]
NET:OPEN [INFO] ALLOWED /usr/lib/postgresql/15/bin/psql(0) -> host.docker.internal:<proxy port> [policy:queryknight-postgres engine:opa]
t|TLSv1.3|TLS_AES_256_GCM_SHA384
ERROR 42501 <policy reason>
ERROR 42501 waiting for approval: qka_…
bindingKind: exact_v2      scope: once
```

- the `DENIED` line names the refused destination, and phase 2 already showed it
  is reachable outside the sandbox;
- the `ALLOWED` line names the admitted policy, so OpenShell permitted exactly
  the intermediary;
- the TLS row comes from `pg_stat_ssl` queried *through the proxy*, so it reports
  the backend session QueryKnight actually forwarded;
- SQLSTATE `42501` plus unchanged rows proves denied SQL never crossed the
  execution boundary;
- `exact_v2` / `once` plus a rejected changed value proves the approval is
  request-bound and single-use;
- the untrusted CA producing a bounded `FATAL` with no SQL proves verification is
  enforced rather than assumed;
- history containing only executed statements means the audit trail matches what
  actually ran.

## 7. Known limitations

- **The QueryKnight proxy is loopback-only.** The harness bridges the sandbox →
  host-loopback hop with a test-only relay (`examples/openshell/tcp-relay.py`),
  because OpenShell resolves `host.docker.internal` to this host's routable
  address. The relay is test plumbing, not a QueryKnight component and not a
  production feature; a real deployment needs operator-managed forwarding until
  a supported non-loopback design exists.
- **The sandbox → QueryKnight frontend hop is plaintext.** PostgreSQL frontend
  TLS is not implemented. That is acceptable only inside the documented trusted,
  OpenShell-controlled boundary. Only the QueryKnight → PostgreSQL hop is
  verified TLS.
- **The proxy is not a general PostgreSQL gateway.** COPY, FunctionCall,
  replication startup, CancelRequest forwarding, and SQL `SET` fail closed.
- **Approvals bind to a per-connection session**, so a retry after approval must
  reuse the connection — which is why the demo drives all three approval attempts
  from one long-lived client.
- **ExactV2 needs a parameterized client**: `psql` 15 cannot bind parameters and
  psycopg 2 interpolates client-side, so the demo uses psycopg 3.
- **MySQL TLS is not implemented.**
- **Public distribution is blocked** pending the repository license decision. Run
  from source; do not promote binary installs.

## 8. How this complements OpenShell

QueryKnight integrates with OpenShell in **two distinct ways** that must not be
conflated:

| | A. HTTP/WebSocket middleware | B. Native PostgreSQL |
|---|---|---|
| Mechanism | `SupervisorMiddleware` RPCs over authenticated HTTPS + extension JWT | `network_policies` egress rules |
| OpenShell role | runs QueryKnight as an in-sandbox middleware for admitted egress | network destination enforcement only |
| QueryKnight role | returns an authorization decision to the supervisor | terminates the PostgreSQL wire protocol, authorizes the statement, forwards on the same backend session |
| Where SQL is inspected | supervisor → middleware RPC | inside the proxy; OpenShell never sees SQL |
| Evidence | `scripts/test-openshell-v0.1.2.sh` | `scripts/test-openshell-postgres-v0.1.2.sh` |

Native PostgreSQL traffic does **not** pass through the HTTP middleware API.
OpenShell gates the destination; QueryKnight enforces the SQL.

A real-client finding from this work is recorded in
[the outreach facts](openshell-outreach-facts.md#scram-sha-256-plus), with a
[recording plan](demo-recording.md) for a short walkthrough.
