# OpenShell outreach facts

An internal evidence sheet for a future conversation with the OpenShell
maintainers. It is deliberately factual: no sales language, no partnership
claim, and no relationship is asserted to exist.

**This is not a Vouch Request.** OpenShell's contribution policy requires
first-time contributors to write that request themselves in their own words.
Nothing here should be submitted verbatim, and nothing in this milestone was
opened, posted, or sent.

## What QueryKnight is

A local SQL authorization/execution toolkit. QueryKnight-owned execution paths
evaluate the current request and require a positive, request-bound permit before
database execution. It ships a policy engine, SQL analysis, approvals, direct
database adapters, PostgreSQL and MySQL wire proxies, an MCP server, a daemon
control plane, and an OpenShell integration.

Status: early technical preview, licensed under Apache-2.0. The source
repository is public-ready; no binary, container, or package release exists, so
run from source only.

## Problem addressed

An agent that can reach a database can run anything the connection permits. Two
questions are usually conflated:

1. *Where* may the agent connect?
2. *What* may it execute once connected?

QueryKnight addresses (2) with deterministic policy evaluation and exact,
request-bound approvals, and composes with an external system that addresses (1).

## Exact OpenShell version verified

| Item | Value |
|---|---|
| Product release | `v0.1.2` |
| Commit | `6648bd0c290efbc41ba131ee9831ee45cd431f94` |
| Supervisor image | `ghcr.io/nvidia/openshell/supervisor:0.1.2` `sha256:d7b5264b…` |
| Sandbox runtime image | `ghcr.io/nvidia/openshell/sandbox:0.1.2` `sha256:bf4797b6…` |
| Extension protocol | `1.0` (unchanged from `v0.1.0`) |
| Verified platforms | macOS / Apple Silicon host; sandbox `linux/arm64` |

## Exact E2E architecture

```
OpenShell v0.1.2 sandbox
      │
      │ direct PostgreSQL   X  DENIED by OpenShell network policy
      │
      │ PostgreSQL protocol (plaintext frontend hop)
      ▼
QueryKnight PostgreSQL proxy
      │
      │ verified TLS (sslmode=require, pinned CA)
      ▼
PostgreSQL 17 (ssl=on)
```

Two separate OpenShell integration mechanisms are exercised, and they are not
interchangeable:

- **A. HTTP/WebSocket middleware** — `SupervisorMiddleware.Describe` /
  `ValidateConfig` / `EvaluateHttpRequest` over authenticated HTTPS with an
  OpenShell extension JWT. Evidence: `scripts/test-openshell-v0.1.2.sh`.
- **B. Native PostgreSQL** — `network_policies` egress rules only. OpenShell
  gates the destination; QueryKnight terminates the PostgreSQL wire protocol and
  enforces SQL. Evidence: `scripts/test-openshell-postgres-v0.1.2.sh`.

Native PostgreSQL traffic does not pass through the HTTP middleware API.

## Network-gating evidence

Policy shape (one rule, `protocol: tcp`, kernel-resolved binary paths):

```yaml
network_policies:
  queryknight-postgres:
    endpoints:
      - { host: host.docker.internal, port: <proxy port>, protocol: tcp }
    binaries:
      - { path: /usr/lib/postgresql/*/bin/psql }
      - { path: /usr/bin/python3* }
```

The PostgreSQL backend port is deliberately absent from the policy.

Denied destination (sandbox → database port):

```text
NET:OPEN [MED] DENIED  /usr/lib/postgresql/15/bin/psql(0) -> <backend ip>:<backend port> [reason:transparent_tcp_mapping_denied]
```

Admitted destination (sandbox → QueryKnight proxy):

```text
NET:OPEN [INFO] ALLOWED /usr/lib/postgresql/15/bin/psql(0) -> host.docker.internal:<proxy port> [policy:queryknight-postgres engine:opa]
```

The denial is attributable to policy, not to connectivity: the same address,
port, and credentials reach the backend from a plain container context in the
same run.

## SQL authorization evidence

| Step | Client | Result |
|---|---|---|
| Allowed read | `psql` `SELECT 1` | returns `1`; recorded as executed |
| Dangerous mutation | `psql` `DELETE FROM accounts` | `ERROR 42501 <policy reason>`; backend rows unchanged |
| Gated mutation | psycopg 3 `DELETE FROM accounts WHERE id = $1`, `$1 = 42` | `ERROR 42501 waiting for approval: qka_…`; row 42 intact |
| Approval | daemon `POST /approvals/<id>/decide` `{"status":"approved","source":"ui","scope":"once"}` | `bindingKind: exact_v2`, `scope: once` |
| Exact retry | same connection, same bound value | one row deleted, exactly once |
| Changed value | same SQL, `$1 = 43` | `ERROR 42501`; row 43 intact; new pending row |

The approval identity is `exact_v2` over dialect, SQL, and ordered bound wire
values, verified against the daemon's live binding. A `once` grant for one bound
value does not authorize another.

## PostgreSQL TLS evidence

| Item | Value |
|---|---|
| Backend transport | `sslmode=require` with `QUERYKNIGHT_PG_SSLROOTCERT` as the only trust anchor |
| Hostname verification | against the certificate SAN (the harness issues `DNS:localhost`) |
| Proof, in-band | `SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()` through the proxy → `t\|TLSv1.3\|TLS_AES_256_GCM_SHA384` |
| Negative case | an untrusted CA makes the same sandbox path fail closed with a bounded `FATAL` and no SQL executed |

`pg_stat_ssl` is queried *through the proxy*, so it reports the TLS state of the
very backend session QueryKnight forwarded.

## SCRAM-SHA-256-PLUS

Found by this E2E, and fixed in QueryKnight (commit `087e7dd`). It is good
evidence that the integration was exercised with real clients rather than fake
protocol fixtures.

- QueryKnight's connection to PostgreSQL is TLS.
- The sandbox → QueryKnight frontend connection is currently plaintext.
- A PostgreSQL backend reached over TLS may advertise `SCRAM-SHA-256-PLUS`
  first, because channel binding is available on that connection.
- A frontend client on a plaintext connection cannot perform TLS channel
  binding, and libpq refuses the mechanism outright instead of falling back:
  *"server offered SCRAM-SHA-256-PLUS authentication over a non-SSL connection"*.
- QueryKnight therefore advertises only mechanisms usable on the frontend hop.
- If no usable mechanism remains, authentication fails closed.

## Known limitations

- QueryKnight's PostgreSQL proxy binds loopback only. The harness bridges the
  sandbox → host-loopback hop with a test-only relay, because OpenShell resolves
  `host.docker.internal` to the host's routable address. A real deployment needs
  operator-managed forwarding until a supported non-loopback design exists.
- PostgreSQL frontend TLS is not implemented; that hop is plaintext inside a
  trusted boundary. Only the QueryKnight → PostgreSQL hop is verified TLS.
- The proxy is not a general PostgreSQL gateway: COPY, FunctionCall, replication
  startup, CancelRequest forwarding, and SQL `SET` fail closed.
- Approvals bind to a per-connection proxy session, so a retry must reuse the
  connection.
- MySQL TLS is not implemented.
- Only OpenShell `v0.1.2` is validated.

## Current-main forward look

Audited `NVIDIA/OpenShell` `main` against `v0.1.2`: 147 commits ahead, 300 files
changed. **No material integration change** in the areas QueryKnight depends on:

| Area | Changed since `v0.1.2` |
|---|---|
| `proto/` (extension and sandbox contracts) | no |
| `crates/openshell-supervisor-network/` (egress enforcement) | no |
| middleware crates | no |
| `crates/openshell-driver-docker/`, `crates/openshell-policy*` | yes — to re-verify at the next tagged release |

`v0.1.2` remains the currently live-verified target; newer OpenShell releases
will be added to the compatibility matrix after release. No speculative
compatibility claim is made.

## Likely discussion angle

**Database-specific L7 enforcement behind OpenShell network policy.**

Questions that may be worth raising later, without asserting answers:

- Is this a useful documented ecosystem pattern?
- Would an external integration example be appropriate?
- Is there an intended future extension point for non-HTTP application
  protocols?
- Is the network-gated intermediary pattern consistent with OpenShell's design?

## Scope of any future contribution

QueryKnight is an external, complementary project. An initial conversation would
not require merging QueryKnight into OpenShell, and no vendor lock-in is
proposed. Possible contributions at most: example documentation, integration
guidance, protocol bug fixes discovered by real use, and extension compatibility
improvements.

## References

- [`openshell-postgres-demo.md`](openshell-postgres-demo.md) — public demo
- [`openshell-compatibility.md`](openshell-compatibility.md) — compatibility matrix
- [`demo-recording.md`](demo-recording.md) — recording plan
- `scripts/test-openshell-postgres-v0.1.2.sh` — native PostgreSQL E2E
- `scripts/test-openshell-v0.1.2.sh` — HTTP middleware E2E
- [`release-security.md`](release-security.md) — frozen security scope
