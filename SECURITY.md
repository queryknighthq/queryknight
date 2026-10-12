# Security policy

## Status and scope

QueryKnight is a **0.1.0 technical preview**. It is not production-ready, and no
remote or multi-tenant deployment is supported.

Supported security boundaries:

- direct database adapters and the wire proxies are intended for **local or
  trusted-host** deployments; the PostgreSQL proxy binds loopback only;
- the PostgreSQL proxy frontend hop is **plaintext by design**, so it must stay
  inside a trusted, controlled network boundary. Only the QueryKnight →
  PostgreSQL hop uses verified TLS;
- OpenShell v0.1.2 external supervisor middleware has a separate supported
  remote boundary: authenticated HTTPS with strict OpenShell extension JWT
  verification, with non-loopback listeners requiring valid TLS and trusted
  gateway keys.

Unsupported and rejected rather than degraded: MySQL TLS, PostgreSQL frontend
TLS, public proxy listeners, plaintext non-loopback OpenShell, mTLS, and the
PostgreSQL protocol operations listed in
[`docs/release-security.md`](docs/release-security.md).

Read [`docs/release-security.md`](docs/release-security.md) for the full
transport matrix, fail-closed exclusions, and deployment assumptions before
relying on any deployment. QueryKnight does not provision or validate an
operator-managed tunnel.

## What to report

Treat as a security vulnerability any way to:

- execute a denied or unapproved request, or forward SQL without a current
  `ExecutionPermit`;
- reuse an approval for a different request, bound value, or scope;
- silently downgrade a transport-security requirement, or fall back from a
  refusal to a plaintext or unguarded path;
- expose credentials, approval material, or bound parameter values through
  errors, logs, history, audit, metrics, or the control plane;
- accept malformed security-sensitive configuration in a way that changes
  trusted policy scope;
- make a documented fail-closed contract disagree with runtime behaviour.

A documented unsupported feature that rejects the operation before any network
execution is not, by itself, a vulnerability.

## Reporting channel

This repository does **not** currently enable a private vulnerability-reporting
channel: no security email address, bounty, or private URL is designated here,
and none should be inferred.

Until the repository owner enables GitHub's private vulnerability reporting (or
an equivalent private channel), do not post exploit details, credentials,
tokens, or personal data in a public issue. A short public report stating that
a class of issue exists, without a working exploit, is acceptable in the
meantime.
