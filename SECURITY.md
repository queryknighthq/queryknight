# Security policy

QueryKnight's direct database/proxy and daemon surfaces are intended for local
or trusted-host deployments. OpenShell v0.1.2 external supervisor middleware
has a separate supported remote boundary: authenticated HTTPS with strict
OpenShell extension JWT verification. Review
[`docs/release-security.md`](docs/release-security.md) for supported transports,
fail-closed exclusions, and deployment assumptions.

## What to report

Please treat as a security vulnerability an unexpected way to execute a denied
or unapproved request, bypass a current `ExecutionPermit`, silently downgrade a
transport-security requirement, expose credentials or approval material, or
accept malformed security-sensitive configuration that changes trusted policy
scope. A documented unsupported feature that rejects the operation before
network execution is not, by itself, a vulnerability; a discrepancy between
the documented fail-closed contract and runtime behavior is security-relevant.

## Reporting channel

This repository does not publish a dedicated security contact or private
vulnerability-reporting channel. No email address, bounty, or private URL is
designated here. Do not include exploit details, credentials, tokens, or
personal data in a public report. Maintainers should establish a private
reporting channel before inviting detailed vulnerability submissions.

## Deployment assumptions

Native PostgreSQL/MySQL TLS and public proxy deployment are not provided.
OpenShell v0.1.2 external supervisor middleware is supported only over HTTPS
with strict OpenShell extension JWT verification; non-loopback listeners
require valid TLS and trusted gateway keys. Unauthenticated remote OpenShell,
plaintext non-loopback, and mTLS are unsupported. Do not assume an
operator-managed tunnel is provisioned or validated by QueryKnight.
