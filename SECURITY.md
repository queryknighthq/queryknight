# Security policy

QueryKnight is a **0.x technical preview** intended for local or trusted-host
deployments. Review [`docs/release-security.md`](docs/release-security.md) before
using it; that document lists supported transports, fail-closed exclusions, and
current deployment assumptions.

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

The current technical-preview profile is local/trusted-host. Native PostgreSQL
and MySQL TLS, remotely authenticated OpenShell, and public proxy deployment
are not provided. Do not expose unauthenticated loopback-oriented listeners as
remote services or assume that an operator-managed tunnel is provisioned or
validated by QueryKnight.
