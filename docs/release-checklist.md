# Release checklist

This is a future release gate, not a claim that packaging or CI already exists.
The source repository now has a CI workflow (`.github/workflows/ci.yml`). It
still has no Docker image and no published release artifacts. Run the checklist against the exact release commit and record the
commands, environment, and results.

## Source and security gates

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
      (the all-features selection is required: feature unification changes at
      workspace scope, so a narrower clippy run can miss a break)
- [ ] `cargo test --workspace`
- [ ] `cargo build --workspace --all-features`
- [ ] `scripts/check-rustls-provider.sh` — the workspace must resolve exactly one
      rustls `CryptoProvider` (`ring`); both `ring` and `aws-lc-rs` enabled makes
      every rustls consumer panic at first TLS use
- [ ] Review every QueryKnight-owned `unsafe` occurrence; confirm the crate-level
      `deny(unsafe_code)` policies still cover intended crates and review unsafe
      in dependencies separately.
- [ ] Review RustSec advisories and dependency updates; record the advisory tool
      and disposition rather than silently ignoring findings.
- [ ] Review dependency and bundled-asset licenses and verify license/notice
      files are included with release artifacts.
- [ ] Run the ExactV2 parameter/type/OID/NULL vectors and Once/Session/
      LegacyShape approval regressions.
- [ ] Run secret-sentinel tests across errors, Debug, logs, MCP, audit, OCSF, and
      proxy protocol errors.
- [ ] Verify sink/history/control-plane failures do not alter authorization or
      cause execution retries.

## Live database contracts

Use isolated disposable databases. QueryKnight does not provision or validate
tunnels.

- [ ] Direct PostgreSQL against PostgreSQL 17 with `sslmode=disable`:

  ```sh
  PG_URL='postgres://user:password@127.0.0.1:5432/testdb?sslmode=disable' \
    cargo test -p qk-db --test live_contract postgres_live_contract -- --ignored
  ```

  Confirm the adapter ping/`SELECT 1`, values, metadata, and cleanup; do not use
  an omitted `sslmode` as a plaintext test URL.
- [ ] PostgreSQL proxy live matrix against PostgreSQL 17 with an explicit
      `sslmode=disable` backend URL:

  ```sh
  QUERYKNIGHT_POSTGRES_TEST_URL='postgres://user:password@127.0.0.1:5432/testdb?sslmode=disable' \
    cargo test -p qk-proxy-postgres --test live_postgres live_postgres17_extended_query_matrix
  ```

- [ ] Verified PostgreSQL backend TLS (direct adapter and wire proxy) against a
      disposable PostgreSQL 17 with `ssl=on`:

  ```sh
  ./scripts/test-postgres-tls.sh
  ```

  Confirm trusted-CA success, unknown-CA failure, hostname-mismatch failure,
  TLS-required-against-plaintext failure, explicit-plaintext success, and that
  a denied statement through the proxy returns SQLSTATE `42501` without
  reaching the backend. Do not accept a plaintext fallback as evidence.

- [ ] Direct MySQL adapter against the supported MySQL server version using a
      plaintext URL with no TLS request:

  ```sh
  MYSQL_URL='mysql://user:password@127.0.0.1:3306/testdb' \
    cargo test -p qk-db --test live_contract mysql_live_contract -- --ignored
  ```
- [ ] MySQL proxy live matrix against MySQL 8.4 with a plaintext backend URL:

  ```sh
  MYSQL_PROXY_TEST_URL='mysql://user:password@127.0.0.1:3306/testdb' \
    cargo test -p qk-proxy-mysql --test live_mysql mysql_84_live_proxy_contract -- --ignored
  ```

- [ ] If MariaDB compatibility is claimed, run a separate MariaDB server matrix;
      do not infer it from MySQL 8.4 tests or from a `mariadb://` URL.

## Integrations and protocol gates

- [ ] `cargo test -p qk-openshell --test grpc` (generated-client config,
      authorization-only outcomes, loopback and Unix-socket behavior).
- [ ] MCP stdio process smoke: initialize, list tools, query, approval/pending,
      and malformed/security-sensitive startup configuration; verify stdout is
      protocol-only and credentials are redacted.
- [ ] CLI smoke: `queryknight --help`, `queryknight policy validate`,
      `queryknight inspect`, `queryknight start/status/stop`, MCP stdio, and
      both proxy help/start paths.
- [ ] PostgreSQL proxy fake-backend and live checks: Simple/Extended Query,
      approval retries, session continuity, no permit caching, TLS refusal,
      COPY/FunctionCall/replication/CancelRequest refusal, and no replay.
- [ ] MySQL proxy fake-backend and live checks: COM_QUERY, PREPARE/EXECUTE,
      ExactV2, SEND_LONG_DATA pending/retry, transaction continuity, capability
      filtering, TLS/compression/LOCAL INFILE/cursor refusal, and no replay.
- [ ] Confirm OpenShell is described and tested as authorization-only; an Allow
      must not be counted as downstream execution.
- [ ] `scripts/test-openshell-v0.1.2.sh` — real OpenShell v0.1.2 sandbox
      middleware E2E (HTTP middleware path).
- [ ] `scripts/test-openshell-postgres-v0.1.2.sh` — real OpenShell v0.1.2
      sandbox + QueryKnight PostgreSQL proxy + PostgreSQL 17 over verified TLS.
      This is the network-gating path: OpenShell must deny the sandbox's direct
      connection to the database while admitting the proxy, and QueryKnight must
      enforce SQL authorization on the proxied session. Do not accept a run that
      skips the direct-denial assertion or falls back to plaintext.

## Packaging and release integrity

- [ ] Add and pass a CI matrix for supported operating systems/toolchains and
      workspace quality gates before publishing.
- [ ] Confirm every product version surface still reports the single
      `[workspace.package] version`: CLI `--version`, daemon `/health`, MCP
      `serverInfo`, and the OpenShell `Describe` implementation metadata. (These
      are asserted by existing tests; protocol and format versions are separate
      and must not move with it.)
- [ ] Build release-profile artifacts for each supported target and verify a
      clean install from those artifacts, not just a developer checkout.
- [ ] Verify embedded UI freshness by rebuilding and byte-comparing the bundle
      according to [`browser-ui.md`](browser-ui.md).
- [ ] Build and smoke-test a Docker image only if Docker distribution is added.
- [ ] Decide checksums and signing; publish checksums with every release and
      document the signing/verification procedure if signing is used.
- [ ] Review SBOM generation and license/notice inclusion for the chosen
      artifacts.
- [ ] Start a clean daemon home and verify daemon lifecycle, token-file
      permissions, status/health, and shutdown.
- [ ] Review this release's support matrix and security wording against source;
      do not expand claims beyond the tested protocol/transport set.
- [ ] Confirm README, SECURITY.md, docs, CLI help, sample configs, and release
      notes all state the same technical-preview scope and transport limits.
