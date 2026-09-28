# QueryKnight (Rust)

Database query safety net: evaluate SQL against a versioned policy before it
runs. This repository is the Rust port; `../queryknight-ts` remains the
read-only behavioral oracle during migration.

## Status

Ported and compatibility-tested: SQL analysis (`qk-sql`), Policy v1
loading/validation (`qk-core`), deterministic evaluation (`qk-core`),
approval resolution (`qk-approval`), and the standalone CLI (`qk-cli`).

Not yet ported: daemon/SQLite persistence, MCP server, DB execution and
adapters, proxies, audit/metrics/OCSF, OpenShell, Vue UI, Docker.

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
Docs: `docs/reference-implementation.md` (oracle map),
`docs/security-invariants.md` (INV-001..INV-025), `docs/evaluator.md`,
`docs/fallback-analysis.md`, `docs/sqlparser-differences.md`.
