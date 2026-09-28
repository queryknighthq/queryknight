# Compatibility corpus

Language-neutral black-box fixtures. Every `*.cases.json` entry:

```json
{
  "name": "unique kebab name",
  "dialect": "postgres|mysql|sqlite",
  "context": {"integration": "mcp", "environment": "production", "database": "main"},
  "sql": "SELECT ...",
  "policy": "policies/standard.yaml",
  "approval": "none|waiting|approved|denied|missing-provider|throws",
  "mode": "enforce|observe",
  "expected": {"decision": "allow|deny|require_approval", "reason_code": "ALLOW_RULE"}
}
```

`policy` may also be inline YAML under `policy_yaml` (validation cases use `policy_yaml` + `valid: false`).
`policy-hardening.cases.json` is Rust-only: duplicate-key and legacy-bool wording pins QueryKnight-owned hardening messages with no oracle counterpart. `sql-analysis-rust.cases.json` mixes shared AST facts with Rust-parser capability cases (labeled in test output). `defensive-scan.cases.json` pins the defensive lexical scanner, whose deltas from the oracle fallback are classified A/B/C in `docs/fallback-analysis.md`. All other fixture files must also pass the TypeScript reference runner.
`approval: missing-provider` = call evaluate with no provider (expect APPROVAL_UNAVAILABLE).
`mode: observe` asserts the OBSERVED_ downgrade path.
Runner: `tools/reference-runner/` executes each case against `../queryknight-ts` via Bun with zero modifications to the reference repo.
