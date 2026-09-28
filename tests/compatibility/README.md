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
`approval: missing-provider` = call evaluate with no provider (expect APPROVAL_UNAVAILABLE).
`mode: observe` asserts the OBSERVED_ downgrade path.
Runner: `tools/reference-runner/` executes each case against `../queryknight-ts` via Bun with zero modifications to the reference repo.
