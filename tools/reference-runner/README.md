# Reference runner

Executes `tests/compatibility/*.cases.json` against `../queryknight-ts` without modifying it (Bun imports core directly).

```sh
bun tools/reference-runner/run.ts
bun tools/reference-runner/run.ts --file unbounded --json
```

Contract-doc entries (`mcp-daemon-contracts.cases.json`) are intentionally skipped here: they pin wire text/status codes covered by the reference daemon/MCP test suites, not by `evaluate()`. The long-term diff harness runs this script plus `cargo test -p qk-compat` on the same fixtures and diffs `{pass, fail}` JSON.

No change to `../queryknight-ts` was required. If a future fixture needs daemon HTTP or live DB I/O, the required helper would be a read-only exported function — report first, do not edit the reference.
