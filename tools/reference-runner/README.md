# Reference runner

Executes `tests/compatibility/*.cases.json` against `../queryknight-ts` without modifying it (Bun imports core directly).

**Optional and developer-only.** The reference implementation is a separately
maintained checkout and is not part of this repository, so `cargo build`,
`cargo test`, and public CI never need it. Set `QUERYKNIGHT_TS_DIR` to point at
a checkout elsewhere. `cargo test -p qk-compat` skips its differential
comparison with a printed reason when the checkout is unavailable; the parity
test against the committed fixtures always runs.

```sh
bun tools/reference-runner/run.ts
bun tools/reference-runner/run.ts --file unbounded --json
```

Contract-doc entries (`mcp-daemon-contracts.cases.json`) are intentionally skipped here: they pin wire text/status codes covered by the reference daemon/MCP test suites, not by `evaluate()`. The long-term diff harness runs this script plus `cargo test -p qk-compat` on the same fixtures and diffs `{pass, fail}` JSON.

No change to `../queryknight-ts` was required. If a future fixture needs daemon HTTP or live DB I/O, the required helper would be a read-only exported function — report first, do not edit the reference.
