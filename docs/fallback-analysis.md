# TypeScript fallback audit (`fallbackScan`)

Reference: `packages/core/src/analysis.ts` (`FALLBACK_PATTERNS`, `fallbackScan`),
`packages/core/src/policy-engine.ts` (`DENY_PARSE_ERROR` message).

## Exact role

1. Called in exactly one place: the `catch` branch of `analyzeSql`, i.e.
   only after `node-sql-parser` throws. It never runs after a successful
   parse.
2. Output: `fallbackKinds: StatementKind[]` plus `possible_<kind>` entries
   in `riskSignals`, plus the truncated `parseError` string.
3. Verdict dependence: none. `evaluatePolicy` maps unparseable input to
   `defaults.on_parse_error` (default `deny`) with reason
   `DENY_PARSE_ERROR` unconditionally. `fallbackKinds` only enriches the
   human-facing message (`possible: delete, select` vs `unknown syntax`).

## Mechanism (not copied, ported as semantics)

- Pre-strip: single-quoted (`''`-aware), double-quoted, and backtick
  spans, `--` line comments, and `/* */` block comments are deleted;
  the remainder is matched with 13 ordered regexes (first hit per pattern
  class, deduped). Deletion (not blanking) means `DR/**/OP` rejoins to
  `DROP` and matches.
- Patterns are phrase-shaped, not bare words: `drop` needs a following
  `database|schema|table|index|view`; `delete` needs `from`; `update`
  needs `<target> set`; `insert` needs `into`; `grant`/`revoke`/`truncate`
  are bare words; `copy` needs `<x> from`; `call` needs `name(`;
  `load data` maps to kind `load`; `select` is a bare word; `merge` and
  `vacuum` map to kind `unknown`. There are no transaction/begin/commit,
  `exec`, `set`, `show`, `explain`, or `use` patterns.
- Not stripped: `$...$` dollar quotes (keywords inside match), `#`
  comments, backslash escapes, `/*!...*/` executable comments. Word
  boundaries are ASCII (`\b`).
- Probed outputs (representative): `SELECT 'DROP TABLE users'` ->
  `[select]`; `SELECT $$ DROP $$` -> `[drop, select]`; `DR/**/OP TABLE
  users` -> `[drop]`; `/*!50000 DROP TABLE users */` -> `[]`;
  `EXECUTE my_proc` -> `[]`; `BEGIN; SELECT 1` -> `[select]`;
  `MERGE ...` -> `[unknown]`; `SELECT [DROP]` -> `[select]` (bare DROP
  never matches); unterminated `'abc` -> `[select]` (remainder scanned).

## Frozen-corpus dependence

None of the 63 executable fixtures depend on fallback output: the shared
runner asserts `decision` + `reason_code` only, and no verdict path reads
`fallbackKinds`. Fallback is message enrichment for humans, not a
decision input.

## Intended bypass coverage

Unparseable-but-dangerous SQL reaching the deny message with a hint of
what it might be: parser gaps (data-modifying CTEs, MERGE, COPY, VACUUM,
DELETE..USING, EXPLAIN), novel statement shapes, and comment/casing
tricks that defeat `node-sql-parser`.

## Consequences for the Rust port

- The AST stays the sole source of structural facts; the defensive scan
  reports *possible* operations and uncertainty only.
- Deltas from the reference are classified per case: (A) exact behavior,
  (B) conservative security improvement (more flags on the failure path,
  e.g. `EXECUTE`, transactions, `/*!...*/`), (C) diagnostic-only
  renaming (e.g. `load` kind vs `Copy`).
- Precision improvements that flag *less* (dollar quotes, SQLite
  brackets, MySQL backslash escapes) are safe: fallback output never
  feeds verdicts, only messages, and the failure path stays fail-closed.
