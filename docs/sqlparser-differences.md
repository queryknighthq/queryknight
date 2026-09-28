# node-sql-parser (reference) vs sqlparser-rs 0.63 (Rust port)

Empirical comparison. TS column: `analyzeSql` from `../queryknight-ts`
(`node-sql-parser`, probed 2026-09-28). Rust column: `qk-sql::analyze`.
Facts only; no policy recommendations.

## Headline: the Rust parser accepts strictly more

Every shape below that the reference rejects with `parsed: false`
(`DENY_PARSE_ERROR` downstream) parses in `qk-sql`. The analysis layer
records facts; fail-closed verdicts for newly-visible shapes belong to the
future evaluator (INV-003).

| SQL | TypeScript | Rust (`qk-sql`) |
|---|---|---|
| `WITH deleted AS (DELETE FROM customers RETURNING *) SELECT * FROM deleted` | reject (`possible_delete,possible_select`) | 1 stmt, op `select`, nested `[delete]`, tables `[customers]`, `read_only=false` |
| `SELECT * FROM t WHERE id = 1 FOR UPDATE` | reject (`possible_select`) | op `select`, `read_only=true` (lock clause not modeled) |
| `COPY customers FROM '/tmp/x.csv'` | reject (`possible_copy`) | op `copy`, tables `[customers]` |
| `VACUUM customers` | reject (`possible_unknown`) | op `vacuum`, tables `[customers]` |
| `MERGE INTO ... WHEN MATCHED THEN UPDATE ... WHEN NOT MATCHED THEN INSERT ...` | reject | op `merge`, nested `[insert, update]`, tables + mutated `[customers]` |
| `EXPLAIN SELECT * FROM t` | reject (`possible_select`) | op `explain`, `read_only=true` |
| `EXPLAIN UPDATE t SET a = 1` | reject | op `explain`, nested `[update]`, `read_only=false` |
| `DELETE FROM films USING producers WHERE ...` | reject (`possible_delete`) | op `delete`, mutated `[films]`, referenced `[films, producers]`, `has_where=true` |
| `CALL refresh_reports()` | parses, op `unknown` | op `call` (category Admin), never read-only |
| `SET search_path TO public` | parses, op `admin` | op `set` (category Admin) |
| `SHOW TABLES` | parses, op `read` | op `show` (category Read) |
| `GRANT SELECT ON customers TO analyst` | parses, no tables | op `grant`, tables `[customers]` (TABLE objects only) |
| `SELECT 1;;` / trailing `;` | tolerated, 1 stmt | tolerated, 1 stmt |
| `SELECT 1; DROP TABLE users` | 2 stmts, strictest wins | 2 stmts, ops `[select, drop]` |
| `INSERT INTO archive SELECT * ...` | 1 stmt `insert`, both tables | same, plus mutated `[archive]` |
| empty / whitespace / comment-only | `parsed:false`, kinds `[unknown]` | `Err(EmptyQuery)` (comments tokenize to zero statements) |
| `FROBNICATE THE customers !!` | `parsed:false` | `Err(ParseError)` (300-char diagnostic) |
| `SELECT FROM WHERE` | reject | lenient accept: op `select`, tables `["WHERE"]` (keyword-as-identifier) |
| unknown dialect string | falls back to MySQL options, keeps label | `Err(UnsupportedDialect)` (intentional strictness) |

## Identifier and extraction notes

- Case: the reference preserves identifier text as written; `qk-sql` also
  preserves text and additionally records `quoted`, so later matching can
  fold unquoted and respect quoted exactly. No blind lowercasing anywhere.
- CTE names: the reference has no CTE-name filtering (it cannot parse the
  shapes where it would matter). `qk-sql` excludes in-scope CTE names from
  table lists (`WITH recent AS (...) SELECT FROM recent` yields only the
  real tables). Documented choice, narrower output.
- Columns: both extract SELECT/WHERE/SET/RETURNING positions. `qk-sql`
  additionally walks function arguments, JOIN .. ON/USING, MERGE branches,
  ORDER BY, and CASE branches. `SELECT *` / `t.*` is always an explicit
  star marker, never invented names; unqualified columns are never
  attributed to a table.
- `has_where`: same presence semantics for UPDATE/DELETE (`Some(bool)`,
  `None` where not applicable). `WHERE TRUE` boundedness is future
  security analysis, not recorded here.
- LIMIT: the reference reads numeric AST literals only. `qk-sql` returns
  `Literal(u64)` / `Parameterized` (`?`, `$1`) / `Expression` (anything
  else, e.g. `LIMIT 1+1`). Non-literals are never coerced.

## Recursion and resource behavior (security-relevant)

- Parser nesting (subqueries, CTEs, parenthesized expressions,
  right-associative operators) is bounded by an explicit
  `SQL_PARSER_RECURSION_LIMIT = 50` (upstream default, kept deliberately).
  Past it the parser returns `RecursionLimitExceeded`, mapped to the
  QueryKnight-owned `SqlAnalysisError::ComplexityLimitExceeded` (stable
  reason-code material, distinct from `ParseError`). Measured: 300-deep
  derived tables, 20k-deep parentheses, 8k-deep function nests, 1500-deep
  subquery chains all terminate typed. Near-limit nesting can surface as a
  plain `ParseError` instead (parser backtracking swallows the limit error
  into a confusing downstream diagnostic); both are typed fail-closed
  errors, so the distinction is diagnostic only.
- Expression chains: the parser counter does NOT cover left-associative
  operator chains (handled iteratively). An 80 KiB `SELECT 1 + 1 + ...`
  (20k terms) parses in ~57 ms (reference: fails closed, ~655 ms). The
  resulting tree is deep but the QueryKnight walk caps at
  `MAX_WALK_DEPTH = 64`, surfacing `RiskSignal::DepthTruncated`,
  `AnalysisCompleteness::DepthTruncated`, and forcing `read_only = false`.
- AST destruction: dropping a deep tree recurses with tree depth
  (measured: dropping a 25k chain aborts a bare 2 MiB thread; 15k
  survives). The whole pipeline therefore runs inside one transient
  `stacker::grow` segment (128 MiB, sized from the measured ~80-130
  bytes/level against the 1 MiB worst case with ~2x margin, freed on
  return; ~21 us to establish). `maybe_grow` was tried and rejected: it
  switches segments at most once and only when the red zone is already
  tripped, so a deep drop starting with ample stack still overflows
  mid-destruction. No per-request threads, no giant reserved stacks.
  `recursive-protection` (default-on; `recursive` + `stacker` verified in
  `Cargo.lock` and covered by a build test) already grows the stack at
  instrumented parser points; panics inside the segment become
  `AnalysisError` via an inner `catch_unwind`, never propagated.
- No `mem::forget`, no leaked ASTs, no Tokio in this layer.
- Input budget: `MAX_SQL_BYTES = 1_000_000` enforced at this boundary,
  mirroring reference `DEFAULT_MAX_SQL_BYTES`. The 64 KiB / 8000-token
  heuristic is a *result* budget owned by the future execution layer. A
  <=64 KiB hostile battery (16k operator chain, 20k parens, 1500
  subqueries, 8k functions, 1200 CASEs, mixed combo) plus 24 concurrent
  hostile analyses on 2 MiB stacks all terminate with typed results.
- `PARSER_RECURSION_LIMIT` (50) vs `ANALYZER_DEPTH_LIMIT` (64): different
  units on purpose. The parser counts its own recursion steps (one nesting
  level can consume several, and chains consume none); the analyzer counts
  AST levels visited. The walker cap is defense in depth for shapes the
  parser counter cannot see.

## Syntax is not database validity

`sqlparser-rs` performs syntactic parsing only and accepts constructs the
real engines reject. Known example: `SELECT FROM WHERE` analyzes as
`select` with table `"WHERE"` (reserved word as identifier). Pinned by
regression test (`keyword_as_table_leniency_documented`).

Consequences, stated plainly:

- Parser acceptance does NOT assert PostgreSQL/MySQL/SQLite validity.
- Actual database execution remains authoritative for semantic validity.
- Policy logic must never treat parser acceptance alone as evidence of
  safety; unknown and unsupported shapes stay non-read (fail-closed
  direction for the future evaluator).

## Defensive lexical scan vs reference `fallbackScan`

The reference runs 13 phrase regexes over comment/string-stripped text,
only after parse failure, feeding the deny message (`possible: ...`) but
never verdicts. The Rust `defensive_scan` (state machine, no regexes) is
word-based and runs independently of parse outcome:

- Exact (A): quoted literals/identifiers hide keywords; `#` comments are
  not stripped; comment-split keywords (`DR/**/OP`) flag via transparent
  comments; word boundaries (`dropbox` safe); mixed case; `CALL`/`COPY`
  keywords; semicolon counting outside protected regions.
- Conservative improvements (B): `EXEC`/`EXECUTE` -> `UnknownAdmin`;
  `BEGIN`/`COMMIT`/`ROLLBACK`/`START` -> `Transaction`; MySQL `/*!...*/`
  executable comments scanned through; bare dangerous words flag without
  needing TS phrase shapes (`DROP` alone, `DELETE` without `FROM`).
- Precision improvements, still safe (B): PostgreSQL dollar quotes and
  SQLite brackets hide keywords (TS flags both); MySQL backslash escapes
  honored (fewer false positives, DB-correct); `LOAD DATA` reports `Copy`
  instead of kind `load`; `MERGE`/`VACUUM` report concretely instead of
  `unknown`. Safe because fallback output never feeds verdicts: the
  failure path stays fail-closed either way.
- `UnknownWrite` is added on any lexically incomplete tail; the scan can
  only add risk, never establish safety (INV-023).

## Known walker gaps (syntactic, documented)

Exotic expression shapes contribute nothing rather than wrong facts:
`Lambda` bodies, `Array`/`Struct`/`Map` literals containing subqueries,
`GroupingSets`/`Cube`/`Rollup` (GROUP BY positions), `JsonTable` pivots,
`SHOW COLUMNS` table scope (op recorded, no table claimed), GRANT objects
other than plain tables, index/sequence DDL targets beyond the mapped
`CreateIndex.table_name`. A nested DML hiding in one of these positions
would be missed by extraction; the lexical-fallback hardening commit is
the designated backstop (fallback may only ever add strictness).
