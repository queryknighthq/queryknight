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

- Subquery/CTE nesting: `sqlparser-rs` enforces its own recursion counter
  and returns a typed error past it (measured: 50-deep derived tables ->
  `recursion limit exceeded`). The walker additionally caps at
  `MAX_WALK_DEPTH = 64` and sets `RiskSignal::DepthTruncated`.
- Expression chains: the parser's counter does NOT cover them. An 80 KiB
  `SELECT 1 + 1 + ...` (20k terms) aborts a 2 MiB thread with an
  uncatchable stack overflow, while the reference fails closed
  (`parsed:false`, ~655 ms; Rust parses the same input in ~57 ms once
  guarded). Mitigation in place: the whole parse-walk-drop pipeline runs
  on a dedicated 512 MiB-stack thread (`ANALYZE_STACK_BYTES`), keeping
  `analyze()` synchronous and abort-free for everything expressible in the
  1 MiB input budget. A second, subtler find: dropping a pathological AST
  recurses with tree depth, so the drop also happens on the guarded
  thread. Residual risk (a >512 MiB frame need inside 1 MiB of input) is
  considered unreachable; revisit if corpus evidence says otherwise.
- Input budget: `MAX_SQL_BYTES = 1_000_000` enforced at this boundary,
  mirroring reference `DEFAULT_MAX_SQL_BYTES`. The 64 KiB / 8000-token
  heuristic is a *result* budget owned by the future execution layer.

## Known walker gaps (syntactic, documented)

Exotic expression shapes contribute nothing rather than wrong facts:
`Lambda` bodies, `Array`/`Struct`/`Map` literals containing subqueries,
`GroupingSets`/`Cube`/`Rollup` (GROUP BY positions), `JsonTable` pivots,
`SHOW COLUMNS` table scope (op recorded, no table claimed), GRANT objects
other than plain tables, index/sequence DDL targets beyond the mapped
`CreateIndex.table_name`. A nested DML hiding in one of these positions
would be missed by extraction; the lexical-fallback hardening commit is
the designated backstop (fallback may only ever add strictness).
