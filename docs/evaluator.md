# Rust evaluator (`qk_core::evaluate`)

Single decision path for every integration. Synchronous, side-effect free,
deterministic: same context, SQL, dialect, policy, and options always yield
the same `EvaluationResult { decision, reason_code, message,
matched_policy?, table?, column?, operation? }`.

## Precedence (first match wins)

1. Empty/whitespace SQL -> deny `EMPTY_QUERY`.
2. Over-size SQL -> deny `QUERY_TOO_LARGE`.
3. Unparseable analysis (`EmptyQuery` from comments-only input,
   `ParseError`, `AnalysisError`) -> `defaults.on_parse_error`
   (`DENY_PARSE_ERROR`).
4. Unknown/unsupported shapes (any `Unknown`-category or `Call` operation,
   top-level or nested) -> `defaults.on_unknown`
   (`DENY_UNKNOWN_STATEMENT`).
5. Depth-truncated analysis -> `defaults.on_unknown`
   (`DENY_UNKNOWN_STATEMENT`). Deliberate: the reference cannot produce
   this state; an uninspected remainder is closest to "unknown", and
   truncation outranks rule matching because no rule is sound against
   unseen statements.
6. Sensitive columns -> deny or require_approval (`SENSITIVE_COLUMN`).
7. Explicit deny rules, first match (`DENY_RULE`).
8. Mutations without WHERE: top-level statements in scope order, then
   nested (`UNBOUNDED_UPDATE` / `UNBOUNDED_DELETE`). Absent mutation
   config defaults to `[update, delete]`; a present-but-empty list
   disables the check (both reference parity).
9. Row safety: any LIMIT-less `SELECT` vs `require_limit`
   (`LIMIT_REQUIRED`); first numeric literal LIMIT vs `max_limit`
   (`LIMIT_EXCEEDED`). Parameterized/expression limits never coerce.
10. Approval rules, first match (`REQUIRE_APPROVAL`). Terminal: this
    function never invokes providers, mints approval IDs, or retries; a
    later layer resolves `RequireApproval` into granted/denied/waiting.
11. Allow rules, first match (`ALLOW_RULE`).
12. `defaults.decision` (`DEFAULT_ALLOW` / `DEFAULT_APPROVAL` /
    `DEFAULT_DENY`).

Rule matching is AND over present fields; empty rules match all; first
array match wins (document order, never hash order). Operation candidates
are kind names, category names, and the `administrative` alias, drawn from
top-level and nested operations alike. Scope resolves exact database,
then `*`, then defaults-only. Missing context fields match as `""`.

## Deliberate divergences from the reference (all deny-side or equal)

- Data-modifying CTEs: the reference cannot parse them
  (`DENY_PARSE_ERROR`); Rust holds a bounded nested write for approval
  exactly like a directly visible bounded write (`REQUIRE_APPROVAL`), and
  denies an unbounded one (`UNBOUNDED_DELETE`) exactly like its visible
  twin. Never a plain read.
- `MERGE`: unparseable upstream (`DENY_PARSE_ERROR`); Rust evaluates it.
  An UPDATE branch matches update rules (`REQUIRE_APPROVAL` under the
  standard policy); otherwise default deny. Never `ALLOW` by accident.
- `CALL`: treated as unknown-effect (`DENY_UNKNOWN_STATEMENT`), matching
  the reference verdict (which reaches it via unknown operation).
- `COPY` / `VACUUM` / `EXPLAIN <write>`: unparseable upstream; Rust
  evaluates them through normal rules (default deny unless a rule names
  the operation). `EXPLAIN <read>` stays read-only but still needs an
  allow rule; it is not allow-by-default.
- Complexity exhaustion and depth truncation: new states with no upstream
  equivalent, routed to the unknown path (`DENY_UNKNOWN_STATEMENT`).
- Multi-hit sensitive queries report the first hit in sorted-column order
  rather than discovery order (both deny `SENSITIVE_COLUMN`; only the
  named table/column can differ).
- Unbounded-mutation `table` uses the first mutated (target) table rather
  than first-discovered table (identical for single-table mutations).
- Three-part names additionally match `database.schema.table` in table
  rules (the reference has no equivalent; only affects names it cannot
  represent).
- CTE-alias-named sensitive patterns do not match (CTE names are excluded
  from analysis tables; patterns for query-local aliases are not a
  supported use).
- Observe mode is omitted: no product caller in the reference enables it
  (library option + unit test only), so `OBSERVED_*` codes do not exist
  here. Approval-resolution codes (`APPROVAL_*`) exist in the taxonomy
  but are produced only by the future provider layer.

## Defensive scan role

`SqlInspection` bundles AST analysis with the defensive scan, but only
failure-path messages read defensive evidence (`possible: ...` lists).
Verdicts never depend on it: failure paths return before rule matching,
and on success the AST operations drive. `possible_*` strings are not in
the signals matching set (in the reference they are verdict-dead for the
same structural reason). INV-023 holds by construction.
