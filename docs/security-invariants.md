# Migration security invariants

Normative for the Rust port. Each invariant cites the reference mechanism. Violating any invariant blocks the migration milestone that touches it. Corpus coverage noted per invariant.

INV-001: Database execution requires an explicit ALLOW decision.
  Only `evaluate() == allow` (direct or via APPROVAL_GRANTED) may precede `adapter.execute`/`runQuery`. `require_approval` without approval, `deny`, and legacy `confirm` without resolution never execute. (evaluate.ts, safety.ts runSafeQuery, mcp/tools.ts dbQueryWithPolicy.) Corpus: policy-evaluation, approvals-rowlimits.

INV-002: Parser failure must not produce ALLOW.
  `parsed=false` routes to `defaults.on_parse_error` (deny|require_approval only — allow is unrepresentable). (policy-engine.ts §1, evaluate fail-closed comment.) Corpus: malformed-unsupported (garbage, data-modifying CTE, merge).

INV-003: Unsupported SQL must not produce ALLOW in enforcement mode.
  `operation unknown` or kinds include `unknown` routes to `defaults.on_unknown` (deny|require_approval). CALL/transaction/VACUUM/MERGE never allow when enforced. Observe mode may report `OBSERVED_*` allow but sets `enforced:false` and never executes. Corpus: malformed-unsupported.

INV-004: All statements in multi-statement SQL are evaluated.
  Details per statement; classification/operation/risk take the strictest; `multi_statement` signal added; unbounded check loops statements; execution layer refuses to run "the safe half" (legacy: max-risk gate; runQuery treats interior `;` as multi, no paging). Corpus: multistatement-nested.

INV-005: Nested mutations must influence the final decision.
  CTE/subquery INSERT/UPDATE/DELETE collected at depth>0 (`nestedDml`); read-top-level + nested DML flips operation to write + `data_modifying_cte`/`nested_<k>`/`nested_write` signals, which policy signals rules can match. Corpus: multistatement-nested (CTE parse-fail case + insert-select).

INV-006: REQUIRE_APPROVAL without a valid approval cannot execute.
  Missing provider -> APPROVAL_UNAVAILABLE deny; provider throw -> APPROVAL_ERROR deny; waiting/denied/expired never convert to allow; daemon retry requires fingerprint match + approved status; timeout flips waiting->expired. (evaluate.ts, safety.ts, approvals.ts waitForApproval, policy-bridge.ts.) Corpus: approvals-rowlimits.

INV-007: Invalid policy cannot replace a valid active policy.
  Strict validation rejects unknown fields/operations/mutations, bad limits/actions, wrong version, bad YAML; loaders fail fast (CLI exit 2, getFilePolicy throws, OpenShell bad_config deny) and the caller keeps the last good policy. (policy-file.ts, policy-cmd.ts, policy-bridge.ts, inspector.ts.) Corpus: policy-validation.

INV-008: Credentials must not appear in logs or audit output.
  `redact()` on URLs/logs, password-stripped `connectionKeyFromUrl`, `databaseKeyFor` excludes passwords, audit default `fingerprint` level, `full_sql` opt-in only, result rows never persisted (counts/bytes/tokens only). (redact.ts, cursors.ts, audit.ts, store.ts.) Pinned by contract fixtures (redacted connections, log levels).

INV-009: Unknown policy fields are rejected.
  `assertNoExtraKeys` at policy/defaults/environments/database/rule/sensitive/mutations/row_safety/test-case levels; typo'd operations rejected against KNOWN_OPERATIONS allowlist. Corpus: policy-validation (4 rejection cases).

INV-010: Fallback security analysis may only make a decision stricter, never more permissive.
  `fallbackScan` output feeds `possible_<kind>` risk signals and parse-error messaging only; the decision still comes from `on_parse_error` (deny default). Regex hits never upgrade to allow. (analysis.ts fallbackScan.) Corpus: malformed-unsupported.

INV-011: Sensitive columns beat allow rules.
  Sensitive check runs before deny/allow/approval matching; only parse/unknown errors precede it. Applies to reads and writes by column presence. Corpus: sensitive-columns.

INV-012: Deny beats approval and allow.
  Precedence deny -> unbounded -> row-safety -> approval -> allow -> default; first match wins; explicit test pins deny+approval overlap. Corpus: policy-evaluation (deny-beats-approval).

INV-013: Unbounded UPDATE/DELETE without WHERE are denied when configured.
  Per-statement `hasWhere` from AST; default `[update, delete]`; configurable subset of `[update, delete, insert]`; checked before row-safety/approval/allow. Corpus: unbounded-mutations.

INV-014: Row-limit policy binds reads only and never widens execution budget.
  `require_limit`/`max_limit` apply to `select` statements; LIMIT parsed from AST numerics; execution paging (`LIMIT maxRows+1`) only narrows. Corpus: approvals-rowlimits.

INV-015: Approval scope is least-privilege by default.
  Scope `once` default; `session` allow stores (sessionId, fingerprint) pairs only, checked pre-decision; fingerprints are literal-stripped hashes, not raw SQL. (approvals.ts, safety.ts, cursors.ts.)

INV-016: Audit sinks and post-execution diffs never break enforcement.
  `evaluate` wraps `auditSink` in try/catch; `recordAfterDiff`/`recordSchemaDiff` best-effort; metrics recording is side-effect only. (evaluate.ts, safety.ts.)

INV-017: Identity context is integrator-provided, never agent-provided.
  `AgentContext` agent_id/session/user come from the authenticated adapter (MCP/OpenShell/proxy/CLI); free-form metadata is untrusted and unused for identity; `databaseKeyFor` prefers explicit config over connection strings. (context.ts, policy-bridge.ts.)

INV-018: Network and auth boundaries stay loopback-only.
  Daemon binds 127.0.0.1; Host/Origin localhost pinning + Bearer token on all non-health API routes + tight CORS; proxies listen 127.0.0.1 with plaintext-local leg documented; `run` strips credential/host vars and repoints non-loopback URLs through the proxy. (daemon app.ts/index.ts, cli/run.ts.)

INV-019: Timeouts fail closed and never imply cancellation.
  Approval timeout -> expired -> deny; DB timeout races client-side with documented may-still-run semantics; cursor TTL (10min) + connection binding expire open handles. (approvals.ts, tools.ts withTimeout, cursors.ts.)

INV-020: Default posture is deny.
  `defaultPolicy()` = deny/deny/deny; unknown db scope falls to `DEFAULT_DENY`; legacy unknown SQL production-deny; OpenShell no-SQL traffic allows (not a firewall) but any extracted SQL evaluates normally. Corpus: policy-evaluation.

INV-022: Untrusted SQL complexity must be bounded before or during parsing and analysis. Resource exhaustion, recursion limits, incomplete traversal, or analysis failure must remain explicit and must never be representable as a complete safe analysis.
  Parser nesting capped by SQL_PARSER_RECURSION_LIMIT (limit breach is ComplexityLimitExceeded, distinct from ParseError); deep operator chains truncated by the analyzer depth cap (DepthTruncated signal + completeness flag + read_only forced false); AST destruction guarded without giant per-request stacks; <=64 KiB hostile battery and concurrent analyses terminate typed. Corpus: qk-sql resources battery + sql-analysis-rust fixtures.

INV-023: Defensive lexical analysis is monotonic: it may add potential-risk facts or uncertainty but may never remove AST-derived risk, establish safety, or make an authorization decision more permissive.
  The scanner emits PossibleOperation evidence and uncertainty signals only (no safe/read_only/allowed output); QueryAnalysis is never mutated by scanning (separate types, pinned by test); an AST failure combined with Select-only defensive evidence stays a failure; incomplete scans add UnknownWrite and keep the evaluator fail-closed. Corpus: defensive-scan fixtures (30) + strictness/differential tests.

INV-024: Approval resolution may only transition an evaluation that originally returned RequireApproval. An approval can never override a Deny decision.
  Resolution returns non-approval evaluations untouched without contacting any provider or store; stored grants are consulted exclusively on the RequireApproval path, so parse errors, unknown statements, sensitive hits, deny rules, unbounded mutations, and limit denials are structurally unresolvable. Literal-only SQL variants intentionally share fingerprint identity (frozen session-allow semantics); every other scope dimension must match exactly. Corpus: qk-approval replay/expiry/scope tests + unlocked approval fixtures.

INV-025: Approval tokens must be cryptographically bound to the exact SQL request and scope. A query-shape fingerprint may be used only for explicitly shape-scoped/session authorization and must not be the sole binding for an exact approval token.
  Exact tokens bind full SHA-256 over domain-separated dialect plus request bytes (any literal, whitespace, or dialect change breaks reuse); session-shape grants bind the frozen 16-hex normalized fingerprint with full scope dimensions and TTL. The 64-bit shape value never authorizes an exact retry on its own. Corpus: exact/session/dialect replay tests + digest vectors + unchanged approval fixtures.

INV-026: Persisted authorization state is untrusted input. Invalid, incomplete, legacy-ambiguous, or corrupted approval records must never broaden authorization or become active grants.
  Reads validate digests, enums, and timestamps into typed errors; scans skip invalid rows without authorizing them; legacy rows without exact identity can never satisfy exact-token replay; unknown persisted values are never defaulted. Corpus: qk-store migration/invalid-row fixtures (legacy, partial, corrupt, future-version databases).

INV-027: A persisted approval may authorize a request only when all security binding fields required by the current approval model are present and valid. Legacy or partially-bound records are historical state only and require a new approval.
  Only `binding_kind = 'exact_v1'` rows (exact digest plus all six scope dimensions, verified at read) are eligible for authorization lookups; `legacy_shape` rows are visible to history APIs but structurally excluded from session-grant scans and exact-token matching. Migration never deletes, and never invents missing scope data to activate old rows. Corpus: quarantine/upgrade/persistence fixtures (legacy, partial, orphan, v2-upgrade databases).

INV-028: Approval persistence failures, conflicts, stale state, or invalid stored records must fail closed. Only a fully verified current approval binding may transition RequireApproval into an executable result.
  Store reads return owned values or typed errors; busy/conflict/corrupt/engine failures map to deny-side reason codes, never Allow; the resolver re-verifies binding, status, scope, and liveness on every store-returned candidate; provider verdicts that cannot be durably recorded fail closed instead of executing. Corpus: failure-injection, SQLite end-to-end/reopen/legacy tests, concurrency tests.

INV-021: Ambiguous or duplicate policy configuration must fail closed and must never be resolved in favor of a more permissive authorization policy.
  YAML 1.1 legacy boolean words (yes/no/on/off, any case) are strings per oracle YAML 1.2 core typing and must never coerce in boolean fields; only true/false (+case variants) are booleans. Duplicate mapping keys at any depth are invalid policy (DuplicateKey), never first-wins or last-wins, so `decision: deny` can never be shadowed by a later `decision: allow`. Parser diagnostics stay QueryKnight-owned (position only, never third-party prose); unrecognized ambiguity shapes degrade to InvalidYaml, still invalid. Corpus: policy-hardening (10) + shared legacy-bool validation cases; unit pins for determinism and no-panic on hostile input. This extends INV-007/INV-009: those cover invalid values and unknown fields, but neither pins scalar-typing ambiguity nor key multiplicity, both of which select between two valid meanings rather than rejecting one invalid value.

INV-029: The control plane listens on loopback by default and gates every non-health route on a bearer token compared in constant time.
  Non-loopback bind is refused without explicit opt-in (asserted at serve time); Host must be loopback/localhost and Origin must be loopback/localhost/null/absent; only GET /status, /health, /ready are unauthenticated; auth accepts Bearer header, ?token=, or x-qk-token; failures are frozen 401/403 text; the token never appears in logs, Debug, or Display. Corpus: qk-daemon HTTP auth/host/origin/redaction tests.

INV-030: The control-plane HTTP error surface is frozen and fail-closed: no internal, store, or parser text ever leaves the process.
  Unknown rows are text `not found` (404); unknown paths are JSON {"error": "not found"} (404); decide on unknown/decided/expired rows is the frozen 400 `Error: approval not waiting` text; malformed input is 400/422 (never a store-shaped 500); busy maps to 503, conflict to 409, corrupt rows to 400, everything else to 500 `internal error`; bodies over 1 MiB are 413 and requests over 30s are 408. Corpus: qk-daemon HTTP dispatch/error/mapping/limit tests.
