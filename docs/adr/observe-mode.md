# ADR: Legacy observe mode

**Status:** Accepted — legacy observe behavior is not shipped in Rust v1.

## Context

The TypeScript reference exposes `EvaluateOptions.mode?: "enforce" | "observe"`.
Omitting `mode` selects enforcement. In legacy observe mode, ordinary non-Allow
decisions are returned as `Allow` with an `OBSERVED_*` reason and
`enforced: false`. This includes policy Deny, RequireApproval before approval
provider resolution, and parser-fallback/unknown-statement outcomes. Empty or
oversized SQL checks and caught policy-evaluation exceptions happen earlier and
remain Deny. `evaluate()` itself does not execute SQL, but a caller that treats
its returned Allow as execution authority may execute the request. No built-in
TypeScript CLI, environment, MCP, or proxy surface enables this mode.

OpenShell's TypeScript `approval_action=allow_with_findings` is separate from
core observe mode. It can convert a result after evaluation; it is not the
`mode` option. Rust rejects `allow_with_findings`, has no observe-mode field,
and rejects unknown OpenShell config fields such as `mode`.

Rust's QueryKnight-owned execution model uses positive, request-specific
authority:

```text
current request → authorize_guarded → ExecutionPermit → execute/forward
```

`ExecutionPermit` is process-local and non-cloneable. A policy Deny,
RequireApproval without a valid resolution, unsupported analysis, or an
unverifiable operation does not produce an executable permit. Audit and
metrics observe typed outcomes after authorization and cannot change them.

## Security conflict

Legacy observe semantics conflict with current Rust guarantees:

- **Fail-closed policy:** Deny, parse fallback, and unknown statements could
  become an externally visible Allow.
- **Positive-capability execution:** a caller could use that Allow without a
  current `ExecutionPermit`.
- **Once approvals:** RequireApproval becomes Allow before provider resolution,
  bypassing exact Once approval.
- **Session approvals:** observe would avoid the normal grant/permit path rather
  than create a request-bound permit under an authorized Session grant.
- **Unsupported protocols and analysis:** an unverifiable operation could be
  reported as executable even though normal adapter/proxy paths refuse it.
- **Observability isolation:** this would make an observability option alter
  authorization, unlike audit and metrics sinks whose failure or output never
  broadens authorization.
- **OpenShell boundary:** OpenShell is authorization-only. Its Allow is returned
  to an external executor and is not proof of execution; converting Deny to
  Allow would deliberately broaden what that executor may do.

`evaluate()` does not itself execute SQL, but its Allow-shaped result is unsafe
as an execution signal when enforcement was intentionally bypassed.

## Options considered

1. **Ship legacy behavior unchanged.** Rejected. It adds a Deny-to-Allow path
   and an explicit exception to the current execution-authority model.
2. **Redesign as evaluation-only/shadow mode.** Viable future work, but not part
   of this freeze. It needs a distinct result type and must not issue execution
   authority or mutate approval state.
3. **Defer.** Selected. Rust v1 does not expose the legacy mode or a compatibility
   switch.

## Decision

**Do not ship legacy Deny-to-execute observe mode in v1.** The TypeScript
behavior remains documented as reference-only behavior; it is not a Rust
compatibility requirement or a supported deployment setting.

## Future evaluation-only alternative

A separate future mode could parse SQL, evaluate policy, emit audit/metrics,
and report `would_allow`, `would_deny`, or `would_require_approval`. Its result
must be explicitly non-enforcing and distinct from `Allow`. It must not mint
an `ExecutionPermit`, execute SQL, consume a Once approval, create a Session
grant, or otherwise mutate approval state. This is a concept for later design,
not a committed feature name or implementation.

## Consequences

- Rust has no `mode=observe` or `observe` configuration field. Strict OpenShell
  validation rejects unknown `mode` fields.
- Deny, RequireApproval, parser fallback, unknown analysis, and unsupported
  protocol operations retain their enforced fail-closed outcomes.
- A future diagnostic feature must use evaluation-only semantics and clearly
  state that it is non-enforcing; it cannot reuse Allow as a bypass signal.
- Existing TypeScript tests/fixtures may continue to describe the reference
  behavior, but Rust must not add them as a port-parity acceptance criterion.

## Future reconsideration criteria

Reconsider only with a separate design and review that specifies a visibly
non-enforcing result (for example, `would_allow`, `would_deny`, and
`would_require_approval`), prevents permit issuance and downstream execution,
leaves Once/Session approval state unchanged, reports audit/metrics truthfully,
and has no hidden compatibility switch that weakens enforcement.
