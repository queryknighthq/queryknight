# Metrics (`qk-metrics`)

Zero-dependency Prometheus exposition over a QueryKnight-owned
registry. Counters and one histogram, incremented from typed
observations — reason strings are never parsed. Audited TS behavior
is in `docs/reference-implementation.md` ("Observability audit").

## Metric set (frozen names)

| Name | Type | Labels |
|---|---|---|
| `queryknight_requests_total` | counter | integration, environment, database, operation |
| `queryknight_decisions_total` | counter | + decision, reason_code |
| `queryknight_policy_denials_total` | counter | base + reason_code (deny only) |
| `queryknight_parse_errors_total` | counter | integration, dialect (`parser_ok == false`) |
| `queryknight_approval_requests_total` | counter | base + result: approved\|denied\|waiting |
| `queryknight_evaluation_duration_seconds` | histogram | (no labels) |

Label values come from enums and trusted context only
(`ReasonCode::as_str()` is bounded). Never labeled: SQL, tables,
URLs, agent ids, approval ids, fingerprints, error messages.

- Approval `result`: approved on granted outcomes, denied on
  denied, waiting otherwise (pending/unavailable/error — frozen).
- The duration histogram records evaluation durations where the
  caller measures them; execution layers that only know total
  handling time do not mislabel it as evaluation time.
- `database` renders `""` when absent (frozen `?? ''`).

## Histogram

Frozen buckets (seconds): `[0.005, 0.01, 0.05, 0.1, 0.5, 1, 5]`.
Cumulative `_bucket{le}` lines plus `+Inf`, `_sum`, `_count`.
Values are seconds — callers convert from millis (suffix matches
units; never observe ms into `_seconds`).

## Rendering (frozen)

```text
# TYPE <name> counter
<name>{k="v",...} <int>
# TYPE <name> histogram
<name>_bucket{le="<b>"} <cumulative>
<name>_bucket{le="+Inf"} <total>
<name>_sum <float>
<name>_count <total>
```

No `# HELP` lines (frozen absence). Label keys sorted; series in
sorted order (deterministic; the reference uses insertion order —
both stable, sorted chosen for test determinism). Empty registry
renders `""`. Escaping covers `\` and `"` exactly like the
reference (no newline escaping — frozen behavior).

## Runtime properties

- Thread-safe (`Mutex`, no unsafe, no globals): concurrent
  increments from daemon/MCP/proxy workers are safe.
- Process-lifetime, no reset endpoint (frozen). Tests use isolated
  registries.
- No metrics HTTP endpoint exists in the frozen product — none is
  added (`/health` stays metrics-free).

## Authorization-only integrations

OpenShell uses the same `Observer`/`MetricsRegistry` for each recognized SQL
candidate. Its counters describe QueryKnight authorization decisions only:
an Allow means “authorized for an external executor,” not DB success. The
frozen set has no execution-success or row-count metrics. The evaluation
histogram measures the `authorize_guarded` path (policy and approval
resolution), not downstream execution or audit-sink time. The embedding host
can access the service’s registry through `OpenShellService::observer()`; no
metrics HTTP endpoint or exporter is added.
