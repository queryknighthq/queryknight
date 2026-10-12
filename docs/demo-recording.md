# Demo recording plan

A 90–150 second plan for recording the OpenShell + QueryKnight + PostgreSQL
showcase. This document is the plan only; no recording is produced in this
milestone.

## Preparation

1. Run the demo once to warm everything (images pulled, workload image built,
   OpenShell gateway and CLI compiled):

   ```sh
   scripts/test-openshell-postgres-v0.1.2.sh
   ```

2. For the recorded take, reuse the build directory so the run starts almost
   immediately and the screen is not idle for minutes:

   ```sh
   OPENSHELL_PERSISTENT_TARGET=/path/to/reusable/target \
   QK_DEMO=1 scripts/test-openshell-postgres-v0.1.2.sh
   ```

3. Terminal: large font, no window chrome, scrollback cleared. Keep the run's
   log directory path visible — that is where a maintainer looks on failure.

Do not edit or shorten the script for the recording. `QK_DEMO=1` changes
verbosity only; every assertion still runs.

## Shot list

| Time | On screen | Narration beat |
|---|---|---|
| 0:00–0:15 | The architecture diagram from `openshell-postgres-demo.md` | Two controls: OpenShell decides where the agent can connect, QueryKnight decides what SQL may run |
| 0:15–0:30 | Phase 5 output plus the `NET:OPEN … DENIED …` line | The sandbox holds valid database credentials and is still refused the database port — by network policy, not by a firewall on the database |
| 0:30–0:45 | Phase 6 and phase 7 output | The same client reaches the QueryKnight proxy, which OpenShell admits; `SELECT 1` returns a row |
| 0:45–1:05 | Phase 7 TLS line and phase 8 output | The proxy's own hop to PostgreSQL is verified TLS; an unbounded `DELETE` is refused with SQLSTATE 42501 and the rows are still there |
| 1:05–1:35 | Phase 9 output, then phase 10 (the approval API call) | A bound `DELETE` cannot run until a human approves exactly that request; the pending row is `exact_v2` |
| 1:35–1:55 | Phase 11 output | The identical retry now executes once, on the same connection |
| 1:55–2:15 | Phase 12 output | The same statement with a different bound value is blocked again and the earlier `once` grant does not apply |
| 2:15–2:30 | Phase 13 and the `✓` success summary | An untrusted certificate makes the proxy fail closed with no SQL executed; every assertion above passed in one run |

Trim or drop the TLS-negative shot if the recording must fit 90 seconds; keep
the direct-denial, `SELECT`, `DELETE`, approval, retry, and changed-value beats.

## Do not

- Do not narrate the deployment as production-ready, end-to-end encrypted, or an
  official OpenShell integration.
- Do not show passwords, tokens, JWTs, or the sandbox's own identifiers.
- Do not paste long log dumps; the `QK_DEMO=1` summary plus one evidence line per
  beat is the intended density.
