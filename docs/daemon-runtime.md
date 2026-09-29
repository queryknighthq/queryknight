# Daemon runtime lifecycle (`qk-daemon` runtime + CLI)

How the control-plane server from `docs/daemon-api.md` becomes a real
standalone process: paths, token, singleton ownership, logging, signals,
and the `start`/`stop`/`status` CLI surface. Audited source behavior is
in `docs/reference-implementation.md` ("Daemon runtime audit"); this
document is the Rust contract, including deliberate hardenings.

## Commands (frozen TS shape)

Top-level, like the reference: `queryknight start`, `queryknight stop`,
`queryknight status`. No `daemon` subgroup, no `restart`.

- `start [--port N] [--home DIR] [--foreground]`: launch and wait for
  readiness. Default mode spawns a detached child running
  `start --foreground` with stdout/stderr appended to `daemon.log`,
  then polls the status probe (bounded, ~2s); prints
  `daemon started (log: <path>)` or the log tail on failure (exit 1).
  `--foreground` runs the daemon in-process (canonical implementation;
  background is a thin launcher around it). Already running prints
  `daemon already running` (exit 0).
- `stop [--home DIR]`: verify ownership (pid alive AND status probe
  reports the same pid), SIGTERM, bounded wait for the probe to go
  dark, unlink the pid file only if still owned. Prints
  `daemon stopped`; missing pid file prints `daemon not running`
  (exit 0). Never kills a pid it does not own.
- `status [--home DIR]`: combine pid-file evidence with the control-plane
  probe. Prints `daemon up pid=<pid>`, `daemon down` (exit 1), or
  `daemon stale (pid=<pid>, not responding)` for a dead pid file.

`--port`/`--home` are CLI overrides (the reference has no daemon flags;
precedence below). `inspect`/`policy`/`version` are unchanged.

## Config precedence

CLI flags > environment > defaults. Environment:
`QUERYKNIGHT_HOME` (default `~/.queryknight`), `QUERYKNIGHT_PORT`
(default `47821`), `QUERYKNIGHT_DAEMON_URL` (client probe base; default
`http://127.0.0.1:<port>`). No stored settings. Resolved once at
startup into a typed config; handlers never read env.

## Paths

```
<home>/
  queryknight.db       SQLite store (WAL; -wal/-shm siblings)
  queryknight.db-wal
  session.token        bearer token (0600)
  daemon.pid           "<pid>\n<port>\n" (compat/status only)
  daemon.lock          singleton lock file (Rust hardening)
  daemon.log           appended operational log
```

`RuntimePaths` centralizes resolution; no handler builds paths; no
scattered home lookups.

## Directory creation

Created with restrictive permissions where the platform supports it:
newly created state dir gets `0700` on Unix; a pre-existing directory
is never chmodded (QueryKnight must not weaken or touch user-owned
parents). Documented, tested.

## Token

- Format (frozen): 24 CSPRNG bytes (`getrandom`), base64url no-pad
  (32 chars), file content is `<token>\n`. Same alphabet as the TS
  `randomBytes(24).base64url`.
- Reuse (frozen): restart reuses any non-empty token file; a token is
  generated only when absent/empty. No rotation endpoint; delete the
  file + restart rotates.
- Fail closed (hardening): empty-after-trim (when the file exists but
  carries nothing), oversized reads (bounded at 4 KiB), and unreadable
  files are typed startup failures, never silent insecure defaults.
- Writes are atomic: temp file in the same directory, `0600` before
  any bytes land (Unix), flush + fsync, atomic rename. Clients never
  observe partial credentials.
- `?token=` URL transport stays for reference compatibility but is
  documented compatibility-only: the future UI must use the
  `Authorization` header. The token never appears in logs, errors, or
  `Debug` output (redaction wrapper; pinned by tests).

## Singleton ownership

- Primary mechanism (Rust hardening): an exclusive non-blocking file
  lock on `daemon.lock`, held for the whole process lifetime. A second
  `start` against the same home fails fast with `AlreadyRunning`
  without touching pid/token state. OS releases the lock on crash, so
  stale locks are impossible by construction.
- `daemon.pid` remains for reference compatibility and `status`/`stop`
  UX, but is never the sole mutual-exclusion mechanism and is never
  trusted as proof of liveness.
- A pid file alone proves nothing: `status`/`stop` always corroborate
  with process aliveness (`kill(pid, 0)` on Unix) and the `/status`
  probe pid. A stale pid is reported distinctly and reclaimed on next
  start; a malformed pid file is a typed error, never a kill of an
  arbitrary number.
- Cleanup verifies ownership: shutdown and `stop` only unlink a pid
  file whose content still names this instance (regression-tested: a
  failed second start never removes the active daemon's pid).

## Startup ordering

```
resolve paths -> ensure dirs -> load/create token -> open/migrate store
  -> acquire singleton lock -> bind listener -> write pid -> serve
```

Pid (`running`) is written only after the listener is bound, so
"started" always means accepting requests. Any phase failure unwinds
only resources owned by this startup (lock released by close/drop,
no pid written, no partial token left behind).

Port-in-use fails clearly (`Bind` error naming address + OS cause)
without assuming the occupant is QueryKnight and without touching
pid/token state.

## Logging

`tracing`, operational log only (not the QueryKnight audit log):

- Always appended to `daemon.log` under the owned runtime dir
  (reference append-forever semantics; no rotation).
- Foreground also logs to stderr (debuggable); spawned background
  children redirect stdout+stderr to the log file (reference shape).
- Bounded formatting; startup/shutdown diagnostics useful. Never
  logged: token bytes, `Authorization` headers, SQL text, provider
  secrets.

## Signals and shutdown

- Foreground installs `Ctrl-C`/SIGINT (all platforms) and SIGTERM
  (Unix) handlers at the daemon boundary only (tokio signals; nothing
  in core/store/approval).
- Sequence: stop accepting -> bounded drain of in-flight HTTP
  (grace period, then drop) -> release store (`Drop` closes SQLite;
  WAL replays on next open, no explicit checkpoint -- cheap shutdown
  is preferred over truncating the WAL every stop) -> remove owned
  pid state -> exit.
- Shutdown never mutates approvals: waiting rows stay waiting.
  There are no long-lived server requests in this port (decide is
  immediate; no `/wait` endpoint), so shutdown cancellation is about
  idle keep-alive connections, which are dropped after the grace
  period.
- `stop` sends SIGTERM to a verified-own pid, waits boundedly for the
  probe to go dark, and does not escalate to SIGKILL (a wedged daemon
  is reported, not force-killed from a script).

## Status probe

Small loopback-only control-plane probe (TCP + minimal HTTP, short
timeout, Bearer where needed): used by `start` readiness,
`stop`/`status` ownership checks, and tests. Not a general HTTP SDK.
Token never appears in probe diagnostics.

## Intentional divergences from TS

1. Singleton lock file (`daemon.lock`) in addition to pid probing --
   pid files are racy; the lock is the real mutual exclusion.
2. `stop` verifies ownership and waits boundedly instead of
   kill-and-unlink blindly.
3. Missing-field validation is `400` before SQLite (already diverged
   in 1631702); same spirit here: malformed pid/token files are typed
   errors, never blind kills or silent defaults.
4. Oversized-token-file rejection (4 KiB bound) and `0700` on
   newly created state dirs (never chmod pre-existing dirs).
5. No SIGKILL escalation in `stop`.
6. Background spawn does not call `setsid` (stays in the caller's
   process group on Unix; detached via handle release + stdio-to-file;
   `DETACHED_PROCESS` on Windows). Documented; avoids `unsafe` in the
  CLI for a marginal isolation gain.
7. `QUERYKNIGHT_AUTOSTART_PROXY_URL`/proxy autostart is NOT ported
   (no proxies in this commit); OS service autostart (launchd/systemd)
   is deferred to a packaging commit.
