#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Flagship E2E: OpenShell + QueryKnight + PostgreSQL.
#
# Proves the composed product story on real components:
#
#   OpenShell controls WHERE the agent can connect.
#   QueryKnight controls WHAT SQL the agent can execute.
#   QueryKnight reaches PostgreSQL over verified TLS.
#
#   real OpenShell v0.1.2 sandbox
#           │ PostgreSQL protocol (plaintext, local/trusted frontend hop)
#           ▼
#   QueryKnight PostgreSQL proxy
#           │ verified TLS (sslmode=require + pinned CA)
#           ▼
#   PostgreSQL 17
#
# and that the sandbox CANNOT reach the PostgreSQL backend directly, because
# OpenShell's network policy does not authorize that destination.
#
# This is integration/test infrastructure. It changes no product behaviour: the
# PostgreSQL proxy still binds loopback only, the frontend hop is still
# plaintext, and OpenShell does not inspect PostgreSQL SQL.
#
# The sandbox is a separate network namespace and OpenShell resolves
# `host.docker.internal` to this host's routable address (it logs
# `Policy DNS mapped host.docker.internal resolved=<host ip>`), so a
# loopback-only listener is not directly reachable. The harness therefore
# bridges that one hop with a small local TCP relay
# (examples/openshell/tcp-relay.py): sandbox -> host:relay -> 127.0.0.1:proxy.
# The relay is dumb byte plumbing, is not a QueryKnight component, and exists
# only for the duration of this test.
#
# Exit 0 only when every assertion below succeeds.
#
# Environment:
#   OPENSHELL_QUERYKNIGHT_HOST  Non-loopback IPv4 of this machine, reachable
#                               from the sandbox (autodetected when possible).
#   OPENSHELL_V012_SOURCE       Optional existing OpenShell checkout at the
#                               pinned commit (skips the clone).
#   OPENSHELL_COMPUTE_DRIVER    docker (default).
#   OPENSHELL_PERSISTENT_TARGET Optional build directory to reuse between runs.
#                               Unset by default: artifacts stay in this run's
#                               temporary directory and are removed on exit.
#   QK_PG_IMAGE                 PostgreSQL image (default postgres:17).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="v0.1.2"
EXPECTED_COMMIT="6648bd0c290efbc41ba131ee9831ee45cd431f94"
DRIVER="${OPENSHELL_COMPUTE_DRIVER:-docker}"
PG_IMAGE="${QK_PG_IMAGE:-postgres:17}"
WORKLOAD_IMAGE="queryknight-openshell-e2e:${TAG}"

usage() {
  sed -n '2,47p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
[[ $# -eq 0 ]] || { usage >&2; exit 2; }

PHASE_TOTAL=14
phase() { printf '\n[%d/%d] %s\n' "$1" "$PHASE_TOTAL" "$2"; }

for command in cargo git jq openssl curl python3 nc "$DRIVER"; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

SMOKE_TMP="$(mktemp -d /tmp/qk-openshell-postgres.XXXXXX)"
LOG_DIR="$SMOKE_TMP/logs"
mkdir -p "$LOG_DIR"

RUN_ID="qk-openshell-pg-$$-$RANDOM"
SANDBOX_NAME="qkpg$(( $$ % 1000000 ))$RANDOM"
QK_HOME="$SMOKE_TMP/queryknight-home"
PG_CONTAINER="qk-openshell-pg-$$"
PKI="$SMOKE_TMP/pki"
JWT="$SMOKE_TMP/gateway-jwt"

# Ephemeral test-only credentials. The sentinel prefix makes any accidental
# leak detectable; the password is never printed, never placed in argv, and
# never written to an artifact on disk.
PG_USER="qk"
PG_DB="qk"
PG_PASSWORD="QK_PG_SENTINEL_$(python3 -c 'import secrets; print(secrets.token_hex(12))')"

QK_PID=""
RELAY_PID=""
NEG_RELAY_PID=""
NEG_PROXY_PID=""
FLOW_PID=""
DAEMON_PID=""
GATEWAY_PID=""
QK_BIN=""
CLI_BIN=""
OPEN_GATEWAY=""
SANDBOX_CREATED=0
SANDBOX_ID=""

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$SANDBOX_CREATED" -eq 1 && -n "$CLI_BIN" && -n "$GATEWAY_PORT" ]]; then
    "$CLI_BIN" --gateway-endpoint "http://127.0.0.1:$GATEWAY_PORT" \
      sandbox delete "$SANDBOX_NAME" >>"$LOG_DIR/setup.log" 2>&1 || true
  fi
  for pid in "$QK_PID" "$NEG_PROXY_PID" "$RELAY_PID" "$NEG_RELAY_PID" "$FLOW_PID" "$DAEMON_PID" "$GATEWAY_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  "$DRIVER" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$QK_HOME" "$PKI" "$JWT"
  if [[ "$status" -eq 0 ]]; then
    rm -rf "$SMOKE_TMP"
  else
    echo "OpenShell + PostgreSQL E2E failed; logs retained at $LOG_DIR" >&2
    for file in "$LOG_DIR"/*; do
      [[ -f "$file" ]] || continue
      printf '\n--- %s ---\n' "$file" >&2
      tail -40 "$file" >&2
    done
  fi
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "ASSERTION FAILED: $*" >&2
  exit 1
}

service_host() {
  if [[ -n "${OPENSHELL_QUERYKNIGHT_HOST:-}" ]]; then
    printf '%s\n' "$OPENSHELL_QUERYKNIGHT_HOST"
    return
  fi
  if [[ "$(uname -s)" == "Darwin" ]] && command -v route >/dev/null 2>&1 && command -v ipconfig >/dev/null 2>&1; then
    local interface
    interface="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
    [[ -n "$interface" ]] && ipconfig getifaddr "$interface" 2>/dev/null && return
  fi
  if command -v ip >/dev/null 2>&1; then
    ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}'
    return
  fi
  echo "set OPENSHELL_QUERYKNIGHT_HOST to the shared non-loopback host IP" >&2
  return 1
}
SERVICE_HOST="$(service_host)"
python3 -c 'import ipaddress,sys
try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
sys.exit(0 if address.version == 4 and not (address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local) else 1)' \
  "$SERVICE_HOST" || {
  echo "OPENSHELL_QUERYKNIGHT_HOST must be a valid non-loopback IPv4 address" >&2
  exit 1
}

wait_port() {
  local host="$1" port="$2" pid="$3" label="$4"
  for _ in {1..90}; do
    kill -0 "$pid" 2>/dev/null || { echo "$label exited before becoming ready" >&2; return 1; }
    nc -z "$host" "$port" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "$label did not become reachable at $host:$port" >&2
  return 1
}

# ---------------------------------------------------------------------------
phase 1 "OpenShell v0.1.2"
# ---------------------------------------------------------------------------
case "$(uname -m)" in
  arm64 | aarch64) SUPERVISOR_PLATFORM="linux/arm64" ;;
  x86_64 | amd64) SUPERVISOR_PLATFORM="linux/amd64" ;;
  *) echo "unsupported sandbox build architecture: $(uname -m)" >&2; exit 1 ;;
esac

SUPERVISOR_IMAGE="ghcr.io/nvidia/openshell/supervisor:${TAG#v}"
SANDBOX_RUNTIME_IMAGE="ghcr.io/nvidia/openshell/sandbox:${TAG#v}"
"$DRIVER" pull --platform "$SUPERVISOR_PLATFORM" "$SUPERVISOR_IMAGE" \
  >"$LOG_DIR/pull-supervisor.log" 2>&1
"$DRIVER" pull --platform "$SUPERVISOR_PLATFORM" "$SANDBOX_RUNTIME_IMAGE" \
  >"$LOG_DIR/pull-sandbox.log" 2>&1
SUPERVISOR_DIGEST="$("$DRIVER" inspect --format='{{index .RepoDigests 0}}' "$SUPERVISOR_IMAGE")"
SANDBOX_DIGEST="$("$DRIVER" inspect --format='{{index .RepoDigests 0}}' "$SANDBOX_RUNTIME_IMAGE")"

# The gateway links the system z3 instead of building the multi-GB bundled
# copy. Artifacts stay in this run's temporary directory: no persistent
# multi-GB target cache is created, and nothing survives the run.
if ! command -v z3 >/dev/null 2>&1; then
  echo "z3 not found on PATH; required to build openshell-gateway without bundled-z3" >&2
  echo "install with: brew install z3" >&2
  exit 1
fi
export PKG_CONFIG_PATH="$(brew --prefix z3 2>/dev/null)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LIBRARY_PATH="$(brew --prefix z3 2>/dev/null)/lib:${LIBRARY_PATH:-}"

OPENSHELL_SRC="${OPENSHELL_V012_SOURCE:-$SMOKE_TMP/OpenShell}"
if [[ ! -d "$OPENSHELL_SRC" ]]; then
  git clone --filter=blob:none --depth=1 --branch "$TAG" \
    https://github.com/NVIDIA/OpenShell.git "$OPENSHELL_SRC" >"$LOG_DIR/clone.log" 2>&1
fi
ACTUAL_COMMIT="$(git -C "$OPENSHELL_SRC" rev-parse HEAD)"
[[ "$ACTUAL_COMMIT" == "$EXPECTED_COMMIT" ]] || {
  echo "OpenShell source commit mismatch: expected $EXPECTED_COMMIT, got $ACTUAL_COMMIT" >&2
  exit 1
}
# Opt-in only: set OPENSHELL_PERSISTENT_TARGET to reuse a build directory.
# The default keeps artifacts in this run's temporary directory, so no
# multi-GB persistent target cache is created.
OPEN_TARGET="${OPENSHELL_PERSISTENT_TARGET:-$SMOKE_TMP/openshell-target}"
mkdir -p "$OPEN_TARGET"
env CARGO_TARGET_DIR="$OPEN_TARGET" cargo build --locked --quiet \
  --manifest-path "$OPENSHELL_SRC/Cargo.toml" -p openshell-gateway --bin openshell-gateway \
  >>"$LOG_DIR/openshell-build.log" 2>&1
env CARGO_TARGET_DIR="$OPEN_TARGET" cargo build --locked --quiet \
  --manifest-path "$OPENSHELL_SRC/Cargo.toml" -p openshell-cli --bin openshell \
  >>"$LOG_DIR/openshell-build.log" 2>&1
OPEN_GATEWAY="$OPEN_TARGET/debug/openshell-gateway"
CLI_BIN="$OPEN_TARGET/debug/openshell"
OPEN_VERSION="$("$CLI_BIN" --version 2>/dev/null || true)"
[[ -n "$OPEN_VERSION" ]] || { echo "OpenShell CLI produced no version output" >&2; exit 1; }
printf 'OpenShell %s commit=%s\n' "$OPEN_VERSION" "$ACTUAL_COMMIT"

"$DRIVER" build --platform "$SUPERVISOR_PLATFORM" \
  -t "$WORKLOAD_IMAGE" \
  -f "$ROOT/tests/openshell-v0.1.2-workload/Dockerfile" \
  "$ROOT/tests/openshell-v0.1.2-workload" >"$LOG_DIR/build-workload.log" 2>&1
WORKLOAD_IMAGE_ID="$("$DRIVER" inspect --format='{{.Id}}' "$WORKLOAD_IMAGE")"

# ---------------------------------------------------------------------------
phase 2 "PostgreSQL 17 + ephemeral TLS"
# ---------------------------------------------------------------------------
# Ports. The QueryKnight proxies bind loopback only; the relays expose them on
# the host's routable address for the sandbox.
PORT_BASE=$((24000 + RANDOM % 15000))
PROXY_PORT="$PORT_BASE"
RELAY_PORT="$((PORT_BASE + 1))"
NEG_PROXY_PORT="$((PORT_BASE + 2))"
NEG_RELAY_PORT="$((PORT_BASE + 3))"
PG_PORT="$((PORT_BASE + 4))"
GATEWAY_PORT="$((PORT_BASE + 5))"
HEALTH_PORT="$((PORT_BASE + 6))"
DAEMON_PORT="$((PORT_BASE + 7))"
for offset in 0 1 2 3 4 5 6 7; do
  port=$((PORT_BASE + offset))
  nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && {
    echo "selected E2E port is already in use: $port" >&2
    exit 1
  }
done

# Ephemeral PKI: one CA, one server certificate whose SAN is exactly the
# hostname QueryKnight uses for the backend (`localhost`), plus an unrelated CA
# for the negative verification case.
mkdir -p "$PKI"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$PKI/ca.key" -out "$PKI/ca.crt" \
  -subj "/CN=QueryKnight ephemeral PostgreSQL test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$PKI/server.key" -out "$PKI/server.csr" \
  -subj "/CN=localhost" >/dev/null 2>&1
cat >"$PKI/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
EOF
openssl x509 -req -in "$PKI/server.csr" \
  -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
  -out "$PKI/server.crt" -days 2 -extfile "$PKI/server.ext" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$PKI/unknown-ca.key" -out "$PKI/unknown-ca.crt" \
  -subj "/CN=QueryKnight untrusted CA" \
  -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
rm -f "$PKI/server.csr" "$PKI/server.ext"

"$DRIVER" run -d --name "$PG_CONTAINER" \
  -p "0.0.0.0:$PG_PORT:5432" \
  -v "$PKI:/certs" \
  -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB="$PG_DB" \
  "$PG_IMAGE" \
  bash -c 'set -e
chown postgres:postgres /certs/server.crt /certs/server.key
chmod 600 /certs/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/certs/server.key' \
  >"$LOG_DIR/pg-run.log" 2>&1

# `pg_isready` without a host answers over the unix socket, which the
# entrypoint's temporary init server also serves. Force TCP so readiness means
# the real server (the only one that listens on 127.0.0.1) is up.
pg_ready=0
for _ in {1..90}; do
  if "$DRIVER" exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -p 5432 \
      -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then
    pg_ready=1
    break
  fi
  sleep 1
done
if [[ "$pg_ready" != 1 ]]; then
  "$DRIVER" logs "$PG_CONTAINER" >&2 || true
  fail "PostgreSQL did not become ready"
fi
[[ "$("$DRIVER" exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc 'show ssl')" == "on" ]] \
  || fail "PostgreSQL did not enable ssl"

# Out-of-band backend access for state assertions (local socket inside the
# container, so no password is needed here).
pg_state() { "$DRIVER" exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "$1"; }

pg_state "DROP TABLE IF EXISTS accounts;
         CREATE TABLE accounts (id int primary key, note text);
         INSERT INTO accounts VALUES (42, 'keep'), (43, 'keep');" >/dev/null
[[ "$(pg_state 'SELECT count(*) FROM accounts')" == "2" ]] || fail "probe table seed failed"

# The backend must be reachable from a container context with these exact
# credentials, so that the sandbox's later direct failure is attributable to
# OpenShell policy rather than to networking or credentials.
if ! "$DRIVER" run --rm -e PGPASSWORD="$PG_PASSWORD" "$PG_IMAGE" \
  psql -h "$SERVICE_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -tAc 'SELECT 1' \
  >"$LOG_DIR/backend-reachability.log" 2>&1; then
  cat "$LOG_DIR/backend-reachability.log" >&2
  fail "backend is not reachable from a container context; direct-denial proof would be meaningless"
fi
grep -qx 1 "$LOG_DIR/backend-reachability.log" || fail "backend reachability probe returned no result"
printf 'PostgreSQL 17 ssl=on port=%s; backend reachable from container context\n' "$PG_PORT"

# ---------------------------------------------------------------------------
phase 3 "QueryKnight daemon + proxy"
# ---------------------------------------------------------------------------
QK_TARGET="$(cargo metadata --format-version=1 --no-deps --manifest-path "$ROOT/Cargo.toml" | jq -er '.target_directory')"
cargo build --locked --quiet --manifest-path "$ROOT/Cargo.toml" -p qk-cli --bin queryknight
QK_BIN="$QK_TARGET/debug/queryknight"

cat >"$SMOKE_TMP/policy.yaml" <<'EOF'
version: 1
defaults:
  decision: deny
  on_parse_error: deny
  on_unknown: deny
environments:
  production:
    databases:
      main:
        allow:
          - operations: [select]
        mutations:
          deny_without_where: [delete]
        approval_required:
          - operations: [delete]
EOF

"$QK_BIN" start --foreground --home "$QK_HOME" --port "$DAEMON_PORT" \
  >"$LOG_DIR/queryknight-daemon.log" 2>&1 &
DAEMON_PID=$!
wait_port 127.0.0.1 "$DAEMON_PORT" "$DAEMON_PID" "QueryKnight control plane"
curl --fail --silent --show-error "http://127.0.0.1:$DAEMON_PORT/health" >/dev/null
CONTROL_CURL_CONFIG="$SMOKE_TMP/control-curl.conf"
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$QK_HOME/session.token")" \
  >"$CONTROL_CURL_CONFIG"
chmod 600 "$CONTROL_CURL_CONFIG"

start_relay() {
  local listen_port="$1" target_port="$2" log="$3"
  python3 "$ROOT/examples/openshell/tcp-relay.py" \
    --listen-host "$SERVICE_HOST" --listen-port "$listen_port" --target-port "$target_port" \
    >"$log" 2>&1 &
  echo $!
}

start_proxy() {
  local listen_port="$1" ca="$2" log="$3"
  env -u MYSQL_URL -u POSTGRES_URL -u QUERYKNIGHT_DAEMON_URL \
    DATABASE_URL="postgres://${PG_USER}:${PG_PASSWORD}@localhost:${PG_PORT}/${PG_DB}?sslmode=require" \
    QUERYKNIGHT_PG_SSLROOTCERT="$ca" \
    QUERYKNIGHT_POLICY_FILE="$SMOKE_TMP/policy.yaml" \
    QUERYKNIGHT_ENV=production \
    QUERYKNIGHT_DATABASE=main \
    QUERYKNIGHT_HOME="$QK_HOME" \
    "$QK_BIN" proxy --listen "$listen_port" >"$log" 2>&1 &
  echo $!
}

RELAY_PID="$(start_relay "$RELAY_PORT" "$PROXY_PORT" "$LOG_DIR/relay.log")"
wait_port "$SERVICE_HOST" "$RELAY_PORT" "$RELAY_PID" "harness relay"
QK_PID="$(start_proxy "$PROXY_PORT" "$PKI/ca.crt" "$LOG_DIR/queryknight-proxy.log")"
wait_port 127.0.0.1 "$PROXY_PORT" "$QK_PID" "QueryKnight PostgreSQL proxy"

# Second proxy with an untrusted CA, used by the negative verification phase.
NEG_RELAY_PID="$(start_relay "$NEG_RELAY_PORT" "$NEG_PROXY_PORT" "$LOG_DIR/neg-relay.log")"
wait_port "$SERVICE_HOST" "$NEG_RELAY_PORT" "$NEG_RELAY_PID" "negative-case relay"
NEG_PROXY_PID="$(start_proxy "$NEG_PROXY_PORT" "$PKI/unknown-ca.crt" "$LOG_DIR/queryknight-proxy-neg.log")"
wait_port 127.0.0.1 "$NEG_PROXY_PORT" "$NEG_PROXY_PID" "negative-case QueryKnight proxy"
printf 'QueryKnight proxies 127.0.0.1:%s (verified TLS) and 127.0.0.1:%s (untrusted CA)\n' \
  "$PROXY_PORT" "$NEG_PROXY_PORT"

# ---------------------------------------------------------------------------
phase 4 "OpenShell sandbox"
# ---------------------------------------------------------------------------
mkdir -p "$JWT"
openssl genpkey -algorithm ed25519 -out "$JWT/signing.pem" >/dev/null 2>&1
openssl pkey -in "$JWT/signing.pem" -pubout -out "$JWT/public.pem" >/dev/null 2>&1
printf '%s\n' "$RUN_ID" >"$JWT/kid"

cat >"$SMOKE_TMP/gateway.toml" <<EOF
[openshell]
version = 2

# Authenticates only the disposable local gateway API used by this harness.
[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$JWT/signing.pem"
public_key_path = "$JWT/public.pem"
kid_path = "$JWT/kid"
gateway_id = "$RUN_ID"
ttl_secs = 3600

[openshell.drivers.$DRIVER]
supervisor_image = "$SUPERVISOR_IMAGE"
sandbox_runtime_image = "$SANDBOX_RUNTIME_IMAGE"
# The sandbox calls back to the gateway; use the host's routable address,
# because the sandbox's own loopback is not the host.
grpc_endpoint = "http://$SERVICE_HOST:$GATEWAY_PORT"
EOF

# Network policy: `psql` may reach the two QueryKnight proxy relays only. The
# PostgreSQL backend port is deliberately absent, so OpenShell denies it.
#
# There is intentionally NO `network_middlewares` section: OpenShell does not
# inspect PostgreSQL SQL here. OpenShell enforces the network destination;
# QueryKnight enforces the SQL authorization. Debian ships `/usr/bin/psql` as a
# symlink, and OpenShell matches the kernel-resolved executable path.
cat >"$SMOKE_TMP/sandbox-policy.yaml" <<EOF
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc, /var/log, /proc, /dev/urandom, /tmp]
  read_write: [/home, /tmp]
landlock:
  compatibility: best_effort
process:
  run_as_user: "65534"
  run_as_group: "65534"
network_policies:
  queryknight-postgres:
    name: QueryKnight PostgreSQL proxy
    endpoints:
      - host: host.docker.internal
        port: $RELAY_PORT
        protocol: tcp
      - host: host.docker.internal
        port: $NEG_RELAY_PORT
        protocol: tcp
    binaries:
      - path: /usr/lib/postgresql/*/bin/psql
      - path: /usr/bin/python3*
EOF

env -u OPENSHELL_DRIVERS -u OPENSHELL_COMPUTE_DRIVER \
  OPENSHELL_SANDBOX_RUNTIME_IMAGE="$SANDBOX_RUNTIME_IMAGE" \
  "$OPEN_GATEWAY" \
  --compute-driver "$DRIVER" \
  --config "$SMOKE_TMP/gateway.toml" \
  --bind-address 0.0.0.0 \
  --port "$GATEWAY_PORT" \
  --health-port "$HEALTH_PORT" \
  --metrics-port 0 \
  --log-level info \
  --disable-tls \
  --db-url "sqlite://$SMOKE_TMP/gateway.db" >"$LOG_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
wait_port 127.0.0.1 "$HEALTH_PORT" "$GATEWAY_PID" "OpenShell v0.1.2 gateway"

CLI=("$CLI_BIN" --gateway-endpoint "http://127.0.0.1:$GATEWAY_PORT")
SANDBOX_CREATED=1
"${CLI[@]}" sandbox create --name "$SANDBOX_NAME" \
  --from "$WORKLOAD_IMAGE" \
  --policy "$SMOKE_TMP/sandbox-policy.yaml" --no-tty --detach -- sleep infinity \
  >"$LOG_DIR/sandbox-create.log" 2>&1 || {
  cat "$LOG_DIR/sandbox-create.log" >&2
  fail "sandbox create failed"
}
SANDBOX_ID="$(grep -F "sandbox_name=$SANDBOX_NAME" "$LOG_DIR/gateway.log" | tail -1 \
  | sed -nE 's/.*sandbox_id=([0-9a-f-]+).*/\1/p')"
[[ -n "$SANDBOX_ID" ]] || fail "could not extract sandbox id from the gateway log"
printf 'Sandbox name=%s id=%s workload=%s\n' "$SANDBOX_NAME" "$SANDBOX_ID" "$WORKLOAD_IMAGE"

# Deliver the test password out of band: the .pgpass body is piped on stdin, so
# the sentinel never appears in argv or in any captured command line.
printf '*:*:*:*:%s\n' "$PG_PASSWORD" | "${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- \
  sh -c 'umask 077; cat > /tmp/qk-pgpass' >"$LOG_DIR/pgpass-write.log" 2>&1
"${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- \
  sh -c 'test -s /tmp/qk-pgpass && echo QK_PGPASS_PRESENT' 2>/dev/null | grep -q QK_PGPASS_PRESENT \
  || fail "sandbox .pgpass was not created"

# Run a real psql inside the sandbox. Host/port/db/user are passed as flags and
# the password comes from .pgpass, so no credential is ever an argument.
sandbox_psql() {
  local port="$1" sql="$2"
  "${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- \
    sh -c "PGPASSFILE=/tmp/qk-pgpass PGSSLMODE=disable PGCONNECT_TIMEOUT=10 \
/usr/bin/psql -h host.docker.internal -p $port -U $PG_USER -d $PG_DB -X -w -tA \
     -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -c '$sql'"
}

# The sandbox filesystem policy mounts /var/log read-only, so the supervisor
# cannot write a log file there. The supervisor pushes its OCSF events to the
# gateway, which buffers them; read them back through the CLI.
# The sandbox filesystem policy mounts /var/log read-only, so the supervisor
# cannot write a log file there. The supervisor pushes its OCSF events to the
# gateway, which buffers them; read them back through the CLI.
sandbox_log() {
  "${CLI[@]}" logs "$SANDBOX_NAME" -n 2000 --source sandbox 2>&1 || true
}

sandbox_container() {
  "$DRIVER" ps -a --filter "label=openshell.ai/sandbox-id=$SANDBOX_ID" --format '{{.ID}}' | head -1
}

# The supervisor runs inside the sandbox container, so its own tracing output
# (including the network-policy denial reason) is the container log. This is
# the enforcement component's own record, not a QueryKnight log.
capture_sandbox_log() {
  sandbox_log >"$LOG_DIR/sandbox-log.txt" 2>&1 || true
  local container
  container="$(sandbox_container)"
  if [[ -n "$container" ]]; then
    printf '%s\n' "$container" >"$LOG_DIR/sandbox-container.txt"
    "$DRIVER" logs "$container" >"$LOG_DIR/sandbox-supervisor.log" 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
phase 5 "direct PostgreSQL access must fail"
# ---------------------------------------------------------------------------
if sandbox_psql "$PG_PORT" 'SELECT 1' >"$LOG_DIR/direct-attempt.log" 2>&1; then
  cat "$LOG_DIR/direct-attempt.log" >&2
  fail "sandbox reached the PostgreSQL backend directly; OpenShell network policy did not deny it"
fi
[[ "$(pg_state 'SELECT count(*) FROM accounts')" == "2" ]] \
  || fail "backend state changed during the denied direct attempt"

capture_sandbox_log
DENY_LINE="$(grep -iE 'denied|not allowed' "$LOG_DIR/sandbox-supervisor.log" "$LOG_DIR/sandbox-log.txt" 2>/dev/null \
  | grep -F ":$PG_PORT" | tail -1 || true)"
[[ -n "$DENY_LINE" ]] || {
  tail -30 "$LOG_DIR/sandbox-supervisor.log" >&2 || true
  tail -10 "$LOG_DIR/sandbox-log.txt" >&2 || true
  fail "no OpenShell denial record naming port $PG_PORT was found"
}
printf 'Direct sandbox -> PostgreSQL DENIED by OpenShell:\n  %s\n' "$DENY_LINE"

# ---------------------------------------------------------------------------
phase 6 "QueryKnight proxy access must succeed"
# ---------------------------------------------------------------------------
sandbox_psql "$RELAY_PORT" 'SELECT 1' >"$LOG_DIR/proxy-reach.log" 2>&1 || {
  cat "$LOG_DIR/proxy-reach.log" >&2
  capture_sandbox_log
  tail -20 "$LOG_DIR/sandbox-supervisor.log" >&2 || true
  fail "sandbox could not reach the QueryKnight PostgreSQL proxy"
}
grep -qx 1 "$LOG_DIR/proxy-reach.log" || {
  cat "$LOG_DIR/proxy-reach.log" >&2
  fail "QueryKnight proxy reachability probe returned no result"
}
printf 'Sandbox -> QueryKnight proxy (%s:%s) allowed, psql returned 1\n' "$SERVICE_HOST" "$RELAY_PORT"

# ---------------------------------------------------------------------------
phase 7 "SELECT allowed"
# ---------------------------------------------------------------------------
sandbox_psql "$RELAY_PORT" 'SELECT 1' >"$LOG_DIR/select.log" 2>&1 || {
  cat "$LOG_DIR/select.log" >&2
  fail "allowed SELECT failed through QueryKnight"
}
grep -qx 1 "$LOG_DIR/select.log" || { cat "$LOG_DIR/select.log" >&2; fail "SELECT 1 returned no row"; }

# The backend hop must be TLS, and PostgreSQL itself reports it for the very
# session QueryKnight forwarded: pg_stat_ssl joins pg_backend_pid() of the
# proxied backend connection.
sandbox_psql "$RELAY_PORT" 'SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()' \
  >"$LOG_DIR/select-tls.log" 2>&1 || {
  cat "$LOG_DIR/select-tls.log" >&2
  fail "backend TLS probe through QueryKnight failed"
}
TLS_ROW="$(cat "$LOG_DIR/select-tls.log")"
printf 'Backend TLS for the proxied session: %s\n' "$TLS_ROW"
[[ "$TLS_ROW" == t\|* ]] || fail "QueryKnight -> PostgreSQL hop is not TLS (pg_stat_ssl.ssl='${TLS_ROW%%|*}')"
printf 'SELECT allowed; QueryKnight -> PostgreSQL transport is TLS\n'

# ---------------------------------------------------------------------------
phase 8 "DELETE denied"
# ---------------------------------------------------------------------------
if sandbox_psql "$RELAY_PORT" 'DELETE FROM accounts' >"$LOG_DIR/deny.log" 2>&1; then
  cat "$LOG_DIR/deny.log" >&2
  fail "unbounded DELETE was not blocked"
fi
grep -q '42501' "$LOG_DIR/deny.log" || {
  cat "$LOG_DIR/deny.log" >&2
  fail "unbounded DELETE was not blocked with SQLSTATE 42501"
}
[[ "$(pg_state 'SELECT count(*) FROM accounts')" == "2" ]] \
  || fail "denied DELETE changed backend state"
printf 'DELETE FROM accounts blocked (SQLSTATE 42501); backend rows=%s\n' \
  "$(pg_state 'SELECT count(*) FROM accounts')"

# ---------------------------------------------------------------------------
phase 9 "approval required"
# ---------------------------------------------------------------------------
# QueryKnight mints one proxy session per frontend connection and binds the
# approval to that trusted session scope, so the retry must be issued on the
# SAME connection, exactly as an interactive client would: the statement fails
# with "waiting for approval", the operator approves, the client re-issues the
# statement without reconnecting. One long-lived sandbox client therefore
# reports one line per attempt.
FLOW_OUTPUT="$LOG_DIR/approval-flow.log"
: >"$FLOW_OUTPUT"
"${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- \
  sh -c "PGPASSFILE=/tmp/qk-pgpass PGCONNECT_TIMEOUT=10 \
/usr/bin/python3 /usr/local/bin/qk-approval-flow.py $RELAY_PORT" \
  >"$FLOW_OUTPUT" 2>&1 &
FLOW_PID=$!

wait_for_line() {
  local file="$1" pattern="$2" seconds="$3"
  local attempts=$((seconds * 10))
  for _ in $(seq 1 "$attempts"); do
    grep -q "$pattern" "$file" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

wait_for_line "$FLOW_OUTPUT" '^ATTEMPT1 ' 60 || {
  cat "$FLOW_OUTPUT" >&2
  fail "sandbox approval flow did not report its first attempt"
}
grep -q '^ATTEMPT1 ERROR 42501 .*waiting for approval' "$FLOW_OUTPUT" || {
  cat "$FLOW_OUTPUT" >&2
  fail "approval-gated DELETE did not report a pending approval with SQLSTATE 42501"
}
[[ "$(pg_state 'SELECT count(*) FROM accounts WHERE id = 42')" == "1" ]] \
  || fail "pending DELETE changed backend state"

APPROVALS=""
for _ in $(seq 1 50); do
  APPROVALS="$(curl --config "$CONTROL_CURL_CONFIG" --fail --silent --show-error \
    "http://127.0.0.1:$DAEMON_PORT/approvals")"
  [[ "$(printf '%s' "$APPROVALS" | jq -er '[.[] | select(.status == "waiting")] | length')" -ge 1 ]] && break
  sleep 0.2
done
printf '%s\n' "$APPROVALS" >"$LOG_DIR/approvals-pending.json"
APPROVAL_ID="$(printf '%s' "$APPROVALS" | jq -er '[.[] | select(.status == "waiting")][-1].id')"
APPROVAL_KIND="$(printf '%s' "$APPROVALS" | jq -er --arg id "$APPROVAL_ID" \
  '.[] | select(.id == $id) | .bindingKind')"
[[ "$APPROVAL_KIND" == exact_v2 ]] || fail "approval is not ExactV2 (got '$APPROVAL_KIND')"
printf 'Pending (ExactV2, bound id=42): id=%s kind=%s; backend row 42 intact\n' \
  "$APPROVAL_ID" "$APPROVAL_KIND"

# ---------------------------------------------------------------------------
phase 10 "exact approval granted"
# ---------------------------------------------------------------------------
curl --config "$CONTROL_CURL_CONFIG" --fail --silent --show-error \
  --request POST --header 'content-type: application/json' \
  --data '{"status":"approved","source":"ui","scope":"once"}' \
  "http://127.0.0.1:$DAEMON_PORT/approvals/$APPROVAL_ID/decide" \
  >"$LOG_DIR/approval-decision.json"
jq -e '.status == "approved" and .scope == "once"' "$LOG_DIR/approval-decision.json" >/dev/null \
  || fail "approval decision did not record approved/once"
printf 'Approved %s with scope=once through the daemon control plane\n' "$APPROVAL_ID"

# ---------------------------------------------------------------------------
phase 11 "exact retry succeeds"
# ---------------------------------------------------------------------------
"${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- \
  sh -c 'touch /tmp/qk-approval-ready' >"$LOG_DIR/grant-signal.log" 2>&1 || {
  cat "$LOG_DIR/grant-signal.log" >&2
  fail "could not signal the sandbox client to retry"
}
wait "$FLOW_PID" || { cat "$FLOW_OUTPUT" >&2; fail "sandbox approval flow exited non-zero"; }
FLOW_PID=""
grep -q '^ATTEMPT2 DELETED 1$' "$FLOW_OUTPUT" || {
  cat "$FLOW_OUTPUT" >&2
  fail "exact retry after approval did not delete exactly one row"
}
[[ "$(pg_state 'SELECT count(*) FROM accounts WHERE id = 42')" == "0" ]] \
  || fail "approved retry did not delete exactly the approved row"
[[ "$(pg_state 'SELECT count(*) FROM accounts')" == "1" ]] \
  || fail "approved retry did not execute exactly once"
printf 'Exact retry executed once on the same connection; remaining rows=%s\n' \
  "$(pg_state 'SELECT count(*) FROM accounts')"

# ---------------------------------------------------------------------------
phase 12 "changed request blocked"
# ---------------------------------------------------------------------------
grep -q '^ATTEMPT3 ERROR 42501 ' "$FLOW_OUTPUT" || {
  cat "$FLOW_OUTPUT" >&2
  fail "a Once approval authorized a changed bound value"
}
[[ "$(pg_state 'SELECT count(*) FROM accounts WHERE id = 43')" == "1" ]] \
  || fail "changed request changed backend state"
[[ "$(pg_state 'SELECT count(*) FROM accounts')" == "1" ]] \
  || fail "changed request mutated the backend"

CHANGED_APPROVALS="$(curl --config "$CONTROL_CURL_CONFIG" --fail --silent --show-error \
  "http://127.0.0.1:$DAEMON_PORT/approvals")"
printf '%s\n' "$CHANGED_APPROVALS" >"$LOG_DIR/approvals-after-changed.json"
APPROVED_COUNT="$(printf '%s' "$CHANGED_APPROVALS" | jq -er '[.[] | select(.status == "approved")] | length')"
WAITING_COUNT="$(printf '%s' "$CHANGED_APPROVALS" | jq -er '[.[] | select(.status == "waiting")] | length')"
[[ "$APPROVED_COUNT" == "1" ]] || fail "expected exactly one approved grant, got $APPROVED_COUNT"
[[ "$WAITING_COUNT" -ge 1 ]] || fail "changed request did not raise a new pending approval"
printf 'Changed bound value (id=43) blocked; approvals approved=%s waiting=%s\n' \
  "$APPROVED_COUNT" "$WAITING_COUNT"

# ---------------------------------------------------------------------------
phase 13 "backend TLS verification negative case"
# ---------------------------------------------------------------------------
if sandbox_psql "$NEG_RELAY_PORT" 'SELECT 1' >"$LOG_DIR/neg.log" 2>&1; then
  cat "$LOG_DIR/neg.log" >&2
  fail "an untrusted backend CA produced a working session"
fi
grep -qE 'TLS handshake failed|TLS is misconfigured' "$LOG_DIR/neg.log" || {
  cat "$LOG_DIR/neg.log" >&2
  fail "untrusted CA did not produce a bounded backend-TLS proxy error"
}
[[ "$(pg_state 'SELECT count(*) FROM accounts')" == "1" ]] \
  || fail "negative TLS case changed backend state"
printf 'Untrusted CA: sandbox reached QueryKnight, backend TLS failed closed, no SQL executed\n'

# ---------------------------------------------------------------------------
phase 14 "audit and cleanup"
# ---------------------------------------------------------------------------
ACTIVITY="$(curl --config "$CONTROL_CURL_CONFIG" --fail --silent --show-error \
  "http://127.0.0.1:$DAEMON_PORT/activity" 2>/dev/null || echo '[]')"
printf '%s\n' "$ACTIVITY" >"$LOG_DIR/activity.json"

# QueryKnight records history only for statements it forwarded. Extended
# protocol statements are recorded as the parsed SQL (`$1` placeholders), not as
# interpolated literals, so the changed bound value cannot be distinguished by
# text; exactly one recorded parameterized DELETE is the proof that the changed
# request never executed.
history_count() {
  printf '%s' "$ACTIVITY" | jq -er --arg sql "$1" '[.[] | select(.sql == $sql)] | length'
}
SELECT_COUNT="$(history_count 'SELECT 1')"
DELETE_COUNT="$(history_count 'DELETE FROM accounts WHERE id = $1')"
DENIED_COUNT="$(history_count 'DELETE FROM accounts')"
[[ "$SELECT_COUNT" -ge 1 ]] || fail "allowed SELECT is missing from recorded history"
[[ "$DELETE_COUNT" == "1" ]] \
  || fail "expected exactly one executed parameterized DELETE, got $DELETE_COUNT"
[[ "$DENIED_COUNT" == "0" ]] || fail "denied unbounded DELETE reached the execution history"
printf 'History: SELECT 1 x%s, parameterized DELETE x%s, denied DELETE x%s\n' \
  "$SELECT_COUNT" "$DELETE_COUNT" "$DENIED_COUNT"

"${CLI[@]}" sandbox delete "$SANDBOX_NAME" >"$LOG_DIR/sandbox-delete.log" 2>&1 || true
SANDBOX_CREATED=0

if grep -rF "$PG_PASSWORD" "$LOG_DIR" "$SMOKE_TMP" >/dev/null 2>&1; then
  fail "the test database sentinel password leaked into captured logs or artifacts"
fi
printf 'No sentinel credential found in logs or artifacts\n'

printf '\nOpenShell + QueryKnight + PostgreSQL E2E: PASS\n'
printf '  openshell version     %s\n' "$OPEN_VERSION"
printf '  openshell commit      %s\n' "$ACTUAL_COMMIT"
printf '  supervisor digest     %s\n' "$SUPERVISOR_DIGEST"
printf '  sandbox runtime       %s\n' "$SANDBOX_DIGEST"
printf '  workload image        %s (%s)\n' "$WORKLOAD_IMAGE" "$WORKLOAD_IMAGE_ID"
printf '  sandbox id            %s\n' "$SANDBOX_ID"
printf '  postgres              %s (ssl=on) port=%s\n' "$PG_IMAGE" "$PG_PORT"
printf '  backend hostname      localhost (SAN DNS:localhost)\n'
printf '  queryknight proxy     %s:%s -> 127.0.0.1:%s (verified TLS)\n' \
  "$SERVICE_HOST" "$RELAY_PORT" "$PROXY_PORT"
printf '  sandbox direct target host.docker.internal:%s DENIED\n' "$PG_PORT"
printf '  sandbox proxy target  host.docker.internal:%s ALLOWED\n' "$RELAY_PORT"
printf '  backend TLS (proxied) %s\n' "$TLS_ROW"
printf '  approvals             approved=%s waiting=%s\n' "$APPROVED_COUNT" "$WAITING_COUNT"
