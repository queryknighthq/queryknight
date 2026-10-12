#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Real OpenShell v0.1.2 sandbox middleware E2E for QueryKnight.
#
# This harness pulls the upstream OpenShell v0.1.2 supervisor and sandbox runtime
# images, builds the OpenShell gateway and CLI from the pinned source, builds a
# small custom debian+curl workload image, and drives Allow / Deny / Approval-
# Pending / Once-Granted / Changed-Request probes through the real
# supervisor + middleware path using `openshell sandbox exec -- curl ...`.
#
# The QueryKnight <-> supervisor <-> gateway handshake is verified through the
# openshell_auth_success / openshell_authorization audit records. Each probe
# is additionally proved by the demo target's request counter incrementing
# (or not) in response to the supervisor's forwarding decision.
#
# The custom workload image at tests/openshell-v0.1.2-workload/ exists only to
# give the sandbox a curl binary; the upstream sandbox:0.1.2 image is
# distroless with no shell or userland tools. The workload image is not part of
# any production deployment.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="v0.1.2"
EXPECTED_COMMIT="6648bd0c290efbc41ba131ee9831ee45cd431f94"
DRIVER="${OPENSHELL_COMPUTE_DRIVER:-docker}"
WORKLOAD_IMAGE="queryknight-openshell-e2e:${TAG}"
WORKLOAD_TAG_PIN="${WORKLOAD_IMAGE}"

usage() {
  cat <<EOF
usage: scripts/test-openshell-v0.1.2.sh

Runs a real OpenShell v0.1.2 sandbox middleware E2E with QueryKnight, driving
Allow/Deny/Approval probes through the supervisor and verifying the
target request counter and the qk-openshell audit log.

Environment:
  OPENSHELL_QUERYKNIGHT_HOST   Non-loopback IP reachable from the sandbox.
  OPENSHELL_COMPUTE_DRIVER     docker (default) or podman.
  OPENSHELL_V012_SOURCE        Optional existing OpenShell checkout (commit is verified).
  OPENSHELL_PERSISTENT_TARGET  Optional cargo target dir for OpenShell gateway+CLI
                               (defaults to \$HOME/.cache/qk-openshell-build/openshell-target).
EOF
}
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
[[ $# -eq 0 ]] || { usage >&2; exit 2; }

PHASE_TOTAL=12
phase() { printf '\n[%d/%d] %s\n' "$1" "$PHASE_TOTAL" "$2"; }

for command in cargo git jq openssl curl python3 nc "$DRIVER"; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

SMOKE_TMP="$(mktemp -d /tmp/qk-openshell-v0.1.2.XXXXXX)"
LOG_DIR="$SMOKE_TMP/logs"
mkdir -p "$LOG_DIR"
RUN_ID="qk-openshell-v012-$$-$RANDOM"
SANDBOX_NAME="qk$(( $$ % 1000000 ))$RANDOM"
QK_HOME="$SMOKE_TMP/queryknight-home"
QK_PID=""
DAEMON_PID=""
TARGET_PID=""
GATEWAY_PID=""
QK_BIN=""
CLI_BIN=""
GATEWAY_PORT=""
DAEMON_PORT=""
CONTROL_CURL_CONFIG=""
SANDBOX_CREATED=0
STATUS=0
WORKLOAD_IMAGE_ID=""

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$SANDBOX_CREATED" -eq 1 && -n "$CLI_BIN" && -n "$GATEWAY_PORT" ]]; then
    "$CLI_BIN" --gateway-endpoint "http://127.0.0.1:$GATEWAY_PORT" \
      sandbox delete "$SANDBOX_NAME" >>"$LOG_DIR/setup.log" 2>&1 || true
  fi
  for pid in "$QK_PID" "$TARGET_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [[ -n "$DAEMON_PID" && -n "$QK_BIN" ]]; then
    "$QK_BIN" stop --home "$QK_HOME" >>"$LOG_DIR/queryknight-daemon.log" 2>&1 || {
      kill "$DAEMON_PID" 2>/dev/null || true
    }
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  [[ -n "$GATEWAY_PID" ]] && kill "$GATEWAY_PID" 2>/dev/null || true
  wait "$GATEWAY_PID" 2>/dev/null || true
  [[ -z "${CONTROL_CURL_CONFIG:-}" ]] || rm -f "$CONTROL_CURL_CONFIG"
  rm -rf "$QK_HOME"
  [[ -z "${PKI:-}" ]] || rm -rf "$PKI"
  [[ -z "${JWT:-}" ]] || rm -rf "$JWT"
  # Keep the OpenShell prebuilt images (downloaded once, reused on re-runs);
  # drop only the scratch smoke dir unless the test failed for inspection.
  if [[ "$status" -eq 0 ]]; then
    rm -rf "$SMOKE_TMP"
  else
    echo "OpenShell v0.1.2 E2E failed; logs retained at $LOG_DIR" >&2
    for file in "$LOG_DIR"/*; do
      [[ -f "$file" ]] || continue
      printf '\n--- %s ---\n' "$file" >&2
      cat "$file" >&2
    done
  fi
  exit "$status"
}
trap cleanup EXIT

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
if ! python3 -c 'import ipaddress,sys
try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
sys.exit(0 if address.version == 4 and not (address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local) else 1)' "$SERVICE_HOST"; then
  echo "OPENSHELL_QUERYKNIGHT_HOST must be a valid non-loopback IPv4 address" >&2
  exit 1
fi

phase 1 "OpenShell v0.1.2 artifacts"
case "$(uname -m)" in
  arm64 | aarch64) SUPERVISOR_PLATFORM="linux/arm64" ;;
  x86_64 | amd64) SUPERVISOR_PLATFORM="linux/amd64" ;;
  *) echo "unsupported sandbox build architecture: $(uname -m)" >&2; exit 1 ;;
esac

# OpenShell publishes the v0.1.2 supervisor and sandbox runtime images to
# GHCR. We pull by tag and record the resolved digest for the report.
SUPERVISOR_IMAGE="ghcr.io/nvidia/openshell/supervisor:${TAG#v}"
SANDBOX_RUNTIME_IMAGE="ghcr.io/nvidia/openshell/sandbox:${TAG#v}"
"$DRIVER" pull --platform "$SUPERVISOR_PLATFORM" "$SUPERVISOR_IMAGE" \
  >"$LOG_DIR/pull-supervisor.log" 2>&1
"$DRIVER" pull --platform "$SUPERVISOR_PLATFORM" "$SANDBOX_RUNTIME_IMAGE" \
  >"$LOG_DIR/pull-sandbox.log" 2>&1
SUPERVISOR_DIGEST="$("$DRIVER" inspect --format='{{index .RepoDigests 0}}' "$SUPERVISOR_IMAGE")"
SANDBOX_DIGEST="$("$DRIVER" inspect --format='{{index .RepoDigests 0}}' "$SANDBOX_RUNTIME_IMAGE")"
printf 'OpenShell v0.1.2 supervisor digest: %s\n' "$SUPERVISOR_DIGEST"
printf 'OpenShell v0.1.2 sandbox digest:   %s\n' "$SANDBOX_DIGEST"

phase 2 "Build OpenShell v0.1.2 gateway + CLI from pinned source"
# The gateway depends on z3 (workspace dep via openshell-server); we link the
# system z3 (homebrew) instead of building it from source, which saves the
# multi-GB bundled-z3 build. The gateway is a local macOS process because
# Docker Desktop's macOS-side Docker socket uses a forwarding protocol that
# bollard's "hyper legacy client" inside a Linux container cannot speak to;
# running the gateway as a local macOS process connects to the real Docker
# daemon via the host's standard unix socket.
OPENSHELL_PERSISTENT_TARGET="${OPENSHELL_PERSISTENT_TARGET:-$HOME/.cache/qk-openshell-build/openshell-target}"
mkdir -p "$OPENSHELL_PERSISTENT_TARGET"
OPEN_TARGET="$OPENSHELL_PERSISTENT_TARGET"

OPENSHELL_SRC="${OPENSHELL_V012_SOURCE:-$SMOKE_TMP/OpenShell}"
if [[ ! -d "$OPENSHELL_SRC" ]]; then
  git clone --filter=blob:none --depth=1 --branch "$TAG" \
    https://github.com/NVIDIA/OpenShell.git "$OPENSHELL_SRC"
fi
ACTUAL_COMMIT="$(git -C "$OPENSHELL_SRC" rev-parse HEAD)"
[[ "$ACTUAL_COMMIT" == "$EXPECTED_COMMIT" ]] || {
  echo "OpenShell source commit mismatch: expected $EXPECTED_COMMIT, got $ACTUAL_COMMIT" >&2
  exit 1
}
if ! command -v z3 >/dev/null 2>&1; then
  echo "z3 not found on PATH; required to build openshell-gateway without bundled-z3" >&2
  echo "install with: brew install z3" >&2
  exit 1
fi
export PKG_CONFIG_PATH="$(brew --prefix z3 2>/dev/null)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LIBRARY_PATH="$(brew --prefix z3 2>/dev/null)/lib:${LIBRARY_PATH:-}"
env CARGO_TARGET_DIR="$OPEN_TARGET" cargo build --locked --quiet \
  --manifest-path "$OPENSHELL_SRC/Cargo.toml" -p openshell-gateway --bin openshell-gateway
env CARGO_TARGET_DIR="$OPEN_TARGET" cargo build --locked --quiet \
  --manifest-path "$OPENSHELL_SRC/Cargo.toml" -p openshell-cli --bin openshell
OPEN_GATEWAY="$OPEN_TARGET/debug/openshell-gateway"
OPEN_CLI="$OPEN_TARGET/debug/openshell"
CLI_BIN="$OPEN_CLI"
OPEN_VERSION="$("$OPEN_CLI" --version 2>/dev/null || true)"
if [[ -z "$OPEN_VERSION" ]]; then
  echo "OpenShell CLI produced no version output" >&2
  exit 1
fi
printf 'OpenShell CLI version string: %s\n' "$OPEN_VERSION"

phase 3 "Build test workload image (debian + curl + ca-certificates)"
"$DRIVER" build --platform "$SUPERVISOR_PLATFORM" \
  -t "$WORKLOAD_IMAGE" \
  -f "$ROOT/tests/openshell-v0.1.2-workload/Dockerfile" \
  "$ROOT/tests/openshell-v0.1.2-workload" \
  >"$LOG_DIR/build-workload.log" 2>&1
WORKLOAD_IMAGE_ID="$("$DRIVER" inspect --format='{{.Id}}' "$WORKLOAD_IMAGE")"
printf 'Workload image: %s (%s)\n' "$WORKLOAD_IMAGE" "$WORKLOAD_IMAGE_ID"

phase 4 "Generate TLS + JWKS for the test"
QK_TARGET="$(cargo metadata --format-version=1 --no-deps --manifest-path "$ROOT/Cargo.toml" | jq -er '.target_directory')"
cargo build --locked --quiet --manifest-path "$ROOT/Cargo.toml" -p qk-cli --bin queryknight
QK_BIN="$QK_TARGET/debug/queryknight"

PORT_BASE=$((22000 + RANDOM % 20000))
QK_PORT="$PORT_BASE"
GATEWAY_PORT="$((PORT_BASE + 1))"
HEALTH_PORT="$((PORT_BASE + 2))"
TARGET_PORT="$((PORT_BASE + 3))"
DAEMON_PORT="$((PORT_BASE + 4))"
for offset in 0 1 2 3 4; do
  port=$((PORT_BASE + offset))
  if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
    echo "selected E2E port is already in use: $port" >&2
    exit 1
  fi
done

PKI="$SMOKE_TMP/pki"
JWT="$SMOKE_TMP/gateway-jwt"
mkdir -p "$JWT"
openssl genpkey -algorithm ed25519 -out "$JWT/signing.pem" >/dev/null 2>&1
openssl pkey -in "$JWT/signing.pem" -pubout -out "$JWT/public.pem" >/dev/null 2>&1
printf '%s\n' "$RUN_ID" >"$JWT/kid"
"$ROOT/examples/openshell/generate-pki.sh" \
  "$SERVICE_HOST" "$JWT/public.pem" "$JWT/kid" "$PKI"

cat >"$SMOKE_TMP/gateway.toml" <<EOF
[openshell]
version = 2

# This flag authenticates only the disposable local gateway API used by this
# test harness. Extension calls remain HTTPS + JWT authenticated below.
[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$JWT/signing.pem"
public_key_path = "$JWT/public.pem"
kid_path = "$JWT/kid"
gateway_id = "$RUN_ID"
ttl_secs = 3600

[[openshell.supervisor.middleware]]
name = "queryknight"
grpc_endpoint = "https://$SERVICE_HOST:$QK_PORT"
tls_ca_cert_path = "$PKI/demo-ca.pem"
audience = "urn:openshell:extension:middleware:queryknight"
max_payload_bytes = 1048576
timeout = "500ms"

[openshell.drivers.$DRIVER]
supervisor_image = "$SUPERVISOR_IMAGE"
sandbox_runtime_image = "$SANDBOX_RUNTIME_IMAGE"
# Sandbox inside the user image calls back to the gateway. Use the host's
# external IP, since loopback inside the container is unreachable.
grpc_endpoint = "http://$SERVICE_HOST:$GATEWAY_PORT"
EOF

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
network_middlewares:
  queryknight-sql:
    name: QueryKnight SQL safety
    middleware: queryknight
    config:
      policy_yaml: |
        version: 1
        defaults:
          decision: deny
        environments:
          production:
            databases:
              main:
                mutations:
                  deny_without_where: [delete]
                approval_required:
                  - operations: [delete]
                allow:
                  - operations: [select]
      dialect: postgres
      database: main
      environment: production
      maxSqlBytes: 200000
    on_error: fail_closed
    endpoints:
      include:
        - $SERVICE_HOST
network_policies:
  queryknight-demo:
    name: QueryKnight demo target
    endpoints:
      - host: $SERVICE_HOST
        port: $TARGET_PORT
    binaries:
      - path: /usr/bin/curl
EOF

wait_port() {
  local host="$1" port="$2" pid="$3" label="$4"
  for _ in {1..60}; do
    kill -0 "$pid" 2>/dev/null || { echo "$label exited before becoming ready" >&2; return 1; }
    nc -z "$host" "$port" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "$label did not become reachable at $host:$port" >&2
  return 1
}

phase 5 "Start QueryKnight daemon + middleware + demo target"
"$QK_BIN" start --foreground --home "$QK_HOME" --port "$DAEMON_PORT" \
  >"$LOG_DIR/queryknight-daemon.log" 2>&1 &
DAEMON_PID=$!
wait_port 127.0.0.1 "$DAEMON_PORT" "$DAEMON_PID" "QueryKnight control plane"
curl --fail --silent --show-error "http://127.0.0.1:$DAEMON_PORT/health" >/dev/null
CONTROL_CURL_CONFIG="$SMOKE_TMP/control-curl.conf"
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$QK_HOME/session.token")" \
  >"$CONTROL_CURL_CONFIG"
chmod 600 "$CONTROL_CURL_CONFIG"

python3 "$ROOT/examples/openshell/target.py" --host 0.0.0.0 --port "$TARGET_PORT" \
  >"$LOG_DIR/target.log" 2>&1 &
TARGET_PID=$!
wait_port 127.0.0.1 "$TARGET_PORT" "$TARGET_PID" "demo target"

env -u MYSQL_URL -u QUERYKNIGHT_DAEMON_URL \
  DATABASE_URL='postgresql://demo:demo@127.0.0.1/not-used' \
  "$QK_BIN" openshell serve \
    --home "$QK_HOME" \
    --listen "0.0.0.0:$QK_PORT" \
    --tls-cert "$PKI/queryknight-server.pem" \
    --tls-key "$PKI/queryknight-server-key.pem" \
    --gateway-id "$RUN_ID" \
    --audience urn:openshell:extension:middleware:queryknight \
    --jwks-file "$PKI/gateway-jwks.json" \
    --advertised-host "$SERVICE_HOST" >"$LOG_DIR/queryknight.log" 2>&1 &
QK_PID=$!
wait_port "$SERVICE_HOST" "$QK_PORT" "$QK_PID" "QueryKnight"

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

phase 6 "Sandbox startup from custom workload image"
CLI=("$OPEN_CLI" --gateway-endpoint "http://127.0.0.1:$GATEWAY_PORT")
"${CLI[@]}" gateway info >"$LOG_DIR/gateway-info.log" 2>&1
grep -qi queryknight "$LOG_DIR/gateway-info.log" || {
  echo "OpenShell gateway info did not report QueryKnight as active" >&2
  exit 1
}
SANDBOX_CREATED=1
"${CLI[@]}" sandbox create --name "$SANDBOX_NAME" \
  --from "$WORKLOAD_IMAGE" \
  --policy "$SMOKE_TMP/sandbox-policy.yaml" --no-tty --detach -- sleep infinity \
  >"$LOG_DIR/sandbox-create.log" 2>&1
SANDBOX_ID="$(grep -F "sandbox_name=$SANDBOX_NAME" "$LOG_DIR/gateway.log" | tail -1 \
  | sed -nE 's/.*sandbox_id=([0-9a-f-]+).*/\1/p')"
[[ -n "$SANDBOX_ID" ]] || { echo "could not extract sandbox id from gateway log" >&2; exit 1; }
printf 'Sandbox: name=%s id=%s workload=%s\n' "$SANDBOX_NAME" "$SANDBOX_ID" "$WORKLOAD_IMAGE"

COUNT_URL="http://127.0.0.1:$TARGET_PORT/__count"
count_requests() { curl --fail --silent --show-error "$COUNT_URL" | jq -er '.requests'; }
[[ "$(count_requests)" == 0 ]] || { echo "demo target must start with zero requests" >&2; exit 1; }

sandbox_request() {
  local body="$1"
  "${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- \
    curl --fail --silent --show-error --max-time 20 \
      "http://$SERVICE_HOST:$TARGET_PORT/query" \
      --header 'content-type: application/json' \
      --data "$body"
}

phase 7 "Auth/handshake (Describe + ValidateConfig through QueryKnight)"
# Wait briefly for the supervisor to finish its bootstrap callbacks so the
# middleware has logged the JWT-validated gateway exchanges.
for _ in {1..20}; do
  grep -q 'openshell_auth_success rpc=Describe caller_kind=gateway' "$LOG_DIR/queryknight.log" \
    && grep -q 'openshell_auth_success rpc=ValidateConfig caller_kind=gateway' "$LOG_DIR/queryknight.log" \
    && break
  sleep 1
done
grep -Fq 'openshell_auth_success rpc=Describe caller_kind=gateway' "$LOG_DIR/queryknight.log" || {
  echo "authenticated Describe was not observed" >&2; exit 1;
}
grep -Fq 'openshell_auth_success rpc=ValidateConfig caller_kind=gateway' "$LOG_DIR/queryknight.log" || {
  echo "authenticated ValidateConfig was not observed" >&2; exit 1;
}
printf 'Auth: Describe + ValidateConfig from gateway accepted\n'

phase 8 "Allow probe (SELECT 1)"
ALLOW_OUTPUT="$SMOKE_TMP/allow.out"
sandbox_request '{"sql":"SELECT 1"}' >"$ALLOW_OUTPUT" 2>"$LOG_DIR/allow.stderr" || {
  echo "allow probe failed; dumping QueryKnight middleware log" >&2
  grep -E "openshell_auth|openshell_authorization" "$LOG_DIR/queryknight.log" \
    | tail -20 >&2 || true
  echo "----- supervisor-side response detail:" >&2
  cat "$LOG_DIR/allow.stderr" >&2 || true
  exit 1
}
grep -Fq 'SELECT 1' "$ALLOW_OUTPUT" || { echo "allowed request did not return SELECT 1 (target unreachable? middleware deny?)" >&2; exit 1; }
ALLOW_COUNT="$(count_requests)"
[[ "$ALLOW_COUNT" == 1 ]] || { echo "expected target count=1 after allow, got $ALLOW_COUNT" >&2; exit 1; }
printf 'Allow: SELECT 1 forwarded, target count=%s\n' "$ALLOW_COUNT"

phase 9 "Deny probe (DELETE without WHERE)"
DENY_OUTPUT="$SMOKE_TMP/deny.out"
if sandbox_request '{"sql":"DELETE FROM accounts"}' >"$DENY_OUTPUT" 2>"$LOG_DIR/deny.stderr"; then
  echo "unbounded DELETE unexpectedly succeeded (request returned 0)" >&2
  exit 1
fi
DENY_COUNT="$(count_requests)"
[[ "$DENY_COUNT" == 1 ]] || { echo "denied request reached the target (count=$DENY_COUNT)" >&2; exit 1; }
printf 'Deny: DELETE FROM accounts blocked, target count=%s\n' "$DENY_COUNT"

phase 10 "Approval pending (DELETE WHERE id=\$1) + grant + exact retry"
PENDING_BODY='{"sql":"DELETE FROM accounts WHERE id = $1","params":[42]}'
PENDING_OUTPUT="$SMOKE_TMP/pending.out"
if sandbox_request "$PENDING_BODY" >"$PENDING_OUTPUT" 2>"$LOG_DIR/pending.stderr"; then
  echo "approval-pending DELETE unexpectedly succeeded" >&2
  exit 1
fi
PENDING_COUNT_AFTER="$(count_requests)"
[[ "$PENDING_COUNT_AFTER" == 1 ]] || { echo "pending request reached the target (count=$PENDING_COUNT_AFTER)" >&2; exit 1; }
printf 'Pending: DELETE WHERE id=$1 (params 42) blocked, target count=%s\n' "$PENDING_COUNT_AFTER"

APPROVALS="$(curl --config "$CONTROL_CURL_CONFIG" --fail --silent --show-error \
  "http://127.0.0.1:$DAEMON_PORT/approvals")"
APPROVAL_ID="$(printf '%s' "$APPROVALS" | jq -er '[.[] | select(.status == "waiting")][-1].id')"
APPROVAL_KIND="$(printf '%s' "$APPROVALS" | jq -er --arg id "$APPROVAL_ID" \
  '.[] | select(.id == $id) | .bindingKind')"
APPROVAL_DIGEST_INFO="$(printf '%s' "$APPROVALS" | jq -er --arg id "$APPROVAL_ID" \
  '.[] | select(.id == $id) | {kind: .bindingKind, status: .status, sandboxId: .sandboxId}')"
[[ "$APPROVAL_KIND" == exact_v2 ]] || {
  echo "approval was not bound as ExactV2 (got '$APPROVAL_KIND'; row=$APPROVAL_DIGEST_INFO)" >&2
  exit 1
}
printf 'Approval: id=%s kind=%s sandboxId-bound-to-supervisor-issued-token\n' \
  "$APPROVAL_ID" "$APPROVAL_KIND"

curl --config "$CONTROL_CURL_CONFIG" --fail --silent --show-error \
  --request POST --header 'content-type: application/json' \
  --data '{"status":"approved","source":"ui","scope":"once"}' \
  "http://127.0.0.1:$DAEMON_PORT/approvals/$APPROVAL_ID/decide" \
  >"$LOG_DIR/approval-decision.json"
jq -e '.status == "approved" and .scope == "once"' "$LOG_DIR/approval-decision.json" >/dev/null

RETRY_OUTPUT="$SMOKE_TMP/retry.out"
sandbox_request "$PENDING_BODY" >"$RETRY_OUTPUT" 2>"$LOG_DIR/retry.stderr"
RETRY_COUNT="$(count_requests)"
[[ "$RETRY_COUNT" == 2 ]] || { echo "approved exact retry did not reach target (count=$RETRY_COUNT)" >&2; exit 1; }
printf 'Approved retry: DELETE WHERE id=$1 (params 42) allowed, target count=%s\n' "$RETRY_COUNT"

phase 11 "Changed-request rejection (params 43 must NOT use the old approval)"
CHANGED_OUTPUT="$SMOKE_TMP/changed.out"
if sandbox_request '{"sql":"DELETE FROM accounts WHERE id = $1","params":[43]}' \
  >"$CHANGED_OUTPUT" 2>"$LOG_DIR/changed.stderr"; then
  echo "Once approval authorized a changed bound value" >&2
  exit 1
fi
CHANGED_COUNT="$(count_requests)"
[[ "$CHANGED_COUNT" == 2 ]] || { echo "changed parameter request reached the target (count=$CHANGED_COUNT)" >&2; exit 1; }
printf 'Changed: DELETE WHERE id=$1 (params 43) blocked, target count=%s\n' "$CHANGED_COUNT"

phase 12 "Audit and cleanup"
grep -Fq 'openshell_auth_success rpc=EvaluateHttpRequest caller_kind=supervisor' "$LOG_DIR/queryknight.log" || {
  echo "authenticated supervisor evaluation was not observed" >&2; exit 1;
}
ALLOW_AUDIT="$(grep -Fc 'openshell_authorization operation=http_request decision=allow' "$LOG_DIR/queryknight.log")"
DENY_AUDIT="$(grep -Fc 'openshell_authorization operation=http_request decision=deny' "$LOG_DIR/queryknight.log")"
PENDING_AUDIT="$(grep -Fc 'openshell_authorization operation=http_request decision=deny reason_code=queryknight_require_approval' "$LOG_DIR/queryknight.log")"
(( ALLOW_AUDIT >= 1 )) || { echo "no QueryKnight allow audit records" >&2; exit 1; }
(( DENY_AUDIT >= 2 )) || { echo "expected >=2 QueryKnight deny records (deny + pending), got $DENY_AUDIT" >&2; exit 1; }
(( PENDING_AUDIT >= 1 )) || { echo "no QueryKnight approval-pending audit records" >&2; exit 1; }
printf 'Audit: allow=%s deny=%s pending=%s\n' "$ALLOW_AUDIT" "$DENY_AUDIT" "$PENDING_AUDIT"

"${CLI[@]}" sandbox delete "$SANDBOX_NAME" >"$LOG_DIR/sandbox-delete.log" 2>&1
SANDBOX_CREATED=0

printf 'OpenShell v0.1.2 E2E: PASS\n'
printf '  version              %s\n' "$OPEN_VERSION"
printf '  commit               %s\n' "$ACTUAL_COMMIT"
printf '  supervisor digest    %s\n' "$SUPERVISOR_DIGEST"
printf '  sandbox digest       %s\n' "$SANDBOX_DIGEST"
printf '  workload image       %s (%s)\n' "$WORKLOAD_IMAGE" "$WORKLOAD_IMAGE_ID"
printf '  sandbox id           %s\n' "$SANDBOX_ID"
printf '  host                 %s\n' "$SERVICE_HOST"
printf '  gateway port         %s\n' "$GATEWAY_PORT"
printf '  middleware port      %s (HTTPS, audience=urn:openshell:extension:middleware:queryknight)\n' "$QK_PORT"
printf '  target port          %s\n' "$TARGET_PORT"
printf '  allow target count   %s\n' "$ALLOW_COUNT"
printf '  deny  target count   %s\n' "$DENY_COUNT"
printf '  pending target count %s\n' "$PENDING_COUNT_AFTER"
printf '  retry  target count  %s\n' "$RETRY_COUNT"
printf '  changed target count %s\n' "$CHANGED_COUNT"
printf '  WebSocket            protocol/generated-client verified, not live sandbox verified\n'
