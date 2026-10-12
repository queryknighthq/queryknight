#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Verified PostgreSQL backend TLS integration.
#
# Provisions an ephemeral PKI and two PostgreSQL 17 servers (one with TLS
# enabled, one plaintext), then runs the ignored live matrices:
#
#   * crates/qk-db/tests/live_postgres_tls.rs            (direct adapter)
#   * crates/qk-proxy-postgres/tests/live_postgres_tls.rs (proxy backend)
#
# The direct matrix proves trusted-CA success, unknown-CA failure,
# hostname-mismatch failure, TLS-required-against-plaintext failure, and
# explicit-plaintext success. The proxy matrix proves an allowed SELECT
# reaches the TLS backend, a denied statement does not, and an untrusted CA
# fails closed.
#
# Nothing is committed: the PKI and containers are ephemeral and removed on
# exit.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_IMAGE="${QK_PG_TLS_IMAGE:-postgres:17}"
DRIVER="${QK_PG_TLS_DRIVER:-docker}"

for command in "$DRIVER" openssl cargo python3; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

TMP="$(mktemp -d /tmp/qk-postgres-tls.XXXXXX)"
PKI="$TMP/pki"
TLS_CONTAINER="qk-pg-tls-$$"
PLAINTEXT_CONTAINER="qk-pg-plain-$$"
STATUS=0

cleanup() {
  local status=$?
  trap - EXIT
  "$DRIVER" rm -f "$TLS_CONTAINER" "$PLAINTEXT_CONTAINER" >/dev/null 2>&1 || true
  if [[ "$status" -eq 0 ]]; then
    rm -rf "$TMP"
  else
    echo "PostgreSQL TLS integration failed; PKI retained at $PKI" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Ephemeral PKI: one CA for the server, one *untrusted* CA for the
#    unknown-CA case. Server SAN is DNS:localhost only, so connecting by IP
#    literal must fail hostname verification.
# ---------------------------------------------------------------------------
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

# A second, unrelated CA that the client does NOT trust.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$PKI/unknown-ca.key" -out "$PKI/unknown-ca.crt" \
  -subj "/CN=QueryKnight untrusted CA" \
  -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1

rm -f "$PKI/server.csr" "$PKI/server.ext"

# ---------------------------------------------------------------------------
# 2. PostgreSQL 17 with TLS enabled. The server key must be 0600 and owned by
#    the postgres user; the bind mount is writable so the entrypoint wrapper
#    can fix ownership before PostgreSQL starts.
# ---------------------------------------------------------------------------
TLS_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
PLAINTEXT_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"

"$DRIVER" run -d --name "$TLS_CONTAINER" \
  -p "127.0.0.1:$TLS_PORT:5432" \
  -v "$PKI:/certs" \
  -e POSTGRES_USER=qk -e POSTGRES_PASSWORD=qk -e POSTGRES_DB=qk \
  "$PG_IMAGE" \
  bash -c 'set -e
chown postgres:postgres /certs/server.crt /certs/server.key
chmod 600 /certs/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/certs/server.key' \
  >/dev/null

"$DRIVER" run -d --name "$PLAINTEXT_CONTAINER" \
  -p "127.0.0.1:$PLAINTEXT_PORT:5432" \
  -e POSTGRES_USER=qk -e POSTGRES_PASSWORD=qk -e POSTGRES_DB=qk \
  "$PG_IMAGE" >/dev/null

wait_ready() {
  local container="$1" label="$2"
  # Force TCP: the entrypoint's temporary init server also serves the unix
  # socket, so a socket-only probe would report readiness during init.
  for _ in $(seq 1 90); do
    if "$DRIVER" exec "$container" pg_isready -h 127.0.0.1 -p 5432 -U qk -d qk >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$label did not become ready" >&2
  "$DRIVER" logs "$container" >&2 || true
  return 1
}
wait_ready "$TLS_CONTAINER" "PostgreSQL TLS server"
wait_ready "$PLAINTEXT_CONTAINER" "PostgreSQL plaintext server"

# Confirm the TLS server really requires TLS (ssl=on) and the other does not.
"$DRIVER" exec "$TLS_CONTAINER" psql -U qk -d qk -tAc "show ssl" | grep -qx on || {
  echo "TLS PostgreSQL server did not enable ssl" >&2
  exit 1
}
"$DRIVER" exec "$PLAINTEXT_CONTAINER" psql -U qk -d qk -tAc "show ssl" | grep -qx off || {
  echo "plaintext PostgreSQL server unexpectedly enabled ssl" >&2
  exit 1
}

export QK_PG_TLS_URL="postgres://qk:qk@localhost:$TLS_PORT/qk?sslmode=require"
export QK_PG_TLS_MISMATCH_URL="postgres://qk:qk@127.0.0.1:$TLS_PORT/qk?sslmode=require"
export QK_PG_PLAINTEXT_URL="postgres://qk:qk@127.0.0.1:$PLAINTEXT_PORT/qk?sslmode=disable"
export QK_PG_TLS_ADMIN_URL="postgres://qk:qk@127.0.0.1:$TLS_PORT/qk?sslmode=disable"
export QK_PG_TLS_REQUIRED_PLAINTEXT_URL="postgres://qk:qk@127.0.0.1:$PLAINTEXT_PORT/qk?sslmode=require"
export QK_PG_TLS_CA="$PKI/ca.crt"
export QK_PG_TLS_UNKNOWN_CA="$PKI/unknown-ca.crt"

printf 'PostgreSQL TLS server: %s\n' "$QK_PG_TLS_URL"
printf 'Hostname-mismatch URL: %s\n' "$QK_PG_TLS_MISMATCH_URL"
printf 'Plaintext server:      %s\n' "$QK_PG_PLAINTEXT_URL"

# ---------------------------------------------------------------------------
# 3. Live matrices.
# ---------------------------------------------------------------------------
echo "== direct qk-db PostgreSQL TLS matrix =="
cargo test --manifest-path "$ROOT/Cargo.toml" -p qk-db --test live_postgres_tls -- --ignored --test-threads=1

echo "== qk-proxy-postgres backend TLS matrix =="
cargo test --manifest-path "$ROOT/Cargo.toml" -p qk-proxy-postgres --test live_postgres_tls -- --ignored --test-threads=1

printf '\nPostgreSQL TLS integration: PASS\n'
