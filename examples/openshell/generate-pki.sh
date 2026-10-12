#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <shared-host-ip-or-dns> <gateway-public.pem> <gateway-kid-file> <output-dir>" >&2
  exit 2
}

[[ $# -eq 4 ]] || usage
HOST="$1"
GATEWAY_PUBLIC_KEY="$2"
GATEWAY_KID_FILE="$3"
OUT_DIR="$4"

for command in openssl jq dd; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 1
  }
done
[[ -r "$GATEWAY_PUBLIC_KEY" && -r "$GATEWAY_KID_FILE" ]] || {
  echo "gateway public key and kid files must be readable" >&2
  exit 1
}
[[ -n "$HOST" && "$HOST" != *[[:space:]]* ]] || {
  echo "host must be a non-empty DNS name or IP address without whitespace" >&2
  exit 1
}

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/demo-ca-key.pem" \
  -out "$OUT_DIR/demo-ca.pem" \
  -days 2 \
  -subj "/CN=QueryKnight ephemeral demo CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
chmod 600 "$OUT_DIR/demo-ca-key.pem"

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/queryknight-server-key.pem" \
  -out "$OUT_DIR/queryknight-server.csr" \
  -subj "/CN=$HOST"
chmod 600 "$OUT_DIR/queryknight-server-key.pem"
if [[ "$HOST" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  SAN="IP:$HOST"
else
  SAN="DNS:$HOST"
fi
cat >"$OUT_DIR/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF
openssl x509 -req \
  -in "$OUT_DIR/queryknight-server.csr" \
  -CA "$OUT_DIR/demo-ca.pem" \
  -CAkey "$OUT_DIR/demo-ca-key.pem" \
  -CAcreateserial \
  -out "$OUT_DIR/queryknight-server.pem" \
  -days 2 \
  -extfile "$OUT_DIR/server.ext"

openssl pkey -pubin -in "$GATEWAY_PUBLIC_KEY" -outform DER -out "$OUT_DIR/gateway-public.der"
DER_BYTES="$(wc -c <"$OUT_DIR/gateway-public.der" | tr -d ' ')"
[[ "$DER_BYTES" -eq 44 ]] || {
  echo "gateway key is not an RFC 8410 Ed25519 public key" >&2
  exit 1
}
dd if="$OUT_DIR/gateway-public.der" of="$OUT_DIR/gateway-public.raw" bs=1 skip=12 count=32 2>/dev/null
X="$(openssl base64 -A -in "$OUT_DIR/gateway-public.raw" | tr '+/' '-_' | tr -d '=')"
KID="$(cat "$GATEWAY_KID_FILE")"
[[ -n "$KID" ]] || {
  echo "gateway kid file is empty" >&2
  exit 1
}
jq -n --arg kid "$KID" --arg x "$X" \
  '{keys:[{kty:"OKP",crv:"Ed25519",alg:"EdDSA",use:"sig",kid:$kid,x:$x}]}' \
  >"$OUT_DIR/gateway-jwks.json"
chmod 600 "$OUT_DIR/gateway-jwks.json"

rm -f "$OUT_DIR/queryknight-server.csr" "$OUT_DIR/server.ext" \
  "$OUT_DIR/gateway-public.der" "$OUT_DIR/gateway-public.raw"
printf 'Ephemeral demo CA, QueryKnight server certificate/key, and local gateway JWKS created in %s\n' "$OUT_DIR"
printf 'SAN: %s\n' "$SAN"
