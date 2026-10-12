# QueryKnight + OpenShell v0.1.2

This example registers QueryKnight as an **authenticated external OpenShell v0.1.2 supervisor middleware**. The gateway and sandbox supervisor reach QueryKnight over HTTPS; every RPC carries an OpenShell extension JWT. QueryKnight then extracts recognized SQL candidates and returns a deterministic authorization decision. It never executes SQL.

The required upstream tag is `v0.1.2` at commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`. The proto descriptor and protocol version are documented in [`docs/openshell-compatibility.md`](../../docs/openshell-compatibility.md). Do not infer compatibility with moving `main` from this example.

## Security model

- Use `OpenShellAuthenticated`: HTTPS, server certificate/key, a local operator-provisioned Ed25519 JWKS, exact gateway issuer, and exact middleware audience.
- The gateway registration name is `queryknight`. The distinct token audience is `urn:openshell:extension:middleware:queryknight`.
- Provision the same `gateway_id` and audience independently to OpenShell and QueryKnight. QueryKnight returns its configured audience from `Describe`; it does not discover its audience from a token or gateway response.
- `Describe` and `ValidateConfig` require the gateway caller token. HTTP and WebSocket evaluation require a supervisor token. For evaluation, the signed `sandbox_id` must exactly equal `RequestContext.sandbox_id`; the display-only sandbox name and workspace are not authorization identity.
- Gateway extension JWTs are EdDSA, `typ=openshell-ext+jwt`, audience-specific, and short-lived. A repeated `jti` remains valid until token expiry. QueryKnight loads a bounded local JWKS; unknown `kid` fails closed. Update the trusted JWKS and restart QueryKnight when the gateway signing key rotates.
- `OpenShellInsecureLocal` is **DEVELOPMENT / TRUSTED TRANSPORT ONLY**. It is explicit, plaintext, unauthenticated, and loopback-only. Never use it for the gateway/supervisor network path. Unix socket mode is for local tests/integration; it is not the normal authenticated v0.1.2 middleware registration path.
- Configure the sandbox attachment with `on_error: fail_closed`. An explicit QueryKnight `DENY` blocks traffic; OpenShell's operator-owned behavior for service failure/timeout follows `on_error`. QueryKnight cannot override a fail-open operator choice.

## 1. Generate ephemeral demo credentials

Choose one non-loopback host IP reachable from both the OpenShell gateway and sandbox supervisor. Do not use `localhost`: a sandbox supervisor does not share the host's loopback namespace. The IP in the gateway endpoint must be in the server certificate IP SAN.

The demo creates short-lived, local-only files in a temporary directory. It does not commit certificates or private keys. Use a gateway signing key provisioned by the OpenShell operator; QueryKnight needs only its public JWKS.

```sh
openssl genpkey -algorithm ed25519 -out /tmp/openshell-jwt-signing.pem
openssl pkey -in /tmp/openshell-jwt-signing.pem -pubout -out /tmp/openshell-jwt-public.pem
printf '%s\n' queryknight-demo-key-1 > /tmp/openshell-jwt-kid

./examples/openshell/generate-pki.sh \
  192.0.2.10 \
  /tmp/openshell-jwt-public.pem \
  /tmp/openshell-jwt-kid \
  /tmp/queryknight-openshell-pki
```

Replace `192.0.2.10` with the actual shared host IP. The script generates a temporary private CA and QueryKnight server certificate/key with that IP in the SAN, and writes a public-only JWKS file. The same CA certificate goes into the OpenShell registration. No verification-disable flag is used.

In a real deployment, provision the gateway public JWKS from the OpenShell operator over a trusted channel (or retrieve the v0.1.2 gateway JWKS endpoint over correctly verified HTTPS). Do not bootstrap trust from an unverified token or URL. QueryKnight does not fetch or refresh remote JWKS itself.

OpenShell's `tls_ca_cert_path` must point to `demo-ca.pem`; the certificate endpoint host must match the IP/DNS SAN created above. Verify an IP identity without disabling checks:

```sh
openssl s_client -connect 192.0.2.10:50051 \
  -CAfile /tmp/queryknight-openshell-pki/demo-ca.pem \
  -verify_ip 192.0.2.10 -verify_return_error </dev/null
```

## 2. Configure QueryKnight

Provide a database URL only to select the SQL dialect and derive a password-redacted approval identity. QueryKnight does **not** connect to this database from OpenShell middleware. Example placeholder values:

```sh
export DATABASE_URL='postgresql://demo:demo@127.0.0.1/not-used'
export QUERYKNIGHT_HOME=/var/lib/queryknight

# The example policy includes DELETE approvals. Start the local daemon in a
# separate terminal before doctor/serve so the approval provider is reachable.
cargo run -p qk-cli --bin queryknight -- start \
  --foreground --home "$QUERYKNIGHT_HOME" --port 47821
```

In another terminal, check configuration:

```sh
cargo run -p qk-cli --bin queryknight -- openshell doctor \
  --home "$QUERYKNIGHT_HOME" \
  --listen 0.0.0.0:50051 \
  --tls-cert /tmp/queryknight-openshell-pki/queryknight-server.pem \
  --tls-key /tmp/queryknight-openshell-pki/queryknight-server-key.pem \
  --gateway-id queryknight-demo \
  --audience urn:openshell:extension:middleware:queryknight \
  --jwks-file /tmp/queryknight-openshell-pki/gateway-jwks.json \
  --advertised-host 192.0.2.10 \
  --policy-file examples/openshell/queryknight-policy.yaml
```

Doctor validates local TLS certificate/key pairing and current validity, checks the SAN when `--advertised-host` is supplied, loads the bounded trusted JWKS, validates the optional local QueryKnight policy, and checks the approval control plane if that policy requires approvals. It does not connect to a database or claim that an OpenShell request has been authenticated.

Start the service with the same listener, trust, and daemon home:

```sh
cargo run -p qk-cli --bin queryknight -- openshell serve \
  --home "$QUERYKNIGHT_HOME" \
  --listen 0.0.0.0:50051 \
  --tls-cert /tmp/queryknight-openshell-pki/queryknight-server.pem \
  --tls-key /tmp/queryknight-openshell-pki/queryknight-server-key.pem \
  --gateway-id queryknight-demo \
  --audience urn:openshell:extension:middleware:queryknight \
  --jwks-file /tmp/queryknight-openshell-pki/gateway-jwks.json \
  --advertised-host 192.0.2.10
```


The server certificate/key are loaded and validated at startup. Restart QueryKnight to load a rotated server certificate or updated JWKS.

## 3. Register QueryKnight in OpenShell v0.1.2

Use the exact v0.1.2 fields in [`gateway.toml.example`](gateway.toml.example). Set the same `gateway_id` and audience as QueryKnight, and set `tls_ca_cert_path` to the generated CA certificate. Keep hostname/IP verification enabled. The `audience` is not the registration name, even when both contain `queryknight`.

```toml
[openshell.gateway.gateway_jwt]
signing_key_path = "/etc/openshell/jwt/signing.pem"
public_key_path = "/etc/openshell/jwt/public.pem"
kid_path = "/etc/openshell/jwt/kid"
gateway_id = "queryknight-demo"
ttl_secs = 900

[[openshell.supervisor.middleware]]
name = "queryknight"
grpc_endpoint = "https://192.0.2.10:50051"
tls_ca_cert_path = "/etc/queryknight/tls/demo-ca.pem"
audience = "urn:openshell:extension:middleware:queryknight"
max_payload_bytes = 1048576
timeout = "500ms"
```

OpenShell v0.1.2 uses a 500 ms default service timeout; allowed configured values are 10 ms–30 s. QueryKnight advertises a 400 ms binding timeout by default, leaving an internal safety margin for bounded approval calls. Increase the operator timeout only when justified by the measured path; do not assume an incoming `grpc-timeout` when OpenShell v0.1.2 does not send one on the external middleware call.

## 4. Attach a fail-closed sandbox policy

[`sandbox-policy.yaml`](sandbox-policy.yaml) includes a v0.1.2 `network_middlewares` attachment and a narrow `network_policies` selector for the demo target. Replace the example host IP in both places with the same target host used by the gateway and supervisor network.

The policy allows `SELECT`, denies mutations without `WHERE`, and requires a daemon-backed ExactV2 approval for bounded `DELETE`. The network policy independently permits only `curl` `POST /query` to the demo HTTP service. The provider's managed `Authorization` header is injected after this middleware boundary, so QueryKnight does not require or reconstruct it.

Create a sandbox using the real OpenShell CLI:

```sh
openshell sandbox create --name qk-demo --policy examples/openshell/sandbox-policy.yaml --no-tty --detach -- sleep infinity
```

OpenShell runs authenticated `Describe` during gateway startup and authenticated `ValidateConfig` when it accepts the sandbox policy. Check the v0.1.2 gateway diagnostic surface with `openshell gateway info` and confirm the negotiated middleware is active.

## 5. Run the allow/deny demo

Target service receives the HTTP request; QueryKnight does not execute SQL:

```sh
python3 examples/openshell/target.py --host 0.0.0.0 --port 18080
```

From the OpenShell sandbox, an allowed candidate proceeds to the target:

```sh
openshell sandbox exec --name qk-demo --no-tty -- \
  curl --fail --silent --show-error http://192.0.2.10:18080/query \
  --header 'content-type: application/json' \
  --data '{"sql":"SELECT 1"}'
```

A denied candidate must not reach the target:

```sh
openshell sandbox exec --name qk-demo --no-tty -- \
  curl --fail --silent --show-error http://192.0.2.10:18080/query \
  --header 'content-type: application/json' \
  --data '{"sql":"DELETE FROM accounts"}'
```

The target's `/__count` endpoint is for the host-side test harness only; it is not allowed by the sandbox network policy:

```sh
curl --fail --silent --show-error http://127.0.0.1:18080/__count
```

Expected: the allow increments the target count; the deny leaves it unchanged. `DENY` means QueryKnight rejected the observed candidate at this boundary; it does not mean QueryKnight executed or rolled back SQL.

For the approval policy in this example, send a bounded delete with ordered JSON parameters:

```sh
openshell sandbox exec --name qk-demo --no-tty -- \
  curl --fail --silent --show-error http://192.0.2.10:18080/query \
  --header 'content-type: application/json' \
  --data '{"sql":"DELETE FROM accounts WHERE id = $1","params":[42]}'
```

QueryKnight records Pending and returns middleware DENY. An operator can approve the exact request with Once scope through the local QueryKnight approval surface; retrying the identical SQL/parameter pair may then Allow. Changing `42` to `43` creates a different ExactV2 request and must remain Pending/DENY. The pinned E2E script automates this approval path against the local daemon API without a human click.

For the deterministic real integration flow, use [`scripts/test-openshell-v0.1.2.sh`](../../scripts/test-openshell-v0.1.2.sh). It archives and builds the exact pinned tag for the gateway, CLI, and supervisor image; starts the authenticated HTTPS service and demo target; creates a real sandbox; and proves Allow, Deny, approval Once retry, and changed-parameter rejection.

## Operational boundaries

- OpenShell middleware is authorization-only. A downstream `ALLOW` does not prove execution. QueryKnight does not execute SQL through a database driver at this boundary.
- `PendingApproval` maps to a middleware `DENY`; the shared audit records Pending distinctly. ExactV2 and Session approval scope remain enforced by the QueryKnight daemon. The middleware proto has no pending execution state.
- Authentication failures are gRPC `UNAUTHENTICATED`; a valid token with an impossible caller role is `PERMISSION_DENIED`; sandbox identity mismatch is rejected before policy/config/SQL work. They are not converted to QueryKnight SQL denial codes.
- Authentication diagnostics contain only bounded RPC/caller/failure-class labels. Bearer tokens, JWT signatures, JWKS contents, and TLS private keys are never logged or passed to the approval provider, audit, OCSF, metrics, database layer, or UI.
- Auth success/failure uses safe structured-style stderr diagnostics; no Prometheus label schema or metric name is added.
- WebSocket authentication is per gRPC stream: OpenShell v0.1.2 sends one supervisor token for that stream. QueryKnight binds the token sandbox to the preflight context, preserves strict increasing sequence order (gaps allowed), inspects text only, and rejects binary messages. The live harness covers HTTP; WebSocket remains generated-client tested, not live-verified by this example.
- Unix socket mode remains useful for local QueryKnight testing, but OpenShell v0.1.2 external supervisor middleware registrations must be reachable from gateway and sandbox supervisors; use HTTPS for that deployment.
- This milestone does not add PostgreSQL/MySQL frontend TLS or backend TLS. Native database traffic should later use the architecture: sandbox policy allows the QueryKnight DB proxy endpoint and denies direct DB destinations; the application `DATABASE_URL` targets QueryKnight; the database receives only SQL permitted by QueryKnight policy and approvals.
- OpenShell controls which network/service destinations an agent can reach. QueryKnight controls SQL/database actions after database access is intentionally granted. OpenShell does not provide generic native PostgreSQL/MySQL SQL inspection.
