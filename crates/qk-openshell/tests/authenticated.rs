use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use qk_audit::{MemorySink, Observer};
use qk_db::DbConfig;
use qk_openshell::proto::supervisor_middleware_client::SupervisorMiddlewareClient;
use qk_openshell::proto::{
    Decision, HttpRequestEvaluation, HttpRequestTarget, MiddlewareDescribeRequest, RequestContext,
    SupervisorMiddlewarePhase, ValidateConfigRequest,
};
use qk_openshell::{
    extension_proto, OpenShellJwtConfig, OpenShellServer, OpenShellServerConfig, OpenShellService,
    OpenShellServiceConfig,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ED25519,
};
use serde::Serialize;
use tempfile::TempDir;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tonic::{Code, Request};

const GATEWAY_ID: &str = "gateway-test";
const AUDIENCE: &str = "urn:openshell:extension:middleware:queryknight";
const KID: &str = "test-ed25519-key";
const CONTRACT: &str = "openshell.supervisor-middleware.contract";

struct TestPki {
    ca_pem: String,
    certificate_pem: String,
    private_key_pem: String,
    signing_key_pem: String,
    jwks: serde_json::Value,
}

fn test_pki(host: &str) -> TestPki {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().expect("generate test CA key");
    let ca = ca_params.self_signed(&ca_key).expect("self-sign test CA");

    let mut server_params = CertificateParams::new(vec![host.to_owned()]).expect("server SAN");
    server_params.is_ca = IsCa::NoCa;
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().expect("generate test server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("sign test server certificate");

    let signing_key =
        KeyPair::generate_for(&PKCS_ED25519).expect("generate test gateway signing key");
    let public_der = signing_key.public_key_der();
    let raw_public = public_der
        .get(public_der.len().saturating_sub(32)..)
        .expect("Ed25519 SPKI raw key");
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_public);
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": KID,
            "x": x
        }]
    });
    TestPki {
        ca_pem: ca.pem(),
        certificate_pem: server_cert.pem(),
        private_key_pem: server_key.serialize_pem(),
        signing_key_pem: signing_key.serialize_pem(),
        jwks,
    }
}

fn write_file(directory: &TempDir, name: &str, contents: &[u8]) -> PathBuf {
    let path = directory.path().join(name);
    std::fs::write(&path, contents).expect("write temporary test material");
    path
}

fn write_jwks(directory: &TempDir, name: &str, jwks: &serde_json::Value) -> PathBuf {
    write_file(
        directory,
        name,
        serde_json::to_string(jwks).unwrap().as_bytes(),
    )
}

fn jwt_config(jwks_file: &Path) -> OpenShellJwtConfig {
    OpenShellJwtConfig::new(GATEWAY_ID, AUDIENCE, jwks_file).expect("valid trust config")
}

#[derive(Serialize, Clone)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    jti: String,
    caller_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
}

fn claims(caller: &str, sandbox_id: Option<&str>) -> Claims {
    let issuer = format!("openshell-gateway:{GATEWAY_ID}");
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs(),
    )
    .expect("Unix time fits i64");
    Claims {
        iss: issuer.clone(),
        aud: AUDIENCE.to_owned(),
        sub: sandbox_id.map_or(issuer, |id| format!("spiffe://openshell/sandbox/{id}")),
        iat: now,
        exp: now + 900,
        jti: "reused-jti".to_owned(),
        caller_kind: caller.to_owned(),
        sandbox_id: sandbox_id.map(str::to_owned),
        nbf: None,
    }
}

fn signed_token(
    signing_key_pem: &str,
    claims: &Claims,
    kid: Option<&str>,
    typ: Option<&str>,
    algorithm: Algorithm,
) -> String {
    let mut header = Header::new(algorithm);
    header.kid = kid.map(str::to_owned);
    header.typ = typ.map(str::to_owned);
    encode(
        &header,
        claims,
        &EncodingKey::from_ed_pem(signing_key_pem.as_bytes()).expect("EdDSA signing key"),
    )
    .expect("sign test token")
}

fn signed_json_token(
    signing_key_pem: &str,
    payload: &serde_json::Value,
    kid: &str,
    typ: &str,
) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_owned());
    header.typ = Some(typ.to_owned());
    encode(
        &header,
        payload,
        &EncodingKey::from_ed_pem(signing_key_pem.as_bytes()).expect("EdDSA signing key"),
    )
    .expect("sign test JSON claims")
}

fn malformed_algorithm_token(algorithm: &str, typ: Option<&str>, claims: &Claims) -> String {
    let mut header = serde_json::json!({"alg": algorithm});
    if let Some(typ) = typ {
        header["typ"] = serde_json::Value::String(typ.to_owned());
    }
    header["kid"] = serde_json::Value::String(KID.to_owned());
    let encode = |value: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    };
    format!(
        "{}.{}.invalid-signature",
        encode(&header),
        encode(&serde_json::to_value(claims).unwrap())
    )
}

fn gateway_peer() -> extension_proto::PeerMetadata {
    extension_proto::PeerMetadata {
        protocol_version: Some(extension_proto::ProtocolVersion { major: 1, minor: 0 }),
        implementation_name: "openshell/gateway".to_owned(),
        implementation_version: "v0.1.2".to_owned(),
        supported_capabilities: vec![CONTRACT.to_owned()],
        required_capabilities: vec![CONTRACT.to_owned()],
    }
}

fn policy_config() -> prost_types::Struct {
    let fields = BTreeMap::from([
        ("policy_yaml".to_owned(), string_value(qk_core::DEMO_POLICY)),
        ("dialect".to_owned(), string_value("postgres")),
        ("database".to_owned(), string_value("main")),
        ("environment".to_owned(), string_value("production")),
    ]);
    prost_types::Struct { fields }
}

fn string_value(value: &str) -> prost_types::Value {
    prost_types::Value {
        kind: Some(prost_types::value::Kind::StringValue(value.to_owned())),
    }
}

fn sql_request(config: prost_types::Struct, sandbox_id: &str) -> HttpRequestEvaluation {
    HttpRequestEvaluation {
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        context: Some(RequestContext {
            request_id: "auth-test-request".to_owned(),
            sandbox_id: sandbox_id.to_owned(),
            originating_process: None,
            sandbox: "reused-or-mismatched-display-name".to_owned(),
            workspace: "display-only-workspace".to_owned(),
        }),
        config: Some(config),
        target: Some(HttpRequestTarget {
            scheme: "http".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 18080,
            method: "POST".to_owned(),
            path: "/query".to_owned(),
            query: String::new(),
        }),
        headers: Vec::new(),
        body: br#"{"sql":"SELECT 1"}"#.to_vec(),
        middleware_name: "queryknight".to_owned(),
    }
}

fn with_bearer<T>(message: T, token: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).expect("valid auth metadata"),
    );
    request
}

async fn connect_client(
    address: SocketAddr,
    ca_pem: &str,
    hostname: &str,
) -> Result<SupervisorMiddlewareClient<tonic::transport::Channel>, tonic::transport::Error> {
    let endpoint = Endpoint::from_shared(format!("https://127.0.0.1:{}", address.port()))?;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name(hostname);
    let channel = endpoint.tls_config(tls)?.connect().await?;
    Ok(SupervisorMiddlewareClient::new(channel))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_server_enforces_jwt_role_audience_and_sandbox_binding() {
    let temp = TempDir::new().expect("temporary test directory");
    let pki = test_pki("localhost");
    let cert_path = write_file(&temp, "server.pem", pki.certificate_pem.as_bytes());
    let key_path = write_file(&temp, "server-key.pem", pki.private_key_pem.as_bytes());
    let jwks_path = write_jwks(&temp, "gateway-jwks.json", &pki.jwks);
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let sink = std::sync::Arc::new(MemorySink::new());
    let observer = Observer::new(vec![sink.clone()]);
    let service = OpenShellService::new(
        OpenShellServiceConfig::new(db)
            .with_expected_audience(AUDIENCE)
            .with_observer(observer),
    );
    let server = OpenShellServer::bind(
        OpenShellServerConfig::authenticated(
            "127.0.0.1:0".parse().unwrap(),
            cert_path,
            key_path,
            jwt_config(&jwks_path),
        )
        .with_advertised_host("localhost"),
        service,
    )
    .await
    .expect("authenticated TLS server starts");
    let address = server.local_addr().expect("bound TCP address");

    let mut client = connect_client(address, &pki.ca_pem, "localhost")
        .await
        .expect("trusted CA and hostname connect");
    let missing_describe = client
        .describe(Request::new(MiddlewareDescribeRequest {
            gateway: Some(gateway_peer()),
        }))
        .await
        .expect_err("Describe requires an extension token");
    assert_eq!(missing_describe.code(), Code::Unauthenticated);
    let gateway = signed_token(
        &pki.signing_key_pem,
        &claims("gateway", None),
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let manifest = client
        .describe(with_bearer(
            MiddlewareDescribeRequest {
                gateway: Some(gateway_peer()),
            },
            &gateway,
        ))
        .await
        .expect("authenticated gateway Describe")
        .into_inner();
    assert_eq!(manifest.expected_audience, AUDIENCE);
    assert_eq!(
        manifest.extension.unwrap().protocol_version.unwrap().minor,
        0
    );

    let config = policy_config();
    let missing_validate = client
        .validate_config(Request::new(ValidateConfigRequest {
            config: Some(config.clone()),
            middleware_name: "queryknight".to_owned(),
        }))
        .await
        .expect_err("ValidateConfig requires a gateway token");
    assert_eq!(missing_validate.code(), Code::Unauthenticated);

    let supervisor = signed_token(
        &pki.signing_key_pem,
        &claims("supervisor", Some("sandbox-a")),
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let no_token = client
        .evaluate_http_request(Request::new(sql_request(config.clone(), "sandbox-a")))
        .await
        .expect_err("network evaluations require a bearer token");
    assert_eq!(no_token.code(), Code::Unauthenticated);
    let unvalidated = client
        .evaluate_http_request(with_bearer(
            sql_request(config.clone(), "sandbox-a"),
            &supervisor,
        ))
        .await
        .expect("authenticated evaluation without setup config")
        .into_inner();
    assert_eq!(unvalidated.decision, Decision::Deny as i32);
    assert_eq!(unvalidated.reason_code, "queryknight_config_not_validated");
    assert!(sink.is_empty(), "auth/config failures perform no SQL audit");

    let validated = client
        .validate_config(with_bearer(
            ValidateConfigRequest {
                config: Some(config.clone()),
                middleware_name: "queryknight".to_owned(),
            },
            &gateway,
        ))
        .await
        .expect("authenticated gateway ValidateConfig")
        .into_inner();
    assert!(validated.valid, "{}", validated.reason);
    assert!(sink.is_empty(), "control-plane calls do not audit SQL");
    let mut deadline_request = with_bearer(sql_request(config.clone(), "sandbox-a"), &supervisor);
    deadline_request.set_timeout(std::time::Duration::ZERO);
    let deadline_status = client
        .evaluate_http_request(deadline_request)
        .await
        .expect_err("expired incoming gRPC timeout cannot authorize SQL");
    assert!(matches!(
        deadline_status.code(),
        Code::DeadlineExceeded | Code::Cancelled
    ));
    assert!(sink.is_empty(), "expired request produced no SQL audit");

    let cross_sandbox = client
        .evaluate_http_request(with_bearer(
            sql_request(config.clone(), "sandbox-b"),
            &supervisor,
        ))
        .await
        .expect_err("sandbox identity mismatch must fail before authorization");
    assert_eq!(cross_sandbox.code(), Code::PermissionDenied);
    assert!(
        sink.is_empty(),
        "cross-sandbox request produced no SQL audit"
    );

    // OpenShell v0.1.2 supervisor bootstrap calls Describe with a
    // supervisor-typed token; the auth contract must allow that.
    let supervisor_describe = client
        .describe(with_bearer(
            MiddlewareDescribeRequest {
                gateway: Some(gateway_peer()),
            },
            &supervisor,
        ))
        .await
        .expect("supervisor may call Describe for middleware bootstrap")
        .into_inner();
    assert_eq!(supervisor_describe.expected_audience, AUDIENCE);
    // No SQL audit fires on a pure discovery call.
    assert!(
        sink.is_empty(),
        "supervisor Describe must not produce SQL authorization audit"
    );

    let supervisor_validate = client
        .validate_config(with_bearer(
            ValidateConfigRequest {
                config: Some(config.clone()),
                middleware_name: "queryknight".to_owned(),
            },
            &supervisor,
        ))
        .await
        .expect_err("supervisor cannot call gateway-only ValidateConfig");
    assert_eq!(supervisor_validate.code(), Code::PermissionDenied);
    let gateway_evaluate = client
        .evaluate_http_request(with_bearer(
            sql_request(config.clone(), "sandbox-a"),
            &gateway,
        ))
        .await
        .expect_err("gateway cannot call supervisor-only evaluation");
    assert_eq!(gateway_evaluate.code(), Code::PermissionDenied);
    assert_eq!(
        sink.events().len(),
        0,
        "caller-role failures do not evaluate SQL"
    );

    let mut changed = claims("supervisor", Some("sandbox-a"));
    changed.jti = "reused-jti".to_owned();
    let repeated_token = signed_token(
        &pki.signing_key_pem,
        &changed,
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    for _ in 0..2 {
        let allowed = client
            .evaluate_http_request(with_bearer(
                sql_request(config.clone(), "sandbox-a"),
                &repeated_token,
            ))
            .await
            .expect("reused extension token remains valid until expiry")
            .into_inner();
        assert_eq!(allowed.decision, Decision::Allow as i32);
    }
    assert_eq!(sink.events().len(), 2);

    let mut invalid_claims = claims("gateway", None);
    invalid_claims.iss = "openshell-gateway:other-gateway".to_owned();
    let wrong_issuer = signed_token(
        &pki.signing_key_pem,
        &invalid_claims,
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let mut invalid_claims = claims("gateway", None);
    invalid_claims.aud = "urn:openshell:extension:middleware:other-service".to_owned();
    let wrong_audience = signed_token(
        &pki.signing_key_pem,
        &invalid_claims,
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let mut sandbox_bootstrap_audience = claims("supervisor", Some("sandbox-a"));
    sandbox_bootstrap_audience.aud = format!("openshell-gateway:{GATEWAY_ID}");
    let sandbox_bootstrap_token = signed_token(
        &pki.signing_key_pem,
        &sandbox_bootstrap_audience,
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let mut gateway_session_claims = claims("gateway", None);
    gateway_session_claims.aud = format!("openshell-gateway:{GATEWAY_ID}");
    let sandbox_to_gateway_token = signed_token(
        &pki.signing_key_pem,
        &gateway_session_claims,
        Some(KID),
        Some("openshell-gateway-session+jwt"),
        Algorithm::EdDSA,
    );
    let future_iat = {
        let mut claims = claims("gateway", None);
        claims.iat += 60;
        claims.exp = claims.iat + 300;
        signed_token(
            &pki.signing_key_pem,
            &claims,
            Some(KID),
            Some("openshell-ext+jwt"),
            Algorithm::EdDSA,
        )
    };
    let future_nbf = {
        let mut claims = claims("gateway", None);
        claims.nbf = Some(claims.iat + 60);
        signed_token(
            &pki.signing_key_pem,
            &claims,
            Some(KID),
            Some("openshell-ext+jwt"),
            Algorithm::EdDSA,
        )
    };
    let excessive_lifetime = {
        let mut claims = claims("gateway", None);
        claims.exp = claims.iat + 7200;
        signed_token(
            &pki.signing_key_pem,
            &claims,
            Some(KID),
            Some("openshell-ext+jwt"),
            Algorithm::EdDSA,
        )
    };
    let expired = {
        let mut claims = claims("gateway", None);
        claims.iat -= 7200;
        claims.exp = claims.iat + 60;
        signed_token(
            &pki.signing_key_pem,
            &claims,
            Some(KID),
            Some("openshell-ext+jwt"),
            Algorithm::EdDSA,
        )
    };
    let wrong_type = signed_token(
        &pki.signing_key_pem,
        &claims("gateway", None),
        Some(KID),
        Some("JWT"),
        Algorithm::EdDSA,
    );
    let missing_type = signed_token(
        &pki.signing_key_pem,
        &claims("gateway", None),
        Some(KID),
        None,
        Algorithm::EdDSA,
    );
    let unknown_kid = signed_token(
        &pki.signing_key_pem,
        &claims("gateway", None),
        Some("unknown-key"),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let mut missing_exp = serde_json::to_value(claims("gateway", None)).unwrap();
    missing_exp.as_object_mut().unwrap().remove("exp");
    let missing_exp =
        signed_json_token(&pki.signing_key_pem, &missing_exp, KID, "openshell-ext+jwt");
    let mut missing_caller = serde_json::to_value(claims("gateway", None)).unwrap();
    missing_caller
        .as_object_mut()
        .unwrap()
        .remove("caller_kind");
    let missing_caller = signed_json_token(
        &pki.signing_key_pem,
        &missing_caller,
        KID,
        "openshell-ext+jwt",
    );
    let mut audience_array = serde_json::to_value(claims("gateway", None)).unwrap();
    audience_array["aud"] = serde_json::json!([AUDIENCE]);
    let audience_array = signed_json_token(
        &pki.signing_key_pem,
        &audience_array,
        KID,
        "openshell-ext+jwt",
    );
    let mut empty_jti = claims("gateway", None);
    empty_jti.jti.clear();
    let empty_jti = signed_token(
        &pki.signing_key_pem,
        &empty_jti,
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let missing_sandbox = signed_token(
        &pki.signing_key_pem,
        &claims("supervisor", None),
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let mut wrong_sub_claims = claims("supervisor", Some("sandbox-a"));
    wrong_sub_claims.sub = "spiffe://openshell/sandbox/sandbox-b".to_owned();
    let wrong_sub = signed_token(
        &pki.signing_key_pem,
        &wrong_sub_claims,
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let gateway_peer = Some(gateway_peer());
    let rejected = [
        wrong_issuer,
        wrong_audience,
        sandbox_bootstrap_token,
        sandbox_to_gateway_token,
        future_iat,
        future_nbf,
        excessive_lifetime,
        expired,
        wrong_type,
        missing_type,
        unknown_kid,
        missing_exp,
        missing_caller,
        audience_array,
        empty_jti,
        missing_sandbox,
        wrong_sub,
        malformed_algorithm_token("HS256", Some("openshell-ext+jwt"), &claims("gateway", None)),
        malformed_algorithm_token("RS256", Some("openshell-ext+jwt"), &claims("gateway", None)),
        malformed_algorithm_token("none", Some("openshell-ext+jwt"), &claims("gateway", None)),
        malformed_algorithm_token("EdDSA", None, &claims("gateway", None)),
    ];
    for token in rejected {
        let status = client
            .describe(with_bearer(
                MiddlewareDescribeRequest {
                    gateway: gateway_peer.clone(),
                },
                &token,
            ))
            .await
            .expect_err("invalid token must fail closed");
        assert_eq!(status.code(), Code::Unauthenticated);
    }
    let bearer_sentinel = "BEARER_SECRET_SENTINEL";
    let redacted_failure = client
        .describe(with_bearer(
            MiddlewareDescribeRequest {
                gateway: gateway_peer.clone(),
            },
            bearer_sentinel,
        ))
        .await
        .expect_err("malformed sentinel credential is rejected");
    assert_eq!(redacted_failure.code(), Code::Unauthenticated);
    assert!(!redacted_failure.message().contains(bearer_sentinel));
    assert_eq!(sink.events().len(), 2, "auth failures create no SQL audit");
    server.stop().await.expect("graceful server shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_rejects_untrusted_ca_wrong_hostname_and_invalid_key_pairs() {
    let temp = TempDir::new().expect("temporary test directory");
    let pki = test_pki("localhost");
    let cert_path = write_file(&temp, "server.pem", pki.certificate_pem.as_bytes());
    let key_path = write_file(&temp, "server-key.pem", pki.private_key_pem.as_bytes());
    let jwks_path = write_jwks(&temp, "gateway-jwks.json", &pki.jwks);
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let service =
        OpenShellService::new(OpenShellServiceConfig::new(db).with_expected_audience(AUDIENCE));
    let server = OpenShellServer::bind(
        OpenShellServerConfig::authenticated(
            "127.0.0.1:0".parse().unwrap(),
            &cert_path,
            &key_path,
            jwt_config(&jwks_path),
        ),
        service.clone(),
    )
    .await
    .expect("TLS server starts");
    let address = server.local_addr().expect("bound address");

    let other_ca = test_pki("localhost");
    assert!(connect_client(address, &other_ca.ca_pem, "localhost")
        .await
        .is_err());
    assert!(connect_client(address, &pki.ca_pem, "wrong.example")
        .await
        .is_err());
    assert!(connect_client(address, &pki.ca_pem, "localhost")
        .await
        .is_ok());
    let wrong_san = OpenShellServerConfig::authenticated(
        "0.0.0.0:0".parse().unwrap(),
        cert_path.clone(),
        key_path.clone(),
        jwt_config(&jwks_path),
    )
    .with_advertised_host("wrong.example");
    assert!(matches!(
        OpenShellServer::validate_configuration(&wrong_san, &service),
        Err(qk_openshell::OpenShellServerError::TlsSanMismatch)
    ));

    let other_key = KeyPair::generate().expect("other TLS key");
    let mismatch_key_path = write_file(
        &temp,
        "PRIVATE_KEY_SENTINEL.pem",
        other_key.serialize_pem().as_bytes(),
    );
    let mismatch = OpenShellServerConfig::authenticated(
        "0.0.0.0:0".parse().unwrap(),
        &cert_path,
        mismatch_key_path,
        jwt_config(&jwks_path),
    );
    assert!(matches!(
        OpenShellServer::validate_configuration(&mismatch, &service),
        Err(qk_openshell::OpenShellServerError::TlsConfiguration)
    ));
    assert!(!format!("{mismatch:?}").contains("PRIVATE_KEY_SENTINEL"));

    let mut expired_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("expired server SAN");
    expired_params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    expired_params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    let expired_key = KeyPair::generate().expect("expired TLS key");
    let expired_cert = expired_params
        .self_signed(&expired_key)
        .expect("expired certificate");
    let expired_cert_path = write_file(&temp, "expired.pem", expired_cert.pem().as_bytes());
    let expired_key_path = write_file(
        &temp,
        "expired-key.pem",
        expired_key.serialize_pem().as_bytes(),
    );
    let expired = OpenShellServerConfig::authenticated(
        "0.0.0.0:0".parse().unwrap(),
        expired_cert_path,
        expired_key_path,
        jwt_config(&jwks_path),
    );
    assert!(matches!(
        OpenShellServer::validate_configuration(&expired, &service),
        Err(qk_openshell::OpenShellServerError::TlsCertificateInvalid)
    ));

    let malformed_cert = write_file(&temp, "malformed.pem", b"PRIVATE_KEY_SENTINEL");
    let malformed = OpenShellServerConfig::authenticated(
        "0.0.0.0:0".parse().unwrap(),
        malformed_cert,
        &key_path,
        jwt_config(&jwks_path),
    );
    let error = OpenShellServer::validate_configuration(&malformed, &service)
        .expect_err("malformed PEM fails startup validation");
    assert!(format!("{error}").contains("certificate"));
    assert!(!format!("{error}").contains("PRIVATE_KEY_SENTINEL"));
    server.stop().await.expect("graceful server shutdown");
}

#[test]
fn authenticated_mode_allows_non_loopback_and_insecure_mode_rejects_it() {
    let temp = TempDir::new().expect("temporary test directory");
    let pki = test_pki("localhost");
    let cert_path = write_file(&temp, "server.pem", pki.certificate_pem.as_bytes());
    let key_path = write_file(&temp, "server-key.pem", pki.private_key_pem.as_bytes());
    let jwks_path = write_jwks(&temp, "gateway-jwks.json", &pki.jwks);
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let service =
        OpenShellService::new(OpenShellServiceConfig::new(db).with_expected_audience(AUDIENCE));
    let authenticated = OpenShellServerConfig::authenticated(
        "0.0.0.0:50051".parse().unwrap(),
        cert_path.clone(),
        key_path.clone(),
        jwt_config(&jwks_path),
    );
    let diagnostics = OpenShellServer::validate_configuration(&authenticated, &service)
        .expect("TLS and JWT allow configured non-loopback listener");
    assert!(diagnostics.authenticated_mode_configured);
    assert_eq!(diagnostics.trusted_jwks_keys, 1);
    let duplicate_key = pki.jwks["keys"][0].clone();
    let mut duplicate_jwks = pki.jwks.clone();
    duplicate_jwks["keys"]
        .as_array_mut()
        .unwrap()
        .push(duplicate_key.clone());
    let duplicate_jwks_path = write_jwks(&temp, "duplicate-jwks.json", &duplicate_jwks);
    let duplicate_config = OpenShellServerConfig::authenticated(
        "0.0.0.0:50051".parse().unwrap(),
        &cert_path,
        &key_path,
        jwt_config(&duplicate_jwks_path),
    );
    assert!(matches!(
        OpenShellServer::validate_configuration(&duplicate_config, &service),
        Err(qk_openshell::OpenShellServerError::Authentication(
            qk_openshell::OpenShellAuthConfigError::InvalidJwks
        ))
    ));

    let mut too_many_keys = vec![duplicate_key; 33];
    for (index, key) in too_many_keys.iter_mut().enumerate() {
        key["kid"] = serde_json::Value::String(format!("key-{index}"));
    }
    let too_many_jwks = serde_json::json!({ "keys": too_many_keys });
    let too_many_path = write_jwks(&temp, "too-many-jwks.json", &too_many_jwks);
    let too_many_config = OpenShellServerConfig::authenticated(
        "0.0.0.0:50051".parse().unwrap(),
        &cert_path,
        &key_path,
        jwt_config(&too_many_path),
    );
    assert!(matches!(
        OpenShellServer::validate_configuration(&too_many_config, &service),
        Err(qk_openshell::OpenShellServerError::Authentication(
            qk_openshell::OpenShellAuthConfigError::InvalidJwks
        ))
    ));

    for (field, value) in [
        ("kty", "RSA"),
        ("crv", "P-256"),
        ("alg", "RS256"),
        ("use", "enc"),
    ] {
        let mut invalid_jwks = pki.jwks.clone();
        invalid_jwks["keys"][0][field] = serde_json::Value::String(value.to_owned());
        let path = write_jwks(&temp, &format!("bad-{field}.json"), &invalid_jwks);
        let config = OpenShellServerConfig::authenticated(
            "0.0.0.0:50051".parse().unwrap(),
            &cert_path,
            &key_path,
            jwt_config(&path),
        );
        assert!(matches!(
            OpenShellServer::validate_configuration(&config, &service),
            Err(qk_openshell::OpenShellServerError::Authentication(
                qk_openshell::OpenShellAuthConfigError::InvalidJwks
            ))
        ));
    }
    let mut private_jwks = pki.jwks.clone();
    private_jwks["keys"][0]["d"] = serde_json::Value::String("PRIVATE_JWK_SENTINEL".to_owned());
    let private_jwks_path = write_jwks(&temp, "private-jwk.json", &private_jwks);
    let private_jwks_config = OpenShellServerConfig::authenticated(
        "0.0.0.0:50051".parse().unwrap(),
        &cert_path,
        &key_path,
        jwt_config(&private_jwks_path),
    );
    assert!(matches!(
        OpenShellServer::validate_configuration(&private_jwks_config, &service),
        Err(qk_openshell::OpenShellServerError::Authentication(
            qk_openshell::OpenShellAuthConfigError::InvalidJwks
        ))
    ));
    assert!(!format!("{private_jwks_config:?}").contains("PRIVATE_JWK_SENTINEL"));

    let insecure = OpenShellServerConfig::insecure_local("0.0.0.0:50051".parse().unwrap());
    assert!(matches!(
        OpenShellServer::validate_configuration(&insecure, &service),
        Err(qk_openshell::OpenShellServerError::NonLoopback)
    ));
}

/// v0.1.2 supervisor-middleware RPC caller matrix. Derived from the tagged
/// OpenShell v0.1.2 source (commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`).
///
/// This table is the spec of record. Any change to upstream must update both
/// the auth contract in `crates/qk-openshell/src/auth.rs` and this matrix; a
/// silent drift between the two is treated as a compatibility bug.
///
///  * `Describe`               — Gateway AND Supervisor (gateway at startup,
///                               supervisor during middleware bootstrap).
///  * `ValidateConfig`         — Gateway only (least privilege; supervisor does
///                               not call it in any observed v0.1.2 code path).
///  * `EvaluateHttpRequest`    — Supervisor only.
///  * `EvaluateWebSocketSession` — Supervisor only (WebSocket-bound).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v0_1_2_caller_matrix_is_table_driven_and_strict() {
    let temp = TempDir::new().expect("temporary test directory");
    let pki = test_pki("localhost");
    let cert_path = write_file(&temp, "server.pem", pki.certificate_pem.as_bytes());
    let key_path = write_file(&temp, "server-key.pem", pki.private_key_pem.as_bytes());
    let jwks_path = write_jwks(&temp, "gateway-jwks.json", &pki.jwks);
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let sink = std::sync::Arc::new(MemorySink::new());
    let observer = Observer::new(vec![sink.clone()]);
    let service = OpenShellService::new(
        OpenShellServiceConfig::new(db)
            .with_expected_audience(AUDIENCE)
            .with_observer(observer),
    );
    let server = OpenShellServer::bind(
        OpenShellServerConfig::authenticated(
            "127.0.0.1:0".parse().unwrap(),
            cert_path,
            key_path,
            jwt_config(&jwks_path),
        )
        .with_advertised_host("localhost"),
        service,
    )
    .await
    .expect("authenticated TLS server starts");
    let address = server.local_addr().expect("bound TCP address");
    let mut client = connect_client(address, &pki.ca_pem, "localhost")
        .await
        .expect("trusted CA and hostname connect");

    let sandbox_id = "sandbox-matrix";
    let config = policy_config();
    let gateway = signed_token(
        &pki.signing_key_pem,
        &claims("gateway", None),
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );
    let supervisor = signed_token(
        &pki.signing_key_pem,
        &claims("supervisor", Some(sandbox_id)),
        Some(KID),
        Some("openshell-ext+jwt"),
        Algorithm::EdDSA,
    );

    // Happy path: Gateway -> Describe.
    let manifest = client
        .describe(with_bearer(
            MiddlewareDescribeRequest {
                gateway: Some(gateway_peer()),
            },
            &gateway,
        ))
        .await
        .expect("Gateway Describe")
        .into_inner();
    assert_eq!(manifest.expected_audience, AUDIENCE);

    // Happy path: Supervisor -> Describe (was the v0.1.2 bootstrap bug).
    let supervisor_manifest = client
        .describe(with_bearer(
            MiddlewareDescribeRequest {
                gateway: Some(gateway_peer()),
            },
            &supervisor,
        ))
        .await
        .expect("Supervisor Describe for middleware bootstrap")
        .into_inner();
    assert_eq!(supervisor_manifest.expected_audience, AUDIENCE);

    // Gateway -> ValidateConfig.
    let validated = client
        .validate_config(with_bearer(
            ValidateConfigRequest {
                config: Some(config.clone()),
                middleware_name: "queryknight".to_owned(),
            },
            &gateway,
        ))
        .await
        .expect("Gateway ValidateConfig")
        .into_inner();
    assert!(validated.valid);

    // Supervisor -> ValidateConfig: still rejected (least privilege).
    let supervisor_validate = client
        .validate_config(with_bearer(
            ValidateConfigRequest {
                config: Some(config.clone()),
                middleware_name: "queryknight".to_owned(),
            },
            &supervisor,
        ))
        .await
        .expect_err("Supervisor must not call ValidateConfig");
    assert_eq!(supervisor_validate.code(), Code::PermissionDenied);

    // Discovery RPCs (Describe by both callers, ValidateConfig) are not SQL
    // authorization operations, so no audit fires from them yet.
    assert!(
        sink.is_empty(),
        "discovery RPCs must not produce SQL authorization audit"
    );

    // Supervisor -> EvaluateHttpRequest (after ValidateConfig).
    client
        .validate_config(with_bearer(
            ValidateConfigRequest {
                config: Some(config.clone()),
                middleware_name: "queryknight".to_owned(),
            },
            &gateway,
        ))
        .await
        .expect("ValidateConfig for supervisor evaluation");
    let supervisor_eval = client
        .evaluate_http_request(with_bearer(
            sql_request(config.clone(), sandbox_id),
            &supervisor,
        ))
        .await
        .expect("Supervisor EvaluateHttpRequest after ValidateConfig")
        .into_inner();
    assert_eq!(supervisor_eval.decision, Decision::Allow as i32);
    let audit_after_eval = sink.events().len();

    // Gateway -> EvaluateHttpRequest: still rejected (least privilege), and
    // the rejected call adds no further audit.
    let gateway_eval = client
        .evaluate_http_request(with_bearer(
            sql_request(config.clone(), sandbox_id),
            &gateway,
        ))
        .await
        .expect_err("Gateway must not call EvaluateHttpRequest");
    assert_eq!(gateway_eval.code(), Code::PermissionDenied);
    assert_eq!(
        sink.events().len(),
        audit_after_eval,
        "rejected gateway evaluation must add no SQL audit"
    );

    server.stop().await.expect("graceful server shutdown");
}
