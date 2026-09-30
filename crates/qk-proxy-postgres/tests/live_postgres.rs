use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use qk_control_plane::{ApprovalBindingKind, ApprovalDecision, ControlPlaneClient};
use qk_core::ExactDigest;
use qk_db::DbConfig;
use qk_proxy_postgres::{ProxyConfig, ProxyServer};
use qk_sql::SqlDialect;
use tokio::sync::oneshot;
use tokio_postgres::types::{Format, IsNull, ToSql, Type};
use tokio_postgres::{Client, Config as PgConfig, NoTls};

const LIVE_URL_ENV: &str = "QUERYKNIGHT_POSTGRES_TEST_URL";
const BIND_SENTINEL: &str = "PG_BIND_SECRET_8675309";
const POLICY: &str = r#"
version: 1
defaults:
  decision: deny
  on_parse_error: deny
  on_unknown: require_approval
environments:
  production:
    databases:
      main:
        allow:
          - operations: [select, insert]
        deny:
          - operations: [drop, update]
        approval_required:
          - operations: [delete]
"#;

struct TestDaemon {
    home: PathBuf,
    client: ControlPlaneClient,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), qk_daemon::runtime::RuntimeError>>,
}

impl TestDaemon {
    async fn start() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let home = std::env::temp_dir().join(format!(
            "qk-pg-extended-live-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("create daemon home");
        let runtime =
            qk_daemon::runtime::DaemonRuntime::with_home(home.clone(), Some(0)).expect("runtime");
        let (ready_tx, ready_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            qk_daemon::runtime::run_foreground(&runtime, Some(ready_tx), async move {
                let _ = shutdown_rx.await;
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .expect("daemon readiness timeout")
            .expect("daemon address");
        let client = ControlPlaneClient::discover_with_url(Some(home.clone()), None)
            .expect("isolated control-plane client");
        Self {
            home,
            client,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    fn store(&self) -> qk_store::Store {
        qk_store::Store::open(&self.home.join("queryknight.db")).expect("daemon store")
    }

    async fn stop(self) {
        if let Some(shutdown) = self.shutdown {
            let _ = shutdown.send(());
        }
        self.task
            .await
            .expect("daemon task")
            .expect("daemon stops cleanly");
        let _ = std::fs::remove_dir_all(self.home);
    }
}

struct RunningProxy {
    addr: std::net::SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), qk_proxy_postgres::ProxyError>>,
}

impl RunningProxy {
    async fn start(
        backend_url: &str,
        policy: qk_core::PolicyFile,
        control_plane: ControlPlaneClient,
    ) -> Self {
        let backend: PgConfig = backend_url.parse().expect("backend URL");
        assert_eq!(
            backend.get_ssl_mode(),
            tokio_postgres::config::SslMode::Disable,
            "live test URL must explicitly disable backend TLS"
        );
        let [tokio_postgres::config::Host::Tcp(host)] = backend.get_hosts() else {
            panic!("live test requires one TCP backend host");
        };
        let user = backend.get_user().expect("backend role");
        let database = backend.get_dbname().expect("backend database");
        let port = backend.get_ports().first().copied().unwrap_or(5432);
        let connection_key = format!("postgres://{user}@{host}:{port}/{database}");
        let config = ProxyConfig::new(
            0,
            DbConfig::from_url(backend_url).expect("typed PostgreSQL backend URL"),
            connection_key,
            "production".to_owned(),
            "main".to_owned(),
            policy,
            Some(control_plane),
        )
        .expect("proxy config");
        let proxy = ProxyServer::bind(config).await.expect("proxy bind");
        let addr = proxy.local_addr().expect("proxy address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            proxy
                .run_until(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        Self {
            addr,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task
            .await
            .expect("proxy task")
            .expect("proxy stops cleanly");
    }
}

#[derive(Debug)]
struct TextInt(&'static str);

impl ToSql for TextInt {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut bytes::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        out.extend_from_slice(self.0.as_bytes());
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::INT4
    }

    tokio_postgres::types::to_sql_checked!();

    fn encode_format(&self, _ty: &Type) -> Format {
        Format::Text
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn connect(
    url: &str,
    port: u16,
) -> (
    Client,
    tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
) {
    let backend: PgConfig = url.parse().expect("backend URL");
    let mut frontend = PgConfig::new();
    frontend.user(backend.get_user().expect("backend role"));
    if let Some(password) = backend.get_password() {
        frontend.password(password);
    }
    frontend.dbname(backend.get_dbname().expect("backend database"));
    frontend.host("127.0.0.1");
    frontend.port(port);
    frontend.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let (client, connection) = frontend
        .connect(NoTls)
        .await
        .expect("tokio-postgres client connects through proxy");
    (client, tokio::spawn(connection))
}

async fn connect_admin(
    backend_url: &str,
) -> (
    Client,
    tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
) {
    let config: PgConfig = backend_url.parse().expect("backend URL");
    let (client, connection) = config
        .connect(NoTls)
        .await
        .expect("direct test database connection");
    (client, tokio::spawn(connection))
}

async fn proxy_session(store: &qk_store::Store) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(session) = store
                .list_sessions()
                .expect("list daemon sessions")
                .into_iter()
                .find(|session| session.source == "proxy")
            {
                break session.id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proxy session creation")
}

async fn another_proxy_session(store: &qk_store::Store, excluded: &str) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(session) = store
                .list_sessions()
                .expect("list daemon sessions")
                .into_iter()
                .find(|session| session.source == "proxy" && session.id != excluded)
            {
                break session.id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("second proxy session creation")
}

fn waiting_grant(
    store: &qk_store::Store,
    session_id: &str,
    sql: &str,
    exact: ExactDigest,
) -> qk_approval::StoredGrant {
    let shape = qk_core::sql_fingerprint(sql);
    store
        .list_grants(now_ms())
        .expect("list stored grants")
        .into_iter()
        .find(|grant| {
            if grant.status != qk_approval::GrantStatus::Waiting
                || grant.shape != shape
                || grant.scope.session_id.as_deref() != Some(session_id)
            {
                return false;
            }
            match (&grant.binding, exact) {
                (qk_approval::ApprovalBinding::ExactV1(actual), ExactDigest::V1(want)) => {
                    actual == &want
                }
                (qk_approval::ApprovalBinding::ExactV2(actual), ExactDigest::V2(want)) => {
                    actual == &want
                }
                _ => false,
            }
        })
        .expect("matching waiting exact grant")
}

fn exact_wire(
    sql: &str,
    representation: qk_core::ParamRepresentation,
    type_hint: u32,
    bytes: &[u8],
) -> ExactDigest {
    ExactDigest::V2(
        qk_core::exact_request_digest_v2(
            SqlDialect::PostgreSql,
            sql,
            &[qk_core::ExecutionParam::Wire {
                representation,
                type_hint: Some(type_hint),
                bytes: bytes.to_vec(),
            }],
        )
        .expect("bounded Exact V2 identity"),
    )
}

fn exact_v1(sql: &str) -> ExactDigest {
    ExactDigest::V1(qk_core::exact_request_digest(SqlDialect::PostgreSql, sql))
}

fn approve(daemon: &TestDaemon, grant: &qk_approval::StoredGrant, scope: qk_approval::Scope) {
    daemon
        .client
        .decide_approval(
            grant.id.as_str(),
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(scope),
        )
        .expect("decide exact approval");
}

async fn assert_table_value(admin: &Client, table: &str, id: i32, expected: Option<&str>) {
    let sql = format!("SELECT value FROM public.{table} WHERE id = $1");
    let row = admin
        .query_opt(&sql, &[&id])
        .await
        .expect("independent row check");
    assert_eq!(row.map(|row| row.get::<_, String>(0)).as_deref(), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_postgres17_extended_query_matrix() {
    let Ok(backend_url) = std::env::var(LIVE_URL_ENV) else {
        // Workspace tests stay isolated; the PostgreSQL 17 matrix is invoked
        // explicitly with QUERYKNIGHT_POSTGRES_TEST_URL set.
        return;
    };
    let (admin, admin_task) = connect_admin(&backend_url).await;
    let version: i32 = admin
        .query_one("SELECT current_setting('server_version_num')::int4", &[])
        .await
        .expect("read PostgreSQL server version")
        .get(0);
    assert!(
        (170_000..180_000).contains(&version),
        "requires PostgreSQL 17, got {version}"
    );

    static NEXT_TABLE: AtomicUsize = AtomicUsize::new(0);
    let table = format!(
        "qk_pg_ext_{}_{}",
        std::process::id(),
        NEXT_TABLE.fetch_add(1, Ordering::Relaxed)
    );
    admin
        .batch_execute(&format!(
            "CREATE TABLE public.{table} (id int4 PRIMARY KEY, value text); \
             INSERT INTO public.{table} (id, value) VALUES \
             (42, 'row-42'), (43, 'row-43'), (44, 'row-44'), (45, 'row-45'), \
             (46, 'row-46'), (47, 'row-47'), (90, 'row-90'), (91, 'row-91'), (92, 'row-92')"
        ))
        .await
        .expect("create isolated live test table");

    let daemon = TestDaemon::start().await;
    let policy = qk_core::parse_policy(POLICY).expect("live proxy policy");
    let proxy = RunningProxy::start(&backend_url, policy, daemon.client.clone()).await;
    let (mut client, client_task) = connect(&backend_url, proxy.addr.port()).await;
    let store = daemon.store();
    let session_id = proxy_session(&store).await;

    // Preparation is protocol setup only. The INSERT has not modified data.
    let insert_sql = format!("INSERT INTO public.{table} (id, value) VALUES ($1, $2)");
    let insert = client
        .prepare_typed(&insert_sql, &[Type::INT4, Type::TEXT])
        .await
        .expect("prepare INSERT");
    assert_table_value(&admin, &table, 48, None).await;
    assert_eq!(
        client
            .execute(&insert, &[&48i32, &"inserted"])
            .await
            .unwrap(),
        1
    );
    assert_table_value(&admin, &table, 48, Some("inserted")).await;

    // Text, NULL, and int4 parameters exercise real Parse/Bind/Execute. The
    // text parameter sentinel must not reach synthetic errors, approvals, or
    // default history even though the returned SELECT row contains it.
    let select_text = client
        .prepare_typed("SELECT $1::text", &[Type::TEXT])
        .await
        .expect("prepare text SELECT");
    let text_row = client
        .query_one(&select_text, &[&BIND_SENTINEL])
        .await
        .expect("text bind SELECT");
    assert_eq!(text_row.get::<_, String>(0), BIND_SENTINEL);
    let select_null = client
        .prepare_typed("SELECT $1::text IS NULL", &[Type::TEXT])
        .await
        .expect("prepare NULL SELECT");
    let null: Option<&str> = None;
    assert!(client
        .query_one(&select_null, &[&null])
        .await
        .expect("NULL bind SELECT")
        .get::<_, bool>(0));
    let select_int = client
        .prepare_typed("SELECT $1::int4", &[Type::INT4])
        .await
        .expect("prepare int4 SELECT");
    assert_eq!(
        client
            .query_one(&select_int, &[&42i32])
            .await
            .expect("binary int4 SELECT")
            .get::<_, i32>(0),
        42
    );

    let secret_delete_sql = format!("DELETE FROM public.{table} WHERE value = $1");
    let secret_delete = client
        .prepare_typed(&secret_delete_sql, &[Type::TEXT])
        .await
        .expect("prepare sentinel Delete");
    let secret_error = client
        .execute(&secret_delete, &[&BIND_SENTINEL])
        .await
        .unwrap_err();
    assert_eq!(secret_error.code().map(|code| code.code()), Some("42501"));
    assert!(!format!("{secret_error:?} {secret_error}").contains(BIND_SENTINEL));
    assert!(daemon
        .client
        .list_approvals()
        .expect("approval metadata")
        .iter()
        .all(|row| !row.reason.contains(BIND_SENTINEL)
            && !row.operation_summary.contains(BIND_SENTINEL)));
    let events = store
        .list_session_event_records(&session_id, 100)
        .expect("read proxy history");
    assert!(events
        .iter()
        .any(|event| event.sql.as_deref() == Some("SELECT $1::text")));
    assert!(events
        .iter()
        .all(|event| !event.sql.as_deref().unwrap_or("").contains(BIND_SENTINEL)));

    // DROP and UPDATE are blocked before backend Execute; independent reads
    // prove that no side effect happened.
    let drop_sql = format!("DROP TABLE public.{table}");
    let drop_statement = client.prepare(&drop_sql).await.expect("Parse DROP");
    let drop_error = client.execute(&drop_statement, &[]).await.unwrap_err();
    assert_eq!(drop_error.code().map(|code| code.code()), Some("42501"));
    let table_exists: bool = admin
        .query_one(
            "SELECT to_regclass($1)::text IS NOT NULL",
            &[&format!("public.{table}")],
        )
        .await
        .expect("check denied DROP side effect")
        .get(0);
    assert!(table_exists);
    let update_sql = format!("UPDATE public.{table} SET value = $1 WHERE id = $2");
    let update = client
        .prepare_typed(&update_sql, &[Type::TEXT, Type::INT4])
        .await
        .expect("prepare UPDATE");
    let update_error = client
        .execute(&update, &[&"must-not-apply", &47i32])
        .await
        .unwrap_err();
    assert_eq!(update_error.code().map(|code| code.code()), Some("42501"));
    assert_table_value(&admin, &table, 47, Some("row-47")).await;

    // Once is exact wire identity. The same binary int4 request retries;
    // a text-encoded semantic int4 and a different binary value both pend.
    let delete_sql = format!("DELETE FROM public.{table} WHERE id = $1");
    let approvals_before_prepare = daemon
        .client
        .list_approvals()
        .expect("approvals before prepared Parse")
        .len();
    let delete = client
        .prepare_typed(&delete_sql, &[Type::INT4])
        .await
        .expect("prepare DELETE");
    assert_eq!(
        daemon
            .client
            .list_approvals()
            .expect("approvals after Parse/Describe")
            .len(),
        approvals_before_prepare
    );
    let first = client.execute(&delete, &[&42i32]).await.unwrap_err();
    assert_eq!(first.code().map(|code| code.code()), Some("42501"));
    assert_table_value(&admin, &table, 42, Some("row-42")).await;
    let pending42 = waiting_grant(
        &store,
        &session_id,
        &delete_sql,
        exact_wire(
            &delete_sql,
            qk_core::ParamRepresentation::Binary,
            23,
            &42i32.to_be_bytes(),
        ),
    );
    assert!(matches!(
        pending42.binding,
        qk_approval::ApprovalBinding::ExactV2(_)
    ));
    approve(&daemon, &pending42, qk_approval::Scope::Once);
    assert_eq!(client.execute(&delete, &[&42i32]).await.unwrap(), 1);
    assert_table_value(&admin, &table, 42, None).await;

    let text_format_error = client
        .execute(&delete, &[&TextInt("42")])
        .await
        .unwrap_err();
    assert_eq!(
        text_format_error.code().map(|code| code.code()),
        Some("42501")
    );
    assert!(!format!("{text_format_error:?} {text_format_error}").contains(BIND_SENTINEL));
    let pending_text42 = waiting_grant(
        &store,
        &session_id,
        &delete_sql,
        exact_wire(&delete_sql, qk_core::ParamRepresentation::Text, 23, b"42"),
    );
    assert_ne!(pending_text42.id, pending42.id);

    let changed_error = client.execute(&delete, &[&43i32]).await.unwrap_err();
    assert_eq!(changed_error.code().map(|code| code.code()), Some("42501"));
    assert_table_value(&admin, &table, 43, Some("row-43")).await;
    let pending43 = waiting_grant(
        &store,
        &session_id,
        &delete_sql,
        exact_wire(
            &delete_sql,
            qk_core::ParamRepresentation::Binary,
            23,
            &43i32.to_be_bytes(),
        ),
    );
    approve(&daemon, &pending43, qk_approval::Scope::Session);
    assert_eq!(client.execute(&delete, &[&44i32]).await.unwrap(), 1);
    assert_table_value(&admin, &table, 44, None).await;

    let other_shape_sql = format!("DELETE FROM public.{table} WHERE id = $1 AND value = $2");
    let other_shape = client
        .prepare_typed(&other_shape_sql, &[Type::INT4, Type::TEXT])
        .await
        .expect("prepare different delete shape");
    let other_shape_error = client
        .execute(&other_shape, &[&46i32, &"row-46"])
        .await
        .unwrap_err();
    assert_eq!(
        other_shape_error.code().map(|code| code.code()),
        Some("42501")
    );
    assert_table_value(&admin, &table, 46, Some("row-46")).await;

    // A second frontend cannot reuse the first session's Session grant. A
    // matching legacy row in that second session remains historical only.
    let (other_client, other_task) = connect(&backend_url, proxy.addr.port()).await;
    let other_session = another_proxy_session(&store, &session_id).await;
    let other_delete = other_client
        .prepare_typed(&delete_sql, &[Type::INT4])
        .await
        .expect("prepare DELETE in second session");
    let other_error = other_client
        .execute(&other_delete, &[&45i32])
        .await
        .unwrap_err();
    assert_eq!(other_error.code().map(|code| code.code()), Some("42501"));
    assert_table_value(&admin, &table, 45, Some("row-45")).await;
    let other_pending = waiting_grant(
        &store,
        &other_session,
        &delete_sql,
        exact_wire(
            &delete_sql,
            qk_core::ParamRepresentation::Binary,
            23,
            &45i32.to_be_bytes(),
        ),
    );
    assert_ne!(other_session, session_id);
    let now = now_ms();
    store
        .insert_grant(
            &qk_approval::StoredGrant {
                id: qk_approval::ApprovalId::new(format!("qka_legacy_live_{}", std::process::id())),
                shape: qk_core::sql_fingerprint(&delete_sql),
                binding: qk_approval::ApprovalBinding::LegacyShape,
                scope: other_pending.scope.clone(),
                status: qk_approval::GrantStatus::Approved,
                reuse: qk_approval::Scope::Session,
                expires_at_ms: now + 60_000,
                reason_code: qk_core::ReasonCode::RequireApproval,
                message: "legacy live fixture".to_owned(),
                schema_ddl: None,
                schema_diff: None,
                risk: "high".to_owned(),
                operation_summary: "delete live table".to_owned(),
                matched_policy: None,
                decided_at_ms: Some(now),
                decided_by: Some(qk_approval::DecisionSource::Ui),
            },
            now,
        )
        .expect("insert matching quarantined legacy grant");
    let legacy_retry = other_client
        .execute(&other_delete, &[&45i32])
        .await
        .unwrap_err();
    assert_eq!(legacy_retry.code().map(|code| code.code()), Some("42501"));
    assert_table_value(&admin, &table, 45, Some("row-45")).await;
    assert!(daemon
        .client
        .list_approvals()
        .expect("approval summaries")
        .iter()
        .any(|row| row.binding_kind == ApprovalBindingKind::LegacyShape));

    // A Parse error is backend-native. A Bind conversion error happens after
    // QueryKnight setup forwarding but before Execute; the session resyncs.
    let parse_error = client
        .prepare(&format!("SELECT * FROM public.qk_missing_{table}"))
        .await
        .unwrap_err();
    assert_eq!(parse_error.code().map(|code| code.code()), Some("42P01"));
    let int_statement = client
        .prepare_typed("SELECT $1::int4", &[Type::INT4])
        .await
        .expect("prepare Bind-error statement");
    let bind_error = client
        .query_one(&int_statement, &[&TextInt("not-an-int")])
        .await
        .unwrap_err();
    assert_eq!(bind_error.code().map(|code| code.code()), Some("22P02"));
    assert!(!format!("{bind_error:?} {bind_error}").contains("not-an-int"));
    let divide = client
        .prepare_typed("SELECT 1 / $1::int4", &[Type::INT4])
        .await
        .expect("prepare Execute-error query");
    let execute_error = client.query_one(&divide, &[&0i32]).await.unwrap_err();
    assert_eq!(execute_error.code().map(|code| code.code()), Some("22012"));
    assert_eq!(
        client
            .query_one("SELECT 1", &[])
            .await
            .expect("connection recovers after backend errors")
            .get::<_, i32>(0),
        1
    );

    // QueryKnight blocks a prepared mutation within a real transaction. The
    // backend remains in T, a permitted read works, and approved COMMIT works.
    let begin_error = client
        .transaction()
        .await
        .err()
        .expect("transaction must require approval");
    assert_eq!(begin_error.code().map(|code| code.code()), Some("42501"));
    let begin_sql = "START TRANSACTION";
    let begin = waiting_grant(&store, &session_id, begin_sql, exact_v1(begin_sql));
    approve(&daemon, &begin, qk_approval::Scope::Once);
    let tx = client.transaction().await.expect("BEGIN after approval");
    let approvals_before_bind = daemon
        .client
        .list_approvals()
        .expect("approval count before Bind")
        .len();
    let bound_only = tx
        .bind(&other_shape, &[&46i32, &"row-46"])
        .await
        .expect("Bind does not request execution authority");
    assert_table_value(&admin, &table, 46, Some("row-46")).await;
    assert_eq!(
        daemon
            .client
            .list_approvals()
            .expect("approval count after Bind")
            .len(),
        approvals_before_bind
    );
    drop(bound_only);
    let transaction_update = tx
        .prepare_typed(&update_sql, &[Type::TEXT, Type::INT4])
        .await
        .expect("prepare transaction UPDATE");
    let blocked_update = tx
        .execute(&transaction_update, &[&"transaction-change", &47i32])
        .await
        .unwrap_err();
    assert_eq!(blocked_update.code().map(|code| code.code()), Some("42501"));
    let transaction_select = tx
        .prepare_typed(
            &format!("SELECT value FROM public.{table} WHERE id = $1"),
            &[Type::INT4],
        )
        .await
        .expect("prepare transaction SELECT");
    assert_eq!(
        tx.query_one(&transaction_select, &[&47i32])
            .await
            .expect("read inside still-valid transaction")
            .get::<_, String>(0),
        "row-47"
    );
    let commit_error = tx.commit().await.unwrap_err();
    assert_eq!(commit_error.code().map(|code| code.code()), Some("42501"));
    let commit = waiting_grant(&store, &session_id, "COMMIT", exact_v1("COMMIT"));
    approve(&daemon, &commit, qk_approval::Scope::Once);
    client
        .batch_execute("COMMIT")
        .await
        .expect("commit approved transaction");
    assert_table_value(&admin, &table, 47, Some("row-47")).await;

    // Once + PortalSuspended on DELETE RETURNING: each Execute is authorized
    // again against the same exact request while PostgreSQL resumes one live
    // portal; no SQL or mutation is replayed from a cached permit.
    let tx = client
        .transaction()
        .await
        .expect("second BEGIN via existing exact grant");
    let returning_sql = format!("DELETE FROM public.{table} WHERE id > $1 RETURNING id");
    let returning = tx
        .prepare_typed(&returning_sql, &[Type::INT4])
        .await
        .expect("prepare DELETE RETURNING");
    let portal = tx
        .bind(&returning, &[&89i32])
        .await
        .expect("Bind mutation portal");
    let pending_returning = tx.query_portal(&portal, 1).await.unwrap_err();
    assert_eq!(
        pending_returning.code().map(|code| code.code()),
        Some("42501")
    );
    let returning_grant = waiting_grant(
        &store,
        &session_id,
        &returning_sql,
        exact_wire(
            &returning_sql,
            qk_core::ParamRepresentation::Binary,
            23,
            &89i32.to_be_bytes(),
        ),
    );
    approve(&daemon, &returning_grant, qk_approval::Scope::Once);
    let first_page = tx
        .query_portal(&portal, 1)
        .await
        .expect("first portal page");
    assert_eq!(first_page.len(), 1);
    assert_eq!(first_page[0].get::<_, i32>(0), 90);
    let second_page = tx
        .query_portal(&portal, 1)
        .await
        .expect("second portal page");
    assert_eq!(second_page.len(), 1);
    assert_eq!(second_page[0].get::<_, i32>(0), 91);
    let final_page = tx
        .query_portal(&portal, 1)
        .await
        .expect("final portal page");
    assert_eq!(final_page.len(), 1);
    assert_eq!(final_page[0].get::<_, i32>(0), 92);
    tx.commit().await.expect("commit resumed mutation portal");
    for id in [90, 91, 92] {
        assert_table_value(&admin, &table, id, None).await;
    }

    // Simple Query remains whole-request gated in the same running session.
    let mixed = format!("SELECT 1; DROP TABLE public.{table}");
    let mixed_error = client.batch_execute(&mixed).await.unwrap_err();
    assert_eq!(mixed_error.code().map(|code| code.code()), Some("42501"));
    let table_exists: bool = admin
        .query_one(
            "SELECT to_regclass($1)::text IS NOT NULL",
            &[&format!("public.{table}")],
        )
        .await
        .expect("check Simple Query side effect")
        .get(0);
    assert!(table_exists);

    drop(portal);
    drop(returning);
    drop(transaction_select);
    drop(transaction_update);
    drop(secret_delete);
    drop(divide);
    drop(int_statement);
    drop(other_shape);
    drop(delete);
    drop(update);
    drop(drop_statement);
    drop(select_int);
    drop(select_null);
    drop(select_text);
    drop(insert);
    client
        .check_connection()
        .await
        .expect("drain prepared-statement Close messages");
    drop(other_delete);
    other_client
        .check_connection()
        .await
        .expect("drain second-session Close messages");
    drop(other_client);
    tokio::time::timeout(Duration::from_secs(2), other_task)
        .await
        .expect("frontend B is joined")
        .expect("frontend B task")
        .expect("frontend B closes cleanly");
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), client_task)
        .await
        .expect("frontend connection is joined")
        .expect("frontend task")
        .expect("frontend closes cleanly");
    proxy.stop().await;
    admin
        .batch_execute(&format!("DROP TABLE IF EXISTS public.{table}"))
        .await
        .expect("drop isolated live test table");
    drop(admin);
    tokio::time::timeout(Duration::from_secs(2), admin_task)
        .await
        .expect("admin connection is joined")
        .expect("admin task")
        .expect("admin closes cleanly");
    drop(store);
    daemon.stop().await;
}
