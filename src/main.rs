mod agent;
mod api;
mod auth;
mod certificates;
mod deployment;
mod dns;
mod enrollment;
mod gateway;
mod infra;
mod model;
mod providers;
mod security;
mod state;
mod storage;
mod vault;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use sqlx::{Row, mysql::MySqlPoolOptions};
use state::App;
use std::{
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};
use tower_http::set_header::SetResponseHeaderLayer;

#[derive(Parser)]
#[command(name = "dnsdoh", version, about = "DNSDOH 私有 DoH 控制平面与解析节点")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, env = "DNSDOH_MODE", default_value = "controller")]
        mode: Mode,
        #[arg(long, env = "DNSDOH_BIND", default_value = "127.0.0.1:18080")]
        bind: SocketAddr,
        #[arg(
            long,
            env = "DNSDOH_PUBLIC_URL",
            default_value = "http://127.0.0.1:18080"
        )]
        public_url: String,
        #[arg(long, env = "DNSDOH_DOH_URL")]
        doh_url: Option<String>,
        #[arg(long, env = "DNSDOH_CONTROLLER_URL")]
        controller_url: Option<String>,
        #[arg(long, env = "DNSDOH_NODE_ID")]
        node_id: Option<String>,
        #[arg(long, env = "DNSDOH_CA_CERT")]
        ca_cert: Option<PathBuf>,
        #[arg(long, env = "DNSDOH_TRUST_PROXY", default_value_t = false)]
        trust_proxy: bool,
    },
    ResetAdmin {
        #[arg(long, env = "DNSDOH_ADMIN_USERNAME", default_value = "admin")]
        username: String,
    },
    Enroll {
        #[arg(long)]
        controller: String,
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "127.0.0.1:18081")]
        bind: SocketAddr,
    },
    NodeMaintain {
        #[arg(long, env = "DNSDOH_CONTROLLER_URL")]
        controller: String,
        #[arg(long, env = "DNSDOH_NODE_ID")]
        node_id: String,
        #[arg(long, env = "DNSDOH_BIND", default_value = "127.0.0.1:18081")]
        bind: SocketAddr,
        #[arg(long, env = "DNSDOH_NODE_ROOT", default_value = "/opt/dnsdoh-node")]
        root: PathBuf,
    },
    ControllerMaintain {
        #[arg(long, env = "DNSDOH_BIND", default_value = "127.0.0.1:18080")]
        bind: SocketAddr,
        #[arg(
            long,
            env = "DNSDOH_TLS_ROOT",
            default_value = "/opt/dnsdoh/runtime/direct-tls"
        )]
        root: PathBuf,
        #[arg(long, default_value = "/etc/nginx/conf.d/dnsdoh-direct.conf")]
        config: PathBuf,
    },
    Migrate,
}
#[derive(Clone, ValueEnum)]
enum Mode {
    Controller,
    Node,
}
#[derive(rust_embed::RustEmbed)]
#[folder = "web/dist/"]
struct Assets;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "dnsdoh=info".into()),
        ))
        .with_target(false)
        .init();
    match Cli::parse().command {
        Command::Enroll {
            controller,
            node_id,
            endpoint,
            output,
            bind,
        } => enrollment::enroll_cli(&controller, &node_id, &endpoint, &output, bind).await?,
        Command::NodeMaintain {
            controller,
            node_id,
            bind,
            root,
        } => agent::maintain(&controller, &node_id, bind, &root).await?,
        Command::ControllerMaintain { bind, root, config } => {
            agent::controller_maintain(database().await?, bind, &root, &config).await?
        }
        Command::Migrate => {
            let pool = database().await?;
            sqlx::migrate!().run(&pool).await?;
            println!("MariaDB schema is up to date");
        }
        Command::ResetAdmin { username } => {
            let pool = database().await?;
            sqlx::migrate!().run(&pool).await?;
            storage::admin_init(
                &pool,
                &username,
                std::env::var("DNSDOH_ADMIN_PASSWORD").ok(),
                true,
            )
            .await?;
            println!("Administrator password updated; previous sessions revoked");
        }
        Command::Serve {
            mode,
            bind,
            public_url,
            doh_url,
            controller_url,
            node_id,
            ca_cert,
            trust_proxy,
        } => {
            let public_url =
                security::endpoint(&public_url).map_err(|e| anyhow::anyhow!(e.message))?;
            let doh_url = security::endpoint(doh_url.as_deref().unwrap_or(&public_url))
                .map_err(|e| anyhow::anyhow!(e.message))?;
            let controller = matches!(mode, Mode::Controller);
            let pool = if controller {
                let pool = database().await?;
                sqlx::migrate!().run(&pool).await?;
                storage::admin_init(
                    &pool,
                    &std::env::var("DNSDOH_ADMIN_USERNAME").unwrap_or_else(|_| "admin".into()),
                    std::env::var("DNSDOH_ADMIN_PASSWORD").ok(),
                    false,
                )
                .await?;
                Some(pool)
            } else {
                None
            };
            let app = App::new(pool, public_url, doh_url, node_id.clone(), trust_proxy);
            if controller {
                storage::reload(&app)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.message))?;
                if let Some(d) = infra::active(&app)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.message))?
                {
                    *app.0.direct_doh.write().unwrap() = Some(format!("https://{}", d.hostname));
                }
                sqlx::query("UPDATE infra_jobs SET state='failed',stage='主控已重启，SSH 凭据未保存，请重新提交部署',updated_at=? WHERE kind='ssh' AND state IN ('queued','running')").bind(model::now()).execute(app.pool().unwrap()).await?;
                tokio::spawn(controller_loop(app.clone()));
                tokio::spawn(gateway::probe_loop(app.clone()));
                if !(std::env::var("DNSDOH_TEST_MODE").as_deref() == Ok("true")
                    && std::env::var("DNSDOH_TEST_DISABLE_INFRA").as_deref() == Ok("true"))
                {
                    tokio::spawn(infra::infrastructure_loop(app.clone()));
                }
            } else {
                let url = security::endpoint(
                    &controller_url
                        .ok_or_else(|| anyhow::anyhow!("DNSDOH_CONTROLLER_URL is required"))?,
                )
                .map_err(|e| anyhow::anyhow!(e.message))?;
                let id = node_id.ok_or_else(|| anyhow::anyhow!("DNSDOH_NODE_ID is required"))?;
                uuid::Uuid::parse_str(&id)?;
                let key = std::env::var("DNSDOH_NODE_PRIVATE_KEY")
                    .ok()
                    .map(|value| {
                        enrollment::decode_key(&value)
                            .map(|bytes| ed25519_dalek::SigningKey::from_bytes(&bytes))
                    })
                    .transpose()?;
                let secret = std::env::var("DNSDOH_NODE_SECRET").unwrap_or_default();
                if key.is_none() && secret.len() != 43 {
                    anyhow::bail!("Invalid node secret format");
                }
                let mut client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .redirect(reqwest::redirect::Policy::none());
                if let Ok(pin) = std::env::var("DNSDOH_CONTROLLER_IP") {
                    if let Ok(address) = pin.parse::<std::net::IpAddr>() {
                        let parsed = url::Url::parse(&url)?;
                        if let Some(host) = parsed.host_str() {
                            client = client.resolve(
                                host,
                                SocketAddr::new(
                                    address,
                                    parsed.port_or_known_default().unwrap_or(443),
                                ),
                            );
                        }
                    }
                }
                if let Some(path) = ca_cert {
                    client = client.add_root_certificate(reqwest::Certificate::from_pem(
                        &std::fs::read(path)?,
                    )?);
                }
                tokio::spawn(node_loop(
                    app.clone(),
                    client.build()?,
                    url,
                    id,
                    secret,
                    key,
                ));
            }
            let listener = tokio::net::TcpListener::bind(bind).await?;
            tracing::info!(%bind,mode=if controller{"controller"}else{"node"},"DNSDOH listening");
            axum::serve(
                listener,
                router(app, controller).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown())
            .await?;
        }
    }
    Ok(())
}
async fn database() -> anyhow::Result<sqlx::MySqlPool> {
    let url = std::env::var("DATABASE_URL").map_err(|_| {
        anyhow::anyhow!("DATABASE_URL is required (MariaDB mysql:// connection string)")
    })?;
    if !url.starts_with("mysql://") {
        anyhow::bail!("DNSDOH requires MariaDB using a mysql:// URL");
    }
    Ok(MySqlPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await?)
}
fn router(app: App, controller: bool) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/readyz", get(ready))
        .route("/dns-query/{token}", get(dns::get).post(dns::post))
        .route("/dns-query/compat/{token}", get(dns::get).post(dns::post));
    if controller {
        router = router
            .route("/install/node.py", get(enrollment::script))
            .route("/internal/node/enroll", post(enrollment::redeem))
            .route("/api/nodes/{id}/install", post(enrollment::issue_api))
            .route(
                "/gateway/dns-query/{token}",
                get(gateway::get).post(gateway::post),
            )
            .route("/api/infrastructure", get(infra::get))
            .route("/api/infrastructure/ip", get(infra::discover_ip))
            .route("/api/providers", post(infra::save_provider))
            .route("/api/providers/{id}", put(infra::update_provider))
            .route("/api/providers/{id}/zones", get(infra::zones))
            .route("/api/domains", post(infra::save_domain))
            .route("/api/domains/{id}/repair", post(infra::repair))
            .route("/api/ssh/probe", post(deployment::probe))
            .route("/api/managed-nodes", post(deployment::create))
            .route(
                "/api/managed-nodes/{id}",
                put(deployment::update).delete(deployment::remove),
            )
            .route("/api/managed-nodes/{id}/deploy", post(deployment::deploy))
            .route("/api/managed-nodes/{id}/adopt", post(deployment::adopt))
            .route("/internal/node/control", post(agent::control))
            .route("/api/login", post(auth::login))
            .route("/api/session", get(auth::session))
            .route("/api/logout", post(auth::logout))
            .route("/api/password", post(auth::password))
            .route("/api/state", get(api::state))
            .route("/api/users", post(api::user_create))
            .route(
                "/api/users/{id}",
                put(api::user_update).delete(api::user_delete),
            )
            .route("/api/zones", post(api::zone_create))
            .route(
                "/api/zones/{id}",
                put(api::zone_update).delete(api::zone_delete),
            )
            .route("/api/records", post(api::record_create))
            .route(
                "/api/records/{id}",
                put(api::record_update).delete(api::record_delete),
            )
            .route("/api/tokens", post(api::token_create))
            .route("/api/tokens/{id}/revoke", post(api::token_revoke))
            .route("/api/nodes", post(api::node_create))
            .route(
                "/api/nodes/{id}",
                put(api::node_update).delete(api::node_delete),
            )
            .route("/api/nodes/{id}/rotate", post(api::node_rotate))
            .route("/api/settings", put(api::settings))
            .route("/internal/node/sync", post(api::sync))
            .fallback(asset);
    }
    if controller {
        router = router.layer(axum::middleware::from_fn_with_state(
            app.clone(),
            infra::setup_guard,
        ));
    }
    router.layer(DefaultBodyLimit::max(65535))
  .layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL,HeaderValue::from_static("no-store")))
  .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS,HeaderValue::from_static("nosniff")))
  .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY,HeaderValue::from_static("no-referrer")))
  .layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")))
  .with_state(app)
}
async fn ready(State(app): State<App>) -> Response {
    match app.view(){Some(s)=>Json(json!({"status":"ready","revision":s.revision,"node_id":app.0.node_id,"mode":if app.0.node_id.is_some(){"node"}else{"controller"}})).into_response(),None=>(StatusCode::SERVICE_UNAVAILABLE,Json(json!({"status":"not_ready"}))).into_response()}
}
async fn asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") || path.starts_with("internal/") || path.starts_with("dns-query") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let file = if path.is_empty() { "index.html" } else { path };
    let Some(content) = Assets::get(file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mime = mime_guess::from_path(file)
        .first_or_octet_stream()
        .to_string();
    ([(header::CONTENT_TYPE, mime)], content.data.into_owned()).into_response()
}
async fn controller_loop(app: App) {
    let mut interval = tokio::time::interval(Duration::from_secs(model::SYNC_SECONDS));
    let mut pending = None;
    let mut last_cleanup = 0;
    loop {
        interval.tick().await;
        {
            let _guard = app.0.mutation.lock().await;
            if storage::reload(&app).await.is_err() {
                tracing::warn!("Configuration refresh failed; local queries fail closed");
            }
        }
        if pending.is_none() {
            pending = app.drain();
        }
        if let Some(report) = &pending {
            if storage::save_report(app.pool().unwrap(), "controller", report)
                .await
                .is_ok()
            {
                pending = None;
            }
        }
        for table in ["node_nonces", "node_enrollments"] {
            let _ = sqlx::query(&format!("DELETE FROM {table} WHERE expires_at<?"))
                .bind(model::now())
                .execute(app.pool().unwrap())
                .await;
        }
        if model::now() - last_cleanup >= 3600 {
            if let Ok(row) = sqlx::query("SELECT retention_days FROM settings WHERE id=1")
                .fetch_one(app.pool().unwrap())
                .await
            {
                let before = model::now() - row.get::<i32, _>("retention_days") as i64 * 86400;
                for sql in [
                    "DELETE FROM metrics WHERE bucket<?",
                    "DELETE FROM audit_events WHERE created_at<?",
                    "DELETE FROM metric_reports WHERE created_at<?",
                ] {
                    let _ = sqlx::query(sql)
                        .bind(before)
                        .execute(app.pool().unwrap())
                        .await;
                }
                let _ = sqlx::query("DELETE FROM sessions WHERE expires_at<?")
                    .bind(model::now())
                    .execute(app.pool().unwrap())
                    .await;
                last_cleanup = model::now();
            }
        }
    }
}
async fn node_loop(
    app: App,
    client: reqwest::Client,
    controller: String,
    id: String,
    secret: String,
    key: Option<ed25519_dalek::SigningKey>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(model::SYNC_SECONDS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending = None;
    let mut was_ready = false;
    loop {
        interval.tick().await;
        if pending.is_none() {
            pending = app.drain();
        }
        let started = Instant::now();
        let request = model::SyncRequest {
            node_id: id.clone(),
            applied_revision: app.view().map(|s| s.revision).unwrap_or(0),
            version: env!("CARGO_PKG_VERSION").into(),
            report: pending.clone(),
        };
        let body = serde_json::to_vec(&request).expect("sync serialization");
        let mut outgoing = client
            .post(format!("{controller}/internal/node/sync"))
            .header("content-type", "application/json");
        if let Some(key) = &key {
            let (time, nonce, signature) = enrollment::sign_request(key, &id, &body);
            outgoing = outgoing
                .header("x-dnsdoh-time", time)
                .header("x-dnsdoh-nonce", nonce)
                .header("x-dnsdoh-signature", signature);
        } else {
            outgoing = outgoing.bearer_auth(&secret);
        }
        match outgoing.body(body).send().await {
            Ok(response) if response.status().is_success() => {
                if let Ok(snapshot) = response.json::<model::SyncResponse>().await {
                    if (1..=30).contains(&snapshot.lease_seconds) {
                        app.install(
                            snapshot.snapshot,
                            Some(started + Duration::from_secs(snapshot.lease_seconds)),
                        );
                        pending = None;
                        if !was_ready {
                            tracing::info!("Node configuration synchronized");
                        }
                        was_ready = true;
                    }
                }
            }
            Ok(response) if response.status() == StatusCode::FORBIDDEN => {
                app.clear();
                if was_ready {
                    tracing::warn!("Node authorization revoked; queries stopped");
                }
                was_ready = false;
            }
            Ok(response) if response.status() == StatusCode::BAD_REQUEST && pending.is_some() => {
                // Stale metrics after a long outage must not prevent config recovery.
                pending = None;
                tracing::warn!("Metrics batch rejected; retrying configuration without that batch");
            }
            _ => {
                if was_ready {
                    tracing::warn!("Controller unreachable; existing lease will expire");
                }
                was_ready = false;
            }
        }
    }
}
async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
