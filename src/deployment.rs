use crate::{
    auth, enrollment, infra,
    model::now,
    security,
    state::{ApiError, ApiResult, App},
    storage,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use russh::{
    ChannelMsg, client,
    keys::{PrivateKeyWithHashAlg, ssh_key},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

struct HostCheck {
    expected: Option<String>,
    observed: Arc<Mutex<Option<String>>>,
}
impl client::Handler for HostCheck {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        let value = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        *self.observed.lock().unwrap() = Some(value.clone());
        Ok(self
            .expected
            .as_ref()
            .is_none_or(|expected| expected == &value))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeInput {
    pub host: String,
    #[serde(default = "port22")]
    pub port: u16,
}
fn port22() -> u16 {
    22
}
async fn connect(
    host: &str,
    port: u16,
    expected: Option<String>,
    observed: Arc<Mutex<Option<String>>>,
) -> ApiResult<client::Handle<HostCheck>> {
    let address: IpAddr = host
        .parse()
        .map_err(|_| ApiError::bad("SSH 主机必须填写 IP 地址"))?;
    if port == 0 {
        return Err(ApiError::bad("SSH 端口无效"));
    }
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(1800)),
        ..Default::default()
    });
    tokio::time::timeout(
        Duration::from_secs(15),
        client::connect(config, (address, port), HostCheck { expected, observed }),
    )
    .await
    .map_err(|_| ApiError::bad("SSH 连接超时"))?
    .map_err(|_| ApiError::bad("SSH 握手失败或服务器指纹发生变化"))
}
pub async fn probe(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<ProbeInput>,
) -> ApiResult<Json<Value>> {
    auth::require(&app, &headers, true).await?;
    let host = infra::ip(&input.host)?;
    let observed = Arc::new(Mutex::new(None));
    let session = connect(&host, input.port, None, observed.clone()).await?;
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "host-key probe", "en")
        .await;
    let fingerprint = observed
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| ApiError::bad("服务器没有返回 SSH 指纹"))?;
    let old: Option<String> =
        sqlx::query_scalar("SELECT fingerprint FROM ssh_hosts WHERE host=? AND port=?")
            .bind(&host)
            .bind(input.port)
            .fetch_optional(app.pool()?)
            .await?;
    Ok(Json(
        json!({"host":host,"port":input.port,"fingerprint":fingerprint,"previous_fingerprint":old,"changed":old.as_ref().is_some_and(|s|s!=&fingerprint),"trusted":old.as_ref()==Some(&fingerprint)}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshInput {
    #[serde(default = "port22")]
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub key_passphrase: String,
    pub fingerprint: String,
    #[serde(default)]
    pub trust_host_key: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInput {
    pub name: String,
    pub ip_address: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub note: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub ssh: Option<SshInput>,
}
fn yes() -> bool {
    true
}
pub async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<NodeInput>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let domain = infra::active(&app)
        .await?
        .ok_or_else(|| ApiError::bad("请先配置统一域名"))?;
    let address = infra::ip(&input.ip_address)?;
    if address == domain.controller_ip {
        return Err(ApiError::bad(
            "该 IP 已由主控本机提供 DoH，请添加其他服务器",
        ));
    }
    let name = security::text(&input.name, 100, "服务器名称")?;
    let note = security::note(&input.note)?;
    if input.region.len() > 80 {
        return Err(ApiError::bad("地区描述过长"));
    }
    if let Some(ssh) = &input.ssh {
        check_ssh(&app, &address, ssh).await?;
    }
    let _guard = app.0.mutation.lock().await;
    if sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM nodes WHERE ip_address=? AND deleted_at IS NULL",
    )
    .bind(&address)
    .fetch_one(app.pool()?)
    .await?
        > 0
    {
        return Err(ApiError::bad("该 IP 已有节点，请在原节点重新部署"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let endpoint = format!("https://{}", domain.hostname);
    let mut tx = app.pool()?.begin().await?;
    sqlx::query("INSERT INTO nodes(id,name,endpoint,region,note,secret_hash,enabled,created_at,ip_address,deploy_state) VALUES(?,?,?,?,?,?,?,?,?,'pending')").bind(&id).bind(&name).bind(&endpoint).bind(&input.region).bind(note).bind(security::digest(&security::secret())).bind(input.enabled).bind(now()).bind(&address).execute(&mut *tx).await?;
    storage::audit(&mut tx, &who.username, "添加直连 DNS 节点", &name).await?;
    tx.commit().await?;
    storage::reload(&app).await?;
    let mut result = json!({"id":id,"endpoint":endpoint});
    if input.enabled {
        let grant = enrollment::issue(&app, &id).await?;
        if let Some(ssh) = input.ssh {
            let job = start_job(app.clone(), id.clone(), address, ssh, grant).await?;
            result["job_id"] = json!(job);
        } else {
            result
                .as_object_mut()
                .unwrap()
                .extend(grant.as_object().unwrap().clone());
        }
    }
    Ok(Json(result))
}
async fn check_ssh(app: &App, host: &str, input: &SshInput) -> ApiResult<()> {
    if input.port == 0
        || input.username.is_empty()
        || input.username.len() > 64
        || !input
            .username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(ApiError::bad("SSH 用户名或端口无效"));
    }
    if (input.password.is_empty() == input.private_key.is_empty())
        || input.password.len() > 4096
        || input.private_key.len() > 65536
        || input.key_passphrase.len() > 4096
    {
        return Err(ApiError::bad("请选择一种 SSH 认证方式：密码或私钥"));
    }
    if !input.fingerprint.starts_with("SHA256:") || input.fingerprint.len() > 100 {
        return Err(ApiError::bad("请先检测并确认 SSH 主机指纹"));
    }
    let old: Option<String> =
        sqlx::query_scalar("SELECT fingerprint FROM ssh_hosts WHERE host=? AND port=?")
            .bind(host)
            .bind(input.port)
            .fetch_optional(app.pool()?)
            .await?;
    if old.as_ref() != Some(&input.fingerprint) && !input.trust_host_key {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "SSH 指纹首次出现或已改变。请核实服务器重装情况，明确确认新指纹后重试",
        ));
    }
    Ok(())
}
pub async fn deploy(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<SshInput>,
) -> ApiResult<Json<Value>> {
    auth::require(&app, &headers, true).await?;
    let address:String=sqlx::query_scalar("SELECT ip_address FROM nodes WHERE id=? AND deleted_at IS NULL AND enabled=1 AND ip_address IS NOT NULL").bind(&id).fetch_optional(app.pool()?).await?.ok_or_else(||ApiError::bad("节点不存在或未启用"))?;
    check_ssh(&app, &address, &input).await?;
    let busy:i64=sqlx::query_scalar("SELECT COUNT(*) FROM infra_jobs WHERE target=? AND kind='ssh' AND state IN ('queued','running')").bind(&id).fetch_one(app.pool()?).await?;
    if busy > 0 {
        return Err(ApiError::bad("该节点已有部署任务"));
    }
    let grant = enrollment::issue(&app, &id).await?;
    let job = start_job(app, id, address, input, grant).await?;
    Ok(Json(json!({"job_id":job})))
}
async fn start_job(
    app: App,
    id: String,
    address: String,
    input: SshInput,
    grant: Value,
) -> ApiResult<String> {
    let job = infra::job(&app, "ssh", &id).await?;
    let job_id = job.clone();
    sqlx::query("UPDATE nodes SET deploy_state='installing' WHERE id=?")
        .bind(&id)
        .execute(app.pool()?)
        .await?;
    tokio::spawn(async move {
        infra::stage(&app, &job_id, "running", "连接服务器并校验 SSH 指纹").await;
        let result = tokio::time::timeout(
            Duration::from_secs(1800),
            install(&app, &job_id, &address, input, &grant),
        )
        .await;
        let (state, message) = match result {
            Ok(Ok(())) => (
                "done",
                "安装完成，正在验证统一域名 HTTPS 并添加公共 DNS 记录".to_string(),
            ),
            Ok(Err(error)) => ("failed", error.message),
            Err(_) => (
                "failed",
                "安装超时；SSH 凭据已从任务内存释放，请检查服务器后重新部署".into(),
            ),
        };
        infra::stage(&app, &job_id, state, &message).await;
        let _ = sqlx::query("UPDATE nodes SET deploy_state=? WHERE id=?")
            .bind(if state == "done" {
                "awaiting_dns"
            } else {
                "failed"
            })
            .bind(id)
            .execute(app.pool().unwrap())
            .await;
    });
    Ok(job)
}
async fn install(
    app: &App,
    job: &str,
    address: &str,
    input: SshInput,
    grant: &Value,
) -> ApiResult<()> {
    let observed = Arc::new(Mutex::new(None));
    let mut session = connect(
        address,
        input.port,
        Some(input.fingerprint.clone()),
        observed,
    )
    .await?;
    // Authentication is reached only after the live host key matches the approved pin.
    sqlx::query("INSERT INTO ssh_hosts(host,port,fingerprint,updated_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE fingerprint=VALUES(fingerprint),updated_at=VALUES(updated_at)").bind(address).bind(input.port).bind(&input.fingerprint).bind(now()).execute(app.pool()?).await?;
    let authenticated = if !input.private_key.is_empty() {
        let key = russh::keys::decode_secret_key(
            &input.private_key,
            if input.key_passphrase.is_empty() {
                None
            } else {
                Some(&input.key_passphrase)
            },
        )
        .map_err(|_| ApiError::bad("无法解析 SSH 私钥或私钥口令错误"))?;
        let hash = session
            .best_supported_rsa_hash()
            .await
            .map_err(|_| ApiError::bad("SSH 密钥算法协商失败"))?
            .flatten();
        session
            .authenticate_publickey(
                &input.username,
                PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
    } else {
        session
            .authenticate_password(&input.username, &input.password)
            .await
    }
    .map_err(|_| ApiError::bad("SSH 身份认证失败"))?;
    if !authenticated.success() {
        return Err(ApiError::bad("SSH 用户名、密码或密钥被服务器拒绝"));
    }
    infra::stage(
        app,
        job,
        "running",
        "SSH 验证通过，安装跨发行版 agent 与 HTTPS 配置",
    )
    .await;
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|_| ApiError::bad("无法创建 SSH 执行通道"))?;
    channel
        .exec(
            true,
            if input.username == "root" {
                "sh -s"
            } else {
                "sudo -n sh -s"
            },
        )
        .await
        .map_err(|_| ApiError::bad("远程执行失败；非 root 用户需要免密 sudo"))?;
    let command = grant["install_command"]
        .as_str()
        .ok_or_else(|| ApiError::bad("安装命令不可用"))?;
    channel
        .data(format!("{command}\n").as_bytes())
        .await
        .map_err(|_| ApiError::bad("安装命令传输失败"))?;
    channel
        .eof()
        .await
        .map_err(|_| ApiError::bad("SSH 传输结束失败"))?;
    let mut code = None;
    let mut seen = 0usize;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
            ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. } => {
                seen = seen.saturating_add(data.len());
                if seen > 8 * 1024 * 1024 {
                    return Err(ApiError::bad("远程安装输出超过限制"));
                }
                // Store only fixed installer stages. Arbitrary remote output may contain secrets.
                let text = String::from_utf8_lossy(data);
                for (marker, label) in [
                    ("DNSDOH_STAGE packages", "正在安装系统依赖"),
                    ("DNSDOH_STAGE binary", "正在下载并校验 agent"),
                    ("DNSDOH_STAGE enrollment", "正在生成节点私钥并接入主控"),
                    ("DNSDOH_STAGE tls", "正在应用统一域名证书"),
                    ("DNSDOH_STAGE ready", "节点已启动，等待 DNS 记录生效"),
                ] {
                    if text.contains(marker) {
                        infra::stage(app, job, "running", label).await;
                    }
                }
            }
            _ => {}
        }
    }
    let _ = session
        .disconnect(
            russh::Disconnect::ByApplication,
            "installation complete",
            "en",
        )
        .await;
    if code != Some(0) {
        return Err(ApiError::bad(
            "远程安装未成功。请检查 /mnt/youlin-data/dnsdoh-node/run/install.log、端口和系统兼容性后重试",
        ));
    }
    Ok(())
}
pub async fn update(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<NodeInput>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let address = infra::ip(&input.ip_address)?;
    let name = security::text(&input.name, 100, "节点名称")?;
    let _guard = app.0.mutation.lock().await;
    let old: String =
        sqlx::query_scalar("SELECT ip_address FROM nodes WHERE id=? AND deleted_at IS NULL")
            .bind(&id)
            .fetch_one(app.pool()?)
            .await?;
    if old != address {
        return Err(ApiError::bad(
            "更换 IP 请删除旧节点并重新添加，避免旧地址记录遗留；重装同 IP 可直接重新部署",
        ));
    }
    let mut tx = app.pool()?.begin().await?;
    sqlx::query("UPDATE nodes SET name=?,region=?,note=?,enabled=? WHERE id=?")
        .bind(name)
        .bind(security::text(
            &if input.region.is_empty() {
                "未设置".into()
            } else {
                input.region
            },
            80,
            "地区",
        )?)
        .bind(security::note(&input.note)?)
        .bind(input.enabled)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    storage::audit(&mut tx, &who.username, "更新直连 DNS 节点", &id).await?;
    tx.commit().await?;
    storage::reload(&app).await?;
    Ok(Json(json!({"ok":true})))
}
pub async fn remove(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let _guard = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    sqlx::query("UPDATE nodes SET enabled=0,deleted_at=?,deploy_state='deleting' WHERE id=? AND ip_address IS NOT NULL").bind(now()).bind(&id).execute(&mut *tx).await?;
    storage::audit(&mut tx, &who.username, "移除节点并清理公共 DNS", &id).await?;
    tx.commit().await?;
    storage::reload(&app).await?;
    Ok(Json(json!({"ok":true,"pending_dns_cleanup":true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptInput {
    pub ip_address: String,
}
pub async fn adopt(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<AdoptInput>,
) -> ApiResult<Json<Value>> {
    auth::require(&app, &headers, true).await?;
    let domain = infra::active(&app)
        .await?
        .ok_or_else(|| ApiError::bad("请先配置统一域名"))?;
    let address = infra::ip(&input.ip_address)?;
    if address == domain.controller_ip {
        return Err(ApiError::bad("该 IP 已由主控提供解析"));
    }
    let _lock = app.0.mutation.lock().await;
    if sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nodes WHERE ip_address=? AND id<>?")
        .bind(&address)
        .bind(&id)
        .fetch_one(app.pool()?)
        .await?
        > 0
    {
        return Err(ApiError::bad("该 IP 已被另一节点使用"));
    }
    let changed=sqlx::query("UPDATE nodes SET ip_address=?,endpoint=?,deploy_state='pending' WHERE id=? AND ip_address IS NULL AND deleted_at IS NULL").bind(address).bind(format!("https://{}",domain.hostname)).bind(&id).execute(app.pool()?).await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::bad("旧版节点不存在或已迁移"));
    }
    Ok(Json(json!({"ok":true})))
}
