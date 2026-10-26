use crate::{
    auth,
    model::now,
    providers::{Credentials, Provider, Record, Zone},
    security,
    state::{ApiError, ApiResult, App},
    vault,
};
use axum::{
    Json,
    extract::Request,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[derive(Clone)]
pub struct Domain {
    pub id: String,
    pub provider_id: String,
    pub zone: Zone,
    pub hostname: String,
    pub controller_ip: String,
    pub state: String,
    pub revision: i64,
    pub certificate: Option<String>,
    pub cert_expires: Option<i64>,
    pub cert_attempt_at: i64,
    pub controller_applied: i64,
}
pub fn domain_row(r: sqlx::mysql::MySqlRow) -> Domain {
    Domain {
        id: r.get("id"),
        provider_id: r.get("provider_id"),
        zone: Zone {
            id: r.get("zone_id"),
            name: r.get("zone_name"),
            status: "active".into(),
            account_id: String::new(),
        },
        hostname: r.get("hostname"),
        controller_ip: r.get("controller_ip"),
        state: r.get("state"),
        revision: r.get("revision"),
        certificate: r.get("certificate"),
        cert_expires: r.get("cert_expires"),
        cert_attempt_at: r.get("cert_attempt_at"),
        controller_applied: r.get("controller_applied"),
    }
}
pub async fn provider(app: &App, id: &str) -> ApiResult<Provider> {
    let row = sqlx::query("SELECT kind,credential FROM dns_providers WHERE id=?")
        .bind(id)
        .fetch_optional(app.pool()?)
        .await?
        .ok_or_else(|| ApiError::bad("供应商配置不存在"))?;
    let secret = vault::open(
        &format!("provider:{id}"),
        &row.get::<String, _>("credential"),
    )?;
    Provider::new(
        &row.get::<String, _>("kind"),
        serde_json::from_slice(&secret).map_err(|_| ApiError::bad("供应商凭据格式错误"))?,
    )
}
pub async fn domains(app: &App) -> ApiResult<Vec<Domain>> {
    Ok(sqlx::query("SELECT * FROM dns_domains ORDER BY revision")
        .fetch_all(app.pool()?)
        .await?
        .into_iter()
        .map(domain_row)
        .collect())
}
pub async fn active(app: &App) -> ApiResult<Option<Domain>> {
    Ok(
        sqlx::query(
            "SELECT * FROM dns_domains WHERE state='active' ORDER BY revision DESC LIMIT 1",
        )
        .fetch_optional(app.pool()?)
        .await?
        .map(domain_row),
    )
}
pub fn ip(value: &str) -> ApiResult<String> {
    let ip: IpAddr = value
        .parse()
        .map_err(|_| ApiError::bad("请输入服务器 IP 地址"))?;
    if ip.is_unspecified()
        || ip.is_multicast()
        || (ip.is_loopback() && std::env::var("DNSDOH_TEST_MODE").as_deref() != Ok("true"))
    {
        return Err(ApiError::bad("服务器 IP 不能是环回、组播或未指定地址"));
    }
    Ok(ip.to_string())
}
pub async fn job(app: &App, kind: &str, target: &str) -> ApiResult<String> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO infra_jobs(id,kind,target,state,stage,created_at,updated_at) VALUES(?,?,?,'queued','等待处理',?,?)").bind(&id).bind(kind).bind(target).bind(now()).bind(now()).execute(app.pool()?).await?;
    Ok(id)
}
pub async fn stage(app: &App, id: &str, state: &str, message: &str) {
    if let Ok(pool) = app.pool() {
        let _ = sqlx::query("UPDATE infra_jobs SET state=?,stage=?,updated_at=? WHERE id=?")
            .bind(state)
            .bind(message)
            .bind(now())
            .bind(id)
            .execute(pool)
            .await;
    }
}
pub async fn status(app: &App) -> ApiResult<Value> {
    let providers:Vec<Value>=sqlx::query("SELECT id,kind,name,created_at FROM dns_providers ORDER BY created_at").fetch_all(app.pool()?).await?.into_iter().map(|r|json!({"id":r.get::<String,_>("id"),"kind":r.get::<String,_>("kind"),"name":r.get::<String,_>("name")})).collect();
    let domains:Vec<Value>=sqlx::query("SELECT id,provider_id,zone_name,hostname,controller_ip,routing,state,last_error,cert_expires,checked_at,retire_at,revision FROM dns_domains ORDER BY revision DESC").fetch_all(app.pool()?).await?.into_iter().map(|r|json!({"id":r.get::<String,_>("id"),"provider_id":r.get::<String,_>("provider_id"),"zone_name":r.get::<String,_>("zone_name"),"hostname":r.get::<String,_>("hostname"),"controller_ip":r.get::<String,_>("controller_ip"),"routing":r.get::<String,_>("routing"),"state":r.get::<String,_>("state"),"last_error":r.get::<String,_>("last_error"),"cert_expires":r.get::<Option<i64>,_>("cert_expires"),"checked_at":r.get::<Option<i64>,_>("checked_at"),"retire_at":r.get::<Option<i64>,_>("retire_at"),"revision":r.get::<i64,_>("revision")})).collect();
    let jobs:Vec<Value>=sqlx::query("SELECT * FROM infra_jobs ORDER BY created_at DESC,id LIMIT 30").fetch_all(app.pool()?).await?.into_iter().map(|r|json!({"id":r.get::<String,_>("id"),"kind":r.get::<String,_>("kind"),"target":r.get::<String,_>("target"),"state":r.get::<String,_>("state"),"stage":r.get::<String,_>("stage"),"updated_at":r.get::<i64,_>("updated_at")})).collect();
    let required = !domains.iter().any(|d| d["state"] == "active")
        && (std::env::var("DNSDOH_TEST_MODE").as_deref() != Ok("true")
            || std::env::var("DNSDOH_REQUIRE_SETUP").as_deref() == Ok("true"));
    Ok(
        json!({"required":required,"providers":providers,"domains":domains,"jobs":jobs,"routing":"公共 DNS 多地址直连；不经过主控转发；普通多记录不保证最低延迟"}),
    )
}
pub async fn get(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::require(&app, &headers, false).await?;
    Ok(Json(status(&app).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInput {
    pub kind: String,
    pub name: String,
    pub credentials: Credentials,
}
pub async fn save_provider(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<ProviderInput>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let name = security::text(&input.name, 100, "供应商名称")?;
    let client = Provider::new(&input.kind, input.credentials.clone())?;
    let zones = client.zones().await?;
    if zones.is_empty() {
        return Err(ApiError::bad(
            "该 API 凭据下没有可访问域名，请检查域名列表读取权限",
        ));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let encrypted = vault::seal(
        &format!("provider:{id}"),
        &serde_json::to_vec(&input.credentials).unwrap(),
    )?;
    sqlx::query("INSERT INTO dns_providers(id,kind,name,credential,created_at) VALUES(?,?,?,?,?)")
        .bind(&id)
        .bind(input.kind)
        .bind(name)
        .bind(encrypted)
        .bind(now())
        .execute(app.pool()?)
        .await?;
    audit(&app, &who.username, "添加 DNS 供应商", &id).await?;
    Ok(Json(json!({"id":id,"zones":zones})))
}
pub async fn update_provider(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<ProviderInput>,
) -> ApiResult<Json<Value>> {
    auth::require(&app, &headers, true).await?;
    let client = Provider::new(&input.kind, input.credentials.clone())?;
    let zones = client.zones().await?;
    let old: String = sqlx::query_scalar("SELECT kind FROM dns_providers WHERE id=?")
        .bind(&id)
        .fetch_one(app.pool()?)
        .await?;
    if old != input.kind {
        return Err(ApiError::bad(
            "更换供应商请添加新配置，原配置用于清理旧记录",
        ));
    }
    let encrypted = vault::seal(
        &format!("provider:{id}"),
        &serde_json::to_vec(&input.credentials).unwrap(),
    )?;
    sqlx::query("UPDATE dns_providers SET name=?,credential=? WHERE id=?")
        .bind(security::text(&input.name, 100, "供应商名称")?)
        .bind(encrypted)
        .bind(&id)
        .execute(app.pool()?)
        .await?;
    Ok(Json(json!({"id":id,"zones":zones})))
}
pub async fn zones(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    auth::require(&app, &headers, false).await?;
    Ok(Json(
        json!({"zones":provider(&app,&id).await?.zones().await?}),
    ))
}
pub async fn discover_ip(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::require(&app, &headers, false).await?;
    if let Ok(value) = std::env::var("DNSDOH_ADVERTISE_IP") {
        return Ok(Json(json!({"ip":ip(&value)?})));
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|_| ApiError::bad("IP 检测不可用"))?;
    let v: Value = http
        .get("https://api.ipify.org?format=json")
        .send()
        .await
        .map_err(|_| ApiError::bad("无法自动检测公网 IP，请手动填写"))?
        .json()
        .await
        .map_err(|_| ApiError::bad("无法检测公网 IP"))?;
    Ok(Json(
        json!({"ip":ip(v["ip"].as_str().unwrap_or_default())?}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainInput {
    pub provider_id: String,
    pub zone_id: String,
    #[serde(default = "default_label")]
    pub label: String,
    pub controller_ip: String,
}
fn default_label() -> String {
    "doh".into()
}
pub async fn save_domain(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<DomainInput>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let address = ip(&input.controller_ip)?;
    let p = provider(&app, &input.provider_id).await?;
    let zone = p
        .zones()
        .await?
        .into_iter()
        .find(|z| z.id == input.zone_id)
        .ok_or_else(|| ApiError::bad("所选域名不在该 API 的可访问列表"))?;
    if zone.status != "active" {
        return Err(ApiError::bad(
            "域名尚未生效，请先修复 DNS 供应商中的域名状态",
        ));
    }
    let label = input.label.trim();
    if label.contains('.') || label.len() > 63 {
        return Err(ApiError::bad(
            "DoH 主机名只能填写单个标签，例如 doh；根域使用 @",
        ));
    }
    let hostname = security::domain(&if label.is_empty() || label == "@" {
        zone.name.clone()
    } else {
        format!("{label}.{}", zone.name)
    })?;
    if hostname
        == url::Url::parse(&app.0.public_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default()
    {
        return Err(ApiError::bad("DoH 域名不能覆盖管理后台域名"));
    }
    let mut existing = p.records(&zone, &hostname).await?;
    let tracked = sqlx::query("SELECT r.remote_id,r.record_type,r.value FROM dns_managed_records r JOIN dns_domains d ON d.id=r.domain_id WHERE d.hostname=? AND d.provider_id=?").bind(&hostname).bind(&input.provider_id).fetch_all(app.pool()?).await?;
    for record in &mut existing {
        record.owned |= tracked.iter().any(|r| {
            r.get::<String, _>("remote_id") == record.id
                && r.get::<String, _>("record_type") == record.kind
                && r.get::<String, _>("value") == record.value
        });
    }
    if existing
        .iter()
        .any(|r| matches!(r.kind.as_str(), "CNAME" | "A" | "AAAA") && !r.owned)
    {
        return Err(ApiError::bad(
            "该主机名已有非本项目记录，请选择未使用的主机名，避免覆盖其他业务",
        ));
    }
    let _guard = app.0.mutation.lock().await;
    if sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM dns_domains WHERE state='preparing'")
        .fetch_one(app.pool()?)
        .await?
        > 0
    {
        return Err(ApiError::bad("已有域名配置任务，请等待完成或修复失败任务"));
    }
    let previous =
        sqlx::query("SELECT id,state,provider_id,zone_id FROM dns_domains WHERE hostname=?")
            .bind(&hostname)
            .fetch_optional(app.pool()?)
            .await?;
    if let Some(row) = &previous {
        if !matches!(
            row.get::<String, _>("state").as_str(),
            "retired" | "retiring"
        ) {
            return Err(ApiError::bad(
                "该域名已配置，请使用修复功能，或选择其他域名",
            ));
        }
        if row.get::<String, _>("provider_id") != input.provider_id
            || row.get::<String, _>("zone_id") != zone.id
        {
            return Err(ApiError::bad(
                "重新启用已有域名时请使用原供应商配置；凭据可在供应商设置中更新",
            ));
        }
    }
    let id = previous
        .as_ref()
        .map(|r| r.get::<String, _>("id"))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let revision: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(revision),0)+1 FROM dns_domains")
        .fetch_one(app.pool()?)
        .await?;
    if previous.is_some() {
        sqlx::query("UPDATE dns_domains SET state='preparing',controller_ip=?,revision=?,controller_applied=0,retire_at=NULL,last_error='',cert_attempt_at=0 WHERE id=?").bind(&address).bind(revision).bind(&id).execute(app.pool()?).await?;
    } else {
        sqlx::query("INSERT INTO dns_domains(id,provider_id,zone_id,zone_name,hostname,controller_ip,revision,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(&id).bind(&input.provider_id).bind(&zone.id).bind(&zone.name).bind(&hostname).bind(&address).bind(revision).bind(now()).execute(app.pool()?).await?;
    }
    for r in existing
        .iter()
        .filter(|r| r.owned && r.value == address && matches!(r.kind.as_str(), "A" | "AAAA"))
    {
        track(&app, &id, "controller", r, "address").await?;
    }
    let job = job(&app, "domain", &id).await?;
    audit(&app, &who.username, "配置统一 DoH 域名", &hostname).await?;
    Ok(Json(json!({"id":id,"job_id":job})))
}
pub async fn repair(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    auth::require(&app, &headers, true).await?;
    sqlx::query("UPDATE dns_domains SET state=IF(state='failed','preparing',state),last_error='',cert_attempt_at=0 WHERE id=?").bind(&id).execute(app.pool()?).await?;
    let job = job(&app, "domain", &id).await?;
    Ok(Json(json!({"job_id":job})))
}
pub async fn audit(app: &App, actor: &str, action: &str, target: &str) -> ApiResult<()> {
    sqlx::query("INSERT INTO audit_events(actor,action,target,created_at) VALUES(?,?,?,?)")
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(now())
        .execute(app.pool()?)
        .await?;
    Ok(())
}
pub async fn track(
    app: &App,
    domain: &str,
    node: &str,
    r: &Record,
    purpose: &str,
) -> ApiResult<()> {
    sqlx::query("INSERT IGNORE INTO dns_managed_records(id,domain_id,node_id,remote_id,name,record_type,value,purpose) VALUES(?,?,?,?,?,?,?,?)").bind(uuid::Uuid::new_v4().to_string()).bind(domain).bind(node).bind(&r.id).bind(&r.name).bind(&r.kind).bind(&r.value).bind(purpose).execute(app.pool()?).await?;
    Ok(())
}
pub async fn remove_record(
    app: &App,
    d: &Domain,
    p: &Provider,
    row: &sqlx::mysql::MySqlRow,
) -> ApiResult<()> {
    let name: String = row.get("name");
    let id: String = row.get("remote_id");
    let records = p.records(&d.zone, &name).await?;
    if let Some(record) = records.iter().find(|r| r.id == id) {
        if record.value != row.get::<String, _>("value")
            || record.kind != row.get::<String, _>("record_type")
        {
            return Err(ApiError::bad(
                "托管 DNS 记录被外部修改，已暂停自动删除，请人工核对",
            ));
        }
        p.delete(&d.zone, &id).await?;
    }
    sqlx::query("DELETE FROM dns_managed_records WHERE id=?")
        .bind(row.get::<String, _>("id"))
        .execute(app.pool()?)
        .await?;
    Ok(())
}
pub async fn ready_at(host: &str, address: &str, node: &str) -> bool {
    let Ok(ip) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(http) = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(host, SocketAddr::new(ip, 443))
        .build()
    else {
        return false;
    };
    let Ok(r) = http.get(format!("https://{host}/readyz")).send().await else {
        return false;
    };
    if !r.status().is_success() {
        return false;
    }
    let Ok(value) = r.json::<Value>().await else {
        return false;
    };
    value["status"] == "ready"
        && if node == "controller" {
            value["mode"] == "controller"
        } else {
            value["node_id"] == node
        }
}
async fn ensure_address(
    app: &App,
    d: &Domain,
    p: &Provider,
    node: &str,
    address: &str,
) -> ApiResult<()> {
    let kind = if address.contains(':') { "AAAA" } else { "A" };
    let records = p.records(&d.zone, &d.hostname).await?;
    let tracked = sqlx::query(
        "SELECT * FROM dns_managed_records WHERE domain_id=? AND node_id=? AND purpose='address'",
    )
    .bind(&d.id)
    .bind(node)
    .fetch_all(app.pool()?)
    .await?;
    if tracked.iter().any(|r| {
        r.get::<String, _>("value") == address
            && records.iter().any(|x| {
                x.id == r.get::<String, _>("remote_id") && x.value == address && x.kind == kind
            })
    }) {
        return Ok(());
    }
    for row in &tracked {
        remove_record(app, d, p, row).await?;
    }
    if let Some(r) = records
        .iter()
        .find(|r| r.value == address && r.kind == kind)
    {
        if !r.owned {
            return Err(ApiError::bad("目标 DNS 记录不属于本项目，请核对记录冲突"));
        }
        track(app, &d.id, node, r, "address").await?;
    } else {
        let r = p.create(&d.zone, &d.hostname, kind, address).await?;
        track(app, &d.id, node, &r, "address").await?;
    }
    Ok(())
}
fn failed_probes(app: &App, domain: &str, node: &str, ready: bool) -> bool {
    let mut health = app.0.direct_health.lock().unwrap();
    let count = health.entry(format!("{domain}/{node}")).or_default();
    *count = if ready { 0 } else { count.saturating_add(1) };
    *count >= 3
}
pub async fn reconcile(app: &App, d: &Domain) -> ApiResult<()> {
    let p = provider(app, &d.provider_id).await?;
    if d.state == "retiring" {
        let at: Option<i64> = sqlx::query_scalar("SELECT retire_at FROM dns_domains WHERE id=?")
            .bind(&d.id)
            .fetch_one(app.pool()?)
            .await?;
        if at.is_some_and(|n| n <= now()) {
            let rows = sqlx::query("SELECT * FROM dns_managed_records WHERE domain_id=?")
                .bind(&d.id)
                .fetch_all(app.pool()?)
                .await?;
            for r in &rows {
                remove_record(app, d, &p, r).await?;
            }
            sqlx::query("UPDATE dns_domains SET state='retired' WHERE id=?")
                .bind(&d.id)
                .execute(app.pool()?)
                .await?;
            return Ok(());
        }
    }
    if d.certificate.is_none() {
        return Ok(());
    }
    let main_ready = d.controller_applied >= d.revision
        && ready_at(&d.hostname, &d.controller_ip, "controller").await;
    let main_failed = failed_probes(app, &d.id, "controller", main_ready);
    if main_ready {
        ensure_address(app, d, &p, "controller", &d.controller_ip).await?;
    } else if main_failed && d.state == "active" {
        let records=sqlx::query("SELECT * FROM dns_managed_records WHERE domain_id=? AND node_id='controller' AND purpose='address'").bind(&d.id).fetch_all(app.pool()?).await?;
        for r in &records {
            remove_record(app, d, &p, r).await?;
        }
    }
    let rows=sqlx::query("SELECT id,ip_address,enabled,deleted_at,domain_revision,last_seen FROM nodes WHERE ip_address IS NOT NULL").fetch_all(app.pool()?).await?;
    for row in rows {
        let id: String = row.get("id");
        let address: String = row.get("ip_address");
        let enabled =
            row.get::<bool, _>("enabled") && row.get::<Option<i64>, _>("deleted_at").is_none();
        let ready = enabled
            && row.get::<i64, _>("domain_revision") >= d.revision
            && row
                .get::<Option<i64>, _>("last_seen")
                .is_some_and(|t| now() - t < 15)
            && ready_at(&d.hostname, &address, &id).await;
        let failed = failed_probes(app, &d.id, &id, ready);
        if ready {
            ensure_address(app, d, &p, &id, &address).await?;
            sqlx::query("UPDATE nodes SET deploy_state='ready' WHERE id=?")
                .bind(&id)
                .execute(app.pool()?)
                .await?;
        } else if failed
            || !enabled
            || row
                .get::<Option<i64>, _>("last_seen")
                .is_none_or(|t| now() - t > 45)
        {
            let records=sqlx::query("SELECT * FROM dns_managed_records WHERE domain_id=? AND node_id=? AND purpose='address'").bind(&d.id).bind(&id).fetch_all(app.pool()?).await?;
            for r in &records {
                remove_record(app, d, &p, r).await?;
            }
        }
    }
    if d.state == "preparing" && main_ready {
        let mut tx = app.pool()?.begin().await?;
        sqlx::query(
            "UPDATE dns_domains SET state='retiring',retire_at=? WHERE state='active' AND id<>?",
        )
        .bind(now() + 7 * 86400)
        .bind(&d.id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE dns_domains SET state='active',last_error='' WHERE id=?")
            .bind(&d.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE nodes SET endpoint=? WHERE ip_address IS NOT NULL")
            .bind(format!("https://{}", d.hostname))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        sqlx::query("UPDATE infra_jobs SET state='done',stage='统一域名证书和主控直连解析已生效；节点就绪后自动加入',updated_at=? WHERE target=? AND kind='domain' AND state IN ('queued','running')").bind(now()).bind(&d.id).execute(app.pool()?).await?;
    }
    if d.state == "active" || (d.state == "preparing" && main_ready) {
        *app.0.direct_doh.write().unwrap() = Some(format!("https://{}", d.hostname));
    }
    Ok(())
}
pub async fn infrastructure_loop(app: App) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut checked = 0;
    loop {
        interval.tick().await;
        let Ok(list) = domains(&app).await else {
            continue;
        };
        for mut d in list
            .into_iter()
            .filter(|d| matches!(d.state.as_str(), "active" | "preparing" | "retiring"))
        {
            if d.state != "retiring"
                && now() - d.cert_attempt_at > 3600
                && (d.certificate.is_none()
                    || d.cert_expires.is_some_and(|t| t < now() + 30 * 86400))
            {
                let _ = sqlx::query("UPDATE dns_domains SET cert_attempt_at=? WHERE id=?")
                    .bind(now())
                    .bind(&d.id)
                    .execute(app.pool().unwrap())
                    .await;
                let result = crate::certificates::provision(&app, &d).await;
                if let Err(error) = result {
                    let _=sqlx::query("UPDATE dns_domains SET last_error=?,state=IF(certificate IS NULL,'failed',state),checked_at=? WHERE id=?").bind(&error.message).bind(now()).bind(&d.id).execute(app.pool().unwrap()).await;
                    let _=sqlx::query("UPDATE infra_jobs SET state='failed',stage=?,updated_at=? WHERE target=? AND kind='domain' AND state IN ('queued','running')").bind(error.message).bind(now()).bind(&d.id).execute(app.pool().unwrap()).await;
                    continue;
                }
                if let Ok(row) = sqlx::query("SELECT * FROM dns_domains WHERE id=?")
                    .bind(&d.id)
                    .fetch_one(app.pool().unwrap())
                    .await
                {
                    d = domain_row(row);
                }
            }
            let result = reconcile(&app, &d).await;
            if let Err(error) = result {
                let _ = sqlx::query("UPDATE dns_domains SET last_error=?,checked_at=? WHERE id=?")
                    .bind(error.message)
                    .bind(now())
                    .bind(&d.id)
                    .execute(app.pool().unwrap())
                    .await;
            } else if now() - checked >= 60 || sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM infra_jobs WHERE target=? AND kind='domain' AND state IN ('queued','running')").bind(&d.id).fetch_one(app.pool().unwrap()).await.unwrap_or(0)>0 {
                let warning = monitor(&app, &d)
                    .await
                    .err()
                    .map(|e| e.message)
                    .unwrap_or_default();
                if d.state == "active" && warning.is_empty() && ready_at(&d.hostname, &d.controller_ip, "controller").await {
                    let _=sqlx::query("UPDATE infra_jobs SET state='done',stage='域名状态、HTTPS 与托管 DNS 检查完成',updated_at=? WHERE target=? AND kind='domain' AND state IN ('queued','running')").bind(now()).bind(&d.id).execute(app.pool().unwrap()).await;
                }
                let _ = sqlx::query("UPDATE dns_domains SET last_error=?,checked_at=? WHERE id=?")
                    .bind(warning)
                    .bind(now())
                    .bind(&d.id)
                    .execute(app.pool().unwrap())
                    .await;
            }
        }
        if now() - checked >= 60 {
            checked = now();
        }
        let _=sqlx::query("DELETE FROM nodes WHERE deleted_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM dns_managed_records r WHERE r.node_id=nodes.id)").execute(app.pool().unwrap()).await;
    }
}
async fn monitor(app: &App, d: &Domain) -> ApiResult<()> {
    let p = provider(app, &d.provider_id).await?;
    let zones = p.zones().await?;
    if !zones
        .iter()
        .any(|z| z.id == d.zone.id && z.status == "active")
    {
        return Err(ApiError::bad(
            "主域名不在有效列表，请修复域名委派/权限或更换域名",
        ));
    }
    if d.state == "preparing" {
        return Err(ApiError::bad("证书已准备，等待主控和节点安装 HTTPS 配置"));
    }
    let response = p
        .http
        .get("https://dns.google/resolve")
        .query(&[("name", d.zone.name.as_str()), ("type", "NS")])
        .send()
        .await
        .map_err(|_| ApiError::bad("公共 DNS 状态检测暂不可用"))?;
    let v: Value = response
        .json()
        .await
        .map_err(|_| ApiError::bad("公共 DNS 状态检测失败"))?;
    if v["Status"] != 0 || v["Answer"].as_array().is_none_or(|a| a.is_empty()) {
        return Err(ApiError::bad(
            "主域名公共 DNS 状态异常，请检查过期、NS 委派或更换域名",
        ));
    }
    Ok(())
}
pub async fn setup_guard(State(app): State<App>, request: Request, next: Next) -> Response {
    use axum::response::IntoResponse;
    let path = request.uri().path();
    let protected = [
        "/api/users",
        "/api/zones",
        "/api/records",
        "/api/tokens",
        "/api/nodes",
        "/api/managed-nodes",
        "/api/ssh",
    ]
    .iter()
    .any(|p| path.starts_with(p));
    if protected
        && (std::env::var("DNSDOH_TEST_MODE").as_deref() != Ok("true")
            || std::env::var("DNSDOH_REQUIRE_SETUP").as_deref() == Ok("true"))
    {
        match active(&app).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return ApiError::new(
                    StatusCode::PRECONDITION_REQUIRED,
                    "请先完成 DNS 供应商与统一域名配置",
                )
                .into_response();
            }
            Err(e) => return e.into_response(),
        }
    }
    next.run(request).await
}
