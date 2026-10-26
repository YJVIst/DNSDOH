use crate::{
    auth,
    model::*,
    security,
    state::{ApiError, ApiResult, App},
    storage,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

async fn changed(
    app: &App,
    mut tx: sqlx::Transaction<'_, sqlx::MySql>,
    actor: &str,
    action: &str,
    target: &str,
) -> ApiResult<Json<Value>> {
    storage::audit(&mut tx, actor, action, target).await?;
    tx.commit().await?;
    storage::reload(app).await?;
    Ok(Json(
        json!({"ok":true,"revision":app.view().map(|s|s.revision),"propagation_seconds":LEASE_SECONDS}),
    ))
}
fn expiry(value: Option<i64>) -> ApiResult<Option<i64>> {
    if value.is_some_and(|v| v <= 0 || v > 4102444800) {
        Err(ApiError::bad("到期时间不正确"))
    } else {
        Ok(value)
    }
}
fn exists(affected: u64) -> ApiResult<()> {
    if affected == 0 {
        Err(ApiError::new(StatusCode::NOT_FOUND, "对象不存在或已被删除"))
    } else {
        Ok(())
    }
}

pub async fn state(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::require(&app, &headers, false).await?;
    let pool = app.pool()?;
    let grants = sqlx::query("SELECT user_id,zone_id FROM user_zones")
        .fetch_all(pool)
        .await?;
    let users:Vec<Value>=sqlx::query("SELECT * FROM users ORDER BY created_at DESC,id").fetch_all(pool).await?.into_iter().map(|r|{let id:String=r.get("id");let zone_ids:Vec<String>=grants.iter().filter(|g|g.get::<String,_>("user_id")==id).map(|g|g.get("zone_id")).collect();json!({"id":id,"name":r.get::<String,_>("name"),"note":r.get::<String,_>("note"),"enabled":r.get::<bool,_>("enabled"),"expires_at":r.get::<Option<i64>,_>("expires_at"),"created_at":r.get::<i64,_>("created_at"),"zone_ids":zone_ids})}).collect();
    let zones:Vec<Value>=sqlx::query("SELECT * FROM zones ORDER BY name").fetch_all(pool).await?.into_iter().map(|r|json!({"id":r.get::<String,_>("id"),"name":r.get::<String,_>("name"),"note":r.get::<String,_>("note"),"enabled":r.get::<bool,_>("enabled"),"created_at":r.get::<i64,_>("created_at")})).collect();
    let records:Vec<Value>=sqlx::query("SELECT r.*,z.name AS zone_name FROM records r JOIN zones z ON z.id=r.zone_id ORDER BY r.name,r.record_type").fetch_all(pool).await?.into_iter().map(|r|json!({"id":r.get::<String,_>("id"),"zone_id":r.get::<String,_>("zone_id"),"zone_name":r.get::<String,_>("zone_name"),"name":r.get::<String,_>("name"),"record_type":r.get::<String,_>("record_type"),"value":r.get::<String,_>("value"),"ttl":r.get::<i32,_>("ttl"),"enabled":r.get::<bool,_>("enabled")})).collect();
    let tokens:Vec<Value>=sqlx::query("SELECT t.id,t.user_id,t.name,t.prefix,t.enabled,t.expires_at,t.created_at,u.name AS user_name FROM tokens t JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC,t.id").fetch_all(pool).await?.into_iter().map(|r|json!({"id":r.get::<String,_>("id"),"user_id":r.get::<String,_>("user_id"),"user_name":r.get::<String,_>("user_name"),"name":r.get::<String,_>("name"),"prefix":r.get::<String,_>("prefix"),"enabled":r.get::<bool,_>("enabled"),"expires_at":r.get::<Option<i64>,_>("expires_at"),"created_at":r.get::<i64,_>("created_at")})).collect();
    let nodes:Vec<Value>=sqlx::query("SELECT id,name,endpoint,region,note,enabled,last_seen,applied_revision,version,public_key,ip_address,deploy_state,domain_revision,deleted_at,created_at FROM nodes ORDER BY created_at,id").fetch_all(pool).await?.into_iter().map(|r|{let seen:Option<i64>=r.get("last_seen");json!({"id":r.get::<String,_>("id"),"ip_address":r.get::<Option<String>,_>("ip_address"),"deploy_state":r.get::<String,_>("deploy_state"),"domain_revision":r.get::<i64,_>("domain_revision"),"deleted_at":r.get::<Option<i64>,_>("deleted_at"),"name":r.get::<String,_>("name"),"endpoint":r.get::<String,_>("endpoint"),"region":r.get::<String,_>("region"),"note":r.get::<String,_>("note"),"enabled":r.get::<bool,_>("enabled"),"last_seen":seen,"online":seen.is_some_and(|t|now()-t<12),"applied_revision":r.get::<i64,_>("applied_revision"),"version":r.get::<String,_>("version"),"auth_mode":if r.get::<Option<String>,_>("public_key").is_some(){"ed25519"}else{"legacy"}})}).collect();
    let audit:Vec<Value>=sqlx::query("SELECT actor,action,target,created_at FROM audit_events ORDER BY id DESC LIMIT 100").fetch_all(pool).await?.into_iter().map(|r|json!({"actor":r.get::<String,_>("actor"),"action":r.get::<String,_>("action"),"target":r.get::<String,_>("target"),"created_at":r.get::<i64,_>("created_at")})).collect();
    let settings = sqlx::query("SELECT revision,token_qps,retention_days FROM settings WHERE id=1")
        .fetch_one(pool)
        .await?;
    let from = now() - 86400;
    let metrics:Vec<Value>=sqlx::query("SELECT (bucket DIV 3600)*3600 AS hour,CAST(SUM(total) AS SIGNED) AS total,CAST(SUM(success) AS SIGNED) AS success,CAST(SUM(denied) AS SIGNED) AS denied,CAST(SUM(errors) AS SIGNED) AS errors,CAST(SUM(latency_us) AS SIGNED) AS latency_us FROM metrics WHERE bucket>=? GROUP BY hour ORDER BY hour").bind(from).fetch_all(pool).await?.into_iter().map(|r|json!({"bucket":r.get::<i64,_>("hour"),"total":r.get::<i64,_>("total"),"success":r.get::<i64,_>("success"),"denied":r.get::<i64,_>("denied"),"errors":r.get::<i64,_>("errors"),"latency_us":r.get::<i64,_>("latency_us")})).collect();
    let per_node:Vec<Value>=sqlx::query("SELECT node_id,CAST(SUM(total) AS SIGNED) AS total,CAST(SUM(success) AS SIGNED) AS success FROM metrics WHERE bucket>=? GROUP BY node_id").bind(from).fetch_all(pool).await?.into_iter().map(|r|json!({"node_id":r.get::<String,_>("node_id"),"total":r.get::<i64,_>("total"),"success":r.get::<i64,_>("success")})).collect();
    Ok(Json(
        json!({"users":users,"zones":zones,"records":records,"tokens":tokens,"nodes":nodes,"audit":audit,"metrics":metrics,"node_metrics":per_node,"settings":{"revision":settings.get::<i64,_>("revision"),"token_qps":settings.get::<i32,_>("token_qps"),"retention_days":settings.get::<i32,_>("retention_days"),"lease_seconds":LEASE_SECONDS,"sync_seconds":SYNC_SECONDS},"infrastructure":crate::infra::status(&app).await?,"gateway":crate::gateway::status(&app),"system":{"version":env!("CARGO_PKG_VERSION"),"database":"MariaDB","uptime_seconds":app.0.started.elapsed().as_secs(),"ready":app.view().is_some(),"public_url":app.0.public_url,"doh_url":app.doh_url(),"now":now()}}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInput {
    pub name: String,
    #[serde(default)]
    pub note: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub zone_ids: Vec<String>,
}
fn yes() -> bool {
    true
}
async fn user_save(
    app: App,
    headers: HeaderMap,
    input: UserInput,
    id: Option<String>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let name = security::text(&input.name, 100, "用户名")?;
    let note = security::note(&input.note)?;
    let expiry = expiry(input.expires_at)?;
    let mut zones = input.zone_ids;
    zones.sort();
    zones.dedup();
    if zones.len() > 100 {
        return Err(ApiError::bad("最多授权 100 个分区"));
    }
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    let editing = id.is_some();
    let id = id.unwrap_or_else(|| Uuid::new_v4().to_string());
    if editing {
        exists(
            sqlx::query("UPDATE users SET name=?,note=?,enabled=?,expires_at=? WHERE id=?")
                .bind(&name)
                .bind(note)
                .bind(input.enabled)
                .bind(expiry)
                .bind(&id)
                .execute(&mut *tx)
                .await?
                .rows_affected(),
        )?;
    } else {
        sqlx::query(
            "INSERT INTO users(id,name,note,enabled,expires_at,created_at) VALUES(?,?,?,?,?,?)",
        )
        .bind(&id)
        .bind(&name)
        .bind(note)
        .bind(input.enabled)
        .bind(expiry)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM user_zones WHERE user_id=?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    for zone in zones {
        sqlx::query("INSERT INTO user_zones(user_id,zone_id) VALUES(?,?)")
            .bind(&id)
            .bind(zone)
            .execute(&mut *tx)
            .await?;
    }
    let mut result = changed(
        &app,
        tx,
        &who.username,
        if editing {
            "更新用户"
        } else {
            "创建用户"
        },
        &name,
    )
    .await?;
    result.0["id"] = json!(id);
    Ok(result)
}
pub async fn user_create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<UserInput>,
) -> ApiResult<Json<Value>> {
    user_save(app, headers, input, None).await
}
pub async fn user_update(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<UserInput>,
) -> ApiResult<Json<Value>> {
    user_save(app, headers, input, Some(id)).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneInput {
    pub name: String,
    #[serde(default)]
    pub note: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}
async fn zone_save(
    app: App,
    headers: HeaderMap,
    input: ZoneInput,
    id: Option<String>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let name = security::domain(&input.name)?;
    let note = security::note(&input.note)?;
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    let editing = id.is_some();
    let id = id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let others: Vec<String> = sqlx::query_scalar("SELECT name FROM zones WHERE id<>?")
        .bind(&id)
        .fetch_all(&mut *tx)
        .await?;
    if others
        .iter()
        .any(|other| security::inside(&name, other) || security::inside(other, &name))
    {
        return Err(ApiError::bad(
            "分区不能重复或包含其他分区，请使用互不重叠的分区域名",
        ));
    }
    if editing {
        let old: String = sqlx::query_scalar("SELECT name FROM zones WHERE id=?")
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "分区不存在"))?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE zone_id=?")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await?;
        if old != name && count > 0 {
            return Err(ApiError::bad(
                "已有记录的分区不能改名，请新建分区后迁移记录",
            ));
        }
        sqlx::query("UPDATE zones SET name=?,note=?,enabled=? WHERE id=?")
            .bind(&name)
            .bind(note)
            .bind(input.enabled)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("INSERT INTO zones(id,name,note,enabled,created_at) VALUES(?,?,?,?,?)")
            .bind(&id)
            .bind(&name)
            .bind(note)
            .bind(input.enabled)
            .bind(now())
            .execute(&mut *tx)
            .await?;
    }
    let mut result = changed(
        &app,
        tx,
        &who.username,
        if editing {
            "更新分区"
        } else {
            "创建分区"
        },
        &name,
    )
    .await?;
    result.0["id"] = json!(id);
    Ok(result)
}
pub async fn zone_create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<ZoneInput>,
) -> ApiResult<Json<Value>> {
    zone_save(app, headers, input, None).await
}
pub async fn zone_update(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<ZoneInput>,
) -> ApiResult<Json<Value>> {
    zone_save(app, headers, input, Some(id)).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordInput {
    pub zone_id: String,
    pub name: String,
    pub record_type: String,
    pub value: String,
    #[serde(default = "ttl")]
    pub ttl: i32,
    #[serde(default = "yes")]
    pub enabled: bool,
}
fn ttl() -> i32 {
    60
}
async fn record_save(
    app: App,
    headers: HeaderMap,
    input: RecordInput,
    id: Option<String>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let name = security::domain(&input.name)?;
    let address: std::net::IpAddr = input
        .value
        .trim()
        .parse()
        .map_err(|_| ApiError::bad("请输入有效 IP 地址"))?;
    if !matches!(
        (input.record_type.as_str(), address),
        ("A", std::net::IpAddr::V4(_)) | ("AAAA", std::net::IpAddr::V6(_))
    ) {
        return Err(ApiError::bad("记录类型与 IP 地址不匹配"));
    }
    if !(10..=86400).contains(&input.ttl) {
        return Err(ApiError::bad("TTL 必须在 10–86400 秒之间"));
    }
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    let zone: String = sqlx::query_scalar("SELECT name FROM zones WHERE id=?")
        .bind(&input.zone_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::bad("分区不存在"))?;
    if !security::inside(&name, &zone) {
        return Err(ApiError::bad("记录域名不属于所选分区"));
    }
    let editing = id.is_some();
    let id = id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE zone_id=? AND name=? AND record_type=? AND id<>?",
    )
    .bind(&input.zone_id)
    .bind(&name)
    .bind(&input.record_type)
    .bind(&id)
    .fetch_one(&mut *tx)
    .await?;
    if count >= 32 {
        return Err(ApiError::bad("同一域名同一类型最多 32 个地址"));
    }
    if editing {
        exists(sqlx::query("UPDATE records SET zone_id=?,name=?,record_type=?,value=?,ttl=?,enabled=? WHERE id=?").bind(&input.zone_id).bind(&name).bind(input.record_type).bind(address.to_string()).bind(input.ttl).bind(input.enabled).bind(&id).execute(&mut *tx).await?.rows_affected())?;
    } else {
        sqlx::query("INSERT INTO records(id,zone_id,name,record_type,value,ttl,enabled,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(&id).bind(&input.zone_id).bind(&name).bind(input.record_type).bind(address.to_string()).bind(input.ttl).bind(input.enabled).bind(now()).execute(&mut *tx).await?;
    }
    let mut result = changed(
        &app,
        tx,
        &who.username,
        if editing {
            "更新记录"
        } else {
            "创建记录"
        },
        &name,
    )
    .await?;
    result.0["id"] = json!(id);
    Ok(result)
}
pub async fn record_create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<RecordInput>,
) -> ApiResult<Json<Value>> {
    record_save(app, headers, input, None).await
}
pub async fn record_update(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<RecordInput>,
) -> ApiResult<Json<Value>> {
    record_save(app, headers, input, Some(id)).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenInput {
    user_id: String,
    name: String,
    expires_at: Option<i64>,
}
pub async fn token_create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<TokenInput>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let name = security::text(&input.name, 100, "令牌名称")?;
    let expires = expiry(input.expires_at)?;
    if expires.is_some_and(|t| t <= now()) {
        return Err(ApiError::bad("新令牌的到期时间必须在未来"));
    }
    let secret = security::secret();
    let id = Uuid::new_v4().to_string();
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    sqlx::query("INSERT INTO tokens(id,user_id,name,token_hash,prefix,expires_at,created_at) VALUES(?,?,?,?,?,?,?)").bind(&id).bind(&input.user_id).bind(&name).bind(security::digest(&secret)).bind(&secret[..8]).bind(expires).bind(now()).execute(&mut *tx).await?;
    let mut result = changed(&app, tx, &who.username, "签发令牌", &name).await?;
    result.0["id"] = json!(id);
    result.0["token"] = json!(secret);
    result.0["doh_url"] = json!(format!("{}/dns-query/{}", app.doh_url(), secret));
    Ok(result)
}
pub async fn token_revoke(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    let name: String = sqlx::query_scalar("SELECT name FROM tokens WHERE id=?")
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "令牌不存在"))?;
    sqlx::query("UPDATE tokens SET enabled=0 WHERE id=?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    changed(&app, tx, &who.username, "撤销令牌", &name).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInput {
    name: String,
    endpoint: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    note: String,
    #[serde(default = "yes")]
    enabled: bool,
}
async fn node_save(
    app: App,
    headers: HeaderMap,
    input: NodeInput,
    id: Option<String>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let name = security::text(&input.name, 100, "节点名称")?;
    let endpoint = security::endpoint(&input.endpoint)?;
    let note = security::note(&input.note)?;
    if input.region.len() > 80 {
        return Err(ApiError::bad("地区描述过长"));
    }
    if endpoint == app.doh_url() || endpoint == app.0.public_url {
        return Err(ApiError::bad(
            "此地址是主控解析入口，请为独立节点使用其他地址",
        ));
    }
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    let editing = id.is_some();
    let id = id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let secret = security::secret();
    if editing {
        exists(
            sqlx::query("UPDATE nodes SET name=?,endpoint=?,region=?,note=?,enabled=? WHERE id=?")
                .bind(&name)
                .bind(endpoint)
                .bind(input.region)
                .bind(note)
                .bind(input.enabled)
                .bind(&id)
                .execute(&mut *tx)
                .await?
                .rows_affected(),
        )?;
    } else {
        sqlx::query("INSERT INTO nodes(id,name,endpoint,region,note,secret_hash,enabled,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(&id).bind(&name).bind(endpoint).bind(input.region).bind(note).bind(security::digest(&secret)).bind(input.enabled).bind(now()).execute(&mut *tx).await?;
    }
    let mut result = changed(
        &app,
        tx,
        &who.username,
        if editing {
            "更新 DNS 节点"
        } else {
            "添加 DNS 节点"
        },
        &name,
    )
    .await?;
    result.0["id"] = json!(id);
    if !editing {
        result.0["secret"] = json!(secret);
        result.0["controller_url"] = json!(app.0.public_url);
        if input.enabled {
            let install = crate::enrollment::issue(&app, &id).await?;
            result
                .0
                .as_object_mut()
                .unwrap()
                .extend(install.as_object().unwrap().clone());
        }
    }
    Ok(result)
}
pub async fn node_create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<NodeInput>,
) -> ApiResult<Json<Value>> {
    node_save(app, headers, input, None).await
}
pub async fn node_update(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<NodeInput>,
) -> ApiResult<Json<Value>> {
    node_save(app, headers, input, Some(id)).await
}
pub async fn node_rotate(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    let secret = security::secret();
    exists(
        sqlx::query("UPDATE nodes SET public_key=NULL,secret_hash=?,last_seen=NULL,applied_revision=0 WHERE id=?")
            .bind(security::digest(&secret))
            .bind(&id)
            .execute(&mut *tx)
            .await?
            .rows_affected(),
    )?;
    sqlx::query("DELETE FROM node_enrollments WHERE node_id=?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    let mut result = changed(&app, tx, &who.username, "轮换节点密钥", &id).await?;
    result.0["id"] = json!(id);
    result.0["secret"] = json!(secret);
    result.0["controller_url"] = json!(app.0.public_url);
    if let Ok(install) = crate::enrollment::issue(&app, &id).await {
        result
            .0
            .as_object_mut()
            .unwrap()
            .extend(install.as_object().unwrap().clone());
    }
    Ok(result)
}
async fn remove(app: App, kind: String, id: String, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let (table, action) = match kind.as_str() {
        "users" => ("users", "删除用户及令牌"),
        "zones" => ("zones", "删除分区及记录"),
        "records" => ("records", "删除记录"),
        "nodes" => ("nodes", "删除 DNS 节点"),
        _ => return Err(ApiError::new(StatusCode::NOT_FOUND, "接口不存在")),
    };
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    let name: String = sqlx::query_scalar(&format!("SELECT name FROM {table} WHERE id=?"))
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "对象不存在"))?;
    sqlx::query(&format!("DELETE FROM {table} WHERE id=?"))
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    changed(&app, tx, &who.username, action, &name).await
}
pub async fn user_delete(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    remove(app, "users".into(), id, headers).await
}
pub async fn zone_delete(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    remove(app, "zones".into(), id, headers).await
}
pub async fn record_delete(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    remove(app, "records".into(), id, headers).await
}
pub async fn node_delete(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    remove(app, "nodes".into(), id, headers).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsInput {
    token_qps: i32,
    retention_days: i32,
}
pub async fn settings(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<SettingsInput>,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    if !(1..=1000).contains(&input.token_qps) || !(1..=90).contains(&input.retention_days) {
        return Err(ApiError::bad(
            "令牌限速范围为 1–1000 QPS；保留时间为 1–90 天",
        ));
    }
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    sqlx::query("UPDATE settings SET token_qps=?,retention_days=? WHERE id=1")
        .bind(input.token_qps)
        .bind(input.retention_days)
        .execute(&mut *tx)
        .await?;
    changed(
        &app,
        tx,
        &who.username,
        "更新系统设置",
        "查询限速与数据保留",
    )
    .await
}

pub async fn sync(
    State(app): State<App>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Json<SyncResponse>> {
    let input: SyncRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad("Invalid sync request"))?;
    if Uuid::parse_str(&input.node_id).is_err() || input.version.len() > 40 {
        return Err(ApiError::bad("Invalid node metadata"));
    }
    let denied = || ApiError::new(StatusCode::FORBIDDEN, "Access denied");
    let _lock = app.0.mutation.lock().await;
    let row = sqlx::query("SELECT public_key,secret_hash FROM nodes WHERE id=? AND enabled=1")
        .bind(&input.node_id)
        .fetch_optional(app.pool()?)
        .await?
        .ok_or_else(denied)?;
    if let Some(public) = row.get::<Option<String>, _>("public_key") {
        let nonce = crate::enrollment::verify_request(&public, &input.node_id, &headers, &body)?;
        let inserted =
            sqlx::query("INSERT IGNORE INTO node_nonces(node_id,nonce,expires_at) VALUES(?,?,?)")
                .bind(&input.node_id)
                .bind(nonce)
                .bind(now() + 90)
                .execute(app.pool()?)
                .await?;
        if inserted.rows_affected() != 1 {
            return Err(denied());
        }
    } else {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| v.len() == 43)
            .ok_or_else(denied)?;
        if security::digest(token) != row.get::<String, _>("secret_hash") {
            return Err(denied());
        }
    }
    let snapshot = app.view().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Configuration unavailable")
    })?;
    if let Some(report) = &input.report {
        if Uuid::parse_str(&report.id).is_err()
            || report.metrics.len() > 120
            || report.metrics.iter().any(|m| {
                m.bucket % 60 != 0
                    || m.bucket > now() + 60
                    || m.bucket < now() - 86400
                    || m.total < 0
                    || m.total > 100000000
                    || m.success < 0
                    || m.denied < 0
                    || m.errors < 0
                    || m.success > m.total
                    || m.denied > m.total
                    || m.errors > m.total
                    || m.success + m.denied + m.errors != m.total
                    || m.latency_us < 0
                    || m.latency_us > 1000000000000000
            })
        {
            return Err(ApiError::bad("Invalid metrics"));
        }
        storage::save_report(app.pool()?, &input.node_id, report).await?;
    }
    sqlx::query("UPDATE nodes SET last_seen=?,applied_revision=?,version=? WHERE id=?")
        .bind(now())
        .bind(input.applied_revision)
        .bind(input.version)
        .bind(input.node_id)
        .execute(app.pool()?)
        .await?;
    Ok(Json(SyncResponse {
        snapshot: (*snapshot).clone(),
        lease_seconds: LEASE_SECONDS,
    }))
}
