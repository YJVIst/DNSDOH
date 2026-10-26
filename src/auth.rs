use crate::{
    model::now,
    security,
    state::{ApiError, ApiResult, App},
};
use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use subtle::ConstantTimeEq;

pub struct Identity {
    pub id: String,
    pub username: String,
    pub csrf: String,
    pub session_hash: String,
}
pub fn client_ip(app: &App, peer: SocketAddr, headers: &HeaderMap) -> String {
    if app.0.trust_proxy && peer.ip().is_loopback() {
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<IpAddr>().ok())
        {
            return ip.to_string();
        }
    }
    peer.ip().to_string()
}
pub fn origin(app: &App, headers: &HeaderMap) -> ApiResult<()> {
    if let Some(value) = headers.get(header::ORIGIN) {
        if value.to_str().ok() != Some(app.0.public_url.as_str()) {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "请求来源不匹配"));
        }
    }
    Ok(())
}
pub async fn require(app: &App, headers: &HeaderMap, write: bool) -> ApiResult<Identity> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .find_map(|p| p.trim().strip_prefix("dnsdoh_session="))
        })
        .filter(|v| v.len() == 43)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "请先登录"))?;
    let hash = security::digest(cookie);
    let row=sqlx::query("SELECT a.id,a.username,s.csrf FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>?").bind(&hash).bind(now()).fetch_optional(app.pool()?).await?.ok_or_else(||ApiError::new(StatusCode::UNAUTHORIZED,"登录已过期，请重新登录"))?;
    let identity = Identity {
        id: row.get("id"),
        username: row.get("username"),
        csrf: row.get("csrf"),
        session_hash: hash,
    };
    if write {
        origin(app, headers)?;
        let csrf = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !bool::from(csrf.as_bytes().ct_eq(identity.csrf.as_bytes())) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "操作验证失败，请刷新页面",
            ));
        }
    }
    Ok(identity)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    username: String,
    password: String,
}
pub async fn login(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> ApiResult<Response> {
    origin(&app, &headers)?;
    if input.username.len() > 100 || input.password.len() > 128 {
        return Err(ApiError::bad("账号或密码格式不正确"));
    }
    let key = format!("login:{}", client_ip(&app, peer, &headers));
    if !app.allow(key, 10, Duration::from_secs(60)) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "登录尝试过于频繁，请一分钟后再试",
        ));
    }
    let row = sqlx::query("SELECT id,username,password_hash FROM admins WHERE username=?")
        .bind(&input.username)
        .fetch_optional(app.pool()?)
        .await?;
    let hash = row.as_ref().map(|r| r.get::<String, _>("password_hash"));
    let password = input.password;
    let valid = tokio::task::spawn_blocking(move || {
        if let Some(hash) = hash {
            security::check_password(&password, &hash)
        } else {
            let _ = security::hash_password(&password);
            false
        }
    })
    .await
    .unwrap_or(false);
    if !valid {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "账号或密码不正确"));
    }
    let row = row.unwrap();
    let secret = security::secret();
    let csrf = security::secret();
    let admin_id: String = row.get("id");
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,csrf,expires_at) VALUES(?,?,?,?)")
        .bind(security::digest(&secret))
        .bind(&admin_id)
        .bind(&csrf)
        .bind(now() + 43200)
        .execute(app.pool()?)
        .await?;
    let secure = if app.0.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "dnsdoh_session={secret}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{secure}"
    );
    Ok((
        [
            (header::SET_COOKIE, cookie),
            (header::CACHE_CONTROL, "no-store".into()),
        ],
        Json(json!({"username":row.get::<String,_>("username"),"csrf":csrf})),
    )
        .into_response())
}
pub async fn session(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let who = require(&app, &headers, false).await?;
    Ok(Json(
        json!({"username":who.username,"csrf":who.csrf,"version":env!("CARGO_PKG_VERSION"),"public_url":app.0.public_url,"doh_url":app.doh_url()}),
    ))
}
pub async fn logout(State(app): State<App>, headers: HeaderMap) -> ApiResult<Response> {
    let who = require(&app, &headers, true).await?;
    sqlx::query("DELETE FROM sessions WHERE token_hash=?")
        .bind(who.session_hash)
        .execute(app.pool()?)
        .await?;
    Ok((
        [(
            header::SET_COOKIE,
            "dnsdoh_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(json!({"ok":true})),
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Password {
    current_password: String,
    new_password: String,
}
pub async fn password(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Password>,
) -> ApiResult<Json<Value>> {
    let who = require(&app, &headers, true).await?;
    security::validate_password(&input.new_password)?;
    if input.current_password.len() > 128 {
        return Err(ApiError::bad("当前密码格式不正确"));
    }
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM admins WHERE id=?")
        .bind(&who.id)
        .fetch_one(app.pool()?)
        .await?;
    let valid = tokio::task::spawn_blocking(move || {
        security::check_password(&input.current_password, &hash)
    })
    .await
    .unwrap_or(false);
    if !valid {
        return Err(ApiError::bad("当前密码不正确"));
    }
    let hash = tokio::task::spawn_blocking(move || security::hash_password(&input.new_password))
        .await
        .map_err(|_| ApiError::bad("密码处理失败"))?
        .map_err(|_| ApiError::bad("密码处理失败"))?;
    let mut tx = app.pool()?.begin().await?;
    sqlx::query("UPDATE admins SET password_hash=? WHERE id=?")
        .bind(hash)
        .bind(&who.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE admin_id=? AND token_hash<>?")
        .bind(&who.id)
        .bind(&who.session_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO audit_events(actor,action,target,created_at) VALUES(?,?,?,?)")
        .bind(&who.username)
        .bind("修改管理员密码")
        .bind(&who.username)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
