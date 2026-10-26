use crate::{
    dns,
    model::now,
    state::{ApiError, App},
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize)]
pub struct Probe {
    pub id: String,
    pub endpoint: String,
    pub healthy: bool,
    pub latency_ms: f64,
    pub revision: i64,
    pub checked_at: i64,
}
fn candidates(app: &App, revision: i64) -> Vec<Probe> {
    let mut nodes: Vec<_> = app
        .0
        .probes
        .read()
        .unwrap()
        .iter()
        .filter(|p| p.healthy && p.revision == revision && now() - p.checked_at < 10)
        .cloned()
        .collect();
    nodes.sort_by(|a, b| a.latency_ms.total_cmp(&b.latency_ms));
    nodes
}
pub fn status(app: &App) -> Value {
    let selected = app
        .view()
        .and_then(|s| candidates(app, s.revision).first().map(|p| p.id.clone()));
    json!({"url":app.doh_url(),"strategy":"入口探测延迟优先；故障切换；主控本地兜底","selected_node":selected,"probes":*app.0.probes.read().unwrap()})
}
pub async fn probe_loop(app: App) {
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let rows = sqlx::query("SELECT id,endpoint,last_seen FROM nodes WHERE enabled=1")
            .fetch_all(app.pool().unwrap())
            .await;
        let Ok(rows) = rows else {
            app.0.probes.write().unwrap().clear();
            continue;
        };
        let previous = app.0.probes.read().unwrap().clone();
        let mut tasks = tokio::task::JoinSet::new();
        for row in rows {
            let id: String = row.get("id");
            let endpoint: String = row.get("endpoint");
            let seen: Option<i64> = row.get("last_seen");
            let http = app.0.http.clone();
            let prior = previous
                .iter()
                .find(|p| p.id == id && p.endpoint == endpoint && p.healthy)
                .map(|p| p.latency_ms);
            tasks.spawn(async move {
                let start = Instant::now();
                let mut probe = Probe {
                    id,
                    endpoint,
                    healthy: false,
                    latency_ms: 0.,
                    revision: 0,
                    checked_at: now(),
                };
                if seen.is_some_and(|t| now() - t < 12) {
                    if let Ok(response) =
                        http.get(format!("{}/readyz", probe.endpoint)).send().await
                    {
                        if response.status().is_success() {
                            if let Ok(body) = response.bytes().await {
                                if body.len() < 4096 {
                                    if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                                        probe.healthy = v["status"] == "ready"
                                            && v["mode"] == "node"
                                            && v["node_id"] == probe.id;
                                        probe.revision = v["revision"].as_i64().unwrap_or(0);
                                    }
                                }
                            }
                        }
                    }
                }
                let ms = start.elapsed().as_secs_f64() * 1000.;
                probe.latency_ms = prior.map(|old| old * 0.7 + ms * 0.3).unwrap_or(ms);
                probe
            });
        }
        let mut probes = Vec::new();
        while let Some(Ok(probe)) = tasks.join_next().await {
            probes.push(probe);
        }
        *app.0.probes.write().unwrap() = probes;
    }
}
fn reply(wire: Vec<u8>, node: &str, route: &str) -> Response {
    let mut response = (
        [
            (header::CONTENT_TYPE, "application/dns-message"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        wire,
    )
        .into_response();
    response
        .headers_mut()
        .insert("x-dnsdoh-node", node.parse().unwrap());
    response
        .headers_mut()
        .insert("x-dnsdoh-route", route.parse().unwrap());
    response
}
async fn process(
    app: App,
    token: String,
    bytes: Vec<u8>,
    peer: SocketAddr,
    headers: HeaderMap,
) -> Response {
    let start = Instant::now();
    // Authenticate and rate-limit once at the unified entrance. The locally computed
    // reply also bounds what a backend is allowed to return for this exact revision.
    let (revision, expected, success) = match dns::prepare(&app, &token, &bytes, peer, &headers) {
        Ok(v) => v,
        Err(e) => {
            app.count(
                if e.status.is_client_error() {
                    "denied"
                } else {
                    "error"
                },
                start.elapsed(),
            );
            return e.into_response();
        }
    };
    if success {
        // Limit total failover work even when many configured backends disappear.
        for node in candidates(&app, revision).into_iter().take(2) {
            if let Ok(response) = app
                .0
                .http
                .post(format!("{}/dns-query/{token}", node.endpoint))
                .header(header::CONTENT_TYPE, "application/dns-message")
                .body(bytes.clone())
                .send()
                .await
            {
                if matches!(
                    response.status(),
                    StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
                ) {
                    return ApiError::new(response.status(), "Selected node denied the request")
                        .into_response();
                }
                if response.status() == StatusCode::OK
                    && response.content_length().is_none_or(|n| n <= 65535)
                {
                    if let Ok(body) = response.bytes().await {
                        if body.as_ref() == expected.as_slice() {
                            if !app.view().is_some_and(|s| s.revision == revision) {
                                return ApiError::new(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "Configuration changed; retry query",
                                )
                                .into_response();
                            }
                            return reply(body.to_vec(), &node.id, "forwarded");
                        }
                    }
                }
            }
            // Quarantine a failed route immediately; periodic probes can recover it.
            if let Some(p) = app
                .0
                .probes
                .write()
                .unwrap()
                .iter_mut()
                .find(|p| p.id == node.id)
            {
                p.healthy = false;
            }
        }
    }
    if !app.view().is_some_and(|s| s.revision == revision) {
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Configuration changed; retry query",
        )
        .into_response();
    }
    app.count(if success { "success" } else { "denied" }, start.elapsed());
    reply(expected, "controller", "local-fallback")
}
pub async fn get(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let raw = query.unwrap_or_default();
    if raw.len() > 8192 {
        return ApiError::new(StatusCode::URI_TOO_LONG, "DNS query too large").into_response();
    }
    let params: Vec<_> = url::form_urlencoded::parse(raw.as_bytes())
        .filter(|(k, _)| k == "dns")
        .collect();
    if params.len() != 1 {
        return ApiError::bad("A single dns query parameter is required").into_response();
    }
    match URL_SAFE_NO_PAD.decode(params[0].1.as_bytes()) {
        Ok(bytes) => process(app, token, bytes, peer, headers).await,
        Err(_) => ApiError::bad("Invalid DNS query encoding").into_response(),
    }
}
pub async fn post(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        != Some("application/dns-message")
    {
        return ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected application/dns-message",
        )
        .into_response();
    }
    process(app, token, body.to_vec(), peer, headers).await
}
