use crate::model::{Metric, Report, Snapshot};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use sqlx::MySqlPool;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Clone)]
pub struct App(pub Arc<Inner>);
pub struct Inner {
    pub pool: Option<MySqlPool>,
    pub snapshot: RwLock<Option<(Arc<Snapshot>, Option<Instant>)>>,
    pub metrics: Mutex<BTreeMap<i64, Metric>>,
    pub limiter: Mutex<HashMap<String, (Instant, u32)>>,
    pub mutation: AsyncMutex<()>,
    pub public_url: String,
    pub doh_url: String,
    pub direct_doh: RwLock<Option<String>>,
    pub direct_health: Mutex<HashMap<String, u8>>,
    pub started: Instant,
    pub node_id: Option<String>,
    pub trust_proxy: bool,
    pub probes: RwLock<Vec<crate::gateway::Probe>>,
    pub http: reqwest::Client,
}
impl App {
    pub fn new(
        pool: Option<MySqlPool>,
        public_url: String,
        doh_url: String,
        node_id: Option<String>,
        trust_proxy: bool,
    ) -> Self {
        Self(Arc::new(Inner {
            pool,
            snapshot: RwLock::new(None),
            metrics: Mutex::new(BTreeMap::new()),
            limiter: Mutex::new(HashMap::new()),
            mutation: AsyncMutex::new(()),
            public_url,
            doh_url,
            direct_doh: RwLock::new(None),
            direct_health: Mutex::new(HashMap::new()),
            started: Instant::now(),
            node_id,
            trust_proxy,
            probes: RwLock::new(Vec::new()),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("HTTP client"),
        }))
    }
    pub fn doh_url(&self) -> String {
        self.0
            .direct_doh
            .read()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.0.doh_url.clone())
    }
    pub fn pool(&self) -> Result<&MySqlPool, ApiError> {
        self.0
            .pool
            .as_ref()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "此节点不提供管理接口"))
    }
    pub fn view(&self) -> Option<Arc<Snapshot>> {
        self.0
            .snapshot
            .read()
            .unwrap()
            .as_ref()
            .filter(|(_, until)| until.is_none_or(|at| Instant::now() < at))
            .map(|(s, _)| s.clone())
    }
    pub fn install(&self, snapshot: Snapshot, until: Option<Instant>) {
        *self.0.snapshot.write().unwrap() = Some((Arc::new(snapshot), until));
    }
    pub fn clear(&self) {
        *self.0.snapshot.write().unwrap() = None;
    }
    pub fn allow(&self, key: String, max: u32, window: Duration) -> bool {
        let mut limits = self.0.limiter.lock().unwrap();
        if limits.len() > 20000 {
            limits.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(300));
            if limits.len() > 20000 && !limits.contains_key(&key) {
                return false;
            }
        }
        let entry = limits.entry(key).or_insert((Instant::now(), 0));
        if entry.0.elapsed() >= window {
            *entry = (Instant::now(), 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= max
    }
    pub fn count(&self, kind: &str, elapsed: Duration) {
        let bucket = crate::model::now() / 60 * 60;
        let mut metrics = self.0.metrics.lock().unwrap();
        let m = metrics.entry(bucket).or_insert(Metric {
            bucket,
            ..Default::default()
        });
        m.total += 1;
        m.latency_us += elapsed.as_micros().min(i64::MAX as u128) as i64;
        match kind {
            "success" => m.success += 1,
            "denied" => m.denied += 1,
            _ => m.errors += 1,
        };
        while metrics.len() > 120 {
            metrics.pop_first();
        }
    }
    pub fn drain(&self) -> Option<Report> {
        let metrics = std::mem::take(&mut *self.0.metrics.lock().unwrap());
        if metrics.is_empty() {
            None
        } else {
            Some(Report {
                id: uuid::Uuid::new_v4().to_string(),
                metrics: metrics.into_values().collect(),
            })
        }
    }
}
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}
impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error":self.message}))).into_response()
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(ref e) = error {
            if e.is_unique_violation() {
                return Self::new(StatusCode::CONFLICT, "名称、地址或记录已存在");
            }
            if e.is_foreign_key_violation() {
                return Self::bad("关联对象不存在，请刷新后重试");
            }
        }
        tracing::error!(kind = "database", "database operation failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "数据库操作失败，请稍后重试",
        )
    }
}
pub type ApiResult<T> = Result<T, ApiError>;
