use crate::{
    model::*,
    security,
    state::{ApiResult, App},
};
use sqlx::{MySqlPool, Row};
use std::collections::HashMap;

pub async fn snapshot(pool: &MySqlPool) -> Result<Snapshot, sqlx::Error> {
    // A repeatable-read transaction prevents mixing a new revision with old grants.
    let mut tx = pool.begin().await?;
    let settings = sqlx::query("SELECT revision,token_qps FROM settings WHERE id=1")
        .fetch_one(&mut *tx)
        .await?;
    let mut zones: Vec<Zone> = sqlx::query("SELECT id,name FROM zones WHERE enabled=1")
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|r| Zone {
            id: r.get("id"),
            name: r.get("name"),
        })
        .collect();
    zones.sort_by_key(|z| std::cmp::Reverse(z.name.len()));
    let records=sqlx::query("SELECT r.zone_id,r.name,r.record_type,r.value,r.ttl FROM records r JOIN zones z ON z.id=r.zone_id WHERE r.enabled=1 AND z.enabled=1").fetch_all(&mut *tx).await?.into_iter().map(|r|DnsRecord{zone_id:r.get("zone_id"),name:r.get("name"),record_type:r.get("record_type"),value:r.get("value"),ttl:r.get::<i32,_>("ttl") as u32}).collect();
    let mut grants: HashMap<String, Vec<String>> = HashMap::new();
    for r in sqlx::query("SELECT user_id,zone_id FROM user_zones")
        .fetch_all(&mut *tx)
        .await?
    {
        grants
            .entry(r.get("user_id"))
            .or_default()
            .push(r.get("zone_id"));
    }
    let mut credentials = HashMap::new();
    for r in sqlx::query("SELECT t.id,t.user_id,t.token_hash,t.expires_at AS token_expiry,u.expires_at AS user_expiry FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.enabled=1 AND u.enabled=1").fetch_all(&mut *tx).await?{
  let a:Option<i64>=r.get("token_expiry");let b:Option<i64>=r.get("user_expiry");let expires_at=a.into_iter().chain(b).min();
  let user_id:String=r.get("user_id");credentials.insert(r.get("token_hash"),Credential{id:r.get("id"),zones:grants.get(&user_id).cloned().unwrap_or_default(),user_id,expires_at});
 }
    tx.commit().await?;
    Ok(Snapshot {
        revision: settings.get("revision"),
        token_qps: settings.get::<i32, _>("token_qps") as u32,
        zones,
        records,
        credentials,
    })
}
pub async fn reload(app: &App) -> ApiResult<()> {
    match snapshot(app.pool()?).await {
        Ok(snap) => {
            app.install(
                snap,
                Some(std::time::Instant::now() + std::time::Duration::from_secs(LEASE_SECONDS)),
            );
            Ok(())
        }
        Err(error) => {
            app.clear();
            Err(error.into())
        }
    }
}
pub async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    actor: &str,
    action: &str,
    target: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit_events(actor,action,target,created_at) VALUES(?,?,?,?)")
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(now())
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE settings SET revision=revision+1 WHERE id=1")
        .execute(&mut **tx)
        .await?;
    Ok(())
}
pub async fn save_report(
    pool: &MySqlPool,
    node_id: &str,
    report: &Report,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let fresh = sqlx::query(
        "INSERT IGNORE INTO metric_reports(report_id,node_id,created_at) VALUES(?,?,?)",
    )
    .bind(&report.id)
    .bind(node_id)
    .bind(now())
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    if fresh {
        for m in &report.metrics {
            sqlx::query("INSERT INTO metrics(node_id,bucket,total,success,denied,errors,latency_us) VALUES(?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE total=total+VALUES(total),success=success+VALUES(success),denied=denied+VALUES(denied),errors=errors+VALUES(errors),latency_us=latency_us+VALUES(latency_us)").bind(node_id).bind(m.bucket).bind(m.total).bind(m.success).bind(m.denied).bind(m.errors).bind(m.latency_us).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}
pub async fn admin_init(
    pool: &MySqlPool,
    username: &str,
    password: Option<String>,
    reset: bool,
) -> anyhow::Result<()> {
    let existing = sqlx::query("SELECT id FROM admins WHERE username=?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    if existing.is_some() && !reset {
        return Ok(());
    }
    let password = password.ok_or_else(|| {
        anyhow::anyhow!(
            "Set DNSDOH_ADMIN_PASSWORD to initialize or reset the administrator (minimum 12 bytes)"
        )
    })?;
    security::validate_password(&password).map_err(|e| anyhow::anyhow!(e.message))?;
    let hash = tokio::task::spawn_blocking(move || security::hash_password(&password)).await??;
    let mut tx = pool.begin().await?;
    if let Some(row) = existing {
        let id: String = row.get("id");
        sqlx::query("UPDATE admins SET password_hash=? WHERE id=?")
            .bind(hash)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE admin_id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("INSERT INTO admins(id,username,password_hash,created_at) VALUES(?,?,?,?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(username)
            .bind(hash)
            .bind(now())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
