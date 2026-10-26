use crate::{
    infra::{self, Domain},
    model::now,
    providers::Provider,
    state::{ApiError, ApiResult, App},
    vault,
};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub chain: String,
    pub key: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Binding {
    pub id: String,
    pub hostname: String,
    pub revision: i64,
    pub certificate: Certificate,
}
pub async fn bindings(app: &App) -> ApiResult<Vec<Binding>> {
    let mut result = Vec::new();
    for d in infra::domains(app)
        .await?
        .into_iter()
        .filter(|d| matches!(d.state.as_str(), "active" | "preparing" | "retiring"))
    {
        if let Some(encrypted) = d.certificate {
            let certificate =
                serde_json::from_slice(&vault::open(&format!("certificate:{}", d.id), &encrypted)?)
                    .map_err(|_| ApiError::bad("证书存储格式错误"))?;
            result.push(Binding {
                id: d.id,
                hostname: d.hostname,
                revision: d.revision,
                certificate,
            });
        }
    }
    Ok(result)
}
fn error(stage: &str) -> ApiError {
    ApiError::bad(format!(
        "证书{stage}失败，请检查 DNS API 写入权限、CAA、NS 委派与 ACME 连通性，再点击修复"
    ))
}
pub async fn provision(app: &App, d: &Domain) -> ApiResult<()> {
    let p = infra::provider(app, &d.provider_id).await?;
    let _=sqlx::query("UPDATE infra_jobs SET state='running',stage='通过 DNS-01 验证统一域名并申请证书',updated_at=? WHERE target=? AND kind='domain' AND state IN ('queued','running')").bind(now()).bind(&d.id).execute(app.pool()?).await;
    let result = tokio::time::timeout(Duration::from_secs(600), issue(app, d, &p))
        .await
        .unwrap_or_else(|_| Err(error("申请超时")));
    // The ledger makes challenge cleanup retryable across failures and restarts.
    let rows =
        sqlx::query("SELECT * FROM dns_managed_records WHERE domain_id=? AND purpose='acme'")
            .bind(&d.id)
            .fetch_all(app.pool()?)
            .await?;
    for row in &rows {
        if infra::remove_record(app, d, &p, row).await.is_err() {
            let _ = infra::audit(app, "system", "DNS 验证记录待清理", &d.hostname).await;
        }
    }
    let (cert, expires) = result?;
    let encrypted = vault::seal(
        &format!("certificate:{}", d.id),
        &serde_json::to_vec(&cert).unwrap(),
    )?;
    let _lock = app.0.mutation.lock().await;
    let revision: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(revision),0)+1 FROM dns_domains")
        .fetch_one(app.pool()?)
        .await?;
    sqlx::query("UPDATE dns_domains SET certificate=?,cert_expires=?,revision=?,controller_applied=0,last_error='等待服务器应用 HTTPS 配置' WHERE id=?").bind(encrypted).bind(expires).bind(revision).bind(&d.id).execute(app.pool()?).await?;
    Ok(())
}
async fn issue(app: &App, d: &Domain, p: &Provider) -> ApiResult<(Certificate, i64)> {
    let key = if std::env::var("DNSDOH_ACME_STAGING").as_deref() == Ok("true") {
        "acme-staging"
    } else {
        "acme-production"
    };
    let stored: Option<String> = sqlx::query_scalar("SELECT value FROM infra_secrets WHERE name=?")
        .bind(key)
        .fetch_optional(app.pool()?)
        .await?;
    let builder = Account::builder().map_err(|_| error("客户端初始化"))?;
    let account = if let Some(stored) = stored {
        builder
            .from_credentials(
                serde_json::from_slice(&vault::open(key, &stored)?)
                    .map_err(|_| error("账户读取"))?,
            )
            .await
            .map_err(|_| error("账户恢复"))?
    } else {
        let url = if key == "acme-staging" {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };
        let (account, credentials) = builder
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                url.to_owned(),
                None,
            )
            .await
            .map_err(|_| error("账户创建"))?;
        let encrypted = vault::seal(
            key,
            &serde_json::to_vec(&credentials).map_err(|_| error("账户保存"))?,
        )?;
        sqlx::query("INSERT INTO infra_secrets(name,value) VALUES(?,?)")
            .bind(key)
            .bind(encrypted)
            .execute(app.pool()?)
            .await?;
        account
    };
    let identifiers = [Identifier::Dns(d.hostname.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|_| error("订单创建"))?;
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut auth = result.map_err(|_| error("验证读取"))?;
        if auth.status == AuthorizationStatus::Valid {
            continue;
        }
        if auth.status != AuthorizationStatus::Pending {
            return Err(error("授权状态"));
        }
        let mut challenge = auth
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| error("DNS 验证类型"))?;
        let name = format!("_acme-challenge.{}", d.hostname);
        let value = challenge.key_authorization().dns_value();
        let record = p.create(&d.zone, &name, "TXT", &value).await?;
        infra::track(app, &d.id, "controller", &record, "acme").await?;
        let mut visible = false;
        for _ in 0..36 {
            if let Ok(response) = p
                .http
                .get("https://dns.google/resolve")
                .query(&[("name", name.as_str()), ("type", "TXT")])
                .send()
                .await
            {
                if let Ok(v) = response.json::<serde_json::Value>().await {
                    visible = v["Answer"].as_array().is_some_and(|a| {
                        a.iter().any(|r| {
                            r["data"]
                                .as_str()
                                .is_some_and(|s| s.trim_matches('"') == value)
                        })
                    });
                }
            }
            if visible {
                break;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        if !visible {
            return Err(error("TXT 传播"));
        }
        challenge.set_ready().await.map_err(|_| error("验证提交"))?;
    }
    drop(authorizations);
    if order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|_| error("DNS 验证"))?
        != OrderStatus::Ready
    {
        return Err(error("订单就绪"));
    }
    let key = order.finalize().await.map_err(|_| error("签发"))?;
    let chain = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|_| error("下载"))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain.as_bytes()).map_err(|_| error("解析"))?;
    let cert = pem.parse_x509().map_err(|_| error("解析"))?;
    Ok((
        Certificate { chain, key },
        cert.validity().not_after.timestamp(),
    ))
}
