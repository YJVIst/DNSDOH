//! DNS APIs. Credentials never appear in request URLs or error/log strings.
use crate::{
    model::now,
    state::{ApiError, ApiResult},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub key_secret: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub account_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub owned: bool,
}
#[derive(Clone)]
pub struct Provider {
    pub kind: String,
    pub credentials: Credentials,
    pub http: reqwest::Client,
}
pub fn hmac256(key: &[u8], input: &str) -> Vec<u8> {
    let mut h = Hmac::<Sha256>::new_from_slice(key).expect("HMAC");
    h.update(input.as_bytes());
    h.finalize().into_bytes().to_vec()
}
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
fn failure(code: &str) -> ApiError {
    ApiError::bad(format!(
        "DNS 供应商调用失败（{code}），请检查权限、域名状态与账户套餐"
    ))
}
fn owner_tag() -> String {
    format!(
        "DNSDOH:{}",
        &crate::security::digest(&std::env::var("DNSDOH_MASTER_KEY").unwrap_or_default())[..16]
    )
}
fn owned_record(record: &Value) -> bool {
    record["comment"]
        .as_str()
        .is_some_and(|s| s.starts_with(&owner_tag()))
        || std::env::var("DNSDOH_LEGACY_RECORD_IDS")
            .unwrap_or_default()
            .split(',')
            .any(|id| !id.is_empty() && record["id"] == id)
}
impl Provider {
    pub fn new(kind: &str, credentials: Credentials) -> ApiResult<Self> {
        if !["cloudflare", "alidns", "dnspod"].contains(&kind) {
            return Err(ApiError::bad("不支持的 DNS 供应商"));
        }
        if kind == "cloudflare" {
            if credentials.token.is_empty()
                && (credentials.email.is_empty() || credentials.key_secret.is_empty())
            {
                return Err(ApiError::bad("请输入 API Token"));
            }
        } else if credentials.key_id.is_empty() || credentials.key_secret.is_empty() {
            return Err(ApiError::bad("请输入 Access/Secret ID 和密钥"));
        }
        if [
            &credentials.token,
            &credentials.key_id,
            &credentials.key_secret,
            &credentials.email,
        ]
        .iter()
        .any(|s| s.len() > 4096 || s.chars().any(char::is_control))
        {
            return Err(ApiError::bad("凭据格式不正确"));
        }
        Ok(Self {
            kind: kind.into(),
            credentials,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| failure("HTTP"))?,
        })
    }
    fn base(&self) -> String {
        if std::env::var("DNSDOH_TEST_MODE").as_deref() == Ok("true") {
            if let Ok(url) = std::env::var("DNSDOH_PROVIDER_TEST_URL") {
                return format!("{url}/{}", self.kind);
            }
        }
        match self.kind.as_str() {
            "cloudflare" => "https://api.cloudflare.com/client/v4",
            "alidns" => "https://alidns.aliyuncs.com",
            _ => "https://dnspod.tencentcloudapi.com",
        }
        .into()
    }
    async fn result(&self, request: reqwest::RequestBuilder) -> ApiResult<Value> {
        let response = request.send().await.map_err(|_| failure("连接或 TLS"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(failure(&format!("HTTP {}", status.as_u16())));
        }
        let body = response.bytes().await.map_err(|_| failure("响应读取"))?;
        if body.len() > 8 * 1024 * 1024 {
            return Err(failure("响应过大"));
        }
        serde_json::from_slice(&body).map_err(|_| failure("响应格式"))
    }
    pub async fn cf(&self, method: &str, path: &str, body: Option<Value>) -> ApiResult<Value> {
        let request = self
            .http
            .request(method.parse().unwrap(), format!("{}{path}", self.base()));
        let mut request = if !self.credentials.token.is_empty() {
            request.bearer_auth(&self.credentials.token)
        } else {
            request
                .header("x-auth-email", &self.credentials.email)
                .header("x-auth-key", &self.credentials.key_secret)
        };
        if let Some(body) = body {
            request = request.json(&body);
        }
        let value = self.result(request).await?;
        if value["success"] != true {
            return Err(failure("API 拒绝"));
        }
        Ok(value)
    }
    async fn rpc(&self, action: &str, params: Value) -> ApiResult<Value> {
        if self.kind == "alidns" {
            let mut args: BTreeMap<String, String> = params
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| v.to_string()),
                    )
                })
                .collect();
            for (k, v) in [
                ("Action", action.to_string()),
                ("AccessKeyId", self.credentials.key_id.clone()),
                ("Format", "JSON".into()),
                ("Version", "2015-01-09".into()),
                ("SignatureMethod", "HMAC-SHA1".into()),
                ("SignatureVersion", "1.0".into()),
                ("SignatureNonce", uuid::Uuid::new_v4().to_string()),
                (
                    "Timestamp",
                    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                ),
            ] {
                args.insert(k.into(), v);
            }
            let canonical = args
                .iter()
                .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            let text = format!("POST&%2F&{}", encode(&canonical));
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(
                format!("{}&", self.credentials.key_secret).as_bytes(),
            )
            .unwrap();
            mac.update(text.as_bytes());
            args.insert(
                "Signature".into(),
                STANDARD.encode(mac.finalize().into_bytes()),
            );
            let value = self
                .result(self.http.post(format!("{}/", self.base())).form(&args))
                .await?;
            if value.get("Code").is_some() {
                return Err(failure("AliDNS API"));
            }
            Ok(value)
        } else {
            let timestamp = now();
            let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
            let body = serde_json::to_vec(&params).unwrap();
            let canonical = format!(
                "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:dnspod.tencentcloudapi.com\n\ncontent-type;host\n{}",
                hex::encode(Sha256::digest(&body))
            );
            let scope = format!("{date}/dnspod/tc3_request");
            let to_sign = format!(
                "TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
                hex::encode(Sha256::digest(canonical.as_bytes()))
            );
            let date_key = hmac256(
                format!("TC3{}", self.credentials.key_secret).as_bytes(),
                &date,
            );
            let service = hmac256(&date_key, "dnspod");
            let signing = hmac256(&service, "tc3_request");
            let authorization = format!(
                "TC3-HMAC-SHA256 Credential={}/{scope}, SignedHeaders=content-type;host, Signature={}",
                self.credentials.key_id,
                hex::encode(hmac256(&signing, &to_sign))
            );
            let value = self
                .result(
                    self.http
                        .post(format!("{}/", self.base()))
                        .header("content-type", "application/json; charset=utf-8")
                        .header("authorization", authorization)
                        .header("x-tc-action", action)
                        .header("x-tc-version", "2021-03-23")
                        .header("x-tc-timestamp", timestamp.to_string())
                        .body(body),
                )
                .await?;
            if action == "DescribeRecordList"
                && value["Response"]["Error"]["Code"] == "ResourceNotFound.NoDataOfRecord"
            {
                return Ok(json!({"RecordList":[]}));
            }
            if value["Response"].get("Error").is_some() {
                return Err(failure("DNSPod API"));
            }
            Ok(value["Response"].clone())
        }
    }
    pub async fn zones(&self) -> ApiResult<Vec<Zone>> {
        let mut all = Vec::new();
        for page in 1..=1000 {
            let rows: Vec<Value> = match self.kind.as_str() {
                "cloudflare" => self
                    .cf("GET", &format!("/zones?per_page=50&page={page}"), None)
                    .await?["result"]
                    .as_array()
                    .cloned()
                    .ok_or_else(|| failure("Zone 列表"))?,
                "alidns" => self
                    .rpc("DescribeDomains", json!({"PageNumber":page,"PageSize":100}))
                    .await?["Domains"]["Domain"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
                _ => self
                    .rpc(
                        "DescribeDomainList",
                        json!({"Offset":(page-1)*100,"Limit":100}),
                    )
                    .await?["DomainList"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            };
            let count = rows.len();
            for row in rows {
                let z = match self.kind.as_str() {
                    "cloudflare" => Zone {
                        id: row["id"].as_str().unwrap_or_default().into(),
                        name: row["name"].as_str().unwrap_or_default().into(),
                        status: row["status"].as_str().unwrap_or_default().into(),
                        account_id: row["account"]["id"].as_str().unwrap_or_default().into(),
                    },
                    "alidns" => Zone {
                        id: row["DomainName"].as_str().unwrap_or_default().into(),
                        name: row["DomainName"].as_str().unwrap_or_default().into(),
                        status: "active".into(),
                        account_id: String::new(),
                    },
                    _ => Zone {
                        id: row["DomainId"].to_string(),
                        name: row["Name"].as_str().unwrap_or_default().into(),
                        status: if row["Status"] == "ENABLE" {
                            "active"
                        } else {
                            "disabled"
                        }
                        .into(),
                        account_id: String::new(),
                    },
                };
                if !z.id.is_empty() && !z.name.is_empty() {
                    all.push(z);
                }
            }
            if count < if self.kind == "cloudflare" { 50 } else { 100 } {
                return Ok(all);
            }
        }
        Err(failure("域名分页超出限制"))
    }
    pub async fn records(&self, zone: &Zone, name: &str) -> ApiResult<Vec<Record>> {
        let mut all = Vec::new();
        for page in 1..=1000 {
            let rows:Vec<Value>=match self.kind.as_str(){
            "cloudflare"=>self.cf("GET",&format!("/zones/{}/dns_records?name={}&per_page=100&page={page}",encode(&zone.id),encode(name)),None).await?["result"].as_array().cloned().unwrap_or_default(),
            "alidns"=>self.rpc("DescribeDomainRecords",json!({"DomainName":zone.name,"PageNumber":page,"PageSize":100,"RRKeyWord":relative(name,&zone.name)})).await?["DomainRecords"]["Record"].as_array().cloned().unwrap_or_default(),
            _=>self.rpc("DescribeRecordList",json!({"Domain":zone.name,"Offset":(page-1)*100,"Limit":100})).await?["RecordList"].as_array().cloned().unwrap_or_default()
        };
            let count = rows.len();
            for r in rows {
                let record = match self.kind.as_str() {
                    "cloudflare" => Record {
                        id: r["id"].as_str().unwrap_or_default().into(),
                        name: r["name"].as_str().unwrap_or_default().into(),
                        kind: r["type"].as_str().unwrap_or_default().into(),
                        value: r["content"].as_str().unwrap_or_default().into(),
                        owned: owned_record(&r),
                    },
                    "alidns" => Record {
                        id: r["RecordId"].as_str().unwrap_or_default().into(),
                        name: full(r["RR"].as_str().unwrap_or_default(), &zone.name),
                        kind: r["Type"].as_str().unwrap_or_default().into(),
                        value: r["Value"].as_str().unwrap_or_default().into(),
                        owned: false,
                    },
                    _ => Record {
                        id: r["RecordId"].to_string(),
                        name: full(r["Name"].as_str().unwrap_or_default(), &zone.name),
                        kind: r["Type"].as_str().unwrap_or_default().into(),
                        value: r["Value"].as_str().unwrap_or_default().into(),
                        owned: false,
                    },
                };
                if record.name == name {
                    all.push(record);
                }
            }
            if count < 100 {
                return Ok(all);
            }
        }
        Err(failure("记录分页超出限制"))
    }
    pub async fn create(
        &self,
        zone: &Zone,
        name: &str,
        kind: &str,
        value: &str,
    ) -> ApiResult<Record> {
        let id=match self.kind.as_str(){
        "cloudflare"=>self.cf("POST",&format!("/zones/{}/dns_records",zone.id),Some(json!({"name":name,"type":kind,"content":value,"ttl":60,"proxied":false,"comment":format!("{} managed direct resolver",owner_tag())}))).await?["result"]["id"].as_str().map(str::to_owned).ok_or_else(||failure("record ID"))?,
        "alidns"=>self.rpc("AddDomainRecord",json!({"DomainName":zone.name,"RR":relative(name,&zone.name),"Type":kind,"Value":value,"TTL":600})).await?["RecordId"].as_str().map(str::to_owned).ok_or_else(||failure("record ID"))?,
        _=>self.rpc("CreateRecord",json!({"Domain":zone.name,"SubDomain":relative(name,&zone.name),"RecordType":kind,"RecordLine":"默认","Value":value,"TTL":600})).await?["RecordId"].as_u64().ok_or_else(||failure("record ID"))?.to_string()
    };
        Ok(Record {
            id,
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
            owned: true,
        })
    }
    pub async fn delete(&self, zone: &Zone, id: &str) -> ApiResult<()> {
        match self.kind.as_str() {
            "cloudflare" => {
                self.cf(
                    "DELETE",
                    &format!("/zones/{}/dns_records/{}", zone.id, encode(id)),
                    None,
                )
                .await?;
            }
            "alidns" => {
                self.rpc("DeleteDomainRecord", json!({"RecordId":id}))
                    .await?;
            }
            _ => {
                self.rpc("DeleteRecord",json!({"Domain":zone.name,"RecordId":id.parse::<u64>().map_err(|_|failure("record ID"))?})).await?;
            }
        }
        Ok(())
    }
}
fn relative<'a>(name: &'a str, zone: &str) -> &'a str {
    if name == zone {
        "@"
    } else {
        name.strip_suffix(&format!(".{zone}")).unwrap_or(name)
    }
}
fn full(label: &str, zone: &str) -> String {
    if label == "@" {
        zone.into()
    } else {
        format!("{label}.{zone}")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_encoding() {
        assert_eq!(encode("a /+~"), "a%20%2F%2B~");
        assert_eq!(relative("doh.example.com", "example.com"), "doh");
        assert_eq!(full("@", "example.com"), "example.com");
    }
    #[tokio::test]
    #[ignore = "run by tests/providers.py with independent local signing fixtures"]
    async fn provider_lifecycle_contract() {
        assert_eq!(std::env::var("DNSDOH_TEST_MODE").as_deref(), Ok("true"));
        assert!(
            std::env::var("DNSDOH_PROVIDER_TEST_URL")
                .unwrap()
                .starts_with("http://127.0.0.1:")
        );
        for (kind, credentials) in [
            ("cloudflare", json!({"token":"cf-contract-token"})),
            (
                "alidns",
                json!({"key_id":"ali-contract-id","key_secret":"ali-contract-secret"}),
            ),
            (
                "dnspod",
                json!({"key_id":"dnspod-contract-id","key_secret":"dnspod-contract-secret"}),
            ),
        ] {
            let p = Provider::new(kind, serde_json::from_value(credentials).unwrap()).unwrap();
            let z = p.zones().await.unwrap().remove(0);
            for (label, typ, value) in [
                ("doh", "A", "192.0.2.10"),
                ("doh6", "AAAA", "2001:db8::10"),
                ("_acme-challenge.doh", "TXT", "test-challenge"),
            ] {
                let name = format!("{label}.{}", z.name);
                let created = p.create(&z, &name, typ, value).await.unwrap();
                let listed = p.records(&z, &name).await.unwrap();
                assert!(
                    listed
                        .iter()
                        .any(|r| r.id == created.id && r.kind == typ && r.value == value)
                );
                if kind == "cloudflare" {
                    assert!(listed.iter().all(|r| r.owned));
                }
                p.delete(&z, &created.id).await.unwrap();
                assert!(p.records(&z, &name).await.unwrap().is_empty());
            }
        }
    }
}
