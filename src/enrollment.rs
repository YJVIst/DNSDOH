use crate::{
    auth,
    model::now,
    security,
    state::{ApiError, ApiResult, App},
    storage,
};
use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{net::SocketAddr, path::Path as FilePath, time::Duration};

pub const INSTALLER: &str = include_str!("../scripts/install-node.py");
pub const TICKET_TTL: i64 = 900;
pub fn installer_hash() -> String {
    hex::encode(Sha256::digest(INSTALLER.as_bytes()))
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
pub fn command(controller: &str, ticket: &str, id: &str, endpoint: &str) -> String {
    let hash = installer_hash();
    let bootstrap = "if ! command -v curl >/dev/null || ! command -v python3 >/dev/null; then if command -v apt-get >/dev/null; then apt-get update -qq; apt-get install -y curl python3 ca-certificates; elif command -v apk >/dev/null; then apk add curl python3 ca-certificates; elif command -v dnf >/dev/null; then dnf install -y curl python3 ca-certificates; elif command -v yum >/dev/null; then yum install -y curl python3 ca-certificates; elif command -v zypper >/dev/null; then zypper --non-interactive install curl python3 ca-certificates; elif command -v pacman >/dev/null; then pacman --noconfirm --needed -S curl python ca-certificates; else echo 'Unsupported package manager'; exit 1; fi; fi";
    let script = format!(
        "set -eu; [ \"$(id -u)\" -eq 0 ] || {{ echo 'Run as root'; exit 1; }}; umask 077; node_root=\"${{DNSDOH_NODE_ROOT:-/opt/dnsdoh-node}}\"; case \"$node_root\" in /*) ;; *) echo 'Node root must be absolute'; exit 1;; esac; case \"$node_root\" in *[!a-zA-Z0-9_./-]*|/|/opt|/usr|/var|/etc|/mnt|/srv|/tmp|/tmp/*|/var/tmp|/var/tmp/*|/root|/root/*|/home|/home/*|*/../*|*/./*|*/..|*/.|*//*|*/) echo 'Invalid node root'; exit 1;; esac; check_path=\"$node_root\"; while [ \"$check_path\" != / ]; do [ ! -L \"$check_path\" ] || exit 1; check_path=$(dirname \"$check_path\"); done; [ -d \"$node_root\" ] || install -d -m 755 \"$node_root\"; mkdir -p \"$node_root/tmp\"; export TMPDIR=\"$node_root/tmp\"; {bootstrap}; d=$(mktemp -d \"$TMPDIR/dnsdoh-install.XXXXXX\"); trap 'rm -rf \"$d\"' EXIT; curl --proto '=https' --tlsv1.2 --fail --silent --show-error {} -o \"$d/install.py\"; printf '%s  %s\\n' {} \"$d/install.py\" | sha256sum --check --status; python3 \"$d/install.py\" --root \"$node_root\" --controller {} --ticket {} --node-id {} --endpoint {}",
        quote(&format!("{controller}/install/node.py")),
        quote(&hash),
        quote(controller),
        quote(ticket),
        quote(id),
        quote(endpoint)
    );
    format!("sh -c {}", quote(&script))
}
pub async fn issue(app: &App, id: &str) -> ApiResult<Value> {
    let mut tx = app.pool()?.begin().await?;
    let endpoint: Option<String> =
        sqlx::query_scalar("SELECT endpoint FROM nodes WHERE id=? AND enabled=1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let endpoint = endpoint.ok_or_else(|| ApiError::bad("节点不存在或已停用"))?;
    let ticket = security::secret();
    let expires = now() + TICKET_TTL;
    sqlx::query("DELETE FROM node_enrollments WHERE node_id=?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO node_enrollments(token_hash,node_id,expires_at,created_at) VALUES(?,?,?,?)",
    )
    .bind(security::digest(&ticket))
    .bind(id)
    .bind(expires)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(
        json!({"install_command":command(&app.0.public_url,&ticket,id,&endpoint),"install_ticket":ticket,"install_expires_at":expires,"installer_sha256":installer_hash(),"endpoint":endpoint}),
    )
}
pub async fn issue_api(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let who = auth::require(&app, &headers, true).await?;
    let _lock = app.0.mutation.lock().await;
    let result = issue(&app, &id).await?;
    sqlx::query("INSERT INTO audit_events(actor,action,target,created_at) VALUES(?,?,?,?)")
        .bind(who.username)
        .bind("生成单次安装命令")
        .bind(&id)
        .bind(now())
        .execute(app.pool()?)
        .await?;
    Ok(Json(result))
}
pub async fn script() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/x-python; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        INSTALLER,
    )
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollInput {
    pub ticket: String,
    pub node_id: String,
    pub endpoint: String,
    pub public_key: String,
}
#[derive(Deserialize, Serialize)]
pub struct EnrollResponse {
    pub node_id: String,
    pub endpoint: String,
    pub controller_url: String,
    pub auth_mode: String,
    #[serde(default)]
    pub controller_ip: String,
}
pub async fn redeem(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<EnrollInput>,
) -> ApiResult<Json<EnrollResponse>> {
    if !app.allow(
        format!("enrollment:{}", auth::client_ip(&app, peer, &headers)),
        20,
        Duration::from_secs(60),
    ) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many enrollment attempts",
        ));
    }
    let denied = || {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "Installation ticket is invalid, expired or already used",
        )
    };
    if input.ticket.len() != 43 || uuid::Uuid::parse_str(&input.node_id).is_err() {
        return Err(denied());
    }
    let public =
        decode_key(&input.public_key).map_err(|_| ApiError::bad("Invalid node public key"))?;
    if VerifyingKey::from_bytes(&public)
        .map_err(|_| ApiError::bad("Invalid node public key"))?
        .is_weak()
    {
        return Err(ApiError::bad("Invalid node public key"));
    }
    let _lock = app.0.mutation.lock().await;
    let mut tx = app.pool()?.begin().await?;
    let row=sqlx::query("SELECT e.node_id,n.endpoint FROM node_enrollments e JOIN nodes n ON n.id=e.node_id WHERE e.token_hash=? AND e.expires_at>? AND n.enabled=1 FOR UPDATE").bind(security::digest(&input.ticket)).bind(now()).fetch_optional(&mut *tx).await?.ok_or_else(denied)?;
    let node_id: String = row.get("node_id");
    let endpoint: String = row.get("endpoint");
    if node_id != input.node_id || endpoint != input.endpoint {
        return Err(denied());
    }
    sqlx::query("DELETE FROM node_enrollments WHERE node_id=?")
        .bind(&node_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE nodes SET public_key=?,secret_hash=?,last_seen=NULL,applied_revision=0 WHERE id=?",
    )
    .bind(&input.public_key)
    .bind(security::digest(&security::secret()))
    .bind(&node_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM node_nonces WHERE node_id=?")
        .bind(&node_id)
        .execute(&mut *tx)
        .await?;
    storage::audit(&mut tx, "节点安装", "启用节点签名认证", &node_id).await?;
    tx.commit().await?;
    storage::reload(&app).await?;
    Ok(Json(EnrollResponse {
        node_id,
        endpoint,
        controller_url: app.0.public_url.clone(),
        auth_mode: "ed25519".into(),
        controller_ip: crate::infra::active(&app)
            .await?
            .map(|d| d.controller_ip)
            .unwrap_or_default(),
    }))
}
pub fn decode_key(value: &str) -> anyhow::Result<[u8; 32]> {
    Ok(URL_SAFE_NO_PAD
        .decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?)
}
pub fn signing_bytes(id: &str, timestamp: &str, nonce: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "DNSDOH-SYNC-V1\n{id}\n{timestamp}\n{nonce}\n{}",
        hex::encode(Sha256::digest(body))
    )
    .into_bytes()
}
pub fn sign_request(key: &SigningKey, id: &str, body: &[u8]) -> (String, String, String) {
    let timestamp = now().to_string();
    let nonce = security::secret();
    let sig = key.sign(&signing_bytes(id, &timestamp, &nonce, body));
    (timestamp, nonce, URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}
pub fn verify_request(
    public: &str,
    id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> ApiResult<String> {
    let denied = || ApiError::new(StatusCode::FORBIDDEN, "Node signature rejected");
    let timestamp = headers
        .get("x-dnsdoh-time")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(denied)?;
    let time = timestamp.parse::<i64>().map_err(|_| denied())?;
    if time.abs_diff(now()) > 30 {
        return Err(denied());
    }
    let nonce = headers
        .get("x-dnsdoh-nonce")
        .and_then(|v| v.to_str().ok())
        .filter(|n| {
            n.len() == 43
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .ok_or_else(denied)?;
    let signature = headers
        .get("x-dnsdoh-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(denied)?;
    let signature =
        Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).map_err(|_| denied())?)
            .map_err(|_| denied())?;
    let key = VerifyingKey::from_bytes(&decode_key(public).map_err(|_| denied())?)
        .map_err(|_| denied())?;
    key.verify_strict(&signing_bytes(id, timestamp, nonce, body), &signature)
        .map_err(|_| denied())?;
    Ok(nonce.to_string())
}
pub async fn enroll_cli(
    controller: &str,
    id: &str,
    endpoint: &str,
    output: &FilePath,
    bind: SocketAddr,
) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    let controller = security::endpoint(controller).map_err(|e| anyhow::anyhow!(e.message))?;
    let endpoint = security::endpoint(endpoint).map_err(|e| anyhow::anyhow!(e.message))?;
    let mut ticket = String::new();
    std::io::stdin().take(100).read_to_string(&mut ticket)?;
    let ticket = ticket.trim().to_string();
    if ticket.len() != 43 {
        anyhow::bail!("Read the 43-character one-time ticket from stdin");
    }
    if output.exists() {
        anyhow::bail!("Refusing to overwrite an existing identity file");
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let input = EnrollInput {
        ticket,
        node_id: id.into(),
        endpoint,
        public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = client
        .post(format!("{controller}/internal/node/enroll"))
        .json(&input)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Enrollment TLS or connection failed"))?;
    if !response.status().is_success() {
        anyhow::bail!("Enrollment rejected (HTTP {})", response.status().as_u16());
    }
    let response = response.json::<EnrollResponse>().await?;
    if response.node_id != id
        || response.endpoint != input.endpoint
        || response.controller_url != controller
    {
        anyhow::bail!("Enrollment identity binding mismatch");
    }
    let text = format!(
        "DNSDOH_MODE=node\nDNSDOH_BIND={bind}\nDNSDOH_PUBLIC_URL={}\nDNSDOH_CONTROLLER_URL={controller}\nDNSDOH_NODE_ID={}\nDNSDOH_NODE_PRIVATE_KEY={}\nDNSDOH_TRUST_PROXY=true\nRUST_LOG=dnsdoh=info\n",
        response.endpoint,
        id,
        URL_SAFE_NO_PAD.encode(key.to_bytes())
    );
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let text = if response.controller_ip.is_empty() {
        text
    } else {
        format!("{text}DNSDOH_CONTROLLER_IP={}\n", response.controller_ip)
    };
    options.open(output)?.write_all(text.as_bytes())?;
    println!("Node enrolled with a locally generated Ed25519 identity");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_bind_request() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let (time, nonce, sig) = sign_request(&key, "node", b"body");
        let mut h = HeaderMap::new();
        h.insert("x-dnsdoh-time", time.parse().unwrap());
        h.insert("x-dnsdoh-nonce", nonce.parse().unwrap());
        h.insert("x-dnsdoh-signature", sig.parse().unwrap());
        let pubkey = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        assert!(verify_request(&pubkey, "node", &h, b"body").is_ok());
        assert!(verify_request(&pubkey, "node", &h, b"changed").is_err());
        assert!(verify_request(&pubkey, "other", &h, b"body").is_err());
        h.insert("x-dnsdoh-time", "0".parse().unwrap());
        assert!(verify_request(&pubkey, "node", &h, b"body").is_err());
    }
    #[test]
    fn command_quotes_input() {
        assert_eq!(quote("a'b"), "'a'\\''b'");
    }
}
