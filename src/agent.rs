use crate::{
    certificates::{self, Binding},
    enrollment, infra,
    model::now,
    security,
    state::{ApiError, ApiResult, App},
};
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use std::{io::Write, net::SocketAddr, path::Path, process::Command, time::Duration};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub node_id: String,
    pub applied_revision: i64,
}
#[derive(Serialize, Deserialize)]
pub struct ControlResponse {
    pub bindings: Vec<Binding>,
    pub controller_ip: String,
}
pub async fn control(
    State(app): State<App>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<ControlResponse>> {
    let input: ControlRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad("Invalid control request"))?;
    let denied = || ApiError::new(StatusCode::FORBIDDEN, "Node control signature rejected");
    let _lock = app.0.mutation.lock().await;
    let key: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM nodes WHERE id=? AND enabled=1 AND deleted_at IS NULL",
    )
    .bind(&input.node_id)
    .fetch_optional(app.pool()?)
    .await?
    .flatten();
    let nonce = enrollment::verify_request(
        &key.ok_or_else(denied)?,
        &format!("{}/control", input.node_id),
        &headers,
        &body,
    )?;
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
    sqlx::query("UPDATE nodes SET domain_revision=? WHERE id=?")
        .bind(input.applied_revision)
        .bind(&input.node_id)
        .execute(app.pool()?)
        .await?;
    let address = infra::active(&app)
        .await?
        .map(|d| d.controller_ip)
        .unwrap_or_default();
    Ok(Json(ControlResponse {
        bindings: certificates::bindings(&app).await?,
        controller_ip: address,
    }))
}
pub fn client(controller: &str, pin: Option<&str>) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(ip) = pin.filter(|s| !s.is_empty()) {
        let url = url::Url::parse(controller)?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Controller hostname missing"))?;
        builder = builder.resolve(
            host,
            SocketAddr::new(ip.parse()?, url.port_or_known_default().unwrap_or(443)),
        );
    }
    Ok(builder.build()?)
}
pub async fn maintain(
    controller: &str,
    id: &str,
    bind: SocketAddr,
    root: &Path,
) -> anyhow::Result<()> {
    let key = ed25519_dalek::SigningKey::from_bytes(&enrollment::decode_key(&std::env::var(
        "DNSDOH_NODE_PRIVATE_KEY",
    )?)?);
    let revision = std::fs::read_to_string(root.join("run/domain-revision"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let body = serde_json::to_vec(&ControlRequest {
        node_id: id.into(),
        applied_revision: revision,
    })?;
    let (time, nonce, signature) = enrollment::sign_request(&key, &format!("{id}/control"), &body);
    let pin = std::env::var("DNSDOH_CONTROLLER_IP").ok();
    let http = client(controller, pin.as_deref())?;
    let response = http
        .post(format!("{controller}/internal/node/control"))
        .header("content-type", "application/json")
        .header("x-dnsdoh-time", time)
        .header("x-dnsdoh-nonce", nonce)
        .header("x-dnsdoh-signature", signature)
        .body(body)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Control HTTPS connection failed"))?;
    if !response.status().is_success() {
        anyhow::bail!(
            "Control request rejected: HTTP {}",
            response.status().as_u16()
        );
    }
    let response: ControlResponse = response
        .json()
        .await
        .map_err(|_| anyhow::anyhow!("Invalid control response"))?;
    if response.bindings.is_empty() {
        anyhow::bail!("No unified domain certificate is available yet");
    }
    let revision = apply(
        &response.bindings,
        bind,
        root,
        Path::new("/etc/nginx/conf.d/dnsdoh-node.conf"),
    )?;
    private_write(
        &root.join("run/domain-revision"),
        revision.to_string().as_bytes(),
        0o600,
    )?;
    Ok(())
}
pub async fn controller_maintain(
    pool: sqlx::MySqlPool,
    bind: SocketAddr,
    root: &Path,
    config: &Path,
) -> anyhow::Result<()> {
    let app = App::new(Some(pool), String::new(), String::new(), None, false);
    let bindings = certificates::bindings(&app)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    if bindings.is_empty() {
        return Ok(());
    }
    apply(&bindings, bind, root, config)?;
    for binding in bindings {
        sqlx::query("UPDATE dns_domains SET controller_applied=? WHERE id=?")
            .bind(binding.revision)
            .bind(binding.id)
            .execute(app.pool().map_err(|e| anyhow::anyhow!(e.message))?)
            .await?;
    }
    Ok(())
}
pub fn private_write(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(temporary, path)?;
    Ok(())
}
const MARKER: &str = "# Managed by DNSDOH node installer\n";
pub fn apply(
    bindings: &[Binding],
    bind: SocketAddr,
    root: &Path,
    config: &Path,
) -> anyhow::Result<i64> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    if !bind.ip().is_loopback() {
        anyhow::bail!("Backend listener must be loopback");
    }
    let mut text = MARKER.to_string();
    let mut revision = 0;
    for binding in bindings {
        let host = security::domain(&binding.hostname).map_err(|e| anyhow::anyhow!(e.message))?;
        uuid::Uuid::parse_str(&binding.id)?;
        // A content-addressed path preserves the previous working key/cert during nginx validation.
        let digest = hex::encode(Sha256::digest(
            format!("{}{}", binding.certificate.chain, binding.certificate.key).as_bytes(),
        ));
        let dir = root
            .join("tls")
            .join(format!("{}-{}", binding.id, &digest[..16]));
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        private_write(
            &dir.join("fullchain.pem"),
            binding.certificate.chain.as_bytes(),
            0o600,
        )?;
        private_write(
            &dir.join("privkey.pem"),
            binding.certificate.key.as_bytes(),
            0o600,
        )?;
        if Command::new("getenforce").output().is_ok_and(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).trim() != "Disabled"
        }) {
            let output = Command::new("restorecon")
                .args(["-RF"])
                .arg(&dir)
                .output()?;
            if !output.status.success() {
                anyhow::bail!("SELinux certificate context update failed");
            }
        }
        revision = revision.max(binding.revision);
        let path = dir.display();
        text.push_str(&format!("server {{\n listen 443 ssl;\n listen [::]:443 ssl;\n server_name {host};\n ssl_certificate {path}/fullchain.pem;\n ssl_certificate_key {path}/privkey.pem;\n ssl_protocols TLSv1.2 TLSv1.3;\n ssl_session_tickets off;\n access_log off;\n error_log /dev/null crit;\n client_max_body_size 64k;\n client_body_buffer_size 64k;\n add_header Strict-Transport-Security \"max-age=31536000\" always;\n location /dns-query/ {{ proxy_pass http://{bind}; proxy_set_header X-Real-IP $remote_addr; proxy_set_header Host $host; proxy_read_timeout 10s; proxy_buffering off; proxy_cache off; }}\n location = /readyz {{ proxy_pass http://{bind}; }}\n location = /healthz {{ proxy_pass http://{bind}; }}\n location / {{ return 404; }}\n}}\nserver {{\n listen 80;\n listen [::]:80;\n server_name {host};\n access_log off;\n error_log /dev/null crit;\n location /dns-query/ {{ return 400; }}\n location / {{ return 308 https://$host$request_uri; }}\n}}\n"));
    }
    let old = std::fs::read(config).ok();
    if let Some(old) = &old {
        if !old.starts_with(MARKER.as_bytes()) {
            anyhow::bail!("Refusing to overwrite an unmanaged nginx configuration");
        }
        if old == text.as_bytes() {
            return Ok(revision);
        }
    }
    private_write(config, text.as_bytes(), 0o644)?;
    let checked = Command::new("nginx").arg("-t").output()?;
    if !checked.status.success() {
        if let Some(old) = old {
            private_write(config, &old, 0o644)?;
        } else {
            std::fs::remove_file(config)?;
        }
        anyhow::bail!("nginx configuration validation failed; previous config restored");
    }
    let mut cmd = if Path::new("/run/systemd/system").exists() {
        let mut c = Command::new("systemctl");
        c.args(["reload", "nginx"]);
        c
    } else {
        let mut c = Command::new("rc-service");
        c.args(["nginx", "reload"]);
        c
    };
    if !cmd.status()?.success() {
        if let Some(old) = old {
            private_write(config, &old, 0o644)?;
        }
        anyhow::bail!("nginx reload failed; previous configuration restored");
    }
    Ok(revision)
}
