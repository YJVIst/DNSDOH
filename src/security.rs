use crate::state::{ApiError, ApiResult};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
pub fn hash_password(value: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(value.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|_| anyhow::anyhow!("password hash failed"))?
        .to_string())
}
pub fn check_password(value: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| {
        Argon2::default()
            .verify_password(value.as_bytes(), &h)
            .is_ok()
    })
}
pub fn validate_password(value: &str) -> ApiResult<()> {
    if !(12..=128).contains(&value.len()) {
        Err(ApiError::bad("密码需为 12–128 字节"))
    } else {
        Ok(())
    }
}
pub fn text(value: &str, max: usize, label: &str) -> ApiResult<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(ApiError::bad(format!("{label}不能为空、过长或含控制字符")));
    }
    Ok(value.to_string())
}
pub fn note(value: &str) -> ApiResult<String> {
    if value.chars().count() > 500 || value.chars().any(|c| c.is_control() && c != '\n') {
        Err(ApiError::bad("备注过长或包含控制字符"))
    } else {
        Ok(value.trim().to_string())
    }
}
pub fn domain(value: &str) -> ApiResult<String> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty()
        || value.contains('*')
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
        || value.parse::<IpAddr>().is_ok()
    {
        return Err(ApiError::bad("请输入完整域名，不支持通配符或 IP"));
    }
    let name = hickory_proto::rr::Name::from_utf8(value)
        .map_err(|_| ApiError::bad("域名格式不正确"))?
        .to_ascii()
        .trim_end_matches('.')
        .to_lowercase();
    if name.len() > 253
        || !name.contains('.')
        || !name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(ApiError::bad("域名格式不正确"));
    }
    Ok(name)
}
pub fn inside(name: &str, zone: &str) -> bool {
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}
pub fn endpoint(value: &str) -> ApiResult<String> {
    let url =
        url::Url::parse(value.trim()).map_err(|_| ApiError::bad("请输入有效的 HTTPS 地址"))?;
    let local = url.host().is_some_and(|h| match h {
        url::Host::Domain(name) => name == "localhost",
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    });
    if (url.scheme() != "https" && !(local && url.scheme() == "http"))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ApiError::bad(
            "地址必须是 HTTPS 根地址，不含路径、凭据或参数；本机测试允许 HTTP",
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zone_boundaries() {
        assert!(inside("a.nodes.example.com", "nodes.example.com"));
        assert!(!inside("evilnodes.example.com", "nodes.example.com"));
        assert!(!inside("nodes.example.com.evil", "nodes.example.com"));
    }
    #[test]
    fn entropy_and_digest() {
        let a = secret();
        assert_eq!(a.len(), 43);
        assert_ne!(a, secret());
        assert_eq!(digest(&a).len(), 64);
    }
    #[test]
    fn input_validation() {
        assert_eq!(domain("NODE.Example.COM.").unwrap(), "node.example.com");
        for v in ["*.example.com", "example.com/evil", "x\ny.com", "127.0.0.1"] {
            assert!(domain(v).is_err());
        }
        assert!(endpoint("https://user:pass@example.com").is_err());
        assert!(endpoint("http://example.com").is_err());
        assert!(endpoint("https://doh.example.com/").is_ok());
    }
}
