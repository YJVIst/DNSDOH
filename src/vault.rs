use crate::state::{ApiError, ApiResult};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;

fn cipher() -> ApiResult<Aes256Gcm> {
    let raw = std::env::var("DNSDOH_MASTER_KEY")
        .map_err(|_| ApiError::bad("主控尚未配置 DNSDOH_MASTER_KEY，无法安全保存供应商凭据"))?;
    let key = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| ApiError::bad("主控加密密钥格式错误"))?;
    Aes256Gcm::new_from_slice(&key).map_err(|_| ApiError::bad("主控加密密钥长度错误"))
}
pub fn seal(context: &str, plain: &[u8]) -> ApiResult<String> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher()?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| ApiError::bad("凭据加密失败"))?;
    let mut bytes = nonce.to_vec();
    bytes.extend(encrypted);
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub fn open(context: &str, value: &str) -> ApiResult<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad("加密数据损坏"))?;
    if bytes.len() < 28 {
        return Err(ApiError::bad("加密数据损坏"));
    }
    cipher()?
        .decrypt(
            Nonce::from_slice(&bytes[..12]),
            Payload {
                msg: &bytes[12..],
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| ApiError::bad("无法解密凭据，请恢复原主控加密密钥"))
}
