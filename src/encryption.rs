use anyhow::{Context, Result};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use argon2::Argon2;
use rand::Rng;

use crate::types::EncryptedKey;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const ARGON2_MEMORY: u32 = 65536;  // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

fn encode_b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("base64 decode failed: {}", e))
}

/// Derive a 32-byte AES-256 key from passphrase + salt using Argon2id
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            ARGON2_MEMORY,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(key.len()),
        ).map_err(|e| anyhow::anyhow!("argon2 params error: {}", e))?,
    )
    .hash_password_into(passphrase.as_bytes(), salt, &mut key)
    .map_err(|e| anyhow::anyhow!("argon2 key derivation failed: {}", e))?;
    Ok(key)
}

/// Encrypt 32-byte plaintext with passphrase, return EncryptedKey
pub fn encrypt_secret_key(passphrase: &str, plaintext: &[u8; 32]) -> Result<EncryptedKey> {
    let mut rng = rand::thread_rng();

    let salt: [u8; SALT_LEN] = rng.gen();
    let nonce_bytes: [u8; NONCE_LEN] = rng.gen();

    let key_bytes = derive_key(passphrase, &salt)?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?;

    Ok(EncryptedKey {
        algorithm: "argon2id-aes256gcm".to_string(),
        salt: encode_b64(&salt),
        nonce: encode_b64(&nonce_bytes),
        ciphertext: encode_b64(&ciphertext),
    })
}

/// Decrypt EncryptedKey back to 32-byte plaintext
pub fn decrypt_secret_key(passphrase: &str, encrypted: &EncryptedKey) -> Result<[u8; 32]> {
    let salt = decode_b64(&encrypted.salt)?;
    let nonce_bytes = decode_b64(&encrypted.nonce)?;
    let ciphertext = decode_b64(&encrypted.ciphertext)?;

    let key_bytes = derive_key(passphrase, &salt)?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed — wrong passphrase or corrupted data: {}", e))?;

    plaintext.as_slice()
        .try_into()
        .context("decrypted data wrong length (expected 32 bytes)")
}
