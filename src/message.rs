use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use serde::Serialize;
use sha2::{Sha256, Digest};

use crate::types::{PostMessage, UnsignedMessage, MAX_MESSAGE_SIZE};

/// Canonical JSON: RFC 8785 JCS — sorted keys, compact format
pub fn canonicalize<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_value(value)?;
    Ok(serde_json::to_string(&json)?)
}

/// Sign a message: remove sig → canonicalize → SHA-256 → Ed25519 sign → base58
pub fn sign_message(mut msg: PostMessage, signing_key: &SigningKey) -> Result<PostMessage> {
    let full_json = serde_json::to_string(&msg)?;
    if full_json.len() > MAX_MESSAGE_SIZE {
        anyhow::bail!("message exceeds {} byte limit", MAX_MESSAGE_SIZE);
    }

    let unsigned: UnsignedMessage = msg.clone().into();
    let canonical = canonicalize(&unsigned)?;
    let hash = Sha256::digest(canonical.as_bytes());
    let signature = signing_key.sign(&hash);
    msg.sig = Some(bs58::encode(signature.to_bytes()).into_string());
    Ok(msg)
}

/// Verify a message: extract sig → canonicalize remaining fields → SHA-256 → verify_strict
pub fn verify_message(msg: &PostMessage, verifying_key: &VerifyingKey) -> Result<()> {
    let sig_b58 = msg.sig.as_ref().context("message has no signature")?;
    let sig_bytes = bs58::decode(sig_b58)
        .into_vec()
        .context("signature base58 decode failed")?;
    let sig_array: [u8; 64] = sig_bytes.as_slice()
        .try_into()
        .context("signature wrong length (expected 64 bytes)")?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    let unsigned = UnsignedMessage {
        id: msg.id.clone(),
        from: msg.from.clone(),
        to: msg.to.clone(),
        msg_type: msg.msg_type.clone(),
        content: msg.content.clone(),
        refs: msg.refs.clone(),
        ts: msg.ts,
        recovery: msg.recovery,
        old_agent_id: msg.old_agent_id.clone(),
    };
    let canonical = canonicalize(&unsigned)?;
    let hash = Sha256::digest(canonical.as_bytes());

    verifying_key.verify_strict(&hash, &signature)
        .context("signature verification failed")?;
    Ok(())
}

/// Serialize message to JSONL line
pub fn message_to_jsonl(msg: &PostMessage) -> Result<String> {
    let json = serde_json::to_string(msg)?;
    Ok(json + "\n")
}

/// Parse JSONL line to message (skip parse failures — corrupt lines have no valid sig)
pub fn jsonl_to_message(line: &str) -> Option<PostMessage> {
    serde_json::from_str(line.trim()).ok()
}
