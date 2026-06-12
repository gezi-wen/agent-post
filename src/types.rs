use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Message type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Text,
    System,
    FileRef,
}

/// A JSONL message (sig field filled after signing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub content: String,
    #[serde(default)]
    pub refs: Vec<String>,
    pub ts: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_agent_id: Option<String>,
}

/// Unsigned message (for canonicalization before signing)
#[derive(Debug, Clone, Serialize)]
pub struct UnsignedMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub content: String,
    #[serde(default)]
    pub refs: Vec<String>,
    pub ts: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_agent_id: Option<String>,
}

impl From<PostMessage> for UnsignedMessage {
    fn from(m: PostMessage) -> Self {
        UnsignedMessage {
            id: m.id,
            from: m.from,
            to: m.to,
            msg_type: m.msg_type,
            content: m.content,
            refs: m.refs,
            ts: m.ts,
            recovery: m.recovery,
            old_agent_id: m.old_agent_id,
        }
    }
}

/// Encrypted private key blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    pub algorithm: String,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Identity file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub agent_id: String,
    pub name: String,
    pub group: String,
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_secret_key: Option<EncryptedKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_cert: Option<String>,
    pub created: DateTime<Utc>,
}

/// Exported identity (without secret key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityExport {
    pub agent_id: String,
    pub name: String,
    pub group: String,
    pub pubkey: String,
    pub created: DateTime<Utc>,
}

/// Pairing handshake message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairPayload {
    pub step: PairStep,
    pub from_id: String,
    pub to_id: String,
    pub group_name: String,
    pub nonce: String,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<bool>,
    pub ts: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PairStep {
    Invite,
    Accept,
    Confirm,
}

/// Group member entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub agent_id: String,
    pub name: String,
    pub pubkey: String,
    pub joined: DateTime<Utc>,
}

/// Route entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub agent_id: String,
    pub inbox_path: String,
}

/// Global config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub default_identity: Option<String>,
    pub default_group: Option<String>,
}

/// Watermark for deduplication
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Watermark {
    #[serde(flatten)]
    pub entries: std::collections::HashMap<String, WatermarkEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkEntry {
    pub last_ts: DateTime<Utc>,
    pub seen_ids: Vec<String>,
}

/// Revocation certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCert {
    pub agent_id: String,
    pub pubkey: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
    pub sig: String,
}

/// Max message size
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64KB

/// Pairing expiry
pub const PAIR_EXPIRY_HOURS: i64 = 72; // 3 days
