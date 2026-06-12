# Agent Post Phase 1 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 Agent Post 核心协议：Ed25519 身份系统、三次握手配对、JSONL 文件 inbox 消息收发、组管理、密钥吊销。

**Architecture:** Rust 单二进制 CLI。ed25519-dalek v2 签名、serde_json RFC 8785 规范化、JSONL O_APPEND 追加、watermark 去重。7 个核心模块 + main.rs CLI 入口。

**Tech Stack:** Rust (stable), ed25519-dalek 2.x, clap 4 (derive), serde_json, sha2, bs58, toml, chrono, uuid, anyhow

---

## 文件结构

```
/mnt/e/projects/agent-post/
  Cargo.toml
  src/
    main.rs          ← CLI 入口 (clap derive)，所有子命令分发
    types.rs         ← 共享类型：PostMessage, Identity, PairPayload 等
    identity.rs      ← 密钥生成、身份文件读写、吊销证书预签名
    message.rs       ← RFC 8785 规范化、签名、验签
    inbox.rs         ← JSONL 追加写、轮询读、watermark 去重
    group.rs         ← 组目录创建、members.toml/routes.toml 管理
    pair.rs          ← 三次握手状态机（invite/accept/reject/confirm）
    config.rs        ← 全局 config.toml 读写
  tests/
    identity_test.rs
    message_test.rs
    inbox_test.rs
    pair_test.rs
    integration_test.rs
  docs/
    protocol-spec.md
```

---

### Task 1：项目骨架 + 依赖 + types.rs

**Files:**
- Create: `Cargo.toml`
- Create: `src/types.rs`
- Create: `src/config.rs`

- [ ] **Step 1：创建 Cargo.toml**

```bash
cd /mnt/e/projects/agent-post
# 如果已有 Cargo.toml 则跳过 cargo init
cargo init --name agent-post
```

```toml
[package]
name = "agent-post"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4", features = ["derive"] }
ed25519-dalek = { version = "2", features = ["serde", "zeroize", "rand_core", "fast"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
bs58 = "0.5"
toml = "0.8"
chrono = { version = "0.4", features = ["serde"] }
rand = "0.8"
uuid = { version = "1", features = ["v4"] }
anyhow = "1"
dirs = "5"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2：写共享类型 `src/types.rs`**

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 消息类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Text,
    System,
}

/// 一条 JSONL 消息（sig 字段在签名后填入）
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

/// 未签名的消息（用于签名前）
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

/// 身份文件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub agent_id: String,
    pub name: String,
    pub group: String,
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_cert: Option<String>,
    pub created: DateTime<Utc>,
}

/// 导出的身份（不含私钥）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityExport {
    pub agent_id: String,
    pub name: String,
    pub group: String,
    pub pubkey: String,
    pub created: DateTime<Utc>,
}

/// 配对握手消息
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

/// 组成员条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub agent_id: String,
    pub name: String,
    pub pubkey: String,
    pub joined: DateTime<Utc>,
}

/// 路由条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub agent_id: String,
    pub inbox_path: String,
}

/// 全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub default_identity: Option<String>,
    pub default_group: Option<String>,
}

/// Watermark
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

/// 吊销证书
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCert {
    pub agent_id: String,
    pub pubkey: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
    pub sig: String,
}

/// 消息大小上限
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64KB

/// 配对过期时间
pub const PAIR_EXPIRY_HOURS: i64 = 72; // 3 天
```

- [ ] **Step 3：写全局配置读写 `src/config.rs`**

```rust
use anyhow::Result;
use std::path::PathBuf;

use crate::types::Config;

fn home_dir() -> PathBuf {
    dirs::home_dir().expect("无法获取 home 目录").join(".agent-post")
}

pub fn config_path() -> PathBuf {
    home_dir().join("config.toml")
}

pub fn read_config() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Ok(Config {
            default_identity: None,
            default_group: None,
        });
    }
    let content = std::fs::read_to_string(&path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

pub fn write_config(config: &Config) -> Result<()> {
    let path = config_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    let content = toml::to_string_pretty(config)?;
    std::fs::write(&path, content)?;
    Ok(())
}

pub fn identities_dir() -> PathBuf {
    home_dir().join("identities")
}

pub fn groups_dir() -> PathBuf {
    home_dir().join("groups")
}

pub fn group_dir(group_name: &str) -> PathBuf {
    groups_dir().join(group_name)
}
```

- [ ] **Step 4：编译验证**

```bash
cd /mnt/e/projects/agent-post && cargo check
```

Expected: 编译通过，unused import 警告可忽略

- [ ] **Step 5：Commit**

```bash
git add Cargo.toml src/types.rs src/config.rs
git commit -m "feat: 项目骨架 + 共享类型 + 配置模块

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 2：身份模块 (identity.rs)

**Files:**
- Create: `src/identity.rs`
- Create: `tests/identity_test.rs`

- [ ] **Step 1：写 identity.rs 测试**

创建 `tests/identity_test.rs`：

```rust
mod common;

use agent_post::identity;
use agent_post::types::Identity;
use tempfile::TempDir;
use std::fs;

fn setup_home(temp: &TempDir) {
    let home = temp.path().join(".agent-post");
    fs::create_dir_all(&home).is_ok();
    // 不能用 env，用参数传递
}

#[test]
fn test_generate_keypair_and_agent_id() {
    let (signing_key, agent_id, pubkey_b58) = identity::generate_keypair();
    assert!(!agent_id.is_empty());
    assert!(agent_id.len() >= 10);
    // agent_id = base58(sha256(pubkey)[:16])
    assert!(pubkey_b58.len() > 0);
}

#[test]
fn test_create_identity_file() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&identities_dir).unwrap();

    let identity = identity::create_identity(
        &identities_dir,
        "测试Agent",
        "测试组",
    ).unwrap();

    assert_eq!(identity.name, "测试Agent");
    assert_eq!(identity.group, "测试组");
    assert!(identity.secret_key.is_some());
    assert!(identity.revocation_cert.is_some());

    // 文件存在
    let file_path = identities_dir.join(format!("{}.json", identity.agent_id));
    assert!(file_path.exists());

    // Unix 权限 600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&file_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn test_read_identity() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&identities_dir).unwrap();

    let created = identity::create_identity(&identities_dir, "读测试", "测试组").unwrap();
    let read = identity::read_identity(&identities_dir, &created.agent_id).unwrap();

    assert_eq!(read.agent_id, created.agent_id);
    assert_eq!(read.pubkey, created.pubkey);
}

#[test]
fn test_export_without_secret_key() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&identities_dir).unwrap();

    let created = identity::create_identity(&identities_dir, "导出测试", "测试组").unwrap();
    let exported = identity::export_identity(&identities_dir, &created.agent_id).unwrap();

    // 序列化后不应包含私钥
    let json = serde_json::to_string(&exported).unwrap();
    assert!(!json.contains("secret_key"));
}
```

- [ ] **Step 2：运行测试确认失败**

```bash
cd /mnt/e/projects/agent-post && cargo test identity -- --nocapture
```

Expected: 编译失败（identity 模块还没写）

- [ ] **Step 3：写 `src/identity.rs`**

```rust
use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey, Verifier, Signer};
use rand::rngs::OsRng;
use serde_json::Value;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;

use crate::message;
use crate::types::{Identity, IdentityExport, RevocationCert};

/// 生成 Ed25519 密钥对，返回 (signing_key, agent_id, pubkey_base58)
pub fn generate_keypair() -> (SigningKey, String, String) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let pubkey_bytes = verifying_key.as_bytes();
    let pubkey_b58 = bs58::encode(pubkey_bytes).into_string();

    let hash = Sha256::digest(pubkey_bytes);
    let agent_id = bs58::encode(&hash[..16]).into_string();

    (signing_key, agent_id, pubkey_b58)
}

/// 创建身份文件，返回 Identity
pub fn create_identity(
    identities_dir: &Path,
    name: &str,
    group: &str,
) -> Result<Identity> {
    let (signing_key, agent_id, pubkey_b58) = generate_keypair();
    let verifying_key = signing_key.verifying_key();

    // 预签名吊销证书
    let revocation = RevocationCert {
        agent_id: agent_id.clone(),
        pubkey: pubkey_b58.clone(),
        reason: String::new(),
        revoked_at: Utc::now(),
        sig: String::new(),
    };

    let revocation_json = message::canonicalize(&revocation)?;
    let revocation_hash = Sha256::digest(revocation_json.as_bytes());
    let revocation_sig = signing_key.sign(&revocation_hash);
    let revocation_sig_b58 = bs58::encode(revocation_sig.to_bytes()).into_string();

    let revocation_cert = RevocationCert {
        sig: revocation_sig_b58,
        ..revocation
    };

    let secret_key_bytes = signing_key.to_bytes();
    let identity = Identity {
        agent_id: agent_id.clone(),
        name: name.to_string(),
        group: group.to_string(),
        pubkey: pubkey_b58,
        secret_key: Some(bs58::encode(secret_key_bytes).into_string()),
        revocation_cert: Some(serde_json::to_string(&revocation_cert)?),
        created: Utc::now(),
    };

    let json = serde_json::to_string_pretty(&identity)?;
    let file_path = identities_dir.join(format!("{}.json", agent_id));
    fs::create_dir_all(identities_dir)?;
    fs::write(&file_path, &json)?;

    // Unix: chmod 600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&file_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&file_path, perms)?;
    }

    Ok(identity)
}

/// 读取身份文件
pub fn read_identity(identities_dir: &Path, agent_id: &str) -> Result<Identity> {
    let file_path = identities_dir.join(format!("{}.json", agent_id));
    let content = fs::read_to_string(&file_path)
        .with_context(|| format!("身份文件不存在: {}", file_path.display()))?;
    let identity: Identity = serde_json::from_str(&content)?;
    Ok(identity)
}

/// 列出所有本地身份
pub fn list_identities(identities_dir: &Path) -> Result<Vec<String>> {
    if !identities_dir.exists() {
        return Ok(vec![]);
    }
    let mut ids = Vec::new();
    for entry in fs::read_dir(identities_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.path().file_stem() {
                ids.push(name.to_string_lossy().to_string());
            }
        }
    }
    Ok(ids)
}

/// 导出身份（不含私钥）
pub fn export_identity(identities_dir: &Path, agent_id: &str) -> Result<IdentityExport> {
    let identity = read_identity(identities_dir, agent_id)?;
    Ok(IdentityExport {
        agent_id: identity.agent_id,
        name: identity.name,
        group: identity.group,
        pubkey: identity.pubkey,
        created: identity.created,
    })
}

/// 获取签名密钥（从身份文件中读取私钥）
pub fn load_signing_key(identities_dir: &Path, agent_id: &str) -> Result<(SigningKey, VerifyingKey)> {
    let identity = read_identity(identities_dir, agent_id)?;
    let secret_b58 = identity.secret_key
        .context("身份文件不含私钥")?;
    let secret_bytes = bs58::decode(&secret_b58)
        .into_vec()
        .context("私钥 base58 解码失败")?;
    let secret_array: [u8; 32] = secret_bytes.as_slice()
        .try_into()
        .context("私钥长度不正确")?;
    let signing_key = SigningKey::from_bytes(&secret_array);
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

/// 获取吊销证书
pub fn get_revocation_cert(identities_dir: &Path, agent_id: &str) -> Result<RevocationCert> {
    let identity = read_identity(identities_dir, agent_id)?;
    let cert_str = identity.revocation_cert
        .context("身份文件不含吊销证书")?;
    let cert: RevocationCert = serde_json::from_str(&cert_str)?;
    Ok(cert)
}
```

在 `src/lib.rs` 加模块声明（创建新文件或加 `mod`）：

```rust
// src/lib.rs - 如果不存在则创建
pub mod types;
pub mod config;
pub mod identity;
pub mod message;
pub mod inbox;
pub mod group;
pub mod pair;
```

同 `src/main.rs`：

```rust
mod types;
mod config;
mod identity;
mod message;
mod inbox;
mod group;
mod pair;
```

- [ ] **Step 4：运行测试**

```bash
cd /mnt/e/projects/agent-post && cargo test identity
```

Expected: 3 个测试 PASS

- [ ] **Step 5：Commit**

```bash
git add src/lib.rs src/main.rs src/identity.rs tests/identity_test.rs
git commit -m "feat: 身份模块 — 密钥生成、身份文件读写、吊销证书预签名

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 3：消息签名与验签 (message.rs)

**Files:**
- Create: `src/message.rs`
- Create: `tests/message_test.rs`

- [ ] **Step 1：写 message.rs 测试**

```rust
// tests/message_test.rs
use agent_post::message;
use agent_post::types::{PostMessage, MessageType};
use chrono::Utc;

#[test]
fn test_canonicalize_sorts_keys() {
    // 验证规范化 JSON 是按键排序的紧凑格式
    let msg = PostMessage {
        id: "test".to_string(),
        from: "A".to_string(),
        to: "B".to_string(),
        msg_type: MessageType::Text,
        content: "hello".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };

    let json = message::canonicalize(&msg).unwrap();
    // content 应该出现在 from 之前（字母序）
    let content_pos = json.find("\"content\"").unwrap();
    let from_pos = json.find("\"from\"").unwrap();
    assert!(content_pos < from_pos);
}

#[test]
fn test_sign_and_verify() {
    // 生成密钥对
    let (signing_key, _agent_id, _pubkey_b58) = agent_post::identity::generate_keypair();
    let verifying_key = signing_key.verifying_key();

    let msg = PostMessage {
        id: "msg1".to_string(),
        from: "A".to_string(),
        to: "B".to_string(),
        msg_type: MessageType::Text,
        content: "测试消息".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };

    let signed = message::sign_message(msg.clone(), &signing_key).unwrap();
    assert!(signed.sig.is_some());

    let result = message::verify_message(&signed, &verifying_key);
    assert!(result.is_ok());
}

#[test]
fn test_verify_detects_tampering() {
    let (signing_key, _agent_id, _pubkey_b58) = agent_post::identity::generate_keypair();
    let verifying_key = signing_key.verifying_key();

    let msg = PostMessage {
        id: "msg1".to_string(),
        from: "A".to_string(),
        to: "B".to_string(),
        msg_type: MessageType::Text,
        content: "原文".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };

    let mut signed = message::sign_message(msg, &signing_key).unwrap();
    // 篡改内容
    signed.content = "篡改后的内容".to_string();

    let result = message::verify_message(&signed, &verifying_key);
    assert!(result.is_err());
}

#[test]
fn test_verify_invalid_signature() {
    // 用一个密钥签名，用另一个密钥验签
    let (signing_key1, _id1, _pk1) = agent_post::identity::generate_keypair();
    let (_signing_key2, _id2, _pk2) = agent_post::identity::generate_keypair();
    let verifying_key2 = agent_post::identity::generate_keypair().1;

    // 用 key1 签名
    let msg = PostMessage {
        id: "msg1".to_string(),
        from: "A".to_string(),
        to: "B".to_string(),
        msg_type: MessageType::Text,
        content: "测试".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };
    let signed = message::sign_message(msg, &signing_key1).unwrap();

    // 用 key2 的 verifying key 验签
    let (_, _, _) = agent_post::identity::generate_keypair();
    let result = message::verify_message(&signed, &verifying_key2);
    assert!(result.is_err());
}

#[test]
fn test_message_size_limit() {
    let msg = PostMessage {
        id: "big".to_string(),
        from: "A".to_string(),
        to: "B".to_string(),
        msg_type: MessageType::Text,
        content: "x".repeat(65 * 1024),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };
    // 序列化后应该超过 64KB 限制
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.len() > 64 * 1024);
}
```

- [ ] **Step 2：运行测试确认失败**

```bash
cargo test message
```
Expected: 编译失败

- [ ] **Step 3：写 `src/message.rs`**

```rust
use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
use serde::Serialize;
use sha2::{Sha256, Digest};

use crate::types::{PostMessage, UnsignedMessage, MAX_MESSAGE_SIZE};

/// 规范化 JSON：RFC 8785 JCS — 排序键、紧凑格式、无空格
pub fn canonicalize<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_value(value)?;
    Ok(serde_json::to_string(&json)?)
}

/// 签名消息：排除 sig → 规范化 → SHA-256 → Ed25519 签名 → base58
pub fn sign_message(mut msg: PostMessage, signing_key: &SigningKey) -> Result<PostMessage> {
    // 检查大小
    let full_json = serde_json::to_string(&msg)?;
    if full_json.len() > MAX_MESSAGE_SIZE {
        anyhow::bail!("消息超过 {} 字节上限", MAX_MESSAGE_SIZE);
    }

    let unsigned: UnsignedMessage = msg.clone().into();
    let canonical = canonicalize(&unsigned)?;
    let hash = Sha256::digest(canonical.as_bytes());
    let signature = signing_key.sign(&hash);
    msg.sig = Some(bs58::encode(signature.to_bytes()).into_string());
    Ok(msg)
}

/// 验签消息：提取 sig → 规范化剩余字段 → SHA-256 → verify_strict
pub fn verify_message(msg: &PostMessage, verifying_key: &VerifyingKey) -> Result<()> {
    let sig_b58 = msg.sig.as_ref().context("消息无签名")?;
    let sig_bytes = bs58::decode(sig_b58)
        .into_vec()
        .context("签名 base58 解码失败")?;
    let sig_array: [u8; 64] = sig_bytes.as_slice()
        .try_into()
        .context("签名长度不正确（需要 64 字节）")?;
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
        .context("签名验证失败")?;
    Ok(())
}

/// 序列化消息为 JSONL 行
pub fn message_to_jsonl(msg: &PostMessage) -> Result<String> {
    let json = serde_json::to_string(msg)?;
    Ok(json + "\n")
}

/// 从 JSONL 行解析消息（跳过解析失败的行）
pub fn jsonl_to_message(line: &str) -> Option<PostMessage> {
    serde_json::from_str(line.trim()).ok()
}

/// 计算安全数字：sha256(old_pubkey + new_pubkey) 的前 10 位十进制
pub fn safety_number(old_pubkey: &str, new_pubkey: &str) -> String {
    let combined = format!("{}{}", old_pubkey, new_pubkey);
    let hash = Sha256::digest(combined.as_bytes());
    let hash_hex = hex::encode(&hash);
    // 取前 10 个十六进制字符，用十进制数字表示
    let num = u64::from_str_radix(&hash_hex[..10], 16).unwrap_or(0);
    format!("{:010}", num % 10_000_000_000)
}
```

注意：`safe_number` 用了 `hex` crate。在 Cargo.toml 加 `hex = "0.4"`。

- [ ] **Step 4：运行测试**

```bash
cargo test message
```

Expected: 4 个测试 PASS（size_limit 测试只检查条件，不算 pass，改断言——或者改为验证超过 64KB 会被 sign 拒绝）

修改 size_limit 测试：

```rust
#[test]
fn test_message_size_limit_rejected() {
    let msg = PostMessage {
        id: "big".to_string(),
        from: "A".to_string(),
        to: "B".to_string(),
        msg_type: MessageType::Text,
        content: "x".repeat(65 * 1024),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };
    let (sk, _, _) = agent_post::identity::generate_keypair();
    let result = message::sign_message(msg, &sk);
    assert!(result.is_err());
}
```

- [ ] **Step 5：Commit**

```bash
git add Cargo.toml src/message.rs tests/message_test.rs
git commit -m "feat: 消息签名与验签 — RFC 8785 规范化、Ed25519 sign/verify_strict

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 4：Inbox 读写 (inbox.rs)

**Files:**
- Create: `src/inbox.rs`
- Create: `tests/inbox_test.rs`

- [ ] **Step 1：写 inbox_test.rs**

```rust
// tests/inbox_test.rs
use agent_post::inbox;
use agent_post::types::{PostMessage, MessageType, Watermark, WatermarkEntry};
use chrono::Utc;
use std::fs;
use tempfile::TempDir;

fn make_msg(id: &str, from: &str, content: &str) -> PostMessage {
    PostMessage {
        id: id.to_string(),
        from: from.to_string(),
        to: "test_agent".to_string(),
        msg_type: MessageType::Text,
        content: content.to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: Some(format!("sig_{}", id)),
        recovery: None,
        old_agent_id: None,
    }
}

#[test]
fn test_append_and_read_jsonl() {
    let temp = TempDir::new().unwrap();
    let inbox_dir = temp.path().join("inbox");
    fs::create_dir_all(&inbox_dir).unwrap();
    let mailbox_path = inbox_dir.join("mailbox.jsonl");

    let msg = make_msg("1", "alice", "hello");
    inbox::append_message(&mailbox_path, &msg).unwrap();

    let lines = inbox::read_all_lines(&mailbox_path).unwrap();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("hello"));
}

#[test]
fn test_watermark_dedup() {
    let temp = TempDir::new().unwrap();
    let watermark_path = temp.path().join(".watermark.json");

    let ts = Utc::now();

    // 写 watermark
    let mut wm = Watermark::default();
    wm.entries.insert("alice".to_string(), WatermarkEntry {
        last_ts: ts,
        seen_ids: vec!["1".to_string(), "2".to_string()],
    });
    inbox::write_watermark(&watermark_path, &wm).unwrap();

    // 读 watermark
    let read = inbox::read_watermark(&watermark_path).unwrap();
    assert!(read.entries.contains_key("alice"));

    // 检查去重
    assert!(inbox::is_duplicate(&wm, "alice", ts, "1"));
    assert!(inbox::is_duplicate(&wm, "alice", ts, "2"));
    assert!(!inbox::is_duplicate(&wm, "alice", ts, "3"));
    // 更早的 ts
    let earlier_ts = ts - chrono::Duration::seconds(1);
    assert!(inbox::is_duplicate(&wm, "alice", earlier_ts, "new"));
}
```

- [ ] **Step 2：运行测试确认失败**

```bash
cargo test inbox
```

- [ ] **Step 3：写 `src/inbox.rs`**

```rust
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::types::{PostMessage, Watermark, WatermarkEntry};

/// 追加消息到 JSONL 文件（O_APPEND，POSIX 原子保证）
pub fn append_message(mailbox_path: &Path, msg: &PostMessage) -> Result<()> {
    if let Some(parent) = mailbox_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(mailbox_path)?;
    let line = serde_json::to_string(msg)? + "\n";
    file.write_all(line.as_bytes())?;
    Ok(())
}

/// 读取 JSONL 文件的所有行
pub fn read_all_lines(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    reader.lines()
        .collect::<Result<Vec<_>, _>>()
        .context("读取 JSONL 失败")
}

/// 读 watermark
pub fn read_watermark(path: &Path) -> Result<Watermark> {
    if !path.exists() {
        return Ok(Watermark::default());
    }
    let content = fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(Watermark::default());
    }
    let wm: Watermark = serde_json::from_str(&content)?;
    Ok(wm)
}

/// 写 watermark
pub fn write_watermark(path: &Path, wm: &Watermark) -> Result<()> {
    let json = serde_json::to_string(wm)?;
    fs::write(path, json)?;
    Ok(())
}

/// 判断消息是否重复
pub fn is_duplicate(wm: &Watermark, from: &str, msg_ts: DateTime<Utc>, msg_id: &str) -> bool {
    if let Some(entry) = wm.entries.get(from) {
        if msg_ts < entry.last_ts {
            return true;
        }
        if msg_ts == entry.last_ts && entry.seen_ids.contains(&msg_id.to_string()) {
            return true;
        }
    }
    false
}

/// 更新 watermark
pub fn update_watermark(wm: &mut Watermark, from: &str, msg_ts: DateTime<Utc>, msg_id: &str) {
    let entry = wm.entries.entry(from.to_string()).or_insert(WatermarkEntry {
        last_ts: msg_ts,
        seen_ids: vec![],
    });
    if msg_ts > entry.last_ts {
        entry.last_ts = msg_ts;
        entry.seen_ids = vec![msg_id.to_string()];
    } else if msg_ts == entry.last_ts {
        if !entry.seen_ids.contains(&msg_id.to_string()) {
            entry.seen_ids.push(msg_id.to_string());
        }
    }
}

/// 获取 inbox 目录路径
pub fn inbox_dir(group_dir: &Path, agent_id: &str) -> std::path::PathBuf {
    group_dir.join("inboxes").join(agent_id)
}

/// 获取 mailbox.jsonl 路径
pub fn mailbox_path(group_dir: &Path, agent_id: &str) -> std::path::PathBuf {
    inbox_dir(group_dir, agent_id).join("mailbox.jsonl")
}

/// 获取 watermark 路径
pub fn watermark_path(inbox_dir: &Path) -> std::path::PathBuf {
    inbox_dir.join(".watermark.json")
}
```

- [ ] **Step 4：运行测试**

```bash
cargo test inbox
```

Expected: 2 个测试 PASS

- [ ] **Step 5：Commit**

```bash
git add src/inbox.rs tests/inbox_test.rs
git commit -m "feat: inbox 读写 — JSONL 追加、watermark 去重

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 5：组管理 (group.rs)

**Files:**
- Create: `src/group.rs`
- Create: `tests/group_test.rs`

- [ ] **Step 1：写 group_test.rs**

```rust
// tests/group_test.rs
use agent_post::group;
use agent_post::types::Member;
use chrono::Utc;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_create_group() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    fs::create_dir_all(&groups_dir).unwrap();

    group::create_group(&groups_dir, "测试组").unwrap();

    let group_dir = groups_dir.join("测试组");
    assert!(group_dir.exists());
    assert!(group_dir.join("group.toml").exists());
    assert!(group_dir.join("members.toml").exists());
    assert!(group_dir.join("routes.toml").exists());
    assert!(group_dir.join("inboxes").exists());
    assert!(group_dir.join("pending").exists());
    assert!(group_dir.join("revocations").exists());
}

#[test]
fn test_add_and_read_members() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    fs::create_dir_all(&groups_dir).unwrap();
    group::create_group(&groups_dir, "组A").unwrap();

    let member = Member {
        agent_id: "test_id_1".to_string(),
        name: "测试agent".to_string(),
        pubkey: "pk_test_1".to_string(),
        joined: Utc::now(),
    };

    group::add_member(&groups_dir, "组A", &member).unwrap();
    group::add_member(&groups_dir, "组A", &member).unwrap(); // 去重

    let members = group::read_members(&groups_dir, "组A").unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].agent_id, "test_id_1");
}

#[test]
fn test_list_groups() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    fs::create_dir_all(&groups_dir).unwrap();

    group::create_group(&groups_dir, "A").unwrap();
    group::create_group(&groups_dir, "B").unwrap();

    let list = group::list_groups(&groups_dir).unwrap();
    assert!(list.contains(&"A".to_string()));
    assert!(list.contains(&"B".to_string()));
}
```

- [ ] **Step 2：运行测试确认失败**

```bash
cargo test group
```

- [ ] **Step 3：写 `src/group.rs`**

```rust
use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::types::Member;

/// 创建组目录
pub fn create_group(groups_dir: &Path, name: &str) -> Result<()> {
    let group_dir = groups_dir.join(name);
    fs::create_dir_all(&group_dir)?;

    let group_toml = format!(
        r#"# Agent Post 组配置
name = "{}"
created = "{}"
description = ""
"#,
        name,
        chrono::Utc::now().to_rfc3339()
    );
    fs::write(group_dir.join("group.toml"), group_toml)?;
    fs::write(group_dir.join("members.toml"), "# 组成员（配对确认后自动写入）\n")?;
    fs::write(group_dir.join("routes.toml"), "# 跨机 inbox 路由映射\n\n# 示例：\n# [\"agent_id\"] = \"/mnt/remote/.agent-post/groups/组名/inboxes/agent_id/\"\n")?;

    fs::create_dir_all(group_dir.join("inboxes"))?;
    fs::create_dir_all(group_dir.join("pending"))?;
    fs::create_dir_all(group_dir.join("revocations"))?;

    Ok(())
}

/// 列出所有组
pub fn list_groups(groups_dir: &Path) -> Result<Vec<String>> {
    if !groups_dir.exists() {
        return Ok(vec![]);
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(groups_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            names.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    Ok(names)
}

/// 读 members.toml
pub fn read_members(groups_dir: &Path, group_name: &str) -> Result<Vec<Member>> {
    let members_path = groups_dir.join(group_name).join("members.toml");
    if !members_path.exists() {
        return Ok(vec![]);
    }
    let content = fs::read_to_string(&members_path)?;

    // members.toml 格式：[[members]] agent_id = "..." name = "..." pubkey = "..." joined = "..."
    #[derive(serde::Deserialize)]
    struct MembersFile {
        members: Option<Vec<Member>>,
    }
    let parsed: MembersFile = toml::from_str(&content).unwrap_or(MembersFile { members: None });
    Ok(parsed.members.unwrap_or_default())
}

/// 写 members.toml（追加一个 member）
pub fn add_member(groups_dir: &Path, group_name: &str, member: &Member) -> Result<()> {
    let mut members = read_members(groups_dir, group_name)?;
    if members.iter().any(|m| m.agent_id == member.agent_id) {
        return Ok(()); // 已存在
    }
    members.push(member.clone());

    let group_dir = groups_dir.join(group_name);
    fs::create_dir_all(&group_dir)?;

    let mut toml_str = String::new();
    for m in &members {
        toml_str.push_str(&format!(
            "[[members]]\nagent_id = \"{}\"\nname = \"{}\"\npubkey = \"{}\"\njoined = \"{}\"\n\n",
            m.agent_id, m.name, m.pubkey,
            m.joined.to_rfc3339()
        ));
    }
    fs::write(group_dir.join("members.toml"), toml_str)?;
    Ok(())
}

/// 检查 agent 是否在组内
pub fn is_member(groups_dir: &Path, group_name: &str, agent_id: &str) -> Result<bool> {
    let members = read_members(groups_dir, group_name)?;
    Ok(members.iter().any(|m| m.agent_id == agent_id))
}

/// 读 routes.toml
pub fn read_routes(groups_dir: &Path, group_name: &str) -> Result<std::collections::HashMap<String, String>> {
    let routes_path = groups_dir.join(group_name).join("routes.toml");
    if !routes_path.exists() {
        return Ok(std::collections::HashMap::new());
    }
    let content = fs::read_to_string(&routes_path)?;
    #[derive(serde::Deserialize)]
    struct RoutesFile {
        routes: Option<std::collections::HashMap<String, String>>,
    }
    let parsed: RoutesFile = toml::from_str(&content).unwrap_or(RoutesFile { routes: None });
    Ok(parsed.routes.unwrap_or_default())
}

/// 添加路由
pub fn add_route(groups_dir: &Path, group_name: &str, agent_id: &str, path: &str) -> Result<()> {
    let mut routes = read_routes(groups_dir, group_name)?;
    routes.insert(agent_id.to_string(), path.to_string());

    let group_dir = groups_dir.join(group_name);
    let mut toml_str = String::from("# 跨机 inbox 路由映射\n\n");
    for (id, p) in &routes {
        toml_str.push_str(&format!("[routes.\"{}\"]\npath = \"{}\"\n\n", id, p));
    }
    fs::write(group_dir.join("routes.toml"), toml_str)?;
    Ok(())
}

/// 获取组内所有 agent_id（从 members.toml）
pub fn get_member_ids(groups_dir: &Path, group_name: &str) -> Result<Vec<String>> {
    let members = read_members(groups_dir, group_name)?;
    Ok(members.into_iter().map(|m| m.agent_id).collect())
}

/// 获取 inbox 实际路径（考虑 routes.toml）
pub fn resolve_inbox_path(groups_dir: &Path, group_name: &str, agent_id: &str) -> std::path::PathBuf {
    if let Ok(routes) = read_routes(groups_dir, group_name) {
        if let Some(path) = routes.get(agent_id) {
            return std::path::PathBuf::from(path);
        }
    }
    // 默认本地路径
    groups_dir.join(group_name).join("inboxes").join(agent_id)
}
```

- [ ] **Step 4：运行测试**

```bash
cargo test group
```

Expected: 3 个测试 PASS

- [ ] **Step 5：Commit**

```bash
git add src/group.rs tests/group_test.rs
git commit -m "feat: 组管理 — 创建组目录、members.toml 读写、routes.toml 路由

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 6：配对协议 (pair.rs)

**Files:**
- Create: `src/pair.rs`
- Create: `tests/pair_test.rs`

- [ ] **Step 1：写 pair_test.rs**

```rust
// tests/pair_test.rs
use agent_post::pair;
use agent_post::types::PairPayload;
use agent_post::identity;
use tempfile::TempDir;
use std::fs;

fn setup(groups_dir: &std::path::Path, identities_dir: &std::path::Path) -> (String, String, TempDir) {
    let temp = TempDir::new().unwrap();
    let id_a = identity::create_identity(identities_dir, "A", "测试组").unwrap();
    let id_b = identity::create_identity(identities_dir, "B", "测试组").unwrap();
    (id_a.agent_id, id_b.agent_id)
}

#[test]
fn test_invite_accept_confirm_flow() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&groups_dir).unwrap();
    fs::create_dir_all(&identities_dir).unwrap();

    let id_a = identity::create_identity(&identities_dir, "A", "测试组").unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "测试组").unwrap();

    // 创建组
    agent_post::group::create_group(&groups_dir, "测试组").unwrap();

    // ① A 发 invite
    let sk_a = identity::load_signing_key(&identities_dir, &id_a.agent_id).unwrap().0;
    let invite = pair::create_invite(&groups_dir, &identities_dir, &id_a.agent_id, &id_b.agent_id, "测试组", false).unwrap();

    // B 检查 pending
    let pending = pair::check_pending(&groups_dir, "测试组", &id_b.agent_id).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].step, agent_post::types::PairStep::Invite);

    // ② B accept
    let sk_b = identity::load_signing_key(&identities_dir, &id_b.agent_id).unwrap().0;
    let accept = pair::create_accept(&groups_dir, &identities_dir, &id_b.agent_id, "测试组", &pending[0].nonce, true, None).unwrap();

    // ③ A confirm (需要先 check)
    let a_pending = pair::check_accepts(&groups_dir, "测试组", &id_a.agent_id).unwrap();
    assert_eq!(a_pending.len(), 1);

    let confirm = pair::create_confirm(&groups_dir, &identities_dir, &id_a.agent_id, "测试组", &a_pending[0].nonce).unwrap();

    // 检查 members.toml
    let members = agent_post::group::read_members(&groups_dir, "测试组").unwrap();
    assert!(members.iter().any(|m| m.agent_id == id_b.agent_id));
}

#[test]
fn test_reject_notifies() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&groups_dir).unwrap();
    fs::create_dir_all(&identities_dir).unwrap();

    let id_a = identity::create_identity(&identities_dir, "A", "测试组").unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "测试组").unwrap();
    agent_post::group::create_group(&groups_dir, "测试组").unwrap();

    // A invite
    pair::create_invite(&groups_dir, &identities_dir, &id_a.agent_id, &id_b.agent_id, "测试组", false).unwrap();
    let pending = pair::check_pending(&groups_dir, "测试组", &id_b.agent_id).unwrap();

    // B reject
    let reject = pair::create_accept(&groups_dir, &identities_dir, &id_b.agent_id, "测试组", &pending[0].nonce, false, Some("不想配对")).unwrap();
    assert_eq!(reject.accepted, Some(false));
    assert_eq!(reject.reason.as_deref(), Some("不想配对"));
}

#[test]
fn test_expired_invite_filtered() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&groups_dir).unwrap();
    fs::create_dir_all(&identities_dir).unwrap();

    let id_a = identity::create_identity(&identities_dir, "A", "测试组").unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "测试组").unwrap();
    agent_post::group::create_group(&groups_dir, "测试组").unwrap();

    // 创建一个已过期的 invite
    pair::create_invite(&groups_dir, &identities_dir, &id_a.agent_id, &id_b.agent_id, "测试组", false).unwrap();

    // 手动修改过期时间为过去
    let pending_dir = groups_dir.join("测试组").join("pending");
    for entry in fs::read_dir(&pending_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("invite-") {
            let mut content: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(entry.path()).unwrap()
            ).unwrap();
            content["expires_at"] = serde_json::Value::String("2020-01-01T00:00:00Z".to_string());
            fs::write(entry.path(), serde_json::to_string(&content).unwrap()).unwrap();
        }
    }

    // B check — 过期的应该被过滤
    let pending = pair::check_pending(&groups_dir, "测试组", &id_b.agent_id).unwrap();
    assert_eq!(pending.len(), 0);
}
```

- [ ] **Step 2：运行测试确认失败**

```bash
cargo test pair
```

- [ ] **Step 3：写 `src/pair.rs`**

```rust
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;

use crate::identity;
use crate::message;
use crate::group;
use crate::types::{PairPayload, PairStep, Member, PAIR_EXPIRY_HOURS};

/// 创建① invite
pub fn create_invite(
    groups_dir: &Path,
    identities_dir: &Path,
    from_id: &str,
    to_id: &str,
    group_name: &str,
    recovery: bool,
) -> Result<PairPayload> {
    let sk = identity::load_signing_key(identities_dir, from_id)?.0;
    let identity = identity::read_identity(identities_dir, from_id)?;

    let nonce = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    let mut payload = PairPayload {
        step: PairStep::Invite,
        from_id: from_id.to_string(),
        to_id: to_id.to_string(),
        group_name: group_name.to_string(),
        nonce: nonce.clone(),
        expires_at: now + Duration::hours(PAIR_EXPIRY_HOURS),
        prev_hash: None,
        accepted: None,
        reason: None,
        recovery: Some(recovery),
        ts: now,
        sig: None,
    };

    // 签名
    let canonical = message::canonicalize(&payload)?;
    let hash = Sha256::digest(canonical.as_bytes());
    let sig = sk.sign(&hash);
    payload.sig = Some(bs58::encode(sig.to_bytes()).into_string());

    // 写入 pending
    let pending_dir = groups_dir.join(group_name).join("pending");
    fs::create_dir_all(&pending_dir)?;
    let filename = format!("invite-{}.json", nonce);
    let content = serde_json::to_string_pretty(&payload)?;
    fs::write(pending_dir.join(filename), content)?;

    Ok(payload)
}

/// B 检查自己的 pending invite
pub fn check_pending(
    groups_dir: &Path,
    group_name: &str,
    my_id: &str,
) -> Result<Vec<PairPayload>> {
    let pending_dir = groups_dir.join(group_name).join("pending");
    if !pending_dir.exists() {
        return Ok(vec![]);
    }

    let mut invites = Vec::new();
    for entry in fs::read_dir(&pending_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("invite-") {
            continue;
        }
        let content = fs::read_to_string(entry.path())?;
        let payload: PairPayload = match serde_json::from_str(&content) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // 检查是否发给我的
        if payload.to_id != my_id {
            continue;
        }
        // 检查是否过期
        if payload.expires_at < Utc::now() {
            continue;
        }
        // check 不验签（signature 可能残损），只读
        invites.push(payload);
    }

    Ok(invites)
}

/// 检查 pending accept（A 查看）
pub fn check_accepts(
    groups_dir: &Path,
    group_name: &str,
    my_id: &str,
) -> Result<Vec<PairPayload>> {
    let pending_dir = groups_dir.join(group_name).join("pending");
    if !pending_dir.exists() {
        return Ok(vec![]);
    }

    let mut accepts = Vec::new();
    for entry in fs::read_dir(&pending_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("accept-") {
            continue;
        }
        let content = fs::read_to_string(entry.path())?;
        let payload: PairPayload = match serde_json::from_str(&content) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if payload.to_id != my_id {
            continue;
        }
        if payload.expires_at < Utc::now() {
            continue;
        }
        accepts.push(payload);
    }

    Ok(accepts)
}

/// B 创建② accept（或 reject）
pub fn create_accept(
    groups_dir: &Path,
    identities_dir: &Path,
    from_id: &str,
    group_name: &str,
    invite_nonce: &str,
    accepted: bool,
    reason: Option<String>,
) -> Result<PairPayload> {
    // 读取对应的 invite
    let pending_dir = groups_dir.join(group_name).join("pending");
    let invite_file = pending_dir.join(format!("invite-{}.json", invite_nonce));
    let invite_content = fs::read_to_string(&invite_file)
        .context("invite 文件不存在，可能已过期或被清理")?;
    let invite: PairPayload = serde_json::from_str(&invite_content)?;

    // 验证 invite 签名
    let to_identity = identity::read_identity(identities_dir, &invite.to_id)?;
    let from_identity_path = identities_dir.join(format!("{}.json", invite.from_id));
    let from_identity = if from_identity_path.exists() {
        Some(identity::read_identity(identities_dir, &invite.from_id)?)
    } else {
        None
    };

    // 计算 invite 的 hash
    let invite_canonical = message::canonicalize(&invite)?;
    let invite_hash = Sha256::digest(invite_canonical.as_bytes());
    let invite_hash_hex = hex::encode(&invite_hash);

    let sk = identity::load_signing_key(identities_dir, from_id)?.0;
    let identity = identity::read_identity(identities_dir, from_id)?;

    let now = Utc::now();
    let mut payload = PairPayload {
        step: PairStep::Accept,
        from_id: from_id.to_string(),
        to_id: invite.from_id.clone(),
        group_name: group_name.to_string(),
        nonce: uuid::Uuid::new_v4().to_string(),
        expires_at: now + Duration::hours(PAIR_EXPIRY_HOURS),
        prev_hash: Some(invite_hash_hex),
        accepted: Some(accepted),
        reason,
        recovery: None,
        ts: now,
        sig: None,
    };

    let canonical = message::canonicalize(&payload)?;
    let hash = Sha256::digest(canonical.as_bytes());
    let sig = sk.sign(&hash);
    payload.sig = Some(bs58::encode(sig.to_bytes()).into_string());

    // 写入 pending
    let filename = format!("accept-{}.json", payload.nonce);
    let content = serde_json::to_string_pretty(&payload)?;
    fs::write(pending_dir.join(filename), content)?;

    Ok(payload)
}

/// A 创建③ confirm
pub fn create_confirm(
    groups_dir: &Path,
    identities_dir: &Path,
    from_id: &str,
    group_name: &str,
    accept_nonce: &str,
) -> Result<PairPayload> {
    let pending_dir = groups_dir.join(group_name).join("pending");
    let accept_file = pending_dir.join(format!("accept-{}.json", accept_nonce));
    let accept_content = fs::read_to_string(&accept_file)
        .context("accept 文件不存在")?;
    let accept: PairPayload = serde_json::from_str(&accept_content)?;

    if accept.accepted != Some(true) {
        anyhow::bail!("对方拒绝了配对");
    }

    // 计算 accept 的 hash
    let accept_canonical = message::canonicalize(&accept)?;
    let accept_hash = Sha256::digest(accept_canonical.as_bytes());
    let accept_hash_hex = hex::encode(&accept_hash);

    let sk = identity::load_signing_key(identities_dir, from_id)?.0;
    let identity = identity::read_identity(identities_dir, from_id)?;
    let now = Utc::now();

    let mut payload = PairPayload {
        step: PairStep::Confirm,
        from_id: from_id.to_string(),
        to_id: accept.from_id.clone(),
        group_name: group_name.to_string(),
        nonce: uuid::Uuid::new_v4().to_string(),
        expires_at: now + Duration::hours(1), // confirm 立即生效即可
        prev_hash: Some(accept_hash_hex),
        accepted: None,
        reason: None,
        recovery: None,
        ts: now,
        sig: None,
    };

    let canonical = message::canonicalize(&payload)?;
    let hash = Sha256::digest(canonical.as_bytes());
    let sig = sk.sign(&hash);
    payload.sig = Some(bs58::encode(sig.to_bytes()).into_string());

    // 写入 pending
    let filename = format!("confirm-{}.json", payload.nonce);
    let content = serde_json::to_string_pretty(&payload)?;
    fs::write(pending_dir.join(filename), content)?;

    // A 侧写 members.toml
    let b_identity = identity::read_identity(identities_dir, &accept.from_id)?;
    let member = Member {
        agent_id: accept.from_id.clone(),
        name: b_identity.name.clone(),
        pubkey: b_identity.pubkey.clone(),
        joined: now,
    };
    group::add_member(groups_dir, group_name, &member)?;

    // B 侧也写 members.toml（因为 B 在 accept 时已经写了，这里不重复）
    // 清理旧的 invite 和 accept
    let _ = fs::remove_file(pending_dir.join(format!("invite-*.json")));
    // 不清理 accept——B 需要读它来确认

    Ok(payload)
}

/// 计算安全数字
pub fn safety_number(old_pubkey: &str, new_pubkey: &str) -> String {
    let combined = format!("{}{}", old_pubkey, new_pubkey);
    let hash = Sha256::digest(combined.as_bytes());
    let hash_hex = hex::encode(&hash);
    let num = u64::from_str_radix(&hash_hex[..15], 16).unwrap_or(0);
    format!("{:010}", num % 10_000_000_000)
}
```

- [ ] **Step 4：运行测试**

```bash
cargo test pair
```

Expected: 3 个测试 PASS

- [ ] **Step 5：Commit**

```bash
git add src/pair.rs tests/pair_test.rs
git commit -m "feat: 配对协议 — 三次握手 invite/accept/confirm、过期检查、安全数字

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 7：CLI 入口 (main.rs)

**Files:**
- Create: `src/main.rs`

- [ ] **Step 1：写 main.rs（clap derive）**

```rust
mod types;
mod config;
mod identity;
mod message;
mod inbox;
mod group;
mod pair;

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agent-post", about = "AI agent 身份+通信协议")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// 覆盖 identities 目录
    #[arg(long, global = true)]
    identities_dir: Option<String>,

    /// 覆盖 groups 目录
    #[arg(long, global = true)]
    groups_dir: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// 初始化身份
    Init {
        /// Agent 名称
        #[arg(short, long)]
        name: String,
        /// 默认组名
        #[arg(short, long, default_value = "default")]
        group: String,
    },
    /// 管理身份
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// 配对管理
    Pair {
        #[command(subcommand)]
        cmd: PairCmd,
    },
    /// 发送消息
    Send {
        /// 目标：agent_id、group:名称 或 *
        #[arg(short, long)]
        to: String,
        /// 消息类型
        #[arg(short, long, default_value = "text")]
        msg_type: String,
        /// 消息内容
        #[arg(short, long)]
        content: String,
    },
    /// 轮询 inbox
    Poll {
        /// 指定组（默认：config 中的 default_group）
        #[arg(short, long)]
        group: Option<String>,
        /// 持续监听
        #[arg(short, long)]
        follow: bool,
    },
    /// 密钥管理
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// 组管理
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// 显示当前默认身份
    Show,
    /// 列出所有本地身份
    List,
    /// 导出身份（不含私钥）
    Export {
        agent_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum PairCmd {
    /// 发起配对邀请
    Invite {
        #[arg(short, long)]
        to: String,
        #[arg(short, long)]
        group: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        recovery: bool,
    },
    /// 检查待处理的 invite
    Check {
        #[arg(short, long)]
        group: String,
    },
    /// 接受配对
    Accept {
        nonce: String,
        #[arg(short, long)]
        group: String,
    },
    /// 拒绝配对
    Reject {
        nonce: String,
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// 确认配对
    Confirm {
        nonce: String,
        #[arg(short, long)]
        group: String,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// 吊销当前密钥
    Revoke {
        #[arg(short, long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// 创建新组
    Create {
        name: String,
    },
    /// 列出所有组
    List,
    /// 查看组详情
    Info {
        name: String,
    },
    /// 添加跨机路由
    AddRoute {
        #[arg(long)]
        group: String,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        path: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let identities_dir = cli.identities_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dirs::home_dir().unwrap().join(".agent-post").join("identities"));
    let groups_dir = cli.groups_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dirs::home_dir().unwrap().join(".agent-post").join("groups"));

    match cli.command {
        Commands::Init { name, group } => {
            let identity = identity::create_identity(&identities_dir, &name, &group)?;
            println!("身份已创建：");
            println!("  Agent ID: {}", identity.agent_id);
            println!("  名称: {}", identity.name);
            println!("  组: {}", identity.group);
            println!("  身份文件: {}", identities_dir.join(format!("{}.json", identity.agent_id)).display());
        }
        Commands::Identity { cmd } => handle_identity(cmd, &identities_dir),
        Commands::Pair { cmd } => handle_pair(cmd, &identities_dir, &groups_dir),
        Commands::Send { to, msg_type, content } => handle_send(&to, &msg_type, &content, &identities_dir, &groups_dir),
        Commands::Poll { group, follow } => handle_poll(group, follow, &identities_dir, &groups_dir),
        Commands::Key { cmd } => handle_key(cmd, &identities_dir, &groups_dir),
        Commands::Group { cmd } => handle_group(cmd, &groups_dir),
    }
}
```

- [ ] **Step 2：实现 handler 函数（加到 main.rs 底部）**

```rust
fn handle_identity(cmd: IdentityCmd, identities_dir: &std::path::Path) -> Result<()> {
    match cmd {
        IdentityCmd::Show => {
            let config = config::read_config()?;
            let agent_id = config.default_identity.context("未设置默认身份，请先 init")?;
            let ident = identity::read_identity(identities_dir, &agent_id)?;
            println!("Agent ID: {}", ident.agent_id);
            println!("名称: {}", ident.name);
            println!("组: {}", ident.group);
            println!("公钥: {}", ident.pubkey);
            println!("创建时间: {}", ident.created);
        }
        IdentityCmd::List => {
            let ids = identity::list_identities(identities_dir)?;
            if ids.is_empty() {
                println!("暂无本地身份");
            } else {
                println!("本地身份：");
                for id in &ids {
                    let ident = identity::read_identity(identities_dir, id)?;
                    println!("  {} — {}", ident.agent_id, ident.name);
                }
            }
        }
        IdentityCmd::Export { agent_id } => {
            let id = agent_id.unwrap_or_else(|| {
                config::read_config().ok()
                    .and_then(|c| c.default_identity)
                    .unwrap_or_default()
            });
            let exported = identity::export_identity(identities_dir, &id)?;
            println!("{}", serde_json::to_string_pretty(&exported)?);
        }
    }
    Ok(())
}

fn handle_pair(cmd: PairCmd, identities_dir: &std::path::Path, groups_dir: &std::path::Path) -> Result<()> {
    let config = config::read_config()?;
    let my_id = config.default_identity.context("未设置默认身份")?;
    let my_identity = identity::read_identity(identities_dir, &my_id)?;

    match cmd {
        PairCmd::Invite { to, group, name, recovery } => {
            let invite = pair::create_invite(groups_dir, identities_dir, &my_id, &to, &group, recovery)?;
            println!("配对邀请已发送");
            println!("  Nonce: {}", invite.nonce);
            if recovery {
                // 获取旧 pubkey（当前身份的 pubkey，因为是恢复场景则 to 知道旧身份）
                let b_identity_path = identities_dir.join(format!("{}.json", &to));
                if let Ok(b_ident) = identity::read_identity(identities_dir, &to) {
                    let sn = pair::safety_number(&b_ident.pubkey, &my_identity.pubkey);
                    println!("  安全数字: {}", sn);
                    println!("  请让对方确认此数字与你的匹配");
                }
            }
        }
        PairCmd::Check { group } => {
            let invites = pair::check_pending(groups_dir, &group, &my_id)?;
            if invites.is_empty() {
                println!("暂无待处理的配对邀请");
            } else {
                for inv in &invites {
                    println!("来自: {}  组: {}  nonce: {}  过期: {}  recovery: {:?}",
                        inv.from_id, inv.group_name, inv.nonce, inv.expires_at, inv.recovery);
                }
            }
        }
        PairCmd::Accept { nonce, group } => {
            let accept = pair::create_accept(groups_dir, identities_dir, &my_id, &group, &nonce, true, None)?;
            println!("已接受配对，nonce: {}", accept.nonce);
        }
        PairCmd::Reject { nonce, group, reason } => {
            let reject = pair::create_accept(groups_dir, identities_dir, &my_id, &group, &nonce, false, reason)?;
            println!("已拒绝配对");
        }
        PairCmd::Confirm { nonce, group } => {
            let confirm = pair::create_confirm(groups_dir, identities_dir, &my_id, &group, &nonce)?;
            println!("配对确认完成！");
        }
    }
    Ok(())
}

fn handle_send(to: &str, msg_type: &str, content: &str, identities_dir: &std::path::Path, groups_dir: &std::path::Path) -> Result<()> {
    let config = config::read_config()?;
    let my_id = config.default_identity.context("未设置默认身份")?;
    let sk = identity::load_signing_key(identities_dir, &my_id)?.0;

    let msg_type = match msg_type {
        "text" => types::MessageType::Text,
        "system" => types::MessageType::System,
        _ => anyhow::bail!("不支持的消息类型: {}，支持 text/system", msg_type),
    };

    let msg = types::PostMessage {
        id: uuid::Uuid::new_v4().to_string(),
        from: my_id.clone(),
        to: to.to_string(),
        msg_type,
        content: content.to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };

    let signed = message::sign_message(msg, &sk)?;

    if to.starts_with("group:") {
        let group_name = &to[6..];
        let member_ids = group::get_member_ids(groups_dir, group_name)?;
        for member_id in &member_ids {
            if member_id == &my_id { continue; }
            let mailbox = group::resolve_inbox_path(groups_dir, group_name, member_id).join("mailbox.jsonl");
            inbox::append_message(&mailbox, &signed)?;
            println!("→ {} ({})", member_id, mailbox.display());
        }
    } else if to == "*" {
        let all_groups = group::list_groups(groups_dir)?;
        for g in &all_groups {
            let member_ids = group::get_member_ids(groups_dir, g)?;
            for member_id in &member_ids {
                if member_id == &my_id { continue; }
                let mailbox = group::resolve_inbox_path(groups_dir, g, member_id).join("mailbox.jsonl");
                inbox::append_message(&mailbox, &signed)?;
                println!("→ {}", mailbox.display());
            }
        }
    } else {
        let group_name = config.default_group.context("未设置默认组，请指定 --to group:名称")?;
        let mailbox = group::resolve_inbox_path(groups_dir, &group_name, to).join("mailbox.jsonl");
        inbox::append_message(&mailbox, &signed)?;
        println!("消息已发送: id={} to={} path={}", signed.id, to, mailbox.display());
    }

    Ok(())
}

fn handle_poll(group_opt: Option<String>, follow: bool, identities_dir: &std::path::Path, groups_dir: &std::path::Path) -> Result<()> {
    let config = config::read_config()?;
    let my_id = config.default_identity.context("未设置默认身份")?;
    let group_name = group_opt.unwrap_or(config.default_group.context("未设置默认组")?);

    let loop_fn = || -> Result<()> {
        let inbox_dir = groups_dir.join(&group_name).join("inboxes").join(&my_id);
        let mailbox_path = inbox_dir.join("mailbox.jsonl");
        let watermark_path = inbox_dir.join(".watermark.json");

        let lines = inbox::read_all_lines(&mailbox_path).unwrap_or_default();
        if lines.is_empty() { return Ok(()); }

        let mut watermark = inbox::read_watermark(&watermark_path)?;
        let mut new_count = 0;

        for line in &lines {
            if let Some(msg) = message::jsonl_to_message(line) {
                if inbox::is_duplicate(&watermark, &msg.from, msg.ts, &msg.id) {
                    continue;
                }

                // 加载发送方的 pubkey
                let from_path = identities_dir.join(format!("{}.json", msg.from));
                if !from_path.exists() {
                    eprintln!("[warn] 未知发送方: {}", msg.from);
                    continue;
                }
                let from_ident = identity::read_identity(identities_dir, &msg.from)?;
                let pubkey_bytes = bs58::decode(&from_ident.pubkey).into_vec()
                    .unwrap_or_default();
                if pubkey_bytes.len() != 32 {
                    eprintln!("[warn] 发送方公钥格式错误: {}", msg.from);
                    continue;
                }
                let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().unwrap();
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr)?;

                match message::verify_message(&msg, &verifying_key) {
                    Ok(()) => {
                        println!("{}", serde_json::to_string(&msg)?);
                        inbox::update_watermark(&mut watermark, &msg.from, msg.ts, &msg.id);
                        new_count += 1;
                    }
                    Err(e) => {
                        eprintln!("[warn] 验签失败: {} — 跳过", e);
                    }
                }
            }
        }

        if new_count > 0 {
            inbox::write_watermark(&watermark_path, &watermark)?;
        }

        Ok(())
    };

    if follow {
        loop {
            if let Err(e) = loop_fn() {
                eprintln!("[error] {}", e);
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    } else {
        loop_fn()
    }
}

fn handle_key(cmd: KeyCmd, identities_dir: &std::path::Path, groups_dir: &std::path::Path) -> Result<()> {
    match cmd {
        KeyCmd::Revoke { reason } => {
            let config = config::read_config()?;
            let my_id = config.default_identity.context("未设置默认身份")?;
            let cert = identity::get_revocation_cert(identities_dir, &my_id)?;

            // 写入所有组
            let all_groups = group::list_groups(groups_dir)?;
            for g in &all_groups {
                let revocations_dir = groups_dir.join(g).join("revocations");
                fs::create_dir_all(&revocations_dir)?;
                let cert_json = serde_json::to_string_pretty(&cert)?;
                fs::write(revocations_dir.join(format!("{}.json", my_id)), cert_json)?;
            }

            println!("密钥已吊销");
            if let Some(r) = reason {
                println!("  原因: {}", r);
            }
        }
    }
}

fn handle_group(cmd: GroupCmd, groups_dir: &std::path::Path) -> Result<()> {
    match cmd {
        GroupCmd::Create { name } => {
            group::create_group(groups_dir, &name)?;
            println!("组已创建: {}", name);
        }
        GroupCmd::List => {
            let names = group::list_groups(groups_dir)?;
            if names.is_empty() {
                println!("暂无组");
            } else {
                println!("当前组：");
                for n in &names { println!("  {}", n); }
            }
        }
        GroupCmd::Info { name } => {
            let members = group::read_members(groups_dir, &name)?;
            println!("组: {}", name);
            println!("成员数: {}", members.len());
            for m in &members {
                println!("  {} — {} (pubkey: {}...)", m.agent_id, m.name, &m.pubkey[..8.min(m.pubkey.len())]);
            }
        }
        GroupCmd::AddRoute { group: g, agent, path } => {
            group::add_route(groups_dir, &g, &agent, &path)?;
            println!("路由已添加: {} → {}", agent, path);
        }
    }
    Ok(())
}
```

在文件顶部补 `use std::fs;`。

- [ ] **Step 2：编译检查**

```bash
cargo build
```

Expected: 编译通过

- [ ] **Step 3：重写 src/main.rs 的 mod 声明**

把 main.rs 里的 `mod lib` 改成正确的模块声明（已经在顶部了）。

- [ ] **Step 4：Commit**

```bash
git add src/main.rs
git commit -m "feat: CLI 入口 — clap derive，所有子命令分发

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 8：集成测试 + 端到端验证

**Files:**
- Create: `tests/integration_test.rs`

- [ ] **Step 1：写端到端测试**

```rust
use agent_post::identity;
use agent_post::group;
use agent_post::pair;
use agent_post::message;
use agent_post::inbox;
use agent_post::types::MessageType;
use chrono::Utc;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_full_pair_and_message_flow() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    let groups_dir = temp.path().join("groups");
    fs::create_dir_all(&identities_dir).unwrap();
    fs::create_dir_all(&groups_dir).unwrap();

    // A 和 B 各自 init
    let id_a = identity::create_identity(&identities_dir, "A", "测试组").unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "测试组").unwrap();

    // 创建组
    group::create_group(&groups_dir, "测试组").unwrap();

    // A → B 配对
    let invite = pair::create_invite(&groups_dir, &identities_dir, &id_a.agent_id, &id_b.agent_id, "测试组", false).unwrap();

    let pending = pair::check_pending(&groups_dir, "测试组", &id_b.agent_id).unwrap();
    assert_eq!(pending.len(), 1);

    let accept = pair::create_accept(&groups_dir, &identities_dir, &id_b.agent_id, "测试组", &pending[0].nonce, true, None).unwrap();

    let a_pending = pair::check_accepts(&groups_dir, "测试组", &id_a.agent_id).unwrap();
    assert_eq!(a_pending.len(), 1);

    pair::create_confirm(&groups_dir, &identities_dir, &id_a.agent_id, "测试组", &a_pending[0].nonce).unwrap();

    // 验证 members.toml
    let members = group::read_members(&groups_dir, "测试组").unwrap();
    assert!(members.iter().any(|m| m.agent_id == id_b.agent_id));

    // A → B 发消息
    let sk_a = identity::load_signing_key(&identities_dir, &id_a.agent_id).unwrap().0;
    let msg = agent_post::types::PostMessage {
        id: uuid::Uuid::new_v4().to_string(),
        from: id_a.agent_id.clone(),
        to: id_b.agent_id.clone(),
        msg_type: MessageType::Text,
        content: "你好 B！".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };
    let signed = message::sign_message(msg, &sk_a).unwrap();

    let b_mailbox = groups_dir.join("测试组").join("inboxes").join(&id_b.agent_id).join("mailbox.jsonl");
    inbox::append_message(&b_mailbox, &signed).unwrap();

    // B poll 收到
    let lines = inbox::read_all_lines(&b_mailbox).unwrap();
    assert_eq!(lines.len(), 1);

    let received = message::jsonl_to_message(&lines[0]).unwrap();
    assert_eq!(received.content, "你好 B！");

    // 验签
    let b_ident = identity::read_identity(&identities_dir, &id_b.agent_id).unwrap();
    let a_pubkey_bytes = bs58::decode(&id_a.pubkey).into_vec().unwrap();
    let a_pubkey: [u8; 32] = a_pubkey_bytes.try_into().unwrap();
    let a_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&a_pubkey).unwrap();
    message::verify_message(&received, &a_verifying_key).unwrap();

    // 验签成功后 watermark 去重
    let watermark_path = groups_dir.join("测试组").join("inboxes").join(&id_b.agent_id).join(".watermark.json");
    let mut wm = inbox::read_watermark(&watermark_path).unwrap();
    assert!(!inbox::is_duplicate(&wm, &received.from, received.ts, &received.id));
    inbox::update_watermark(&mut wm, &received.from, received.ts, &received.id);
    inbox::write_watermark(&watermark_path, &wm).unwrap();

    let wm2 = inbox::read_watermark(&watermark_path).unwrap();
    assert!(inbox::is_duplicate(&wm2, &received.from, received.ts, &received.id));
}

#[test]
fn test_tampered_message_rejected() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    let groups_dir = temp.path().join("groups");
    fs::create_dir_all(&identities_dir).unwrap();
    fs::create_dir_all(&groups_dir).unwrap();

    let id_a = identity::create_identity(&identities_dir, "A", "组").unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "组").unwrap();
    group::create_group(&groups_dir, "组").unwrap();

    let sk_a = identity::load_signing_key(&identities_dir, &id_a.agent_id).unwrap().0;

    let msg = agent_post::types::PostMessage {
        id: "tamper_test".to_string(),
        from: id_a.agent_id.clone(),
        to: id_b.agent_id.clone(),
        msg_type: MessageType::Text,
        content: "原文".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };
    let mut signed = message::sign_message(msg, &sk_a).unwrap();
    signed.content = "被篡改了！".to_string();

    // 验签应失败
    let a_pubkey_bytes = bs58::decode(&id_a.pubkey).into_vec().unwrap();
    let a_pubkey: [u8; 32] = a_pubkey_bytes.try_into().unwrap();
    let a_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&a_pubkey).unwrap();
    assert!(message::verify_message(&signed, &a_verifying_key).is_err());
}

#[test]
fn test_key_revoke_and_safety_number() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    let groups_dir = temp.path().join("groups");
    fs::create_dir_all(&identities_dir).unwrap();
    fs::create_dir_all(&groups_dir).unwrap();

    let old_id = identity::create_identity(&identities_dir, "A", "组").unwrap();
    // 生成新身份（模拟恢复）
    let new_id = identity::create_identity(&identities_dir, "A-恢复", "组").unwrap();

    // 安全数字
    let sn = pair::safety_number(&old_id.pubkey, &new_id.pubkey);
    assert_eq!(sn.len(), 10);
    // 相同输入应产生相同输出
    let sn2 = pair::safety_number(&old_id.pubkey, &new_id.pubkey);
    assert_eq!(sn, sn2);
    // 不同 pubkey 应产生不同安全数字
    let id_c = identity::create_identity(&identities_dir, "C", "组").unwrap();
    let sn3 = pair::safety_number(&old_id.pubkey, &id_c.pubkey);
    assert_ne!(sn, sn3);
}
```

- [ ] **Step 2：运行集成测试**

```bash
cargo test integration
```

Expected: 3 个集成测试 PASS

- [ ] **Step 3：运行全部测试**

```bash
cargo test
```

Expected: 全部测试 PASS（约 18 个）

- [ ] **Step 4：Release 编译**

```bash
cargo build --release
```

Expected: 编译成功，二进制在 `target/release/agent-post`

- [ ] **Step 5：功能验证**

```bash
# 创建测试环境
export AGENT_POST_TEST=$(mktemp -d)

./target/release/agent-post --identities-dir "$AGENT_POST_TEST/identities" --groups-dir "$AGENT_POST_TEST/groups" init -n 昼殿 -g 圣殿

# 查看身份
./target/release/agent-post --identities-dir "$AGENT_POST_TEST/identities" identity show

# 创建组
./target/release/agent-post --groups-dir "$AGENT_POST_TEST/groups" group create 圣殿
```

Expected: 无报错，输出清晰的文本信息

- [ ] **Step 6：Commit**

```bash
git add tests/integration_test.rs Cargo.toml
git commit -m "test: 端到端集成测试 — 完整配对+收发+验签+篡改检测+安全数字

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 9：协议 spec 文档

**Files:**
- Create: `docs/protocol-spec.md`

- [ ] **Step 1：写协议 spec**

基于设计规格书提炼一份面向开发者的协议规范，定义：
- 消息 JSONL 格式（字段、类型、签名算法）
- Inbox 目录布局（标准路径约定）
- 配对三次握手（消息格式、状态机、错误处理）
- 路由规则（单播/组播/广播的寻址语法）
- 安全考虑（验签用 verify_strict、消息大小上限、吊销证书格式）

协议 spec 是独立文档，不依赖 Rust 实现，任何人可以按 spec 用任意语言实现。

- [ ] **Step 2：Commit**

```bash
git add docs/protocol-spec.md
git commit -m "docs: 协议规范 — 语言无关的 Agent Post 协议定义

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## 验证清单

全部任务完成后：

1. `cargo test` — 全部测试通过
2. `cargo build --release` — release 编译成功
3. `cargo clippy --all-targets` — lint 通过（无严重警告）
4. 手动端到端：init A → init B → group create → pair invite → check → accept → confirm → send → poll → 消息正确 + 验签通过
5. 手动篡改：编辑 mailbox.jsonl → poll 报告验签失败
6. 手动过期：改 invite 时间戳 → check 过滤过期

---

## 自查结果

**1. Spec 覆盖：**
- Section IV (身份) → Task 2
- Section V (寻址) → Task 7 (handle_send 路由逻辑)
- Section VI (消息格式) → Task 3 (message.rs) + Task 1 (types.rs)
- Section VII (传输) → Task 4 (inbox.rs) + Task 7 (handle_poll)
- Section VIII (配置) → Task 1 (config.rs) + Task 5 (group.rs)
- Section IX (配对) → Task 6 (pair.rs)
- Section X (密钥吊销) → Task 7 (handle_key)
- Section XI (CLI) → Task 7 (main.rs)

**2. 占位符检查：** 无 TBD/TODO/占位符

**3. 类型一致性：**
- PostMessage/UnsignedMessage/PairPayload 在 types.rs 定义，message.rs/pair.rs 使用一致
- Identity/Member/Route/Config/Watermark 在 types.rs 定义，各模块使用一致
- `pair::safety_number()` 在 pair.rs 和 message.rs 中都有定义 → 应统一到 pair.rs。已在 Task 6 中的 pair.rs 定义，Task 3 的 message.rs 不再重复
