use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use ed25519_dalek::Signer;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;

use crate::identity;
use crate::message;
use crate::group;
use crate::types::{PairPayload, PairStep, Member, PAIR_EXPIRY_HOURS};

/// Create invite (step 1), writes invite-{nonce}.json to pending/
pub fn create_invite(
    groups_dir: &Path,
    identities_dir: &Path,
    from_id: &str,
    to_id: &str,
    group_name: &str,
    recovery: bool,
    passphrase: Option<&str>,
) -> Result<PairPayload> {
    let sk = identity::load_signing_key(identities_dir, from_id, passphrase)?.0;

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

    let canonical = message::canonicalize(&payload)?;
    let hash = Sha256::digest(canonical.as_bytes());
    let sig = sk.sign(&hash);
    payload.sig = Some(bs58::encode(sig.to_bytes()).into_string());

    let pending_dir = groups_dir.join(group_name).join("pending");
    fs::create_dir_all(&pending_dir)?;
    let filename = format!("invite-{}.json", nonce);
    fs::write(pending_dir.join(filename), serde_json::to_string_pretty(&payload)?)?;

    Ok(payload)
}

/// Check pending invites for me (B's perspective)
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
        if payload.to_id != my_id {
            continue;
        }
        if payload.expires_at < Utc::now() {
            continue;
        }
        invites.push(payload);
    }
    Ok(invites)
}

/// Check pending accepts for me (A's perspective)
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

/// B creates accept or reject (step 2), writes accept-{nonce}.json to pending/
pub fn create_accept(
    groups_dir: &Path,
    identities_dir: &Path,
    from_id: &str,
    group_name: &str,
    invite_nonce: &str,
    accepted: bool,
    reason: Option<String>,
    passphrase: Option<&str>,
) -> Result<PairPayload> {
    let sk = identity::load_signing_key(identities_dir, from_id, passphrase)?.0;
    let pending_dir = groups_dir.join(group_name).join("pending");
    let invite_file = pending_dir.join(format!("invite-{}.json", invite_nonce));
    let invite_content = fs::read_to_string(&invite_file)
        .context("invite file not found, may have expired or been cleaned up")?;
    let invite: PairPayload = serde_json::from_str(&invite_content)?;

    // Compute invite hash for chaining
    let invite_canonical = message::canonicalize(&invite)?;
    let invite_hash = Sha256::digest(invite_canonical.as_bytes());
    let invite_hash_hex = hex::encode(&invite_hash);

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

    let filename = format!("accept-{}.json", payload.nonce);
    fs::write(pending_dir.join(filename), serde_json::to_string_pretty(&payload)?)?;

    // If accepted, B writes members.toml immediately
    if accepted {
        let a_identity = identity::read_identity(identities_dir, &invite.from_id)?;
        let member = Member {
            agent_id: invite.from_id.clone(),
            name: a_identity.name.clone(),
            pubkey: a_identity.pubkey.clone(),
            joined: now,
        };
        group::add_member(groups_dir, group_name, &member)?;
    }

    Ok(payload)
}

/// A creates confirm (step 3), writes confirm-{nonce}.json, adds B to members.toml
pub fn create_confirm(
    groups_dir: &Path,
    identities_dir: &Path,
    from_id: &str,
    group_name: &str,
    accept_nonce: &str,
    passphrase: Option<&str>,
) -> Result<PairPayload> {
    let pending_dir = groups_dir.join(group_name).join("pending");
    let accept_file = pending_dir.join(format!("accept-{}.json", accept_nonce));
    let accept_content = fs::read_to_string(&accept_file)
        .context("accept file not found")?;
    let accept: PairPayload = serde_json::from_str(&accept_content)?;

    if accept.accepted != Some(true) {
        anyhow::bail!("pairing was rejected by the other party");
    }

    // Compute accept hash for chaining
    let accept_canonical = message::canonicalize(&accept)?;
    let accept_hash = Sha256::digest(accept_canonical.as_bytes());
    let accept_hash_hex = hex::encode(&accept_hash);

    let sk = identity::load_signing_key(identities_dir, from_id, passphrase)?.0;
    let now = Utc::now();

    let mut payload = PairPayload {
        step: PairStep::Confirm,
        from_id: from_id.to_string(),
        to_id: accept.from_id.clone(),
        group_name: group_name.to_string(),
        nonce: uuid::Uuid::new_v4().to_string(),
        expires_at: now + Duration::hours(1),
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

    let filename = format!("confirm-{}.json", payload.nonce);
    fs::write(pending_dir.join(filename), serde_json::to_string_pretty(&payload)?)?;

    // A adds B to members.toml
    let b_identity = identity::read_identity(identities_dir, &accept.from_id)?;
    let member = Member {
        agent_id: accept.from_id.clone(),
        name: b_identity.name.clone(),
        pubkey: b_identity.pubkey.clone(),
        joined: now,
    };
    group::add_member(groups_dir, group_name, &member)?;

    Ok(payload)
}

/// Calculate safety number: first 10 decimal digits of sha256(old_pubkey + new_pubkey)
pub fn safety_number(old_pubkey: &str, new_pubkey: &str) -> String {
    let combined = format!("{}{}", old_pubkey, new_pubkey);
    let hash = Sha256::digest(combined.as_bytes());
    let hash_hex = hex::encode(&hash);
    let num = u64::from_str_radix(&hash_hex[..15], 16).unwrap_or(0);
    format!("{:010}", num % 10_000_000_000)
}
