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

    // A and B each init
    let id_a = identity::create_identity(&identities_dir, "A", "test_group", None).unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "test_group", None).unwrap();

    // Create group
    group::create_group(&groups_dir, "test_group").unwrap();

    // A -> B: pair invite
    let _invite = pair::create_invite(&groups_dir, &identities_dir, &id_a.agent_id, &id_b.agent_id, "test_group", false, None).unwrap();

    let pending = pair::check_pending(&groups_dir, "test_group", &id_b.agent_id).unwrap();
    assert_eq!(pending.len(), 1);

    // B accepts
    let _accept = pair::create_accept(&groups_dir, &identities_dir, &id_b.agent_id, "test_group", &pending[0].nonce, true, None, None).unwrap();

    let a_pending = pair::check_accepts(&groups_dir, "test_group", &id_a.agent_id).unwrap();
    assert_eq!(a_pending.len(), 1);

    // A confirms
    pair::create_confirm(&groups_dir, &identities_dir, &id_a.agent_id, "test_group", &a_pending[0].nonce, None).unwrap();

    // Verify members.toml
    let members = group::read_members(&groups_dir, "test_group").unwrap();
    assert!(members.iter().any(|m| m.agent_id == id_b.agent_id));

    // A -> B: send message
    let (sk_a, _vk_a) = identity::load_signing_key(&identities_dir, &id_a.agent_id, None).unwrap();
    let msg = agent_post::types::PostMessage {
        id: uuid::Uuid::new_v4().to_string(),
        from: id_a.agent_id.clone(),
        to: id_b.agent_id.clone(),
        msg_type: MessageType::Text,
        content: "Hello B!".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };
    let signed = message::sign_message(msg, &sk_a).unwrap();

    let b_mailbox = groups_dir.join("test_group").join("inboxes").join(&id_b.agent_id).join("mailbox.jsonl");
    inbox::append_message(&b_mailbox, &signed).unwrap();

    // B polls inbox
    let lines = inbox::read_all_lines(&b_mailbox).unwrap();
    assert_eq!(lines.len(), 1);

    let received = message::jsonl_to_message(&lines[0]).unwrap();
    assert_eq!(received.content, "Hello B!");

    // Verify signature
    let a_pubkey_bytes = bs58::decode(&id_a.pubkey).into_vec().unwrap();
    let a_pubkey: [u8; 32] = a_pubkey_bytes.try_into().unwrap();
    let a_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&a_pubkey).unwrap();
    message::verify_message(&received, &a_verifying_key).unwrap();

    // Watermark dedup
    let watermark_path = groups_dir.join("test_group").join("inboxes").join(&id_b.agent_id).join(".watermark.json");
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

    let id_a = identity::create_identity(&identities_dir, "A", "group", None).unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "group", None).unwrap();
    group::create_group(&groups_dir, "group").unwrap();

    let (sk_a, _vk_a) = identity::load_signing_key(&identities_dir, &id_a.agent_id, None).unwrap();

    let msg = agent_post::types::PostMessage {
        id: "tamper_test".to_string(),
        from: id_a.agent_id.clone(),
        to: id_b.agent_id.clone(),
        msg_type: MessageType::Text,
        content: "original".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };
    let mut signed = message::sign_message(msg, &sk_a).unwrap();
    // Tamper with content
    signed.content = "tampered!".to_string();

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

    let old_id = identity::create_identity(&identities_dir, "A", "group", None).unwrap();
    // Generate new identity (simulating recovery)
    let new_id = identity::create_identity(&identities_dir, "A-recovered", "group", None).unwrap();

    // Safety number is deterministic
    let sn = pair::safety_number(&old_id.pubkey, &new_id.pubkey);
    assert_eq!(sn.len(), 10);
    let sn2 = pair::safety_number(&old_id.pubkey, &new_id.pubkey);
    assert_eq!(sn, sn2);

    // Different pubkey produces different safety number
    let id_c = identity::create_identity(&identities_dir, "C", "group", None).unwrap();
    let sn3 = pair::safety_number(&old_id.pubkey, &id_c.pubkey);
    assert_ne!(sn, sn3);

    // Revocation cert exists and is valid JSON
    assert!(old_id.revocation_cert.is_some());
    let cert: agent_post::types::RevocationCert = serde_json::from_str(old_id.revocation_cert.as_ref().unwrap()).unwrap();
    assert_eq!(cert.agent_id, old_id.agent_id);
}
