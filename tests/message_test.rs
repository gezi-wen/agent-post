use agent_post::message;
use agent_post::types::{MessageType, PostMessage};
use chrono::Utc;

#[test]
fn test_canonicalize_sorts_keys() {
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
    // content should appear before from (alphabetical order)
    let content_pos = json.find("\"content\"").unwrap();
    let from_pos = json.find("\"from\"").unwrap();
    assert!(content_pos < from_pos);
}

#[test]
fn test_sign_and_verify() {
    let (signing_key, _agent_id, _pubkey_b58) = agent_post::identity::generate_keypair();
    let verifying_key = signing_key.verifying_key();

    let msg = PostMessage {
        id: "msg1".to_string(),
        from: "A".to_string(),
        to: "B".to_string(),
        msg_type: MessageType::Text,
        content: "test message".to_string(),
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
        content: "original".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };

    let mut signed = message::sign_message(msg, &signing_key).unwrap();
    signed.content = "tampered!".to_string();

    let result = message::verify_message(&signed, &verifying_key);
    assert!(result.is_err());
}

#[test]
fn test_verify_wrong_key() {
    let (signing_key1, _id1, _pk1) = agent_post::identity::generate_keypair();
    let (signing_key2, _id2, _pk2) = agent_post::identity::generate_keypair();
    let verifying_key2 = signing_key2.verifying_key();

    let msg = PostMessage {
        id: "msg1".to_string(),
        from: "A".to_string(),
        to: "B".to_string(),
        msg_type: MessageType::Text,
        content: "test".to_string(),
        refs: vec![],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };
    let signed = message::sign_message(msg, &signing_key1).unwrap();

    let result = message::verify_message(&signed, &verifying_key2);
    assert!(result.is_err());
}

#[test]
fn test_file_ref_message_type() {
    let msg = PostMessage {
        id: "file_ref_test".to_string(),
        from: "A".to_string(),
        to: "B".to_string(),
        msg_type: MessageType::FileRef,
        content: "files/photo.png".to_string(),
        refs: vec!["files/photo.png".to_string()],
        ts: Utc::now(),
        sig: None,
        recovery: None,
        old_agent_id: None,
    };
    let (sk, _, _) = agent_post::identity::generate_keypair();
    let signed = message::sign_message(msg, &sk).unwrap();
    assert_eq!(signed.msg_type, MessageType::FileRef);
    assert_eq!(signed.refs, vec!["files/photo.png"]);
}

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
