use agent_post::inbox;
use agent_post::types::{MessageType, PostMessage, Watermark, WatermarkEntry};
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

    // write watermark
    let mut wm = Watermark::default();
    wm.entries.insert(
        "alice".to_string(),
        WatermarkEntry {
            last_ts: ts,
            seen_ids: vec!["1".to_string(), "2".to_string()],
        },
    );
    inbox::write_watermark(&watermark_path, &wm).unwrap();

    // read watermark
    let read = inbox::read_watermark(&watermark_path).unwrap();
    assert!(read.entries.contains_key("alice"));

    // check dedup
    assert!(inbox::is_duplicate(&wm, "alice", ts, "1"));
    assert!(inbox::is_duplicate(&wm, "alice", ts, "2"));
    assert!(!inbox::is_duplicate(&wm, "alice", ts, "3"));
    // earlier timestamp
    let earlier_ts = ts - chrono::Duration::seconds(1);
    assert!(inbox::is_duplicate(&wm, "alice", earlier_ts, "new"));
}

#[test]
fn test_watermark_update() {
    let mut wm = Watermark::default();
    let ts = Utc::now();

    inbox::update_watermark(&mut wm, "alice", ts, "msg1");
    assert!(wm.entries.contains_key("alice"));
    assert_eq!(wm.entries["alice"].seen_ids, vec!["msg1"]);

    // same timestamp, new message
    inbox::update_watermark(&mut wm, "alice", ts, "msg2");
    assert_eq!(wm.entries["alice"].seen_ids.len(), 2);

    // newer timestamp resets seen_ids
    let newer_ts = ts + chrono::Duration::seconds(10);
    inbox::update_watermark(&mut wm, "alice", newer_ts, "msg3");
    assert_eq!(wm.entries["alice"].last_ts, newer_ts);
    assert_eq!(wm.entries["alice"].seen_ids, vec!["msg3"]);
}

#[test]
fn test_read_empty_inbox() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("nonexistent.jsonl");
    let lines = inbox::read_all_lines(&path).unwrap();
    assert!(lines.is_empty());
}

#[test]
fn test_multiple_appends() {
    let temp = TempDir::new().unwrap();
    let mailbox_path = temp.path().join("mailbox.jsonl");

    for i in 0..5 {
        let msg = make_msg(&i.to_string(), "alice", &format!("msg{}", i));
        inbox::append_message(&mailbox_path, &msg).unwrap();
    }

    let lines = inbox::read_all_lines(&mailbox_path).unwrap();
    assert_eq!(lines.len(), 5);
}
