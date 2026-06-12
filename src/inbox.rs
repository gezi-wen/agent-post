use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::types::{PostMessage, Watermark, WatermarkEntry};

/// Append a message to a JSONL file (O_APPEND, POSIX atomic guarantee for single-line writes)
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

/// Read all lines from a JSONL file
pub fn read_all_lines(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    reader
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read JSONL")
}

/// Read watermark
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

/// Write watermark
pub fn write_watermark(path: &Path, wm: &Watermark) -> Result<()> {
    let json = serde_json::to_string(wm)?;
    fs::write(path, json)?;
    Ok(())
}

/// Check if a message is a duplicate
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

/// Update watermark after processing a message
pub fn update_watermark(wm: &mut Watermark, from: &str, msg_ts: DateTime<Utc>, msg_id: &str) {
    let entry = wm
        .entries
        .entry(from.to_string())
        .or_insert(WatermarkEntry {
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

/// Get inbox directory path for an agent within a group
pub fn inbox_dir(group_dir: &Path, agent_id: &str) -> std::path::PathBuf {
    group_dir.join("inboxes").join(agent_id)
}

/// Get mailbox.jsonl path
pub fn mailbox_path(group_dir: &Path, agent_id: &str) -> std::path::PathBuf {
    inbox_dir(group_dir, agent_id).join("mailbox.jsonl")
}

/// Get watermark path for an agent's inbox
pub fn watermark_path(inbox_dir: &Path) -> std::path::PathBuf {
    inbox_dir.join(".watermark.json")
}
