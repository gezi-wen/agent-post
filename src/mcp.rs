use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write, stdin, stdout};

use crate::{config, group, identity, inbox, message, pair};
use crate::types::MessageType;
use chrono::Utc;

// ── JSON-RPC 2.0 types ──

#[derive(Debug, Deserialize)]
struct Request {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

fn ok(id: Option<Value>, result: Value) -> Response {
    Response { jsonrpc: "2.0", id, result: Some(result), error: None }
}

fn err(id: Option<Value>, code: i32, message: &str) -> Response {
    Response {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(json!({"code": code, "message": message})),
    }
}

fn notify(method: &str, params: Value) {
    let notification = json!({"jsonrpc":"2.0","method":method,"params":params});
    let mut out = stdout();
    let _ = writeln!(out, "{}", serde_json::to_string(&notification).unwrap_or_default());
    let _ = out.flush();
}

fn respond(resp: &Response) {
    let mut out = stdout();
    let json_str = serde_json::to_string(resp).unwrap_or_default();
    let _ = writeln!(out, "{}", json_str);
    let _ = out.flush();
}

fn log(msg: &str) {
    eprintln!("[agent-post-mcp] {}", msg);
}

// ── Tool definitions ──

fn tool_defs() -> Vec<Value> {
    vec![
        json!({
            "name": "init",
            "description": "Initialize a new Agent Post identity with optional passphrase encryption",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Agent display name"},
                    "group": {"type": "string", "description": "Default group name", "default": "default"},
                    "passphrase": {"type": "string", "description": "Optional passphrase to encrypt the private key"}
                },
                "required": ["name"]
            }
        }),
        json!({
            "name": "identity_show",
            "description": "Show current default identity",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }),
        json!({
            "name": "identity_list",
            "description": "List all local identities",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }),
        json!({
            "name": "pair_invite",
            "description": "Send a pairing invitation to another agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Target agent_id"},
                    "group": {"type": "string", "description": "Group name"},
                    "recovery": {"type": "boolean", "description": "Whether this is a key recovery pairing", "default": false}
                },
                "required": ["to", "group"]
            }
        }),
        json!({
            "name": "pair_check",
            "description": "Check pending pairing invitations",
            "inputSchema": {
                "type": "object",
                "properties": {"group": {"type": "string", "description": "Group name"}},
                "required": ["group"]
            }
        }),
        json!({
            "name": "pair_accept",
            "description": "Accept a pending pairing invitation",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "nonce": {"type": "string", "description": "Invitation nonce"},
                    "group": {"type": "string", "description": "Group name"}
                },
                "required": ["nonce", "group"]
            }
        }),
        json!({
            "name": "pair_reject",
            "description": "Reject a pending pairing invitation",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "nonce": {"type": "string", "description": "Invitation nonce"},
                    "group": {"type": "string", "description": "Group name"},
                    "reason": {"type": "string", "description": "Optional reason for rejection"}
                },
                "required": ["nonce", "group"]
            }
        }),
        json!({
            "name": "pair_confirm",
            "description": "Confirm a pairing acceptance",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "nonce": {"type": "string", "description": "Accept nonce"},
                    "group": {"type": "string", "description": "Group name"}
                },
                "required": ["nonce", "group"]
            }
        }),
        json!({
            "name": "send_message",
            "description": "Send a signed message to another agent or group",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient: agent_id, group:name, or *"},
                    "msg_type": {"type": "string", "description": "Message type: text, system, or file_ref", "default": "text"},
                    "content": {"type": "string", "description": "Message content"}
                },
                "required": ["to", "content"]
            }
        }),
        json!({
            "name": "poll_inbox",
            "description": "Poll inbox for new messages (returns new messages with verified signatures)",
            "inputSchema": {
                "type": "object",
                "properties": {"group": {"type": "string", "description": "Group name (uses default if omitted)"}},
                "required": []
            }
        }),
        json!({
            "name": "group_create",
            "description": "Create a new Agent Post group",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "description": "Group name"}},
                "required": ["name"]
            }
        }),
        json!({
            "name": "group_list",
            "description": "List all groups",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }),
        json!({
            "name": "group_info",
            "description": "Show group details including members",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "description": "Group name"}},
                "required": ["name"]
            }
        }),
    ]
}

// ── Tool dispatch ──

fn call_tool(
    identities_dir: &std::path::Path,
    groups_dir: &std::path::Path,
    name: &str,
    params: &Value,
) -> Result<String> {
    let cfg = config::read_config()?;
    let my_id = cfg.default_identity.as_deref().unwrap_or("");

    macro_rules! s { ($p:ident) => { params[stringify!($p)].as_str() }; }
    macro_rules! sopt { ($p:expr) => { params.get($p).and_then(|v| v.as_str()) }; }
    macro_rules! bopt { ($p:expr) => { params.get($p).and_then(|v| v.as_bool()).unwrap_or(false) }; }

    match name {
        "init" => {
            let name = sopt!("name").unwrap_or("agent");
            let group = sopt!("group").unwrap_or("default");
            let pw = sopt!("passphrase").filter(|s| !s.is_empty());
            let ident = identity::create_identity(identities_dir, name, group, pw)?;

            let mut c = config::read_config()?;
            c.default_identity = Some(ident.agent_id.clone());
            c.default_group = Some(group.to_string());
            config::write_config(&c)?;

            Ok(json!({"agent_id": ident.agent_id, "name": ident.name, "group": ident.group}).to_string())
        }
        "identity_show" => {
            let id = identity::read_identity(identities_dir, my_id)?;
            Ok(json!({"agent_id": id.agent_id, "name": id.name, "group": id.group, "pubkey": id.pubkey}).to_string())
        }
        "identity_list" => {
            let ids = identity::list_identities(identities_dir)?;
            let list: Vec<_> = ids.iter().filter_map(|id_| {
                identity::read_identity(identities_dir, id_).ok().map(|i| {
                    json!({"agent_id": i.agent_id, "name": i.name, "group": i.group})
                })
            }).collect();
            Ok(serde_json::to_string(&list)?)
        }
        "pair_invite" => {
            let to = sopt!("to").context("to is required")?;
            let group = sopt!("group").context("group is required")?;
            let recovery = bopt!("recovery");
            let invite = pair::create_invite(groups_dir, identities_dir, my_id, to, group, recovery, None)?;
            Ok(json!({"nonce": invite.nonce, "status": "invited"}).to_string())
        }
        "pair_check" => {
            let group = sopt!("group").context("group is required")?;
            let pending = pair::check_pending(groups_dir, group, my_id)?;
            Ok(serde_json::to_string(&pending)?)
        }
        "pair_accept" => {
            let nonce = sopt!("nonce").context("nonce is required")?;
            let group = sopt!("group").context("group is required")?;
            let accept = pair::create_accept(groups_dir, identities_dir, my_id, group, nonce, true, None, None)?;
            Ok(json!({"nonce": accept.nonce, "status": "accepted"}).to_string())
        }
        "pair_reject" => {
            let nonce = sopt!("nonce").context("nonce is required")?;
            let group = sopt!("group").context("group is required")?;
            let reason = sopt!("reason").map(|s| s.to_string());
            pair::create_accept(groups_dir, identities_dir, my_id, group, nonce, false, reason, None)?;
            Ok(json!({"status": "rejected"}).to_string())
        }
        "pair_confirm" => {
            let nonce = sopt!("nonce").context("nonce is required")?;
            let group = sopt!("group").context("group is required")?;
            pair::create_confirm(groups_dir, identities_dir, my_id, group, nonce, None)?;
            Ok(json!({"status": "confirmed"}).to_string())
        }
        "send_message" => {
            let to = sopt!("to").context("to is required")?;
            let content = sopt!("content").context("content is required")?;
            let msg_type = match sopt!("msg_type").unwrap_or("text") {
                "system" => MessageType::System,
                "file_ref" => MessageType::FileRef,
                _ => MessageType::Text,
            };

            let msg_id = uuid::Uuid::new_v4().to_string();

            // Auto-switch to file_ref if content exceeds 64KB limit
            let (final_type, final_content, final_refs) = if content.len() > 64 * 1024 {
                let gname = if to.starts_with("group:") {
                    &to[6..]
                } else if let Some(ref dg) = cfg.default_group {
                    dg.as_str()
                } else {
                    "default"
                };
                let files_dir = groups_dir.join(gname).join("files");
                std::fs::create_dir_all(&files_dir)?;
                let filename = format!("{}.txt", &msg_id);
                std::fs::write(files_dir.join(&filename), content)?;
                (MessageType::FileRef, format!("Content saved to files/{}", filename), vec![format!("files/{}", filename)])
            } else {
                (msg_type, content.to_string(), vec![])
            };

            let passphrase = None; // MCP caller handles encryption externally
            let sk = identity::load_signing_key(identities_dir, my_id, passphrase)?.0;

            let msg = crate::types::PostMessage {
                id: msg_id,
                from: my_id.to_string(),
                to: to.to_string(),
                msg_type: final_type,
                content: final_content,
                refs: final_refs,
                ts: Utc::now(),
                sig: None,
                recovery: None,
                old_agent_id: None,
            };
            let signed = message::sign_message(msg, &sk)?;

            let paths = if to.starts_with("group:") {
                let gname = &to[6..];
                let members = group::get_member_ids(groups_dir, gname)?;
                members.iter().filter(|m| *m != my_id).map(|mid| {
                    let mbox = group::resolve_inbox_path(groups_dir, gname, mid).join("mailbox.jsonl");
                    inbox::append_message(&mbox, &signed).ok();
                    mbox.to_string_lossy().to_string()
                }).collect::<Vec<_>>()
            } else if to == "*" {
                let groups = group::list_groups(groups_dir)?;
                let mut paths = vec![];
                for g in &groups {
                    for mid in &group::get_member_ids(groups_dir, g)? {
                        if mid == my_id { continue; }
                        let mbox = group::resolve_inbox_path(groups_dir, g, mid).join("mailbox.jsonl");
                        inbox::append_message(&mbox, &signed).ok();
                        paths.push(mbox.to_string_lossy().to_string());
                    }
                }
                paths
            } else {
                let gname = cfg.default_group.context("no default group")?;
                let mbox = group::resolve_inbox_path(groups_dir, &gname, to).join("mailbox.jsonl");
                inbox::append_message(&mbox, &signed)?;
                vec![mbox.to_string_lossy().to_string()]
            };

            Ok(json!({"id": signed.id, "delivered_to": paths}).to_string())
        }
        "poll_inbox" => {
            let group_name = sopt!("group").or(cfg.default_group.as_deref()).context("no group specified")?;
            let inbox_dir = groups_dir.join(group_name).join("inboxes").join(my_id);
            let mailbox_path = inbox_dir.join("mailbox.jsonl");
            let watermark_path = inbox_dir.join(".watermark.json");

            let lines = inbox::read_all_lines(&mailbox_path).unwrap_or_default();
            if lines.is_empty() { return Ok("[]".to_string()); }

            let mut watermark = inbox::read_watermark(&watermark_path)?;
            let mut new_messages: Vec<Value> = vec![];
            let mut new_count = 0;

            for line in &lines {
                if let Some(msg) = message::jsonl_to_message(line) {
                    if inbox::is_duplicate(&watermark, &msg.from, msg.ts, &msg.id) {
                        continue;
                    }
                    let from_path = identities_dir.join(format!("{}.json", &msg.from));
                    if !from_path.exists() { continue; }
                    if let Ok(fi) = identity::read_identity(identities_dir, &msg.from) {
                        let pkb = bs58::decode(&fi.pubkey).into_vec().unwrap_or_default();
                        if pkb.len() == 32 {
                            let arr: [u8; 32] = match pkb.as_slice().try_into() {
                                Ok(a) => a,
                                Err(_) => continue,
                            };
                            let vk = match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            if message::verify_message(&msg, &vk).is_ok() {
                                    new_messages.push(json!({
                                        "id": msg.id, "from": msg.from, "content": msg.content,
                                        "type": msg.msg_type, "ts": msg.ts
                                    }));
                                    inbox::update_watermark(&mut watermark, &msg.from, msg.ts, &msg.id);
                                    new_count += 1;
                                }
                        }
                    }
                }
            }
            if new_count > 0 { inbox::write_watermark(&watermark_path, &watermark)?; }
            Ok(serde_json::to_string(&new_messages)?)
        }
        "group_create" => {
            let name = sopt!("name").context("name is required")?;
            group::create_group(groups_dir, name)?;
            Ok(json!({"group": name, "status": "created"}).to_string())
        }
        "group_list" => {
            let names = group::list_groups(groups_dir)?;
            Ok(serde_json::to_string(&names)?)
        }
        "group_info" => {
            let name = sopt!("name").context("name is required")?;
            let members = group::read_members(groups_dir, name)?;
            let list: Vec<_> = members.iter().map(|m| {
                json!({"agent_id": m.agent_id, "name": m.name, "pubkey": &m.pubkey[..8.min(m.pubkey.len())]})
            }).collect();
            Ok(json!({"group": name, "member_count": members.len(), "members": list}).to_string())
        }
        _ => anyhow::bail!("unknown tool: {}", name),
    }
}

// ── MCP lifecycle ──

pub fn serve(identities_dir: &std::path::Path, groups_dir: &std::path::Path) -> Result<()> {
    let stdin = stdin();
    let reader = BufReader::new(stdin.lock());

    log("MCP server started on stdio");
    log(&format!("identities_dir: {}", identities_dir.display()));
    log(&format!("groups_dir: {}", groups_dir.display()));

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() { continue; }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                log(&format!("parse error: {}", e));
                respond(&err(None, -32700, "Parse error"));
                continue;
            }
        };

        match req.method.as_str() {
            "initialize" => {
                log("→ initialize");
                respond(&ok(req.id.clone(), json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "agent-post",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })));

                // Read the next line for notifications/initialized
                // We handle it in the next loop iteration
            }
            "notifications/initialized" => {
                log("→ initialized");
                // No response needed for notifications
            }
            "tools/list" => {
                log("→ tools/list");
                respond(&ok(req.id.clone(), json!({"tools": tool_defs()})));
            }
            "tools/call" => {
                let tool_name = req.params["name"].as_str().unwrap_or("").to_string();
                let tool_args = req.params.get("arguments").cloned().unwrap_or(Value::Null);
                log(&format!("→ tools/call {}", tool_name));

                match call_tool(identities_dir, groups_dir, &tool_name, &tool_args) {
                    Ok(result_text) => {
                        // Try to parse result_text as JSON, fall back to text content
                        let content: Value = serde_json::from_str(&result_text)
                            .unwrap_or_else(|_| json!({"text": result_text}));

                        respond(&ok(req.id.clone(), json!({
                            "content": [{"type": "text", "text": serde_json::to_string(&content).unwrap_or(result_text)}]
                        })));
                    }
                    Err(e) => {
                        log(&format!("tool error: {}", e));
                        respond(&ok(req.id.clone(), json!({
                            "content": [{"type": "text", "text": format!("Error: {}", e)}],
                            "isError": true
                        })));
                    }
                }
            }
            "ping" => {
                respond(&ok(req.id.clone(), json!({})));
            }
            _ => {
                log(&format!("unknown method: {}", req.method));
                respond(&err(req.id, -32601, &format!("Method not found: {}", req.method)));
            }
        }
    }

    log("MCP server stopped");
    Ok(())
}
