use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write, Read};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use crate::{group, identity, inbox, message};

/// Send a signed message to a remote relay via HTTP POST.
/// Returns Ok(true) if relayed, Ok(false) if no relay configured.
pub fn maybe_send_via_relay(
    groups_dir: &Path,
    from_group: &str,
    target_group: &str,
    msg: &crate::types::PostMessage,
) -> Result<bool> {
    let relays = group::read_relays(groups_dir, from_group)?;
    let relay_url = match relays.get(target_group) {
        Some(url) => url.clone(),
        None => return Ok(false),
    };

    let body = serde_json::to_string(&serde_json::json!({
        "group": target_group,
        "message": msg,
    }))?;

    let result = http_post(&relay_url, &body)?;
    eprintln!("[agent-post-relay] Relayed to {}: {}", relay_url, result);
    Ok(true)
}

/// Minimal HTTP POST with JSON body. Parses URL, opens TCP, sends request.
fn http_post(url: &str, body: &str) -> Result<String> {
    // Parse URL: http://host:port/path
    let url = url.trim_end_matches('/');
    let (host, port, path) = if let Some(rest) = url.strip_prefix("http://") {
        let (hp, path) = rest.split_once('/').unwrap_or((rest, "/relay"));
        let (host, port) = hp.split_once(':').unwrap_or((hp, "80"));
        (host.to_string(), port.parse::<u16>().unwrap_or(80), path.to_string())
    } else {
        anyhow::bail!("unsupported URL scheme (only http:// supported): {}", url);
    };

    let addr = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .context("failed to resolve host")?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, port, body.len(), body
    );
    stream.write_all(request.as_bytes())?;

    let mut reader = BufReader::new(&stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;

    // Skip headers
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header == "\r\n" || header == "\n" {
            break;
        }
    }

    let mut response_body = String::new();
    reader.read_to_string(&mut response_body)?;

    let status = status_line.trim().to_string();
    if status.contains("200") {
        Ok(response_body)
    } else {
        Ok(format!("relay returned {}: {}", status, response_body.trim()))
    }
}

#[derive(Debug, Deserialize)]
struct RelayPayload {
    group: String,
    message: Value,
}

#[derive(Debug, Serialize)]
struct RelayResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Start relay HTTP server. Listens for POST /relay to receive forwarded messages.
pub fn serve(
    identities_dir: &Path,
    groups_dir: &Path,
    port: u16,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)
        .with_context(|| format!("failed to bind to {}", addr))?;

    eprintln!("[agent-post-relay] Listening on http://{}", addr);
    eprintln!("[agent-post-relay] identities_dir: {}", identities_dir.display());
    eprintln!("[agent-post-relay] groups_dir: {}", groups_dir.display());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_connection(stream, identities_dir, groups_dir) {
                    eprintln!("[agent-post-relay] Connection error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("[agent-post-relay] Accept error: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream, identities_dir: &Path, groups_dir: &Path) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return http_response(&mut stream, 400, "Bad Request");
    }
    let method = parts[0];
    let path = parts[1];

    // Read headers
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header == "\r\n" || header == "\n" || header.is_empty() {
            break;
        }
        if header.to_lowercase().starts_with("content-length:") {
            content_length = header.split(':').nth(1)
                .unwrap_or("0").trim().parse().unwrap_or(0);
        }
    }

    match (method, path) {
        ("GET", "/health") => {
            let resp = serde_json::to_string(&RelayResponse { status: "ok".to_string(), error: None })?;
            http_json_response(&mut stream, 200, &resp)?;
        }
        ("POST", "/relay") => {
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body)?;
            }

            let payload: RelayPayload = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(e) => {
                    let resp = RelayResponse { status: "error".to_string(), error: Some(format!("invalid JSON: {}", e)) };
                    http_json_response(&mut stream, 400, &serde_json::to_string(&resp)?)?;
                    return Ok(());
                }
            };

            if content_length > 128 * 1024 {
                let resp = RelayResponse { status: "error".to_string(), error: Some("payload too large (max 128KB)".to_string()) };
                http_json_response(&mut stream, 413, &serde_json::to_string(&resp)?)?;
                return Ok(());
            }

            let msg: crate::types::PostMessage = match serde_json::from_value(payload.message.clone()) {
                Ok(m) => m,
                Err(e) => {
                    let resp = RelayResponse { status: "error".to_string(), error: Some(format!("invalid message: {}", e)) };
                    http_json_response(&mut stream, 400, &serde_json::to_string(&resp)?)?;
                    return Ok(());
                }
            };

            // Verify sender's signature
            let from_path = identities_dir.join(format!("{}.json", msg.from));
            if !from_path.exists() {
                let resp = RelayResponse { status: "error".to_string(), error: Some("unknown sender".to_string()) };
                http_json_response(&mut stream, 403, &serde_json::to_string(&resp)?)?;
                return Ok(());
            }
            let from_ident = identity::read_identity(identities_dir, &msg.from)?;
            let pubkey_bytes = bs58::decode(&from_ident.pubkey).into_vec().unwrap_or_default();
            if pubkey_bytes.len() != 32 {
                let resp = RelayResponse { status: "error".to_string(), error: Some("invalid sender pubkey".to_string()) };
                http_json_response(&mut stream, 403, &serde_json::to_string(&resp)?)?;
                return Ok(());
            }
            let arr: [u8; 32] = pubkey_bytes.try_into().unwrap();
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map_err(|_| anyhow::anyhow!("invalid pubkey"))?;

            if message::verify_message(&msg, &vk).is_err() {
                let resp = RelayResponse { status: "error".to_string(), error: Some("signature verification failed".to_string()) };
                http_json_response(&mut stream, 403, &serde_json::to_string(&resp)?)?;
                return Ok(());
            }

            // Route to correct inbox
            let target_id = if msg.to.starts_with("group:") {
                let gname = &msg.to[6..];
                let members = group::get_member_ids(groups_dir, gname)?;
                // Write to all members in target group
                for mid in &members {
                    if mid == &msg.from { continue; }
                    let mbox = group::resolve_inbox_path(groups_dir, gname, mid).join("mailbox.jsonl");
                    inbox::append_message(&mbox, &msg)?;
                }
                group::get_member_ids(groups_dir, gname)?.join(", ")
            } else {
                let gname = &payload.group;
                let mbox = group::resolve_inbox_path(groups_dir, gname, &msg.to).join("mailbox.jsonl");
                inbox::append_message(&mbox, &msg)?;
                msg.to.clone()
            };

            eprintln!("[agent-post-relay] Delivered message {} to {}", msg.id, target_id);

            let resp = RelayResponse { status: "delivered".to_string(), error: None };
            http_json_response(&mut stream, 200, &serde_json::to_string(&resp)?)?;
        }
        _ => {
            let resp = RelayResponse { status: "error".to_string(), error: Some("not found".to_string()) };
            http_json_response(&mut stream, 404, &serde_json::to_string(&resp)?)?;
        }
    }

    Ok(())
}

fn http_response(stream: &mut TcpStream, code: u16, body: &str) -> Result<()> {
    let status = match code {
        200 => "200 OK",
        400 => "400 Bad Request",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        413 => "413 Payload Too Large",
        _ => "500 Internal Server Error",
    };
    write!(stream, "HTTP/1.1 {}\r\nContent-Length: {}\r\n\r\n{}", status, body.len(), body)?;
    Ok(())
}

fn http_json_response(stream: &mut TcpStream, code: u16, body: &str) -> Result<()> {
    let status = match code {
        200 => "200 OK",
        400 => "400 Bad Request",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        413 => "413 Payload Too Large",
        _ => "500 Internal Server Error",
    };
    write!(stream, "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", status, body.len(), body)?;
    Ok(())
}
