mod types;
mod config;
mod identity;
mod message;
mod inbox;
mod group;
mod pair;
mod encryption;
mod mcp;
mod relay;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use std::fs;

#[derive(Parser)]
#[command(name = "agent-post", about = "AI agent identity + communication protocol")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true)]
    identities_dir: Option<String>,

    #[arg(long, global = true)]
    groups_dir: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start MCP server on stdio
    Mcp,
    /// Initialize a new identity
    Init {
        #[arg(short, long)]
        name: String,
        #[arg(short, long, default_value = "default")]
        group: String,
        /// Passphrase to encrypt the private key (interactive prompt if omitted)
        #[arg(short, long)]
        passphrase: Option<String>,
    },
    /// Manage identities
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Pairing management
    Pair {
        #[command(subcommand)]
        cmd: PairCmd,
    },
    /// Send a message
    Send {
        #[arg(short, long)]
        to: String,
        #[arg(short, long, default_value = "text")]
        msg_type: String,
        #[arg(short, long)]
        content: String,
    },
    /// Poll inbox for new messages
    Poll {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        follow: bool,
    },
    /// Key management
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Group management
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    /// Start relay HTTP server
    Relay {
        #[arg(short, long, default_value = "9876")]
        port: u16,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Show current default identity
    Show,
    /// List all local identities
    List,
    /// Export identity (without secret key)
    Export {
        agent_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum PairCmd {
    /// Send pairing invitation
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
    /// Check pending invites
    Check {
        #[arg(short, long)]
        group: String,
    },
    /// Accept pairing
    Accept {
        nonce: String,
        #[arg(short, long)]
        group: String,
    },
    /// Reject pairing
    Reject {
        nonce: String,
        #[arg(short, long)]
        group: String,
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Confirm pairing
    Confirm {
        nonce: String,
        #[arg(short, long)]
        group: String,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Revoke current key
    Revoke {
        #[arg(short, long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Create a new group
    Create {
        name: String,
    },
    /// List all groups
    List,
    /// Show group details
    Info {
        name: String,
    },
    /// Add cross-machine inbox route
    AddRoute {
        #[arg(long)]
        group: String,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        path: String,
    },
}

/// Prompt for passphrase if identity has encrypted secret key.
fn resolve_passphrase(identities_dir: &std::path::Path, agent_id: &str) -> Result<Option<String>> {
    let identity = identity::read_identity(identities_dir, agent_id)?;
    if identity.encrypted_secret_key.is_some() {
        eprint!("Passphrase: ");
        let pw = rpassword::read_password()?;
        Ok(Some(pw))
    } else {
        Ok(None)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let identities_dir = cli
        .identities_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| config::identities_dir());
    let groups_dir = cli
        .groups_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| config::groups_dir());

    match cli.command {
        Commands::Mcp => {
            mcp::serve(&identities_dir, &groups_dir)
        }
        Commands::Init { name, group, passphrase } => {
            let passphrase = passphrase.or_else(|| {
                eprint!("Passphrase (empty for no encryption): ");
                rpassword::read_password().ok()
            });
            let passphrase = passphrase.filter(|p| !p.is_empty());

            let identity = identity::create_identity(&identities_dir, &name, &group, passphrase.as_deref())?;
            let mut cfg = config::read_config()?;
            cfg.default_identity = Some(identity.agent_id.clone());
            cfg.default_group = Some(group.clone());
            config::write_config(&cfg)?;

            println!("Identity created:");
            println!("  Agent ID: {}", identity.agent_id);
            println!("  Name: {}", identity.name);
            println!("  Group: {}", identity.group);
            if identity.encrypted_secret_key.is_some() {
                println!("  Encrypted: yes");
            } else {
                println!("  Encrypted: no (plaintext — consider using --passphrase)");
            }
            println!(
                "  File: {}",
                identities_dir
                    .join(format!("{}.json", identity.agent_id))
                    .display()
            );
            Ok(())
        }
        Commands::Identity { cmd } => handle_identity(cmd, &identities_dir),
        Commands::Pair { cmd } => handle_pair(cmd, &identities_dir, &groups_dir),
        Commands::Send {
            to,
            msg_type,
            content,
        } => handle_send(&to, &msg_type, &content, &identities_dir, &groups_dir),
        Commands::Poll { group, follow } => {
            handle_poll(group, follow, &identities_dir, &groups_dir)
        }
        Commands::Key { cmd } => handle_key(cmd, &identities_dir, &groups_dir),
        Commands::Group { cmd } => handle_group(cmd, &groups_dir),
        Commands::Relay { port } => relay::serve(&identities_dir, &groups_dir, port),
    }
}

fn handle_identity(cmd: IdentityCmd, identities_dir: &std::path::Path) -> Result<()> {
    match cmd {
        IdentityCmd::Show => {
            let config = config::read_config()?;
            let agent_id = config
                .default_identity
                .context("No default identity set. Run 'init' first.")?;
            let ident = identity::read_identity(identities_dir, &agent_id)?;
            println!("Agent ID: {}", ident.agent_id);
            println!("Name: {}", ident.name);
            println!("Group: {}", ident.group);
            println!("Pubkey: {}", ident.pubkey);
            println!("Encrypted: {}", ident.encrypted_secret_key.is_some());
            println!("Created: {}", ident.created);
        }
        IdentityCmd::List => {
            let ids = identity::list_identities(identities_dir)?;
            if ids.is_empty() {
                println!("No local identities.");
            } else {
                println!("Local identities:");
                for id in &ids {
                    let ident = identity::read_identity(identities_dir, id)?;
                    let enc = if ident.encrypted_secret_key.is_some() { " [encrypted]" } else { "" };
                    println!("  {} — {}{}", ident.agent_id, ident.name, enc);
                }
            }
        }
        IdentityCmd::Export { agent_id } => {
            let id = agent_id.unwrap_or_else(|| {
                config::read_config()
                    .ok()
                    .and_then(|c| c.default_identity)
                    .unwrap_or_default()
            });
            let exported = identity::export_identity(identities_dir, &id)?;
            println!("{}", serde_json::to_string_pretty(&exported)?);
        }
    }
    Ok(())
}

fn handle_pair(
    cmd: PairCmd,
    identities_dir: &std::path::Path,
    groups_dir: &std::path::Path,
) -> Result<()> {
    let config = config::read_config()?;
    let my_id = config
        .default_identity
        .context("No default identity set.")?;
    let my_identity = identity::read_identity(identities_dir, &my_id)?;
    let passphrase = resolve_passphrase(identities_dir, &my_id)?;

    match cmd {
        PairCmd::Invite {
            to,
            group,
            name: _,
            recovery,
        } => {
            let invite = pair::create_invite(
                groups_dir,
                identities_dir,
                &my_id,
                &to,
                &group,
                recovery,
                passphrase.as_deref(),
            )?;
            println!("Pairing invitation sent");
            println!("  Nonce: {}", invite.nonce);
            if recovery {
                if let Ok(b_ident) = identity::read_identity(identities_dir, &to) {
                    let sn = pair::safety_number(&b_ident.pubkey, &my_identity.pubkey);
                    println!("  Safety Number: {}", sn);
                    println!("  Have the other party confirm this number matches theirs.");
                }
            }
        }
        PairCmd::Check { group } => {
            let invites = pair::check_pending(groups_dir, &group, &my_id)?;
            if invites.is_empty() {
                println!("No pending invitations.");
            } else {
                for inv in &invites {
                    println!(
                        "From: {}  Group: {}  Nonce: {}  Expires: {}  Recovery: {:?}",
                        inv.from_id, inv.group_name, inv.nonce, inv.expires_at, inv.recovery
                    );
                }
            }
        }
        PairCmd::Accept { nonce, group } => {
            let accept = pair::create_accept(
                groups_dir,
                identities_dir,
                &my_id,
                &group,
                &nonce,
                true,
                None,
                passphrase.as_deref(),
            )?;
            println!("Pairing accepted. Nonce: {}", accept.nonce);
        }
        PairCmd::Reject {
            nonce,
            group,
            reason,
        } => {
            pair::create_accept(
                groups_dir,
                identities_dir,
                &my_id,
                &group,
                &nonce,
                false,
                reason,
                passphrase.as_deref(),
            )?;
            println!("Pairing rejected.");
        }
        PairCmd::Confirm { nonce, group } => {
            pair::create_confirm(groups_dir, identities_dir, &my_id, &group, &nonce, passphrase.as_deref())?;
            println!("Pairing confirmed!");
        }
    }
    Ok(())
}

fn handle_send(
    to: &str,
    msg_type: &str,
    content: &str,
    identities_dir: &std::path::Path,
    groups_dir: &std::path::Path,
) -> Result<()> {
    let config = config::read_config()?;
    let my_id = config
        .default_identity
        .context("No default identity set.")?;
    let passphrase = resolve_passphrase(identities_dir, &my_id)?;
    let sk = identity::load_signing_key(identities_dir, &my_id, passphrase.as_deref())?.0;

    let msg_type = match msg_type {
        "text" => types::MessageType::Text,
        "system" => types::MessageType::System,
        "file_ref" => types::MessageType::FileRef,
        _ => anyhow::bail!("Unsupported message type: {}. Supported: text, system, file_ref", msg_type),
    };

    let msg_id = uuid::Uuid::new_v4().to_string();

    // Auto-switch to file_ref if content exceeds 64KB limit
    let (final_type, final_content, final_refs) = if content.len() > 64 * 1024 {
        let gname = if to.starts_with("group:") {
            &to[6..]
        } else if let Some(ref default_group) = config.default_group {
            default_group.as_str()
        } else {
            "default"
        };
        let files_dir = groups_dir.join(gname).join("files");
        fs::create_dir_all(&files_dir)?;
        let filename = format!("{}.txt", &msg_id);
        fs::write(files_dir.join(&filename), content)?;
        (types::MessageType::FileRef, format!("Content saved to files/{}", filename), vec![format!("files/{}", filename)])
    } else {
        (msg_type, content.to_string(), vec![])
    };

    let msg = types::PostMessage {
        id: msg_id,
        from: my_id.clone(),
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

    if to.starts_with("group:") {
        let group_name = &to[6..];
        let member_ids = group::get_member_ids(groups_dir, group_name)?;

        // Try relay if no local members
        if member_ids.is_empty() {
            let my_group = config.default_group.as_deref().unwrap_or("default");
            let relayed = relay::maybe_send_via_relay(groups_dir, my_group, group_name, &signed)?;
            if relayed {
                println!("Message relayed to group:{}", group_name);
            } else {
                println!("No local members and no relay configured for group:{}", group_name);
            }
        } else {
            for member_id in &member_ids {
                if member_id == &my_id { continue; }
                let mailbox = group::resolve_inbox_path(groups_dir, group_name, member_id)
                    .join("mailbox.jsonl");
                inbox::append_message(&mailbox, &signed)?;
                println!("-> {} ({})", member_id, mailbox.display());
            }
        }
    } else if to == "*" {
        let all_groups = group::list_groups(groups_dir)?;
        for g in &all_groups {
            let member_ids = group::get_member_ids(groups_dir, g)?;
            for member_id in &member_ids {
                if member_id == &my_id {
                    continue;
                }
                let mailbox = group::resolve_inbox_path(groups_dir, g, member_id)
                    .join("mailbox.jsonl");
                inbox::append_message(&mailbox, &signed)?;
                println!("-> {}", mailbox.display());
            }
        }
    } else {
        let group_name = config.default_group.context(
            "No default group set. Use --to group:name or set a default group.",
        )?;
        let mailbox = group::resolve_inbox_path(groups_dir, &group_name, to)
            .join("mailbox.jsonl");
        inbox::append_message(&mailbox, &signed)?;
        println!(
            "Message sent: id={} to={} path={}",
            signed.id,
            to,
            mailbox.display()
        );
    }

    Ok(())
}

fn handle_poll(
    group_opt: Option<String>,
    follow: bool,
    identities_dir: &std::path::Path,
    groups_dir: &std::path::Path,
) -> Result<()> {
    let config = config::read_config()?;
    let my_id = config
        .default_identity
        .context("No default identity set.")?;
    let group_name =
        group_opt.unwrap_or(config.default_group.context("No default group set.")?);

    let loop_fn = || -> Result<()> {
        let inbox_dir = groups_dir.join(&group_name).join("inboxes").join(&my_id);
        let mailbox_path = inbox_dir.join("mailbox.jsonl");
        let watermark_path = inbox_dir.join(".watermark.json");

        let lines = inbox::read_all_lines(&mailbox_path).unwrap_or_default();
        if lines.is_empty() {
            return Ok(());
        }

        let mut watermark = inbox::read_watermark(&watermark_path)?;
        let mut new_count = 0;

        for line in &lines {
            if let Some(msg) = message::jsonl_to_message(line) {
                if inbox::is_duplicate(&watermark, &msg.from, msg.ts, &msg.id) {
                    continue;
                }

                let from_path = identities_dir.join(format!("{}.json", msg.from));
                if !from_path.exists() {
                    eprintln!("[warn] Unknown sender: {}", msg.from);
                    continue;
                }
                let from_ident = identity::read_identity(identities_dir, &msg.from)?;
                let pubkey_bytes =
                    bs58::decode(&from_ident.pubkey).into_vec().unwrap_or_default();
                if pubkey_bytes.len() != 32 {
                    eprintln!("[warn] Invalid pubkey format for sender: {}", msg.from);
                    continue;
                }
                let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().unwrap();
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr)?;

                match message::verify_message(&msg, &verifying_key) {
                    Ok(()) => {
                        println!("{}", serde_json::to_string(&msg)?);
                        inbox::update_watermark(
                            &mut watermark,
                            &msg.from,
                            msg.ts,
                            &msg.id,
                        );
                        new_count += 1;
                    }
                    Err(e) => {
                        eprintln!(
                            "[warn] Signature verification failed: {} — skipping",
                            e
                        );
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

fn handle_key(
    cmd: KeyCmd,
    identities_dir: &std::path::Path,
    groups_dir: &std::path::Path,
) -> Result<()> {
    match cmd {
        KeyCmd::Revoke { reason } => {
            let config = config::read_config()?;
            let my_id = config
                .default_identity
                .context("No default identity set.")?;
            let cert = identity::get_revocation_cert(identities_dir, &my_id)?;

            let all_groups = group::list_groups(groups_dir)?;
            for g in &all_groups {
                let revocations_dir = groups_dir.join(g).join("revocations");
                fs::create_dir_all(&revocations_dir)?;
                let cert_json = serde_json::to_string_pretty(&cert)?;
                fs::write(revocations_dir.join(format!("{}.json", my_id)), cert_json)?;
            }

            println!("Key revoked.");
            if let Some(r) = reason {
                println!("  Reason: {}", r);
            }
            Ok(())
        }
    }
}

fn handle_group(cmd: GroupCmd, groups_dir: &std::path::Path) -> Result<()> {
    match cmd {
        GroupCmd::Create { name } => {
            group::create_group(groups_dir, &name)?;
            println!("Group created: {}", name);
        }
        GroupCmd::List => {
            let names = group::list_groups(groups_dir)?;
            if names.is_empty() {
                println!("No groups.");
            } else {
                println!("Groups:");
                for n in &names {
                    println!("  {}", n);
                }
            }
        }
        GroupCmd::Info { name } => {
            let members = group::read_members(groups_dir, &name)?;
            println!("Group: {}", name);
            println!("Members: {}", members.len());
            for m in &members {
                println!(
                    "  {} — {} (pubkey: {}...)",
                    m.agent_id,
                    m.name,
                    &m.pubkey[..8.min(m.pubkey.len())]
                );
            }
        }
        GroupCmd::AddRoute { group: g, agent, path } => {
            group::add_route(groups_dir, &g, &agent, &path)?;
            println!("Route added: {} -> {}", agent, path);
        }
    }
    Ok(())
}
