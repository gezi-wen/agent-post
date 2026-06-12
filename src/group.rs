use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::types::Member;

/// Create a group directory with all required subdirectories and config files
pub fn create_group(groups_dir: &Path, name: &str) -> Result<()> {
    let group_dir = groups_dir.join(name);
    fs::create_dir_all(&group_dir)?;

    let group_toml = format!(
        r#"# Agent Post group config
name = "{}"
created = "{}"
description = ""
"#,
        name,
        chrono::Utc::now().to_rfc3339()
    );
    fs::write(group_dir.join("group.toml"), group_toml)?;
    fs::write(group_dir.join("members.toml"), "# Group members (auto-written after pairing confirmation)\n")?;
    fs::write(group_dir.join("routes.toml"), "# Cross-machine inbox route mapping\n\n# Example:\n# [routes.\"agent_id\"]\n# path = \"/mnt/remote/.agent-post/groups/group_name/inboxes/agent_id/\"\n")?;

    fs::create_dir_all(group_dir.join("inboxes"))?;
    fs::create_dir_all(group_dir.join("pending"))?;
    fs::create_dir_all(group_dir.join("revocations"))?;

    Ok(())
}

/// List all group names
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

/// Read all members from a group
pub fn read_members(groups_dir: &Path, group_name: &str) -> Result<Vec<Member>> {
    let members_path = groups_dir.join(group_name).join("members.toml");
    if !members_path.exists() {
        return Ok(vec![]);
    }
    let content = fs::read_to_string(&members_path)?;

    #[derive(serde::Deserialize)]
    struct MembersFile {
        members: Option<Vec<Member>>,
    }
    let parsed: MembersFile = toml::from_str(&content).unwrap_or(MembersFile { members: None });
    Ok(parsed.members.unwrap_or_default())
}

/// Add a member to a group (deduplicates by agent_id)
pub fn add_member(groups_dir: &Path, group_name: &str, member: &Member) -> Result<()> {
    let mut members = read_members(groups_dir, group_name)?;
    if members.iter().any(|m| m.agent_id == member.agent_id) {
        return Ok(());
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

/// Check if an agent is a member of a group
pub fn is_member(groups_dir: &Path, group_name: &str, agent_id: &str) -> Result<bool> {
    let members = read_members(groups_dir, group_name)?;
    Ok(members.iter().any(|m| m.agent_id == agent_id))
}

/// Read routes from routes.toml
pub fn read_routes(groups_dir: &Path, group_name: &str) -> Result<HashMap<String, String>> {
    let routes_path = groups_dir.join(group_name).join("routes.toml");
    if !routes_path.exists() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(&routes_path)?;
    #[derive(serde::Deserialize)]
    struct RoutesWrapper {
        routes: Option<HashMap<String, InnerRoute>>,
    }
    #[derive(serde::Deserialize)]
    struct InnerRoute {
        path: String,
    }
    let parsed: RoutesWrapper = toml::from_str(&content).unwrap_or(RoutesWrapper { routes: None });
    Ok(parsed.routes.unwrap_or_default().into_iter().map(|(k, v)| (k, v.path)).collect())
}

/// Add a route for cross-machine inbox delivery
pub fn add_route(groups_dir: &Path, group_name: &str, agent_id: &str, path: &str) -> Result<()> {
    let mut routes = read_routes(groups_dir, group_name)?;
    routes.insert(agent_id.to_string(), path.to_string());

    let group_dir = groups_dir.join(group_name);
    let mut toml_str = String::from("# Cross-machine inbox route mapping\n\n");
    for (id, p) in &routes {
        toml_str.push_str(&format!("[routes.\"{}\"]\npath = \"{}\"\n\n", id, p));
    }
    fs::write(group_dir.join("routes.toml"), toml_str)?;
    Ok(())
}

/// Get all member agent_ids from a group
pub fn get_member_ids(groups_dir: &Path, group_name: &str) -> Result<Vec<String>> {
    let members = read_members(groups_dir, group_name)?;
    Ok(members.into_iter().map(|m| m.agent_id).collect())
}

/// Resolve the actual inbox path for an agent (checks routes.toml first, falls back to local default)
pub fn resolve_inbox_path(groups_dir: &Path, group_name: &str, agent_id: &str) -> PathBuf {
    if let Ok(routes) = read_routes(groups_dir, group_name) {
        if let Some(path) = routes.get(agent_id) {
            return PathBuf::from(path);
        }
    }
    // Default local path
    groups_dir.join(group_name).join("inboxes").join(agent_id)
}

/// Read relay endpoints from routes.toml
pub fn read_relays(groups_dir: &Path, group_name: &str) -> Result<HashMap<String, String>> {
    let routes_path = groups_dir.join(group_name).join("routes.toml");
    if !routes_path.exists() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(&routes_path)?;
    #[derive(serde::Deserialize)]
    struct RoutesWrapper {
        relays: Option<HashMap<String, String>>,
    }
    let parsed: RoutesWrapper = toml::from_str(&content).unwrap_or(RoutesWrapper { relays: None });
    Ok(parsed.relays.unwrap_or_default())
}

/// Add a relay endpoint to routes.toml
pub fn add_relay(groups_dir: &Path, group_name: &str, target_group: &str, url: &str) -> Result<()> {
    let mut relays = read_relays(groups_dir, group_name)?;
    relays.insert(target_group.to_string(), url.to_string());

    // Re-read existing routes and relays, rewrite the file
    let existing_routes = read_routes(groups_dir, group_name)?;
    let group_dir = groups_dir.join(group_name);

    let mut toml_str = String::from("# Cross-machine inbox route mapping\n\n");
    for (id, p) in &existing_routes {
        toml_str.push_str(&format!("[routes.\"{}\"]\npath = \"{}\"\n\n", id, p));
    }
    toml_str.push_str("# Cross-group relay endpoints\n\n");
    for (g, u) in &relays {
        toml_str.push_str(&format!("[relays.\"{}\"]\nurl = \"{}\"\n\n", g, u));
    }
    fs::write(group_dir.join("routes.toml"), toml_str)?;
    Ok(())
}
