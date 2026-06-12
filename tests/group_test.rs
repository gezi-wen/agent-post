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

    group::create_group(&groups_dir, "test_group").unwrap();

    let group_dir = groups_dir.join("test_group");
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
    group::create_group(&groups_dir, "groupA").unwrap();

    let member = Member {
        agent_id: "test_id_1".to_string(),
        name: "test_agent".to_string(),
        pubkey: "pk_test_1".to_string(),
        joined: Utc::now(),
    };

    group::add_member(&groups_dir, "groupA", &member).unwrap();
    // Adding duplicate should not duplicate
    group::add_member(&groups_dir, "groupA", &member).unwrap();

    let members = group::read_members(&groups_dir, "groupA").unwrap();
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

#[test]
fn test_is_member() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    fs::create_dir_all(&groups_dir).unwrap();
    group::create_group(&groups_dir, "G").unwrap();

    let member = Member {
        agent_id: "id1".to_string(),
        name: "agent1".to_string(),
        pubkey: "pk1".to_string(),
        joined: Utc::now(),
    };
    group::add_member(&groups_dir, "G", &member).unwrap();

    assert!(group::is_member(&groups_dir, "G", "id1").unwrap());
    assert!(!group::is_member(&groups_dir, "G", "id2").unwrap());
}

#[test]
fn test_routes_add_and_read() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    fs::create_dir_all(&groups_dir).unwrap();
    group::create_group(&groups_dir, "G").unwrap();

    group::add_route(&groups_dir, "G", "agent_x", "/mnt/remote/inboxes/agent_x/").unwrap();

    let routes = group::read_routes(&groups_dir, "G").unwrap();
    assert_eq!(routes.get("agent_x").unwrap(), "/mnt/remote/inboxes/agent_x/");
}

#[test]
fn test_resolve_inbox_path_default() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");

    // Default path when no route is set
    let path = group::resolve_inbox_path(&groups_dir, "G", "agent_y");
    assert!(path.to_string_lossy().contains("inboxes"));
    assert!(path.to_string_lossy().contains("agent_y"));
}
