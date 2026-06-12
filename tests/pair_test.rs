use agent_post::pair;
use agent_post::identity;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_invite_accept_confirm_flow() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&groups_dir).unwrap();
    fs::create_dir_all(&identities_dir).unwrap();

    let id_a = identity::create_identity(&identities_dir, "A", "test_group", None).unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "test_group", None).unwrap();

    agent_post::group::create_group(&groups_dir, "test_group").unwrap();

    // Step 1: A sends invite
    let invite = pair::create_invite(&groups_dir, &identities_dir, &id_a.agent_id, &id_b.agent_id, "test_group", false, None).unwrap();
    assert_eq!(invite.step, agent_post::types::PairStep::Invite);

    // B checks pending
    let pending = pair::check_pending(&groups_dir, "test_group", &id_b.agent_id).unwrap();
    assert_eq!(pending.len(), 1);

    // Step 2: B accepts
    let _accept = pair::create_accept(&groups_dir, &identities_dir, &id_b.agent_id, "test_group", &pending[0].nonce, true, None, None).unwrap();

    // A checks accepts
    let a_pending = pair::check_accepts(&groups_dir, "test_group", &id_a.agent_id).unwrap();
    assert_eq!(a_pending.len(), 1);

    // Step 3: A confirms
    pair::create_confirm(&groups_dir, &identities_dir, &id_a.agent_id, "test_group", &a_pending[0].nonce, None).unwrap();

    // Verify members.toml has B
    let members = agent_post::group::read_members(&groups_dir, "test_group").unwrap();
    assert!(members.iter().any(|m| m.agent_id == id_b.agent_id));
}

#[test]
fn test_reject_notifies() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&groups_dir).unwrap();
    fs::create_dir_all(&identities_dir).unwrap();

    let id_a = identity::create_identity(&identities_dir, "A", "test_group", None).unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "test_group", None).unwrap();
    agent_post::group::create_group(&groups_dir, "test_group").unwrap();

    pair::create_invite(&groups_dir, &identities_dir, &id_a.agent_id, &id_b.agent_id, "test_group", false, None).unwrap();
    let pending = pair::check_pending(&groups_dir, "test_group", &id_b.agent_id).unwrap();

    let reason: Option<String> = Some("don't want to pair".to_string());
    let reject = pair::create_accept(&groups_dir, &identities_dir, &id_b.agent_id, "test_group", &pending[0].nonce, false, reason, None).unwrap();
    assert_eq!(reject.accepted, Some(false));
    assert_eq!(reject.reason.as_deref(), Some("don't want to pair"));
}

#[test]
fn test_expired_invite_filtered() {
    let temp = TempDir::new().unwrap();
    let groups_dir = temp.path().join("groups");
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&groups_dir).unwrap();
    fs::create_dir_all(&identities_dir).unwrap();

    let id_a = identity::create_identity(&identities_dir, "A", "test_group", None).unwrap();
    let id_b = identity::create_identity(&identities_dir, "B", "test_group", None).unwrap();
    agent_post::group::create_group(&groups_dir, "test_group").unwrap();

    pair::create_invite(&groups_dir, &identities_dir, &id_a.agent_id, &id_b.agent_id, "test_group", false, None).unwrap();

    // Manually set expiry to past
    let pending_dir = groups_dir.join("test_group").join("pending");
    for entry in fs::read_dir(&pending_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("invite-") {
            let mut content: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(entry.path()).unwrap()
            ).unwrap();
            content["expires_at"] = serde_json::Value::String("2020-01-01T00:00:00Z".to_string());
            fs::write(entry.path(), serde_json::to_string(&content).unwrap()).unwrap();
        }
    }

    let pending = pair::check_pending(&groups_dir, "test_group", &id_b.agent_id).unwrap();
    assert_eq!(pending.len(), 0);
}

#[test]
fn test_safety_number_deterministic() {
    let sn1 = pair::safety_number("pk_old", "pk_new");
    let sn2 = pair::safety_number("pk_old", "pk_new");
    assert_eq!(sn1, sn2);
    assert_eq!(sn1.len(), 10);

    let sn3 = pair::safety_number("pk_old", "pk_different");
    assert_ne!(sn1, sn3);
}
