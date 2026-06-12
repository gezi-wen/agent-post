use agent_post::identity;
use agent_post::types::Identity;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_generate_keypair_and_agent_id() {
    let (signing_key, agent_id, pubkey_b58) = identity::generate_keypair();
    assert!(!agent_id.is_empty());
    assert!(agent_id.len() >= 10);
    // agent_id = base58(sha256(pubkey)[:16])
    assert!(!pubkey_b58.is_empty());
}

#[test]
fn test_create_identity_file() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&identities_dir).unwrap();

    let identity = identity::create_identity(
        &identities_dir,
        "测试Agent",
        "测试组",
        None,
    ).unwrap();

    assert_eq!(identity.name, "测试Agent");
    assert_eq!(identity.group, "测试组");
    assert!(identity.secret_key.is_some());
    assert!(identity.revocation_cert.is_some());

    // File exists
    let file_path = identities_dir.join(format!("{}.json", identity.agent_id));
    assert!(file_path.exists());

    // Unix permissions 600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&file_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn test_read_identity() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&identities_dir).unwrap();

    let created = identity::create_identity(&identities_dir, "读测试", "测试组", None).unwrap();
    let read = identity::read_identity(&identities_dir, &created.agent_id).unwrap();

    assert_eq!(read.agent_id, created.agent_id);
    assert_eq!(read.pubkey, created.pubkey);
}

#[test]
fn test_export_without_secret_key() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&identities_dir).unwrap();

    let created = identity::create_identity(&identities_dir, "导出测试", "测试组", None).unwrap();
    let exported = identity::export_identity(&identities_dir, &created.agent_id).unwrap();

    // Serialized output must NOT contain secret_key
    let json = serde_json::to_string(&exported).unwrap();
    assert!(!json.contains("secret_key"));
}

#[test]
fn test_list_identities() {
    let temp = TempDir::new().unwrap();
    let identities_dir = temp.path().join("identities");
    fs::create_dir_all(&identities_dir).unwrap();

    identity::create_identity(&identities_dir, "A", "组1", None).unwrap();
    identity::create_identity(&identities_dir, "B", "组1", None).unwrap();

    let list = identity::list_identities(&identities_dir).unwrap();
    assert_eq!(list.len(), 2);
}
