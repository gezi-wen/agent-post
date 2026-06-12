use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;

use crate::message;
use crate::encryption;
use crate::types::{Identity, IdentityExport, RevocationCert};

/// Generate Ed25519 keypair, returns (signing_key, agent_id, pubkey_base58)
pub fn generate_keypair() -> (SigningKey, String, String) {
    use rand::rngs::OsRng;
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let pubkey_bytes = verifying_key.as_bytes();
    let pubkey_b58 = bs58::encode(pubkey_bytes).into_string();

    let hash = Sha256::digest(pubkey_bytes);
    let agent_id = bs58::encode(&hash[..16]).into_string();

    (signing_key, agent_id, pubkey_b58)
}

/// Create identity file, returns Identity.
/// If passphrase is provided, encrypts the secret key with argon2id + AES-256-GCM.
pub fn create_identity(
    identities_dir: &Path,
    name: &str,
    group: &str,
    passphrase: Option<&str>,
) -> Result<Identity> {
    let (signing_key, agent_id, pubkey_b58) = generate_keypair();

    // Pre-sign revocation certificate
    let revocation = RevocationCert {
        agent_id: agent_id.clone(),
        pubkey: pubkey_b58.clone(),
        reason: String::new(),
        revoked_at: Utc::now(),
        sig: String::new(),
    };

    let revocation_json = message::canonicalize(&revocation)?;
    let revocation_hash = Sha256::digest(revocation_json.as_bytes());
    let revocation_sig = signing_key.sign(&revocation_hash);
    let revocation_sig_b58 = bs58::encode(revocation_sig.to_bytes()).into_string();

    let revocation_cert = RevocationCert {
        sig: revocation_sig_b58,
        ..revocation
    };

    let secret_key_bytes = signing_key.to_bytes();

    let (secret_key_field, encrypted_key_field) = if let Some(pw) = passphrase {
        let encrypted = encryption::encrypt_secret_key(pw, &secret_key_bytes)?;
        (None, Some(encrypted))
    } else {
        (Some(bs58::encode(secret_key_bytes).into_string()), None)
    };

    let identity = Identity {
        agent_id: agent_id.clone(),
        name: name.to_string(),
        group: group.to_string(),
        pubkey: pubkey_b58,
        secret_key: secret_key_field,
        encrypted_secret_key: encrypted_key_field,
        revocation_cert: Some(serde_json::to_string(&revocation_cert)?),
        created: Utc::now(),
    };

    let json = serde_json::to_string_pretty(&identity)?;
    let file_path = identities_dir.join(format!("{}.json", agent_id));
    fs::create_dir_all(identities_dir)?;
    fs::write(&file_path, &json)?;

    // Unix: chmod 600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&file_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&file_path, perms)?;
    }

    Ok(identity)
}

/// Read identity file
pub fn read_identity(identities_dir: &Path, agent_id: &str) -> Result<Identity> {
    let file_path = identities_dir.join(format!("{}.json", agent_id));
    let content = fs::read_to_string(&file_path)
        .with_context(|| format!("identity file not found: {}", file_path.display()))?;
    let identity: Identity = serde_json::from_str(&content)?;
    Ok(identity)
}

/// List all local identities
pub fn list_identities(identities_dir: &Path) -> Result<Vec<String>> {
    if !identities_dir.exists() {
        return Ok(vec![]);
    }
    let mut ids = Vec::new();
    for entry in fs::read_dir(identities_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.path().file_stem() {
                ids.push(name.to_string_lossy().to_string());
            }
        }
    }
    Ok(ids)
}

/// Export identity (without secret key)
pub fn export_identity(identities_dir: &Path, agent_id: &str) -> Result<IdentityExport> {
    let identity = read_identity(identities_dir, agent_id)?;
    Ok(IdentityExport {
        agent_id: identity.agent_id,
        name: identity.name,
        group: identity.group,
        pubkey: identity.pubkey,
        created: identity.created,
    })
}

/// Load signing key from identity file.
/// If passphrase is None and key is encrypted, returns an error.
pub fn load_signing_key(
    identities_dir: &Path,
    agent_id: &str,
    passphrase: Option<&str>,
) -> Result<(SigningKey, VerifyingKey)> {
    let identity = read_identity(identities_dir, agent_id)?;

    let secret_bytes: [u8; 32] = if let Some(encrypted) = &identity.encrypted_secret_key {
        let pw = passphrase.context("this identity has an encrypted private key — passphrase required")?;
        encryption::decrypt_secret_key(pw, encrypted)?
    } else if let Some(secret_b58) = &identity.secret_key {
        let bytes = bs58::decode(secret_b58)
            .into_vec()
            .context("secret key base58 decode failed")?;
        bytes.as_slice()
            .try_into()
            .context("secret key wrong length (expected 32 bytes)")?
    } else {
        anyhow::bail!("identity file has no secret key or encrypted key");
    };

    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

/// Get revocation certificate
pub fn get_revocation_cert(identities_dir: &Path, agent_id: &str) -> Result<RevocationCert> {
    let identity = read_identity(identities_dir, agent_id)?;
    let cert_str = identity.revocation_cert
        .context("identity file has no revocation cert")?;
    let cert: RevocationCert = serde_json::from_str(&cert_str)?;
    Ok(cert)
}
