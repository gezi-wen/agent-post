use anyhow::Result;
use std::path::PathBuf;

use crate::types::Config;

pub fn home_dir() -> PathBuf {
    dirs::home_dir().expect("cannot get home directory").join(".agent-post")
}

pub fn config_path() -> PathBuf {
    home_dir().join("config.toml")
}

pub fn read_config() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Ok(Config {
            default_identity: None,
            default_group: None,
        });
    }
    let content = std::fs::read_to_string(&path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

pub fn write_config(config: &Config) -> Result<()> {
    let path = config_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    let content = toml::to_string_pretty(config)?;
    std::fs::write(&path, content)?;
    Ok(())
}

pub fn identities_dir() -> PathBuf {
    home_dir().join("identities")
}

pub fn groups_dir() -> PathBuf {
    home_dir().join("groups")
}

pub fn group_dir(group_name: &str) -> PathBuf {
    groups_dir().join(group_name)
}
