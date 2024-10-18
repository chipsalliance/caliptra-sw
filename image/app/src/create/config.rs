/*++

Licensed under the Apache-2.0 license.

File Name:

   config.rs

Abstract:

    File contains utilities for parsing configuration files

--*/

use anyhow::Context;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;

/// Vendor Key Configuration
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct VendorKeyConfig {
    pub ecc_pub_keys: Vec<String>,

    pub lms_pub_keys: Vec<String>,

    pub ecc_priv_keys: Option<Vec<String>>,

    pub lms_priv_keys: Option<Vec<String>>,
}

/// Owner Key Configuration
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct OwnerKeyConfig {
    pub ecc_pub_key: String,

    pub ecc_priv_key: Option<String>,

    pub lms_pub_key: String,

    pub lms_priv_key: Option<String>,
}

// Key Configuration
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct KeyConfig {
    pub vendor: VendorKeyConfig,

    pub owner: Option<OwnerKeyConfig>,
}

/// Load Key Configuration from file
pub(crate) fn load_key_config(path: &PathBuf) -> anyhow::Result<KeyConfig> {
    let config_str = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read the config file {}", path.display()))?;

    let config: KeyConfig = toml::from_str(&config_str)
        .with_context(|| format!("Failed to parse config file {}", path.display()))?;

    Ok(config)
}
