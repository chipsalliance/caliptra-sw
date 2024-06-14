/*++

Licensed under the Apache-2.0 license.

File Name:

   config.rs

Abstract:

    File contains utilities for parsing image authorization configuration files

--*/

use anyhow::Context;
use caliptra_auth_man_gen::AuthManifestGeneratorKeyConfig;
use caliptra_auth_man_types::{AuthManifestImageMetadata, AuthManifestPrivKeys};
#[cfg(feature = "openssl")]
use caliptra_image_crypto::OsslCrypto as Crypto;
#[cfg(feature = "rustcrypto")]
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_crypto::{lms_priv_key_from_pem, lms_pub_key_from_pem};
use caliptra_image_gen::*;
use serde_derive::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Authorization Manifest Key Configuration
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct AuthManKeyConfig {
    pub ecc_pub_key: String,

    pub ecc_priv_key: Option<String>,

    pub lms_pub_key: String,

    pub lms_priv_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ImageMetadata {
    digest: String,
    source: u32,
}

// Key Configuration
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct AuthManMasterKeyConfig {
    pub vendor_fw_key_config: AuthManKeyConfig,

    pub vendor_man_key_config: AuthManKeyConfig,

    pub owner_fw_key_config: Option<AuthManKeyConfig>,

    pub owner_man_key_config: Option<AuthManKeyConfig>,

    pub image_metadata_list: Vec<ImageMetadata>,
}

/// Load Authorization Manifest Key Configuration from file
pub(crate) fn load_auth_man_config(path: &PathBuf) -> anyhow::Result<AuthManMasterKeyConfig> {
    let config_str = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read the config file {}", path.display()))?;

    let config: AuthManMasterKeyConfig = toml::from_str(&config_str)
        .with_context(|| format!("Failed to parse config file {}", path.display()))?;

    Ok(config)
}

fn key_config(
    path: &Path,
    config: &AuthManKeyConfig,
) -> anyhow::Result<AuthManifestGeneratorKeyConfig> {
    let mut gen_config = AuthManifestGeneratorKeyConfig::default();

    // Get the Public Keys.
    let pub_key_path = path.join(&config.ecc_pub_key);
    gen_config.pub_keys.ecc_pub_key = Crypto::ecc_pub_key_from_pem(&pub_key_path)?;

    let pub_key_path = path.join(&config.lms_pub_key);
    gen_config.pub_keys.lms_pub_key = lms_pub_key_from_pem(&pub_key_path)?;

    // Get the Private Keys.
    let mut priv_keys = AuthManifestPrivKeys::default();
    if let Some(pem_file) = &config.ecc_priv_key {
        let priv_key_path = path.join(pem_file);
        priv_keys.ecc_priv_key = Crypto::ecc_priv_key_from_pem(&priv_key_path)?;
        gen_config.priv_keys = Some(priv_keys);
    }

    if let Some(pem_file) = &config.lms_priv_key {
        let priv_key_path = path.join(pem_file);
        priv_keys.lms_priv_key = lms_priv_key_from_pem(&priv_key_path)?;
        gen_config.priv_keys = Some(priv_keys);
    }

    Ok(gen_config)
}

pub(crate) fn vendor_config(
    path: &Path,
    config: &AuthManKeyConfig,
) -> anyhow::Result<AuthManifestGeneratorKeyConfig> {
    key_config(path, config)
}

pub(crate) fn owner_config(
    path: &Path,
    config: &Option<AuthManKeyConfig>,
) -> anyhow::Result<Option<AuthManifestGeneratorKeyConfig>> {
    if let Some(config) = config {
        let gen_config = key_config(path, config)?;
        Ok(Some(gen_config))
    } else {
        Ok(None)
    }
}

pub(crate) fn image_metadata_config(
    config: &Vec<ImageMetadata>,
) -> anyhow::Result<Vec<AuthManifestImageMetadata>> {
    let mut image_metadata_list = Vec::new();

    for image in config {
        let digest_vec = hex::decode(&image.digest)?;
        let image_source = image.source;

        let image_metadata = AuthManifestImageMetadata {
            digest: digest_vec.try_into().unwrap(),
            image_source,
        };

        image_metadata_list.push(image_metadata);
    }

    Ok(image_metadata_list)
}
