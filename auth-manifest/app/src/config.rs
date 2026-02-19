/*++

Licensed under the Apache-2.0 license.

File Name:

   config.rs

Abstract:

    File contains utilities for parsing image authorization configuration files

--*/

use anyhow::Context;
use caliptra_auth_man_gen::AuthManifestGeneratorKeyConfig;
use caliptra_auth_man_types::ImageMetadataFlags;
use caliptra_auth_man_types::{
    Addr64, AuthManifestImageMetadata, AuthManifestPrivKeysConfig, AuthManifestPubKeysConfig,
};
#[cfg(feature = "openssl")]
use caliptra_image_crypto::OsslCrypto as Crypto;
#[cfg(feature = "rustcrypto")]
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_crypto::{lms_priv_key_from_pem, lms_pub_key_from_pem};
use caliptra_image_gen::*;
use serde_derive::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Authorization Manifest Key configuration from config file.
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct AuthManifestKeyConfigFromFile {
    pub ecc_pub_key: String,

    pub ecc_priv_key: Option<String>,

    pub lms_pub_key: String,

    pub lms_priv_key: Option<String>,

    pub mldsa_pub_key: String,

    pub mldsa_priv_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ImageMetadataConfigFromFile {
    digest: String,
    source: u32,
    fw_id: u32,
    exec_bit: u32,
    ignore_auth_check: bool,
    component_id: u32,
    size: u32,
    image_load_address: u64,
    image_staging_address: u64,
    classification: u32,
}

// Authorization Manifest configuration from TOML file
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct AuthManifestConfigFromFile {
    pub vendor_fw_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub vendor_man_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub owner_fw_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub owner_man_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub image_metadata_list: Vec<ImageMetadataConfigFromFile>,
}

/// Load Authorization Manifest Key Configuration from file
pub(crate) fn load_auth_man_config_from_file(
    path: &PathBuf,
) -> anyhow::Result<AuthManifestConfigFromFile> {
    let config_str = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read the config file {}", path.display()))?;

    let config: AuthManifestConfigFromFile = toml::from_str(&config_str)
        .with_context(|| format!("Failed to parse the config file {}", path.display()))?;

    Ok(config)
}

fn key_config_from_file(
    path: &Path,
    config: &AuthManifestKeyConfigFromFile,
) -> anyhow::Result<AuthManifestGeneratorKeyConfig> {
    // Get the Private Keys.
    let mut priv_keys = AuthManifestPrivKeysConfig::default();
    if let Some(pem_file) = &config.ecc_priv_key {
        let priv_key_path = path.join(pem_file);
        priv_keys.ecc_priv_key = Crypto::ecc_priv_key_from_pem(&priv_key_path)?;
    }

    if let Some(pem_file) = &config.lms_priv_key {
        let priv_key_path = path.join(pem_file);
        priv_keys.lms_priv_key = lms_priv_key_from_pem(&priv_key_path)?;
    }

    if let Some(pem_file) = &config.mldsa_priv_key {
        let priv_key_path = path.join(pem_file);
        priv_keys.mldsa_priv_key = Crypto::mldsa_priv_key_from_file(&priv_key_path)?;
    }

    Ok(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: Crypto::ecc_pub_key_from_pem(&path.join(&config.ecc_pub_key))?,
            lms_pub_key: lms_pub_key_from_pem(&path.join(&config.lms_pub_key))?,
            mldsa_pub_key: Crypto::mldsa_pub_key_from_file(&path.join(&config.mldsa_pub_key))?,
        },

        priv_keys: Some(priv_keys),
    })
}

pub(crate) fn optional_key_config_from_file(
    path: &Path,
    config: &Option<AuthManifestKeyConfigFromFile>,
) -> anyhow::Result<Option<AuthManifestGeneratorKeyConfig>> {
    if let Some(config) = config {
        let gen_config = key_config_from_file(path, config)?;
        Ok(Some(gen_config))
    } else {
        Ok(None)
    }
}

pub(crate) fn image_metadata_config_from_file(
    config: &Vec<ImageMetadataConfigFromFile>,
) -> anyhow::Result<Vec<AuthManifestImageMetadata>> {
    let mut image_metadata_list = Vec::new();
    let mut fw_ids: Vec<u32> = Vec::new();

    for image in config {
        // Check if the firmware ID is already present in the list.
        if fw_ids.contains(&image.fw_id) {
            return Err(anyhow::anyhow!(
                "Duplicate firmware ID found in the image metadata list"
            ));
        } else {
            fw_ids.push(image.fw_id);
        }

        let digest_vec = hex::decode(&image.digest)?;
        let mut flags = ImageMetadataFlags(0);
        flags.set_ignore_auth_check(image.ignore_auth_check);
        flags.set_image_source(image.source);
        flags.set_exec_bit(image.exec_bit);

        let image_metadata = AuthManifestImageMetadata {
            fw_id: image.fw_id,
            flags: flags.0,
            digest: digest_vec.try_into().unwrap(),
            component_id: image.component_id,
            size: image.size,
            image_load_address: {
                let addr = image.image_load_address;
                Addr64 {
                    lo: (addr & 0xFFFFFFFF) as u32,
                    hi: (addr >> 32) as u32,
                }
            },
            image_staging_address: {
                let addr = image.image_staging_address;
                Addr64 {
                    lo: (addr & 0xFFFFFFFF) as u32,
                    hi: (addr >> 32) as u32,
                }
            },
            classification: image.classification,
        };

        image_metadata_list.push(image_metadata);
    }

    Ok(image_metadata_list)
}
