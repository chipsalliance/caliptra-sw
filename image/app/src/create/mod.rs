/*++

Licensed under the Apache-2.0 license.

File Name:

   mod.rs

Abstract:

    File contains implementation Caliptra Image creation command.

--*/

mod config;
mod crypto;
mod executable;

use anyhow::Context;
use caliptra_image_gen::*;
use caliptra_image_serde::ImageBundleWriter;
use caliptra_image_types::*;
use clap::ArgMatches;
use std::path::Path;
use std::path::PathBuf;

use config::{OwnerKeyConfig, VendorKeyConfig};
use crypto::OsslCrypto;
use executable::ElfExecutable;

use self::crypto::{ecc_priv_key_from_pem, ecc_pub_key_from_pem};

/// Run the command
pub(crate) fn run_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let config_path: &PathBuf = args
        .get_one::<PathBuf>("key-config")
        .with_context(|| "key-config arg not specified")?;

    let fmc_path: &PathBuf = args
        .get_one::<PathBuf>("fmc")
        .with_context(|| "fmc arg not specified")?;

    let fmc_svn: &u32 = args
        .get_one::<u32>("fmc-svn")
        .with_context(|| "fmc-svn arg not specified")?;

    let fmc_min_svn: &u32 = args
        .get_one::<u32>("fmc-min-svn")
        .with_context(|| "fmc-min-svn arg not specified")?;

    let fmc_rev: &String = args
        .get_one::<String>("fmc-rev")
        .with_context(|| "fmc-rev arg not specified")?;

    let runtime_path: &PathBuf = args
        .get_one::<PathBuf>("rt")
        .with_context(|| "rt arg not specified")?;

    let runtime_svn: &u32 = args
        .get_one::<u32>("rt-svn")
        .with_context(|| "rt-svn arg not specified")?;

    let runtime_min_svn: &u32 = args
        .get_one::<u32>("rt-min-svn")
        .with_context(|| "rt-min-svn arg not specified")?;

    let runtime_rev: &String = args
        .get_one::<String>("rt-rev")
        .with_context(|| "rt-rev arg not specified")?;

    let ecc_key_idx: &u32 = args
        .get_one::<u32>("ecc-pk-idx")
        .with_context(|| "ecc-pk-idx arg not specified")?;

    let out_path: &PathBuf = args
        .get_one::<PathBuf>("out")
        .with_context(|| "out arg not specified")?;

    let config = config::load_key_config(config_path)?;

    let fmc_rev = hex::decode(fmc_rev)?;
    let fmc = ElfExecutable::new(
        fmc_path,
        *fmc_svn,
        *fmc_min_svn,
        fmc_rev[..IMAGE_REVISION_BYTE_SIZE].try_into()?,
    )?;

    let runtime_rev = hex::decode(runtime_rev)?;
    let runtime = ElfExecutable::new(
        runtime_path,
        *runtime_svn,
        *runtime_min_svn,
        runtime_rev[..IMAGE_REVISION_BYTE_SIZE].try_into()?,
    )?;

    let config_dir = config_path
        .parent()
        .with_context(|| "Invalid parent path")?;

    let gen_config = ImageGeneratorConfig::<ElfExecutable> {
        vendor_config: vendor_config(config_dir, &config.vendor, *ecc_key_idx)?,
        owner_config: owner_config(config_dir, &config.owner)?,
        fmc,
        runtime,
    };

    let gen = ImageGenerator::new(OsslCrypto::default());
    let image = gen.generate(&gen_config).unwrap();

    let out_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path)
        .with_context(|| format!("Failed to create file {}", out_path.display()))?;

    let mut writer = ImageBundleWriter::new(out_file);
    writer.write(&image)?;

    Ok(())
}

/// Generate Vendor Config
fn vendor_config(
    path: &Path,
    config: &VendorKeyConfig,
    ecc_key_idx: u32,
) -> anyhow::Result<ImageGeneratorVendorConfig> {
    let mut gen_config = ImageGeneratorVendorConfig::default();
    let ecc_pub_keys = &config.ecc_pub_keys;

    for (i, pem_file) in ecc_pub_keys
        .iter()
        .enumerate()
        .take(VENDOR_ECC_KEY_COUNT as usize)
    {
        let pub_key_path = path.join(pem_file);
        gen_config.pub_keys.ecc_pub_keys[i] = ecc_pub_key_from_pem(&pub_key_path)?;
    }

    if let Some(ecc_priv_keys) = &config.ecc_priv_keys {
        let mut priv_keys = ImageVendorPrivKeys::default();
        for (i, pem_file) in ecc_priv_keys
            .iter()
            .enumerate()
            .take(VENDOR_ECC_KEY_COUNT as usize)
        {
            let priv_key_path = path.join(pem_file);
            priv_keys.ecc_priv_keys[i] = ecc_priv_key_from_pem(&priv_key_path)?;
        }
        gen_config.priv_keys = Some(priv_keys);
    }

    gen_config.ecc_key_idx = ecc_key_idx;

    Ok(gen_config)
}

/// Generate owner config
fn owner_config(
    path: &Path,
    config: &Option<OwnerKeyConfig>,
) -> anyhow::Result<Option<ImageGeneratorOwnerConfig>> {
    if let Some(config) = config {
        let mut gen_config = ImageGeneratorOwnerConfig::default();
        let pem_file = &config.ecc_pub_key;

        let pub_key_path = path.join(pem_file);
        gen_config.pub_keys.ecc_pub_key = ecc_pub_key_from_pem(&pub_key_path)?;

        if let Some(pem_file) = &config.ecc_priv_key {
            let mut priv_keys = ImageOwnerPrivKeys::default();
            let pub_key_path = path.join(pem_file);
            priv_keys.ecc_priv_key = ecc_priv_key_from_pem(&pub_key_path)?;
            gen_config.priv_keys = Some(priv_keys);
        }

        Ok(Some(gen_config))
    } else {
        Ok(None)
    }
}
