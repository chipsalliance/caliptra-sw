/*++

Licensed under the Apache-2.0 license.

File Name:

   mod.rs

Abstract:

    File contains implementation Caliptra Image creation command.

--*/

mod config;

use anyhow::anyhow;
use anyhow::Context;
use caliptra_image_crypto::lms_priv_key_from_pem;
use caliptra_image_crypto::lms_pub_key_from_pem;
#[cfg(feature = "openssl")]
use caliptra_image_crypto::OsslCrypto as Crypto;
#[cfg(feature = "rustcrypto")]
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_gen::*;
use caliptra_image_serde::ImageBundleWriter;
use caliptra_image_types::*;
use clap::ArgMatches;
use std::path::Path;
use std::path::PathBuf;

use caliptra_image_elf::ElfExecutable;
use config::{OwnerKeyConfig, VendorKeyConfig};

use chrono::NaiveDate;

///
/// This function takes the string as the input
/// and extracts year, month and day from the string
/// and then performs some basic validity checks
///
fn check_date(from_date: &str, to_date: &str) -> anyhow::Result<bool> {
    let time_fmt = "YYYYMMDDHHMMSS";

    let current_date = chrono::Utc::now().date_naive();

    if from_date.len() < time_fmt.len() || to_date.len() < time_fmt.len() {
        return Err(anyhow!("Invalid Date Input Format"));
    }

    let from_date_str: &str = &from_date[0..8];
    let to_date_str: &str = &to_date[0..8];

    let from_date_in = match NaiveDate::parse_from_str(from_date_str, "%Y%m%d") {
        Ok(d) => d,
        Err(_) => return Err(anyhow!("Invalid From Date Input Format")),
    };

    let to_date_in = match NaiveDate::parse_from_str(to_date_str, "%Y%m%d") {
        Ok(d) => d,
        Err(_) => return Err(anyhow!("Invalid To Date Input Format")),
    };

    if from_date_in < current_date || to_date_in < current_date {
        return Err(anyhow!("Invalid Input Date"));
    }

    if from_date_in > to_date_in {
        return Err(anyhow!("From Date Is greater Than To Date"));
    }

    Ok(true)
}

/// Run the command
pub(crate) fn run_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let pqc_key_type: &u32 = args
        .get_one::<u32>("pqc-key-type")
        .with_context(|| "pqc-key-type arg not specified")?;

    let config_path: &PathBuf = args
        .get_one::<PathBuf>("key-config")
        .with_context(|| "key-config arg not specified")?;

    let fmc_path: &PathBuf = args
        .get_one::<PathBuf>("fmc")
        .with_context(|| "fmc arg not specified")?;

    let fmc_version: &u32 = args
        .get_one::<u32>("fmc-version")
        .with_context(|| "fmc-version arg not specified")?;

    let fmc_svn: &u32 = args
        .get_one::<u32>("fmc-svn")
        .with_context(|| "fmc-svn arg not specified")?;

    let fmc_rev: &String = args
        .get_one::<String>("fmc-rev")
        .with_context(|| "fmc-rev arg not specified")?;

    let runtime_path: &PathBuf = args
        .get_one::<PathBuf>("rt")
        .with_context(|| "rt arg not specified")?;

    let runtime_version: &u32 = args
        .get_one::<u32>("rt-version")
        .with_context(|| "rt-version arg not specified")?;

    let runtime_svn: &u32 = args
        .get_one::<u32>("rt-svn")
        .with_context(|| "rt-svn arg not specified")?;

    let runtime_rev: &String = args
        .get_one::<String>("rt-rev")
        .with_context(|| "rt-rev arg not specified")?;

    let ecc_key_idx: &u32 = args
        .get_one::<u32>("ecc-pk-idx")
        .with_context(|| "ecc-pk-idx arg not specified")?;

    let pqc_key_idx: &u32 = args
        .get_one::<u32>("pqc-pk-idx")
        .with_context(|| "pqc-pk-idx arg not specified")?;

    let out_path: &PathBuf = args
        .get_one::<PathBuf>("out")
        .with_context(|| "out arg not specified")?;

    //YYYYMMDDHHMMSS - Zulu Time
    let mut own_from_date: [u8; 15] = [0u8; 15];
    let mut own_to_date: [u8; 15] = [0u8; 15];
    if let Some(from_date) = args.get_one::<String>("own-from-date") {
        if let Some(to_date) = args.get_one::<String>("own-to-date") {
            check_date(from_date, to_date)?;
            own_from_date[0..14].copy_from_slice(&from_date.as_bytes()[0..14]);
            own_from_date[14] = b'Z';
            own_to_date[0..14].copy_from_slice(&to_date.as_bytes()[0..14]);
            own_to_date[14] = b'Z';
        }
    }

    //YYYYMMDDHHMMSS - Zulu Time
    let mut mfg_from_date: [u8; 15] = [0u8; 15];
    let mut mfg_to_date: [u8; 15] = [0u8; 15];
    if let Some(from_date) = args.get_one::<String>("mfg-from-date") {
        if let Some(to_date) = args.get_one::<String>("mfg-to-date") {
            check_date(from_date, to_date)?;
            mfg_from_date[0..14].copy_from_slice(&from_date.as_bytes()[0..14]);
            mfg_from_date[14] = b'Z';
            mfg_to_date[0..14].clone_from_slice(&to_date.as_bytes()[0..14]);
            mfg_to_date[14] = b'Z';
        }
    }

    let config = config::load_key_config(config_path)?;

    let fmc_rev = hex::decode(fmc_rev)?;
    let fmc = ElfExecutable::open(
        fmc_path,
        *fmc_version,
        *fmc_svn,
        fmc_rev[..IMAGE_REVISION_BYTE_SIZE].try_into()?,
    )?;

    let runtime_rev = hex::decode(runtime_rev)?;
    let runtime = ElfExecutable::open(
        runtime_path,
        *runtime_version,
        *runtime_svn,
        runtime_rev[..IMAGE_REVISION_BYTE_SIZE].try_into()?,
    )?;

    let config_dir = config_path
        .parent()
        .with_context(|| "Invalid parent path")?;

    let pqc_key_type = if *pqc_key_type == 1 {
        FwVerificationPqcKeyType::Lms
    } else {
        FwVerificationPqcKeyType::Mldsa
    };

    let gen_config = ImageGeneratorConfig::<ElfExecutable> {
        fw_image_type: pqc_key_type,
        vendor_config: vendor_config(
            pqc_key_type,
            config_dir,
            &config.vendor,
            *ecc_key_idx,
            *pqc_key_idx,
            mfg_from_date,
            mfg_to_date,
        )?,
        owner_config: owner_config(
            pqc_key_type,
            config_dir,
            &config.owner,
            own_from_date,
            own_to_date,
        )?,
        fmc,
        runtime,
    };

    let gen = ImageGenerator::new(Crypto::default());
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
    pqc_key_type: FwVerificationPqcKeyType,
    path: &Path,
    config: &VendorKeyConfig,
    ecc_key_idx: u32,
    pqc_key_idx: u32,
    from_date: [u8; 15],
    to_date: [u8; 15],
) -> anyhow::Result<ImageGeneratorVendorConfig> {
    let mut gen_config = ImageGeneratorVendorConfig::default();

    let ecc_key_count = config.ecc_pub_keys.len() as u32;
    let lms_key_count = config.lms_pub_keys.len() as u32;
    let mldsa_key_count = config.mldsa_pub_keys.len() as u32;

    if ecc_key_count > VENDOR_ECC_MAX_KEY_COUNT {
        return Err(anyhow!("Invalid ECC Public Key Count"));
    }

    if ecc_key_idx >= ecc_key_count {
        return Err(anyhow!("Invalid ECC Public Key Index"));
    }

    let ecc_pub_keys = &config.ecc_pub_keys;
    for (i, pem_file) in ecc_pub_keys.iter().enumerate().take(ecc_key_count as usize) {
        let pub_key_path = path.join(pem_file);
        gen_config.pub_keys.ecc_pub_keys[i] = Crypto::ecc_pub_key_from_pem(&pub_key_path)?;
    }

    let mut priv_keys = ImageVendorPrivKeys::default();
    if let Some(ecc_priv_keys) = &config.ecc_priv_keys {
        for (i, pem_file) in ecc_priv_keys
            .iter()
            .enumerate()
            .take(ecc_key_count as usize)
        {
            let priv_key_path = path.join(pem_file);
            priv_keys.ecc_priv_keys[i] = Crypto::ecc_priv_key_from_pem(&priv_key_path)?;
        }
        gen_config.priv_keys = Some(priv_keys);
    }

    if pqc_key_type == FwVerificationPqcKeyType::Lms {
        if lms_key_count > VENDOR_LMS_MAX_KEY_COUNT {
            return Err(anyhow!("Invalid LMS Public Key Count"));
        }

        if pqc_key_idx >= lms_key_count {
            return Err(anyhow!("Invalid LMS Public Key Index"));
        }

        let lms_pub_keys = &config.lms_pub_keys;
        for (i, pem_file) in lms_pub_keys.iter().enumerate().take(lms_key_count as usize) {
            let pub_key_path = path.join(pem_file);
            gen_config.pub_keys.lms_pub_keys[i] = lms_pub_key_from_pem(&pub_key_path)?;
        }

        if let Some(lms_priv_keys) = &config.lms_priv_keys {
            for (i, pem_file) in lms_priv_keys
                .iter()
                .enumerate()
                .take(lms_key_count as usize)
            {
                let priv_key_path = path.join(pem_file);
                priv_keys.lms_priv_keys[i] = lms_priv_key_from_pem(&priv_key_path)?;
            }
            gen_config.priv_keys = Some(priv_keys);
        }
    } else {
        if mldsa_key_count > VENDOR_MLDSA_MAX_KEY_COUNT {
            return Err(anyhow!("Invalid MLDSA Public Key Count"));
        }
        if pqc_key_idx >= mldsa_key_count {
            return Err(anyhow!("Invalid MLDSA Public Key Index"));
        }

        let mldsa_pub_keys = &config.mldsa_pub_keys;
        for (i, file) in mldsa_pub_keys
            .iter()
            .enumerate()
            .take(mldsa_key_count as usize)
        {
            let pub_key_path = path.join(file);
            gen_config.pub_keys.mldsa_pub_keys[i] = Crypto::mldsa_pub_key_from_file(&pub_key_path)?;
        }

        if let Some(mldsa_priv_keys) = &config.mldsa_priv_keys {
            for (i, file) in mldsa_priv_keys
                .iter()
                .enumerate()
                .take(mldsa_key_count as usize)
            {
                let priv_key_path = path.join(file);
                priv_keys.mldsa_priv_keys[i] = Crypto::mldsa_priv_key_from_file(&priv_key_path)?;
            }
            gen_config.priv_keys = Some(priv_keys);
        }
    }

    gen_config.ecc_key_idx = ecc_key_idx;
    gen_config.pqc_key_idx = pqc_key_idx;
    gen_config.not_before = from_date;
    gen_config.not_after = to_date;
    gen_config.ecc_key_count = ecc_key_count;
    gen_config.lms_key_count = lms_key_count;
    gen_config.mldsa_key_count = mldsa_key_count;

    Ok(gen_config)
}

/// Generate owner config
fn owner_config(
    pqc_key_type: FwVerificationPqcKeyType,
    path: &Path,
    config: &Option<OwnerKeyConfig>,
    from_date: [u8; 15],
    to_date: [u8; 15],
) -> anyhow::Result<Option<ImageGeneratorOwnerConfig>> {
    if let Some(config) = config {
        let mut gen_config = ImageGeneratorOwnerConfig::default();

        let pem_file = &config.ecc_pub_key;
        let pub_key_path = path.join(pem_file);
        gen_config.pub_keys.ecc_pub_key = Crypto::ecc_pub_key_from_pem(&pub_key_path)?;

        let mut priv_keys = ImageOwnerPrivKeys::default();
        if let Some(pem_file) = &config.ecc_priv_key {
            let pub_key_path = path.join(pem_file);
            priv_keys.ecc_priv_key = Crypto::ecc_priv_key_from_pem(&pub_key_path)?;
            gen_config.priv_keys = Some(priv_keys);
        }

        if pqc_key_type == FwVerificationPqcKeyType::Lms {
            let pem_file = &config.lms_pub_key;
            let pub_key_path = path.join(pem_file);
            gen_config.pub_keys.lms_pub_key = lms_pub_key_from_pem(&pub_key_path)?;

            if let Some(pem_file) = &config.lms_priv_key {
                let priv_key_path = path.join(pem_file);
                priv_keys.lms_priv_key = lms_priv_key_from_pem(&priv_key_path)?;
                gen_config.priv_keys = Some(priv_keys);
            }
        } else {
            let file = &config.mldsa_pub_key;
            let pub_key_path = path.join(file);
            gen_config.pub_keys.mldsa_pub_key = Crypto::mldsa_pub_key_from_file(&pub_key_path)?;

            if let Some(file) = &config.mldsa_priv_key {
                let priv_key_path = path.join(file);
                priv_keys.mldsa_priv_key = Crypto::mldsa_priv_key_from_file(&priv_key_path)?;
                gen_config.priv_keys = Some(priv_keys);
            }
        }
        gen_config.not_before = from_date;
        gen_config.not_after = to_date;

        Ok(Some(gen_config))
    } else {
        Ok(None)
    }
}
