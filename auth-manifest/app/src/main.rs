/*++

Licensed under the Apache-2.0 license.

File Name:

   main.rs

Abstract:

    Main entry point for Caliptra Authorization Manifest application

--*/

use anyhow::Context;
use caliptra_auth_man_gen::{AuthManifestGenerator, AuthManifestGeneratorConfig};
use caliptra_auth_man_types::AuthManifestFlags;
#[cfg(feature = "openssl")]
use caliptra_image_crypto::OsslCrypto as Crypto;
#[cfg(feature = "rustcrypto")]
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_types::{FwVerificationPqcKeyType, IMAGE_ALIGNMENT};
use clap::ArgMatches;
use clap::{arg, value_parser, Command};
use std::io::Write;
use std::path::PathBuf;
use zerocopy::IntoBytes;

mod config;

/// Entry point
fn main() {
    let sub_cmds = vec![Command::new("create-auth-man")
        .about("Create a new authorization manifest")
        .arg(
            arg!(--"version" <U32> "Manifest Version Number")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"svn" <U32> "Manifest Security Version Number")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"flags" <U32> "Manifest Flags")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"key-dir" <FILE> "Key files directory path")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(--"config" <FILE> "Manifest configuration file")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(--"pqc-key-type" <U32> "Type of PQC key validation: 1: MLDSA; 3: LMS")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"out" <FILE> "Output file")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )];

    let cmd = Command::new("caliptra-auth-man-app")
        .arg_required_else_help(true)
        .subcommands(sub_cmds)
        .about("Caliptra authorization manifest tools")
        .get_matches();

    let result = match cmd.subcommand().unwrap() {
        ("create-auth-man", args) => run_auth_man_cmd(args),
        (_, _) => unreachable!(),
    };

    result.unwrap();
}

pub(crate) fn run_auth_man_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let version: &u32 = args
        .get_one::<u32>("version")
        .with_context(|| "version arg not specified")?;

    let svn: &u32 = args
        .get_one::<u32>("svn")
        .with_context(|| "svn arg not specified")?;

    if *svn > 128 {
        return Err(anyhow::anyhow!("Invalid SVN value"));
    }

    let flags: AuthManifestFlags = AuthManifestFlags::from_bits_truncate(
        *args
            .get_one::<u32>("flags")
            .with_context(|| "flags arg not specified")?,
    );

    let pqc_key_type: &u32 = args
        .get_one::<u32>("pqc-key-type")
        .with_context(|| "Type of PQC key validation: 1: MLDSA; 3: LMS")?;
    let pqc_key_type = match *pqc_key_type {
        1 => FwVerificationPqcKeyType::MLDSA,
        3 => FwVerificationPqcKeyType::LMS,
        _ => return Err(anyhow::anyhow!("Invalid PQC key type")),
    };

    let config_path: &PathBuf = args
        .get_one::<PathBuf>("config")
        .with_context(|| "config arg not specified")?;

    if !config_path.exists() {
        return Err(anyhow::anyhow!("Invalid config file path"));
    }

    let key_dir: &PathBuf = args
        .get_one::<PathBuf>("key-dir")
        .with_context(|| "key-dir arg not specified")?;

    if !key_dir.exists() {
        return Err(anyhow::anyhow!("Invalid key directory path"));
    }

    let out_path: &PathBuf = args
        .get_one::<PathBuf>("out")
        .with_context(|| "out arg not specified")?;

    // Load the manifest configuration from the config file.
    let config = config::load_auth_man_config_from_file(config_path)?;

    // Decode the configuration.
    let gen_config = AuthManifestGeneratorConfig {
        version: *version,
        svn: *svn,
        flags,
        pqc_key_type,
        vendor_man_key_info: config::optional_key_config_from_file(
            key_dir,
            &config.vendor_man_key_config,
        )?,
        owner_man_key_info: config::optional_key_config_from_file(
            key_dir,
            &config.owner_man_key_config,
        )?,
        vendor_fw_key_info: config::optional_key_config_from_file(
            key_dir,
            &config.vendor_fw_key_config,
        )?,
        owner_fw_key_info: config::optional_key_config_from_file(
            key_dir,
            &config.owner_fw_key_config,
        )?,
        image_metadata_list: config::image_metadata_config_from_file(&config.image_metadata_list)?,
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    let manifest = gen.generate(&gen_config).unwrap();

    let mut out_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path)
        .with_context(|| format!("Failed to create file {}", out_path.display()))?;

    out_file.write_all(manifest.as_bytes())?;
    // Pad to IMAGE_ALIGNMENT boundary
    let len = manifest.as_bytes().len();
    let padded = len.next_multiple_of(IMAGE_ALIGNMENT);
    if padded > len {
        out_file.write_all(&vec![0u8; padded - len])?;
    }

    Ok(())
}
