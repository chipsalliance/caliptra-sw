/*++

Licensed under the Apache-2.0 license.

File Name:

   main.rs

Abstract:

    Main entry point for Caliptra Authorization Manifest application

--*/

use anyhow::Context;
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorConfig, ImcGenerator, ImcGeneratorConfig,
};
use caliptra_auth_man_types::AuthManifestFlags;
#[cfg(feature = "openssl")]
use caliptra_image_crypto::OsslCrypto as Crypto;
#[cfg(feature = "rustcrypto")]
use caliptra_image_crypto::RustCrypto as Crypto;
use clap::ArgMatches;
use clap::{arg, value_parser, Command};
use std::io::Write;
use std::path::PathBuf;
use zerocopy::AsBytes;

mod config;

/// Entry point
fn main() {
    let sub_cmds = vec![
        Command::new("create-auth-man")
            .about("Create a new authorization manifest")
            .arg(
                arg!(--"version" <U32> "Manifest Version Number")
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
                arg!(--"out" <FILE> "Output file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            ),
        Command::new("create-imc")
            .about("Create a new image metadata collection")
            .arg(
                arg!(--"revision" <U32> "Image Metadata Collection Revision")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                arg!(--"flags" <U32> "Manifest Flags")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                arg!(--"key-dir" <FILE> "Manifest Private Key files directory path")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"config" <FILE> "Image Metadata Collection configuration file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"out" <FILE> "Output file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            ),
    ];

    let cmd = Command::new("caliptra-auth-man-app")
        .arg_required_else_help(true)
        .subcommands(sub_cmds)
        .about("Caliptra authorization manifest tools")
        .get_matches();

    let result = match cmd.subcommand().unwrap() {
        ("create-auth-man", args) => run_auth_man_cmd(args),
        ("create-imc", args) => run_imc_cmd(args),
        (_, _) => unreachable!(),
    };

    result.unwrap();
}

pub(crate) fn run_auth_man_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let version: &u32 = args
        .get_one::<u32>("version")
        .with_context(|| "version arg not specified")?;

    let flags: AuthManifestFlags = AuthManifestFlags::from_bits_truncate(
        *args
            .get_one::<u32>("flags")
            .with_context(|| "flags arg not specified")?,
    );

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
        flags,
        vendor_man_key_info: config::vendor_config_from_file(
            key_dir,
            &config.vendor_man_key_config,
        )?,
        owner_man_key_info: config::owner_config_from_file(key_dir, &config.owner_man_key_config)?,
        vendor_fw_key_info: config::vendor_config_from_file(key_dir, &config.vendor_fw_key_config)?,
        owner_fw_key_info: config::owner_config_from_file(key_dir, &config.owner_fw_key_config)?,
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

    Ok(())
}

pub(crate) fn run_imc_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let revision: &u32 = args
        .get_one::<u32>("revision")
        .with_context(|| "revision arg not specified")?;

    let flags: AuthManifestFlags = AuthManifestFlags::from_bits_truncate(
        *args
            .get_one::<u32>("flags")
            .with_context(|| "flags arg not specified")?,
    );

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
    let config = config::load_imc_config_from_file(config_path)?;

    // Decode the configuration.
    let gen_config = ImcGeneratorConfig {
        revision: *revision,
        flags,
        owner_man_key_info: config::owner_config_from_file(key_dir, &config.owner_man_key_config)?,
        vendor_man_key_info: config::vendor_config_from_file(
            key_dir,
            &config.vendor_man_key_config,
        )?,
        image_metadata_list: config::image_metadata_config_from_file(&config.image_metadata_list)?,
    };

    let gen = ImcGenerator::new(Crypto::default());
    let imc = gen.generate(&gen_config).unwrap();

    let mut out_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path)
        .with_context(|| format!("Failed to create file {}", out_path.display()))?;

    out_file.write_all(imc.as_bytes())?;

    Ok(())
}
