// Licensed under the Apache-2.0 license

pub use config::{BootRegisters, ExpectedStage, StatusRegisters};
pub use platform::{Error, TestRunnerPlatform};

use caliptra_api_types::Fuses;
use clap::Parser;
use config::{Config, DevIdKeys, FieldEntropyOptions, UdsOptions};
use std::path::PathBuf;
use x509_parser::nom::Parser as _;
use x509_parser::prelude::public_key::PublicKey;
use x509_parser::prelude::X509CertificateParser;

mod config;
mod platform;

/// Runs a management core integration test with the given environment and
/// checks for the expected end state
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Set the test environment and expected behavior with the given toml file
    #[clap(long)]
    config_path: PathBuf,
    /// Path to the pre-built firmware images
    #[clap(long)]
    image_bundle: PathBuf,
    /// Configuration file with expected IDevIDs for different configurations
    #[clap(long)]
    expected_keys_path: Option<PathBuf>,
}

struct ExpectedKeys {
    idev: Vec<u8>,
    ldev: Vec<u8>,
}

pub fn run_test_scenario(platform: &mut impl TestRunnerPlatform) {
    let args = Args::parse();

    let config: Config =
        toml::from_str(&std::fs::read_to_string(&args.config_path).unwrap()).unwrap();
    run_test_with_config(&args, &config, platform).unwrap();
}

fn run_test_with_config(
    args: &Args,
    config: &Config,
    platform: &mut impl TestRunnerPlatform,
) -> Result<(), Error> {
    let image_bundle = std::fs::read(&args.image_bundle).unwrap();

    let expected_keys = if let Some(expected_keys_path) = &args.expected_keys_path {
        Some(get_expected_keys(expected_keys_path, config)?)
    } else {
        None
    };

    if config.env.enable_debug {
        platform.enable_debug()?;
    }

    platform.set_device_lifecycle(config.env.lifecycle)?;

    platform.boot()?;

    platform.boot_fsm_go()?;

    platform.wait_for(ExpectedStage::ReadyForFuses)?;

    platform.set_boot_registers(&config.env.registers)?;

    let fuses = Fuses {
        uds_seed: config.env.uds.uds(),
        field_entropy: config.env.field_entropy.field_entropy(),
        ..config.env.fuses.clone()
    };

    platform.init_fuses(&fuses)?;

    platform.wait_for(ExpectedStage::ReadyForFw)?;

    if platform.upload_firmware(&image_bundle).is_ok() {
        platform.wait_for(ExpectedStage::ReadyForRuntime)?;
    }

    if platform.read_status_regs()? != config.end_state {
        println!("Expected: {:?}", config.end_state);
        println!("Actual: {:?}", platform.read_status_regs()?);
        return Err(Error::IncorrectStatusRegs);
    }

    if let Some(expected_keys) = expected_keys {
        let idev_info = platform.get_idev_info()?;
        let mut idev = idev_info.idev_pub_x.to_vec();
        idev.extend_from_slice(&idev_info.idev_pub_y);

        if expected_keys.idev != idev {
            println!("Expected: {}", hex::encode(expected_keys.idev));
            println!("Actual: {}", hex::encode(idev));
            return Err(Error::IncorrectIDevPublicKey);
        }

        let ldev_info = platform.get_ldev_cert()?;
        let ldev_cert_bytes = &ldev_info.data[..ldev_info.data_size as usize];
        let mut parser = X509CertificateParser::new();
        let (_, cert) = parser.parse(ldev_cert_bytes).unwrap();
        let PublicKey::EC(ec_point) = cert.subject_pki.parsed().unwrap() else {
                panic!("Error: Failed to parse public key correctly.");
            };
        // skip first 0x04 der encoding byte
        let pub_key = ec_point.data()[1..].to_vec();
        if expected_keys.ldev != pub_key {
            println!("Expected: {}", hex::encode(expected_keys.ldev));
            println!("Actual: {}", hex::encode(pub_key));
            return Err(Error::IncorrectLDevPublicKey);
        }
    }

    Ok(())
}

fn get_expected_keys(path: &PathBuf, config: &Config) -> Result<ExpectedKeys, Error> {
    let enable_debug = config.env.enable_debug;
    let uds = config.env.uds;
    let field_entropy = config.env.field_entropy;

    // Only test debug with UDS A and empty field entropy
    if enable_debug && (field_entropy != FieldEntropyOptions::Empty || uds != UdsOptions::A) {
        return Err(Error::OtherUdsOptionWithDebugEnabled);
    }

    let keys: DevIdKeys = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

    // IDevIDs should be different when debug is enabled
    if keys.idev_uds_a_debug_enabled == keys.idev_uds_a_debug_disabled {
        return Err(Error::DuplicateIDevPublicKey);
    }

    // UDS A and UDS B should produce different IDevIDs
    if keys.idev_uds_a_debug_disabled == keys.idev_uds_b {
        return Err(Error::DuplicateIDevPublicKey);
    }

    // All UDS A LDevIDs should be the different
    if keys.ldev_uds_a_fe_0_debug_disabled == keys.ldev_uds_a_fe_a
        || keys.ldev_uds_a_fe_0_debug_disabled == keys.ldev_uds_a_fe_b
        || keys.ldev_uds_a_fe_a == keys.ldev_uds_a_fe_b
    {
        return Err(Error::SameLDevPublicKeyWhenShouldBeDifferent);
    }

    let idev = match uds {
        UdsOptions::A if enable_debug => hex::decode(&keys.idev_uds_a_debug_enabled),
        UdsOptions::A => hex::decode(&keys.idev_uds_a_debug_disabled),
        UdsOptions::B => hex::decode(&keys.idev_uds_b),
    }
    .map_err(|_| Error::InvalidIDevPublicKey)?;

    let ldev = match (uds, field_entropy) {
        (UdsOptions::A, FieldEntropyOptions::Empty) if enable_debug => {
            hex::decode(&keys.ldev_uds_a_fe_0_debug_enabled)
        }
        (UdsOptions::A, FieldEntropyOptions::Empty) => {
            hex::decode(&keys.ldev_uds_a_fe_0_debug_disabled)
        }
        (UdsOptions::A, FieldEntropyOptions::A) => hex::decode(&keys.ldev_uds_a_fe_a),
        (UdsOptions::A, FieldEntropyOptions::B) => hex::decode(&keys.ldev_uds_a_fe_b),
        (UdsOptions::B, FieldEntropyOptions::A) => hex::decode(&keys.ldev_uds_b_fe_a),
        (UdsOptions::B, FieldEntropyOptions::Empty) | (UdsOptions::B, FieldEntropyOptions::B) => {
            return Err(Error::InvalidIdevCombo)
        }
    }
    .map_err(|_| Error::InvalidLDevPublicKey)?;

    Ok(ExpectedKeys { idev, ldev })
}
