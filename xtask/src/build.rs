// Licensed under the Apache-2.0 license

use crate::util::run_command;
use crate::PROJECT_ROOT;
use anyhow::{bail, Result};
use caliptra_auth_man_gen::default_test_manifest::{default_test_soc_manifest, DEFAULT_MCU_FW};
use caliptra_builder::{
    firmware::{APP_WITH_UART_FPGA, FMC_FPGA_WITH_UART},
    ImageOptions,
};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_types::FwVerificationPqcKeyType;
use log::{error, info};
use std::path::Path;
use std::process::Command;
use zerocopy::IntoBytes;

pub fn build_all() -> Result<()> {
    build_rom()?;
    build_fmc()?;
    build_runtime()?;
    build_driver_test_fw()?;
    Ok(())
}

pub fn build_rom() -> Result<()> {
    info!("Building ROM...");
    let args = vec![
        "build",
        "--locked",
        "--target=riscv32imc-unknown-none-elf",
        "--profile=firmware",
        "--no-default-features",
        "--features=cfi",
        "--bin=caliptra-rom",
    ];

    let mut cmd = Command::new("cargo");

    cmd.current_dir((*PROJECT_ROOT).join("rom/dev/")).args(args);

    if let Err(e) = run_command(&mut cmd) {
        error!("{}", e);
        bail!("cargo build for ROM failed");
    }
    info!("ROM build succeeded");
    Ok(())
}

pub fn build_fmc() -> Result<()> {
    info!("Building FMC...");
    let args = vec![
        "build",
        "--locked",
        "--target=riscv32imc-unknown-none-elf",
        "--profile=firmware",
        "--no-default-features",
        "--features=cfi,riscv",
        "--bin=caliptra-fmc",
    ];

    let mut cmd = Command::new("cargo");

    cmd.current_dir((*PROJECT_ROOT).join("fmc/")).args(args);

    if let Err(e) = run_command(&mut cmd) {
        error!("{}", e);
        bail!("cargo build for FMC failed");
    }
    info!("FMC build succeeded");
    Ok(())
}

pub fn build_runtime() -> Result<()> {
    info!("Building runtime...");
    let args = vec![
        "build",
        "--locked",
        "--target=riscv32imc-unknown-none-elf",
        "--profile=firmware",
        "--no-default-features",
        "--features=cfi,riscv",
        "--bin=caliptra-runtime",
    ];

    let mut cmd = Command::new("cargo");

    cmd.current_dir((*PROJECT_ROOT).join("runtime/")).args(args);

    if let Err(e) = run_command(&mut cmd) {
        error!("{}", e);
        bail!("cargo build for runtime failed");
    }
    info!("runtime build succeeded");
    Ok(())
}

pub fn build_driver_test_fw() -> Result<()> {
    info!("Building driver test-fw...");
    let args = vec![
        "build",
        "--locked",
        "--target=riscv32imc-unknown-none-elf",
        "--profile=firmware",
        "--features=riscv",
    ];

    let mut cmd = Command::new("cargo");

    cmd.current_dir((*PROJECT_ROOT).join("drivers/test-fw/"))
        .args(args);

    if let Err(e) = run_command(&mut cmd) {
        error!("{}", e);
        bail!("cargo build for driver test-fw failed");
    }
    info!("driver test-fw build succeeded");
    Ok(())
}

pub fn build_ocp_recovery_images(out_dir: &Path, pqc_key_type: FwVerificationPqcKeyType) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;

    info!("Compiling Caliptra FPGA Firmware Bundle (FMC + RT)...");
    let mut opts = ImageOptions::default();
    opts.pqc_key_type = pqc_key_type;
    let image_bundle =
        caliptra_builder::build_and_sign_image(&FMC_FPGA_WITH_UART, &APP_WITH_UART_FPGA, opts)?;
    let bundle_bytes = image_bundle
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("Failed to serialize image bundle: {e}"))?;
    let fw_path = out_dir.join("caliptra_firmware.bin");
    std::fs::write(&fw_path, &bundle_bytes)?;
    info!(
        "Created {} ({} bytes)",
        fw_path.display(),
        bundle_bytes.len()
    );

    info!("Generating test SoC Authorization Manifest...");
    let manifest = default_test_soc_manifest(&DEFAULT_MCU_FW, pqc_key_type, 0, Crypto::default());
    let manifest_bytes = manifest.as_bytes();
    let manifest_path = out_dir.join("soc_manifest.bin");
    std::fs::write(&manifest_path, manifest_bytes)?;
    info!(
        "Created {} ({} bytes)",
        manifest_path.display(),
        manifest_bytes.len()
    );

    info!("Writing test MCU firmware binary...");
    let mcu_path = out_dir.join("mcu_firmware.bin");
    std::fs::write(&mcu_path, &DEFAULT_MCU_FW)?;
    info!(
        "Created {} ({} bytes)",
        mcu_path.display(),
        DEFAULT_MCU_FW.len()
    );

    info!(
        "All 3 FPGA recovery artifacts generated in {}",
        out_dir.display()
    );
    Ok(())
}
