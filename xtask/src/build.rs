// Licensed under the Apache-2.0 license

use crate::util::run_command;
use crate::PROJECT_ROOT;
use anyhow::{bail, Result};
use log::{error, info};
use std::process::Command;

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
