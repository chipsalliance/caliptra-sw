// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use log::info;
use std::process::Command;

use crate::PROJECT_ROOT;

pub(crate) fn clippy() -> Result<()> {
    clippy_all()?;
    Ok(())
}

fn clippy_all() -> Result<()> {
    info!("Running: cargo clippy");
    let args = vec![
        "clippy",
        "--locked",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ];
    let output = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .env("RUSTFLAGS", "-Dwarnings")
        .output()?;

    if !output.status.success() {
        log::error!("{}", String::from_utf8_lossy(&output.stdout));
        log::error!("{}", String::from_utf8_lossy(&output.stderr));
        bail!("cargo clippy failed");
    }

    info!("cargo clippy passed!");
    Ok(())
}
