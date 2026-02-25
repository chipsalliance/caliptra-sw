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
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .env("RUSTFLAGS", "-Dwarnings")
        .status()?;

    if !status.success() {
        bail!("cargo clippy failed");
    }
    Ok(())
}
