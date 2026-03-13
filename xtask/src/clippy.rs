// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use log::{error, info};
use std::process::Command;

use crate::util::run_command;
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
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT)
        .args(args)
        .env("RUSTFLAGS", "-Dwarnings");

    if let Err(e) = run_command(&mut cmd) {
        error!("{}", e);
        bail!("cargo clippy failed");
    }

    info!("cargo clippy passed!");
    Ok(())
}
