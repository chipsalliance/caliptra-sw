// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use log::{error, info};
use std::process::Command;

use crate::util::run_command;
use crate::PROJECT_ROOT;

pub(crate) fn check_format() -> Result<()> {
    info!("Checking source-code formatting...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT)
        .args(["fmt", "--check", "--all"]);

    if let Err(e) = run_command(&mut cmd) {
        error!("{}", e);
        bail!("Source-code formatting check failed. Run 'cargo fmt --all' to fix.");
    }

    info!("Formatting check passed!");
    Ok(())
}
