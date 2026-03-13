// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use log::{error, info};
use std::process::Command;

use crate::util::run_command;
use crate::PROJECT_ROOT;

pub(crate) fn check_license_headers() -> Result<()> {
    info!("Checking license headers...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT).args([
        "run",
        "-p",
        "caliptra-file-header-fix",
        "--locked",
        "--",
        "--check",
    ]);

    if let Err(e) = run_command(&mut cmd) {
        error!("{}", e);
        bail!("License header check failed. Run 'cargo run -p caliptra-file-header-fix' to fix.");
    }

    info!("License header check passed!");
    Ok(())
}
