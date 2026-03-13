// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use log::{error, info};
use std::process::Command;

use crate::util::run_command;
use crate::PROJECT_ROOT;

pub(crate) fn check_cargo_lock() -> Result<()> {
    info!("Checking that Cargo.lock doesn't need to be updated...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&*PROJECT_ROOT).args(["tree", "--locked"]);

    if let Err(e) = run_command(&mut cmd) {
        error!("Please include required changes to Cargo.lock in your pull request");
        error!("{}", e);

        // Without the --locked flag, cargo will do the minimal possible update to Cargo.lock
        let _ = Command::new("cargo")
            .current_dir(&*PROJECT_ROOT)
            .args(["tree"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        // Print out the differences to ease debugging
        let diff = Command::new("git")
            .current_dir(&*PROJECT_ROOT)
            .args(["diff", "Cargo.lock"])
            .output()?;

        error!("{}", String::from_utf8_lossy(&diff.stdout));

        bail!("Cargo.lock check failed");
    }

    info!("Cargo.lock check passed!");
    Ok(())
}
