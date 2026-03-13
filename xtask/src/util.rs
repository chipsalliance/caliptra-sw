// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use log::log_enabled;
use std::process::{Command, Output};

pub(crate) fn run_command(cmd: &mut Command) -> Result<()> {
    if log_enabled!(log::Level::Debug) {
        let status = cmd.status()?;
        if !status.success() {
            bail!("Command failed with status {}", status);
        }
    } else {
        let output = cmd.output()?;
        if !output.status.success() {
            return Err(CommandError { output }.into());
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct CommandError {
    pub output: Output,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.output.stdout.is_empty() {
            writeln!(
                f,
                "STDOUT:\n{}",
                String::from_utf8_lossy(&self.output.stdout)
            )?;
        }
        if !self.output.stderr.is_empty() {
            writeln!(
                f,
                "STDERR:\n{}",
                String::from_utf8_lossy(&self.output.stderr)
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for CommandError {}
