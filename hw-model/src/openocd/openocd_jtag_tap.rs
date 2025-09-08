// Licensed under the Apache-2.0 license
//
// Derived from OpenTitan's opentitanlib with original copyright:
//
// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::openocd::openocd_server::{OpenOcdError, OpenOcdServer};

/// Available JTAG TAPs in Calitpra Subsystem.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
pub enum JtagTap {
    /// RISC-V Veer core's TAP for Caliptra Core.
    CaliptraCoreTap,
    /// RISC-V Veer core's TAP for Caliptra MCU.
    CaliptraMcuTap,
    /// Lifecycle Controller's TAP.
    LccTap,
    /// No TAP selected.
    NoTap,
}

/// JTAG parameters to pass to OpenOCD server on startup.
#[derive(Debug, Clone)]
pub struct JtagParams {
    /// OpenOCD binary path.
    pub openocd: PathBuf,

    /// JTAG adapter speed in kHz.
    pub adapter_speed_khz: u64,

    /// Whether or not to log OpenOCD server messages to stdio.
    pub log_stdio: bool,
}

/// A JTAG TAP accessible through an OpenOCD server.
pub struct OpenOcdJtagTap {
    /// OpenOCD server instance.
    openocd: OpenOcdServer,
    /// JTAG TAP OpenOCD server is connected to.
    jtag_tap: JtagTap,
}

impl OpenOcdJtagTap {
    /// Starts an OpenOCD server and connects to a specified JTAG TAP.
    pub fn new(params: &JtagParams, tap: JtagTap) -> Result<Box<OpenOcdJtagTap>> {
        let target_tap = match tap {
            JtagTap::CaliptraCoreTap => "core",
            JtagTap::CaliptraMcuTap => "mcu",
            JtagTap::LccTap => "lcc",
            // "none" will cause the OpenOCD startup stript to fail.
            JtagTap::NoTap => "none",
        };
        let adapter_cfg = &format!(
            "{} configure_adapter {}",
            include_str!(env!("OPENOCD_SYSFSGPIO_ADAPTER_CFG")),
            target_tap,
        );
        let tap_cfg = &format!(
            "{} configure_tap {}",
            include_str!(env!("OPENOCD_TAP_CFG")),
            target_tap,
        );

        // Spawn the OpenOCD server, configure the adapter, and connect to the TAP.
        let mut openocd = OpenOcdServer::spawn(&params.openocd, params.log_stdio)?;
        openocd.execute(adapter_cfg)?;
        openocd.execute(&format!("adapter speed {}", params.adapter_speed_khz))?;
        openocd.execute("transport select jtag")?;
        openocd.execute(tap_cfg)?;

        // Capture outputs during initialization to see if error has occurred during the process.
        let resp = openocd.execute("capture init")?;
        println!("Resp: {}", resp);
        if resp.contains("JTAG scan chain interrogation failed") {
            bail!(OpenOcdError::InitializeFailure(resp));
        }

        Ok(Box::new(OpenOcdJtagTap {
            openocd,
            jtag_tap: tap,
        }))
    }

    /// Stop the OpenOCD server, disconnecting from the TAP in the process.
    pub fn disconnect(&mut self) -> Result<()> {
        self.openocd.shutdown()
    }

    /// Return the TAP we are currently connected to.
    pub fn tap(&self) -> JtagTap {
        self.jtag_tap
    }
}
