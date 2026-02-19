// Licensed under the Apache-2.0 license
//
// Derived from OpenTitan's opentitanlib with original copyright:
//
// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::jtag::{CsrReg, DmReg, JtagAccessibleReg};
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

/// Errors related to the JTAG interface.
#[derive(Error, Debug, Deserialize, Serialize)]
pub enum JtagError {
    #[error("Operation not valid on selected JTAG TAP: {0:?}")]
    Tap(JtagTap),
    #[error("JTAG timeout")]
    Timeout,
    #[error("JTAG busy")]
    Busy,
    #[error("Generic error {0}")]
    Generic(String),
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

    pub fn reexamine_cpu_target(&mut self) -> Result<()> {
        ensure!(
            self.jtag_tap != JtagTap::NoTap,
            JtagError::Tap(self.jtag_tap)
        );
        let _ = self.openocd.execute("riscv.cpu arp_examine")?;
        Ok(())
    }

    pub fn set_sysbus_access(&mut self) -> Result<()> {
        ensure!(
            self.jtag_tap != JtagTap::NoTap,
            JtagError::Tap(self.jtag_tap)
        );
        let _ = self.openocd.execute("riscv set_mem_access sysbus")?;
        Ok(())
    }

    pub fn read_reg(&mut self, reg: &dyn JtagAccessibleReg) -> Result<u32> {
        ensure!(
            self.jtag_tap != JtagTap::NoTap,
            JtagError::Tap(self.jtag_tap)
        );
        let reg_offset = reg.word_offset();
        let cmd = format!("riscv dmi_read 0x{reg_offset:x}");
        let response = self.openocd.execute(cmd.as_str())?;
        let response_hexstr = response.trim();
        let value = u32::from_str_radix(
            response_hexstr
                .strip_prefix("0x")
                .unwrap_or(response_hexstr),
            16,
        )
        .context(format!(
            "expected response to be hexadecimal word, got '{response}'"
        ))?;

        Ok(value)
    }

    pub fn write_reg(&mut self, reg: &dyn JtagAccessibleReg, value: u32) -> Result<()> {
        ensure!(
            self.jtag_tap != JtagTap::NoTap,
            JtagError::Tap(self.jtag_tap)
        );
        let reg_offset = reg.word_offset();
        let cmd = format!("riscv dmi_write 0x{reg_offset:x} 0x{value:x}");
        let response = self.openocd.execute(cmd.as_str())?;

        if !response.is_empty() {
            bail!("unexpected response: '{response}'");
        }

        Ok(())
    }

    pub fn read_memory_32(&mut self, addr: u32) -> Result<u32> {
        ensure!(
            self.jtag_tap != JtagTap::NoTap,
            JtagError::Tap(self.jtag_tap)
        );
        let cmd = format!("read_memory 0x{addr:x} 32 1 phys");
        let response = self.openocd.execute(cmd.as_str())?;
        let response_hexstr = response.trim();
        let value = u32::from_str_radix(
            response_hexstr
                .strip_prefix("0x")
                .unwrap_or(response_hexstr),
            16,
        )
        .context(format!(
            "expected response to be hexadecimal word, got '{response}'"
        ))?;
        Ok(value)
    }

    pub fn write_memory_32(&mut self, addr: u32, value: u32) -> Result<()> {
        ensure!(
            self.jtag_tap != JtagTap::NoTap,
            JtagError::Tap(self.jtag_tap)
        );
        let cmd = format!("write_memory 0x{addr:x} 32 {{ 0x{value:x} }} phys");
        let response = self.openocd.execute(cmd.as_str())?;
        if !response.is_empty() {
            bail!("unexpected response: '{response}'");
        }
        Ok(())
    }

    /// Poll until any bits in a given mask are set in the dmstatus register
    pub fn wait_status(&mut self, mask: u32, timeout: Duration) -> Result<()> {
        for _ in 0..100 {
            let status = self.read_reg(&DmReg::DmStatus)?;
            if status & mask > 0 {
                return Ok(());
            }
            std::thread::sleep(timeout / 100);
        }

        bail!("Timed out waiting for status register")
    }

    /// Send a halt request to the dmcontrol register
    pub fn halt(&mut self) -> Result<()> {
        const HALT_REQ: u32 = 1 << 31 | 1;
        self.write_reg(&DmReg::DmControl, HALT_REQ)
    }

    /// Send a resume request to the dmcontrol register
    pub fn resume(&mut self) -> Result<()> {
        const RESUME_REQ: u32 = 1 << 30 | 1;
        self.write_reg(&DmReg::DmControl, RESUME_REQ)
    }

    /// Write a value to a CSR using the abstract command register
    pub fn write_csr_reg(&mut self, reg: CsrReg, value: u32) -> Result<()> {
        self.write_reg(&DmReg::DmAbstractData0, value)?;

        // From https://chipsalliance.github.io/Cores-VeeR-EL2/html/main/docs_rendered/html/debugging.html#abstract-command-register-command
        let abstract_cmd = 0x00230000 | (reg as u32 & 0xFFF);
        self.write_reg(&DmReg::DmAbstractCommand, abstract_cmd)
    }
}
