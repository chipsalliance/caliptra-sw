/*++

Licensed under the Apache-2.0 license.

File Name:

    state.rs

Abstract:

    File contains Device state related API

--*/

use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::soc_ifc::enums::DeviceLifecycleE;
use caliptra_registers::soc_ifc::{self, SocIfcReg};

use crate::FuseBank;

pub type Lifecycle = DeviceLifecycleE;

// [TODO] Move memory layout out of the common crate
// to avoid circular dependency with the drivers crate.
pub const BOOT_STATUS_ORG: u32 = 0x500047FC;

pub fn report_boot_status(val: u32) {
    let mut soc_ifc = unsafe { soc_ifc::SocIfcReg::new() };

    // Save the boot status in DCCM.
    unsafe {
        let ptr = BOOT_STATUS_ORG as *mut u32;
        *ptr = val;
    };

    // For testability, save the boot status in the boot status register only if debugging is enabled.
    if !soc_ifc.regs().cptra_security_state().read().debug_locked() {
        soc_ifc.regs_mut().cptra_boot_status().write(|_| val);
    }
}

pub fn reset_reason() -> ResetReason {
    let soc_ifc = unsafe { SocIfcReg::new() };

    let soc_ifc_regs = soc_ifc.regs();
    let bit0 = soc_ifc_regs.cptra_reset_reason().read().fw_upd_reset();
    let bit1 = soc_ifc_regs.cptra_reset_reason().read().warm_reset();

    match (bit0, bit1) {
        (true, true) => ResetReason::Unknown,
        (false, true) => ResetReason::WarmReset,
        (true, false) => ResetReason::UpdateReset,
        (false, false) => ResetReason::ColdReset,
    }
}

/// Device State
pub struct SocIfc {
    soc_ifc: SocIfcReg,
}

impl SocIfc {
    pub fn new(soc_ifc: SocIfcReg) -> Self {
        Self { soc_ifc }
    }
    /// Retrieve the device lifecycle state
    pub fn lifecycle(&self) -> Lifecycle {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs
            .cptra_security_state()
            .read()
            .device_lifecycle()
    }

    /// Check if device is locked for debug
    pub fn debug_locked(&self) -> bool {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs.cptra_security_state().read().debug_locked()
    }

    /// Locks or unlocks the ICCM.
    ///
    /// # Arguments
    /// * `lock` - Desired lock state of the ICCM
    ///
    pub fn set_iccm_lock(&mut self, lock: bool) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs.internal_iccm_lock().modify(|w| w.lock(lock));
    }

    /// Retrieve reset reason
    pub fn reset_reason(&mut self) -> ResetReason {
        reset_reason()
    }

    /// Set IDEVID CSR ready
    ///
    /// # Arguments
    ///
    /// * None
    pub fn flow_status_set_idevid_csr_ready(&mut self) {
        let soc_ifc = self.soc_ifc.regs_mut();
        soc_ifc
            .cptra_flow_status()
            .write(|w| w.idevid_csr_ready(true));
    }

    /// Set ready for firmware
    ///
    /// # Arguments
    ///
    /// * None
    pub fn flow_status_set_ready_for_firmware(&mut self) {
        let soc_ifc = self.soc_ifc.regs_mut();
        soc_ifc.cptra_flow_status().write(|w| w.ready_for_fw(true));
    }

    pub fn fuse_bank(&self) -> FuseBank {
        FuseBank {
            soc_ifc: &self.soc_ifc,
        }
    }

    /// Returns the flag indicating whether to generate Initial Device ID Certificate
    /// Signing Request (CSR)
    pub fn mfg_flag_gen_idev_id_csr(&mut self) -> bool {
        let soc_ifc_regs = self.soc_ifc.regs();
        let flags: MfgFlags = soc_ifc_regs.cptra_dbg_manuf_service_reg().read().into();
        flags.contains(MfgFlags::GENERATE_IDEVID_CSR)
    }

    /// Enable or disable WDT1
    ///
    /// # Arguments
    /// * `enable` - Enable or disable WDT1
    ///
    pub fn configure_wdt1(&mut self, enable: bool) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs
            .cptra_wdt_timer1_en()
            .write(|w| w.timer1_en(enable));
    }

    /// Stop WDT1.
    ///
    /// This is useful to call from a fatal-error-handling routine.
    ///
    ///  # Safety
    ///
    /// The caller must be certain that it is safe to stop the WDT1.
    ///
    /// This function is safe to call from a trap handler.
    pub unsafe fn stop_wdt1() {
        let mut soc_ifc = SocIfcReg::new();
        soc_ifc
            .regs_mut()
            .cptra_wdt_timer1_en()
            .write(|w| w.timer1_en(false));
    }

    pub fn get_cycle_count(&self, seconds: u32) -> CaliptraResult<u64> {
        const GIGA_UNIT: u32 = 1_000_000_000;
        let clock_period_picosecs = self.soc_ifc.regs().cptra_timer_config().read();
        if clock_period_picosecs == 0 {
            Err(CaliptraError::DRIVER_SOC_IFC_INVALID_TIMER_CONFIG)
        } else {
            // Dividing GIGA_UNIT by clock_period_picosecs gives frequency in KHz.
            // This is being done to avoid 64-bit division (at the loss of precision)
            Ok((seconds as u64) * ((GIGA_UNIT / clock_period_picosecs) as u64) * 1000)
        }
    }

    /// Sets WDT1 timeout
    ///
    /// # Arguments
    /// * `cycle_count` - Timeout period in cycles
    ///
    pub fn set_wdt1_timeout(&mut self, cycle_count: u64) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs
            .cptra_wdt_timer1_timeout_period()
            .at(0)
            .write(|_| cycle_count as u32);
        soc_ifc_regs
            .cptra_wdt_timer1_timeout_period()
            .at(1)
            .write(|_| (cycle_count >> 32) as u32);
    }

    /// Sets WDT2 timeout
    ///
    /// # Arguments
    /// * `cycle_count` - Timeout period in cycles
    ///
    pub fn set_wdt2_timeout(&mut self, cycle_count: u64) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs
            .cptra_wdt_timer2_timeout_period()
            .at(0)
            .write(|_| cycle_count as u32);
        soc_ifc_regs
            .cptra_wdt_timer2_timeout_period()
            .at(1)
            .write(|_| (cycle_count >> 32) as u32);
    }

    pub fn reset_wdt1(&mut self) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs
            .cptra_wdt_timer1_ctrl()
            .write(|w| w.timer1_restart(true));
    }

    pub fn internal_fw_update_reset_wait_cycles(&self) -> u32 {
        self.soc_ifc
            .regs()
            .internal_fw_update_reset_wait_cycles()
            .read()
            .into()
    }
    pub fn assert_fw_update_reset(&mut self) {
        self.soc_ifc
            .regs_mut()
            .internal_fw_update_reset()
            .write(|w| w.core_rst(true));
    }

    pub fn assert_ready_for_runtime(&mut self) {
        self.soc_ifc
            .regs_mut()
            .cptra_flow_status()
            .write(|w| w.ready_for_runtime(true));
    }

    pub fn set_fmc_fw_rev_id(&mut self, fmc_version: u32) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs.cptra_fw_rev_id().at(0).write(|_| fmc_version);
    }

    pub fn set_rt_fw_rev_id(&mut self, rt_version: u32) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs.cptra_fw_rev_id().at(1).write(|_| rt_version);
    }
}

bitflags::bitflags! {
    /// Manufacturing State
    pub struct MfgFlags : u32 {
        /// Generate Initial Device Id Certificate Signing Request
       const GENERATE_IDEVID_CSR = 0x01;
    }
}

impl From<u32> for MfgFlags {
    /// Converts to this type from the input type.
    fn from(value: u32) -> Self {
        MfgFlags::from_bits_truncate(value)
    }
}

/// Reset Reason
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ResetReason {
    /// Cold Reset
    ColdReset,

    /// Warm Reset
    WarmReset,

    /// Update Reset
    UpdateReset,

    /// Unknown Reset
    Unknown,
}
