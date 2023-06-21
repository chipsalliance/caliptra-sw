/*++

Licensed under the Apache-2.0 license.

File Name:

    state.rs

Abstract:

    File contains Device state related API

--*/

use caliptra_registers::soc_ifc::enums::DeviceLifecycleE;
use caliptra_registers::soc_ifc::{self, SocIfcReg};

use crate::FuseBank;

/// Device Life Cycle State
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Lifecycle {
    /// Unprovisioned
    Unprovisioned = 0x0,

    /// Manufacturing
    Manufacturing = 0x1,

    /// Production
    Production = 0x2,

    /// Unknown
    Unknown = 0x3,
}

impl From<DeviceLifecycleE> for Lifecycle {
    /// Converts to this type from the input type.
    fn from(value: DeviceLifecycleE) -> Self {
        match value {
            DeviceLifecycleE::Unprovisioned => Lifecycle::Unprovisioned,
            DeviceLifecycleE::Manufacturing => Lifecycle::Manufacturing,
            DeviceLifecycleE::Production => Lifecycle::Production,
            _ => Lifecycle::Unknown,
        }
    }
}

pub fn report_boot_status(val: u32) {
    let mut soc_ifc = unsafe { soc_ifc::SocIfcReg::new() };
    soc_ifc.regs_mut().cptra_boot_status().write(|_| val);
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
            .into()
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
        let soc_ifc_regs = self.soc_ifc.regs();
        let bit0 = soc_ifc_regs.cptra_reset_reason().read().fw_upd_reset();
        let bit1 = soc_ifc_regs.cptra_reset_reason().read().warm_reset();
        match (bit0, bit1) {
            (true, true) => ResetReason::Unknown,
            (false, true) => ResetReason::WarmReset,
            (true, false) => ResetReason::UpdateReset,
            (false, false) => ResetReason::ColdReset,
        }
    }

    /// Set IDEVID CSR ready
    ///
    /// # Arguments
    ///
    /// * None
    pub fn flow_status_set_idevid_csr_ready(&mut self) {
        let soc_ifc = self.soc_ifc.regs_mut();
        soc_ifc.cptra_flow_status().write(|w| w.status(0x0800_0000));
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
