/*++

Licensed under the Apache-2.0 license.

File Name:

    reset.rs

Abstract:

    File contains reset related API

--*/

use caliptra_registers::soc_ifc;

/// Reset Reason
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ResetReason {
    /// Cold Reset
    ColdReset,

    /// Wram Reset
    WarmReset,

    /// Update Reset
    UpdateReset,

    /// Unknown Reset
    Unknown,
}

/// Reset Service
#[derive(Default, Debug)]
pub struct ResetService {}

impl ResetService {
    /// Retrieve reset reason
    pub fn reset_reason(&self) -> ResetReason {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();
        let bit0 = soc_ifc_regs.cptra_reset_reason().read().fw_upd_reset();
        let bit1 = soc_ifc_regs.cptra_reset_reason().read().warm_reset();
        match (bit0, bit1) {
            (true, true) => ResetReason::Unknown,
            (true, false) => ResetReason::WarmReset,
            (false, true) => ResetReason::UpdateReset,
            (false, false) => ResetReason::ColdReset,
        }
    }
}
