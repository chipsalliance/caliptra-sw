/*++
Licensed under the Apache-2.0 license.

File Name:

    helpers.rs

Abstract:

    Helper Functions

--*/

use caliptra_drivers::ResetReason;

pub fn reset_reason() -> ResetReason {
    let soc_ifc = unsafe { caliptra_registers::soc_ifc::SocIfcReg::new() };

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
