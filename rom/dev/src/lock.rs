/*++

Licensed under the Apache-2.0 license.

File Name:

    lock.rs

Abstract:

    File contains function to lock registers based on reset reason.

--*/

use crate::{cprintln, rom_env::RomEnv};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_common::{
    lock_datavault_region,
    pcr::{PCR_ID_FMC_CURRENT, PCR_ID_FMC_JOURNEY, PCR_ID_STASH_MEASUREMENT},
};
use caliptra_drivers::{ColdResetEntries, ResetReason, WarmResetEntries};
use core::mem::size_of;

/// Lock registers
///
/// # Arguments
///
/// * `env` - ROM Environment
/// * `reset_reason` - Reset reason
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub fn lock_registers(env: &mut RomEnv, reset_reason: ResetReason) {
    cprintln!("[state] Locking Datavault");
    if reset_reason == ResetReason::ColdReset {
        lock_cold_reset_reg(env);
        lock_common_reg_set(env);
    } else {
        // For both UpdateReset and WarmReset, we lock the common set of registers.
        lock_common_reg_set(env);
    }

    env.pcr_bank.set_pcr_lock(PCR_ID_FMC_CURRENT);
    env.pcr_bank.set_pcr_lock(PCR_ID_FMC_JOURNEY);
    env.pcr_bank.set_pcr_lock(PCR_ID_STASH_MEASUREMENT);

    env.soc_ifc.set_iccm_lock(true);
}

/// Lock registers on a cold reset
///
/// # Arguments
///
/// * `env` - ROM Environment
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub fn lock_cold_reset_reg(env: &mut RomEnv) {
    let base_addr = &env
        .persistent_data
        .get_mut()
        .rom
        .data_vault
        .cold_reset_entries as *const _ as usize;
    lock_datavault_region(base_addr, size_of::<ColdResetEntries>(), true);
}

/// Lock all common registers across all reset types
///
/// # Arguments
///
/// * `env` - ROM Environment
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
fn lock_common_reg_set(env: &mut RomEnv) {
    let base_addr = &env
        .persistent_data
        .get_mut()
        .rom
        .data_vault
        .warm_reset_entries as *const _ as usize;
    lock_datavault_region(base_addr, size_of::<WarmResetEntries>(), false);
}
