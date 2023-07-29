/*++

Licensed under the Apache-2.0 license.

File Name:

    lock.rs

Abstract:

    File contains function to lock registers based on reset reason.

--*/

use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_common::pcr::{PCR_ID_FMC_CURRENT, PCR_ID_FMC_JOURNEY, PCR_ID_STASH_MEASUREMENT};
use caliptra_drivers::{
    ColdResetEntry4, ColdResetEntry48, ResetReason, WarmResetEntry4, WarmResetEntry48,
};

use crate::{cprintln, rom_env::RomEnv};

/// Lock registers
///
/// # Arguments
///
/// * `env` - ROM Environment
/// * `reset_reason` - Reset reason
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn lock_registers(env: &mut RomEnv, reset_reason: ResetReason) {
    cprintln!("[state] Locking Datavault");
    if reset_reason == ResetReason::ColdReset {
        lock_cold_reset_reg(env);
        lock_common_reg_set(env);
    } else {
        // For both UpdateReset and WarmReset, we lock the comm
        // set of registers
        lock_common_reg_set(env);
    }

    cprintln!("[state] Locking PCR0, PCR1 and PCR31");
    env.pcr_bank.set_pcr_lock(PCR_ID_FMC_CURRENT);
    env.pcr_bank.set_pcr_lock(PCR_ID_FMC_JOURNEY);
    env.pcr_bank.set_pcr_lock(PCR_ID_STASH_MEASUREMENT);

    cprintln!("[state] Locking ICCM");
    env.soc_ifc.set_iccm_lock(true);
}

/// Lock registers on a cold reset
///
/// # Arguments
///
/// * `env` - ROM Environment
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
fn lock_cold_reset_reg(env: &mut RomEnv) {
    // Lock the FMC TCI in data vault until next cold reset
    env.data_vault
        .lock_cold_reset_entry48(ColdResetEntry48::FmcTci);

    // Lock the FMC SVN  in data vault until next cold reset
    env.data_vault
        .lock_cold_reset_entry4(ColdResetEntry4::FmcSvn);

    // Lock the FMC entry point in data vault until next cold reset
    env.data_vault
        .lock_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint);

    // Lock the Owner Public Key Hash in data vault until next cold reset
    env.data_vault
        .lock_cold_reset_entry48(ColdResetEntry48::OwnerPubKeyHash);

    // Lock the Ecc Vendor Public Key Index in data vault until next cold reset
    env.data_vault
        .lock_cold_reset_entry4(ColdResetEntry4::EccVendorPubKeyIndex);

    // Lock the Lms Vendor Public Key Index in data vault until next cold reset
    env.data_vault
        .lock_cold_reset_entry4(ColdResetEntry4::LmsVendorPubKeyIndex);
}

/// Lock all common registers across all reset types
///
/// # Arguments
///
/// * `env` - ROM Environment
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
fn lock_common_reg_set(env: &mut RomEnv) {
    // Lock the Runtime TCI in data vault until next reset
    env.data_vault
        .lock_warm_reset_entry48(WarmResetEntry48::RtTci);

    // Lock the Runtime SVN  in data vault until next reset
    env.data_vault
        .lock_warm_reset_entry4(WarmResetEntry4::RtSvn);

    // Lock the Runtime entry point in data vault until next reset
    env.data_vault
        .lock_warm_reset_entry4(WarmResetEntry4::RtEntryPoint);

    // Lock the Manifest addr in data vault until next reset
    env.data_vault
        .lock_warm_reset_entry4(WarmResetEntry4::ManifestAddr);
}
