/*++

Licensed under the Apache-2.0 license.

File Name:

    lock.rs

Abstract:

    File contains function to lock registers based on reset reason.

--*/

use caliptra_drivers::{
    ColdResetEntry4, ColdResetEntry48, ResetReason, WarmResetEntry4, WarmResetEntry48,
};

use crate::rom_env::RomEnv;

/// Lock registers
///
/// # Arguments
///
/// * `env` - ROM Environment
/// * `reset_reason` - Reset reason
pub fn lock_registers(env: &RomEnv, reset_reason: ResetReason) {
    if reset_reason == ResetReason::ColdReset {
        lock_cold_reset_reg(env);
        lock_warm_reset_reg(env);
    } else if reset_reason == ResetReason::WarmReset {
        lock_warm_reset_reg(env);
    } else if reset_reason == ResetReason::UpdateReset {
    }
}

/// Lock registers on a cold reset
///
/// # Arguments
///
/// * `env` - ROM Environment
fn lock_cold_reset_reg(env: &RomEnv) {
    // Lock the FMC TCI in data vault until next cold reset
    env.data_vault()
        .map(|d| d.lock_cold_reset_entry48(ColdResetEntry48::FmcTci));

    // Lock the FMC SVN  in data vault until next cold reset
    env.data_vault()
        .map(|d| d.lock_cold_reset_entry4(ColdResetEntry4::FmcSvn));

    // Lock the FMC load address in data vault until next cold reset
    env.data_vault()
        .map(|d| d.lock_cold_reset_entry4(ColdResetEntry4::FmcLoadAddr));

    // Lock the FMC entry point in data vault until next cold reset
    env.data_vault()
        .map(|d| d.lock_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint));

    // Lock the Owner Public Key Hash in data vault until next cold reset
    env.data_vault()
        .map(|d| d.lock_cold_reset_entry48(ColdResetEntry48::OwnerPubKeyHash));

    // Lock the Vendor Public Key Index in data vault until next cold reset
    env.data_vault()
        .map(|d| d.lock_cold_reset_entry4(ColdResetEntry4::VendorPubKeyIndex));
}

/// Lock registers on a warm reset
///
/// # Arguments
///
/// * `env` - ROM Environment
fn lock_warm_reset_reg(env: &RomEnv) {
    // Lock the Runtime TCI in data vault until next warm reset
    env.data_vault()
        .map(|d| d.lock_warm_reset_entry48(WarmResetEntry48::RtTci));

    // Lock the Runtime SVN  in data vault until next warm reset
    env.data_vault()
        .map(|d| d.lock_warm_reset_entry4(WarmResetEntry4::RtSvn));

    // Lock the Runtime load address in data vault until next warm reset
    env.data_vault()
        .map(|d| d.lock_warm_reset_entry4(WarmResetEntry4::RtLoadAddr));

    // Lock the Runtime entry point in data vault until next warm reset
    env.data_vault()
        .map(|d| d.lock_warm_reset_entry4(WarmResetEntry4::RtEntryPoint));

    // Lock the Manifest addr in data vault until next warm reset
    env.data_vault()
        .map(|d| d.lock_warm_reset_entry4(WarmResetEntry4::ManifestAddr));
}
