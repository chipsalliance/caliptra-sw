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
    // Note that these registers should already have been locked when they
    // were first written; locking is performed here as a precaution.
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
    // Lock values until next cold reset.
    env.data_vault().map(|d| {
        d.lock_cold_reset_entry48(ColdResetEntry48::FmcTci);
        d.lock_cold_reset_entry4(ColdResetEntry4::FmcSvn);
        d.lock_cold_reset_entry4(ColdResetEntry4::FmcLoadAddr);
        d.lock_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint);
        d.lock_cold_reset_entry48(ColdResetEntry48::OwnerPubKeyHash);
        d.lock_cold_reset_entry4(ColdResetEntry4::VendorPubKeyIndex);
        d.lock_cold_reset_entry48(ColdResetEntry48::FmcMeasurements);
	});
}

/// Lock registers on a warm reset
///
/// # Arguments
///
/// * `env` - ROM Environment
fn lock_warm_reset_reg(env: &RomEnv) {
    // Lock values until next warm reset
    env.data_vault().map(|d| {
    	d.lock_warm_reset_entry48(WarmResetEntry48::RtTci);
    	d.lock_warm_reset_entry4(WarmResetEntry4::RtSvn);
    	d.lock_warm_reset_entry4(WarmResetEntry4::RtLoadAddr);
    	d.lock_warm_reset_entry4(WarmResetEntry4::RtEntryPoint);
    	d.lock_warm_reset_entry4(WarmResetEntry4::ManifestAddr);
    });
}