/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    File contains execution routines for extending PCR0 & PCR1

Environment:

    ROM

Note:

    PCR0 - Journey PCR unlocked and cleared on cold reset
    PCR1 - Current PCR unlocked and cleared on any reset

--*/

use crate::rom_env::RomEnv;
use caliptra_drivers::{Array4x12, CaliptraResult, PcrId};

/// Extend PCR0
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn extend_pcr0(env: &RomEnv) -> CaliptraResult<()> {
    let sha = env.sha384();
    let pcr_bank = env.pcr_bank();

    // Clear the PCR
    pcr_bank.map(|p| p.erase_pcr(caliptra_drivers::PcrId::PcrId0))?;

    // Lock the PCR from clear
    pcr_bank.map(|p| p.set_pcr_lock(caliptra_drivers::PcrId::PcrId0));

    let extend = |data: Array4x12| {
        let bytes: &[u8; 48] = &data.into();
        sha.map(|s| pcr_bank.map(|p| p.extend_pcr(PcrId::PcrId0, s, bytes)))
    };

    let extend_u8 = |data: u8| {
        let bytes = &data.to_le_bytes();
        sha.map(|s| pcr_bank.map(|p| p.extend_pcr(PcrId::PcrId0, s, bytes)))
    };

    extend_u8(env.dev_state().map(|d| d.lifecycle()) as u8)?;
    extend_u8(env.dev_state().map(|d| d.debug_locked()) as u8)?;
    extend_u8(env.fuse_bank().map(|f| f.anti_rollback_disable()) as u8)?;
    extend(env.fuse_bank().map(|f| f.vendor_pub_key_hash()))?;
    extend(env.data_vault().map(|d| d.owner_pk_hash()))?;
    extend_u8(env.data_vault().map(|d| d.vendor_pk_index()) as u8)?;
    extend(env.data_vault().map(|d| d.fmc_tci()))?;
    extend_u8(env.data_vault().map(|d| d.fmc_svn()) as u8)?;

    // TODO: Check PCR0 != 0

    Ok(())
}
