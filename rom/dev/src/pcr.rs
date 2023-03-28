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
use caliptra_drivers::{CaliptraResult, PcrId};

/// Extend PCR0
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn extend_pcr0(env: &RomEnv) -> CaliptraResult<()> {
    let pcr_bank = env.pcr_bank();

    // Clear the PCR
    pcr_bank.map(|p| p.erase_pcr(caliptra_drivers::PcrId::PcrId0))?;

    // Lock the PCR from clear
    pcr_bank.map(|p| p.set_pcr_lock(caliptra_drivers::PcrId::PcrId0));

    // Extend common data into PCR
    extend_pcr_common(env, PcrId::PcrId0)
}

/// Extend PCR1
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn extend_pcr1(env: &RomEnv) -> CaliptraResult<()> {
    let pcr_bank = env.pcr_bank();

    // Clear the PCR
    pcr_bank.map(|p| p.erase_pcr(caliptra_drivers::PcrId::PcrId1))?;

    // Extend common data into PCR
    extend_pcr_common(env, PcrId::PcrId1)
}

/// Extend common data into PCR
///
/// # Arguments
///
/// * `env` - ROM Environment
/// * `pcr_id` - PCR slot to extend the data into
fn extend_pcr_common(env: &RomEnv, pcr_id: PcrId) -> CaliptraResult<()> {
    let pcr_bank = env.pcr_bank();
    let sha = env.sha384();

    // Extend Device Lifecycle state
    let data = env.dev_state().map(|d| d.lifecycle()) as u8;
    let bytes = &data.to_le_bytes();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    // Extend Debug Lock state
    let data = env.dev_state().map(|d| d.debug_locked()) as u8;
    let bytes = &data.to_le_bytes();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    // Extend Anti-Rollback disable fuse
    let data = env.fuse_bank().map(|f| f.anti_rollback_disable()) as u8;
    let bytes = &data.to_le_bytes();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    // Extend Vendor Public Key Hash
    let data = env.fuse_bank().map(|f| f.vendor_pub_key_hash());
    let bytes: &[u8; 48] = &data.into();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    // Extend Owner Public Key Hash
    let data = env.data_vault().map(|d| d.owner_pk_hash());
    let bytes: &[u8; 48] = &data.into();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    // Extend Vendor Public Key Index used to validate the firmware image bundle
    let data = env.data_vault().map(|d| d.vendor_pk_index()) as u8;
    let bytes = &data.to_le_bytes();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    // Extend FMC TCI (Hash)
    let data = env.data_vault().map(|d| d.fmc_tci());
    let bytes: &[u8; 48] = &data.into();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    // Extend FMC SVN
    let data = env.data_vault().map(|d| d.fmc_svn()) as u8;
    let bytes = &data.to_le_bytes();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    Ok(())
}
