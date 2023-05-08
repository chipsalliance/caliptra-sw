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
use caliptra_common::{PcrLogEntry, PcrLogEntryId};
use caliptra_drivers::{Array4x12, CaliptraResult, PcrId};
use caliptra_error::caliptra_err_def;
use zerocopy::AsBytes;

caliptra_err_def! {
    RomGlobal,
    GlobalErr
    {
        PcrLogInvalidEntryId = 0x4,
        PcrLogUnsupportedDataLength = 0x5,
    }
}

extern "C" {
    static mut PCR_LOG_ORG: u8;
}

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

    let extend = |data: Array4x12, pcr_entry_id: PcrLogEntryId| {
        let bytes: &[u8; 48] = &data.into();
        sha.map(|s| pcr_bank.map(|p| p.extend_pcr(PcrId::PcrId0, s, bytes)))?;
        log_pcr(pcr_entry_id, PcrId::PcrId0, bytes)
    };

    let extend_u8 = |data: u8, pcr_entry_id: PcrLogEntryId| {
        let bytes = &data.to_le_bytes();
        sha.map(|s| pcr_bank.map(|p| p.extend_pcr(PcrId::PcrId0, s, bytes)))?;
        log_pcr(pcr_entry_id, PcrId::PcrId0, bytes)
    };

    extend_u8(
        env.dev_state().map(|d| d.lifecycle()) as u8,
        PcrLogEntryId::DeviceLifecycle,
    )?;
    extend_u8(
        env.dev_state().map(|d| d.debug_locked()) as u8,
        PcrLogEntryId::DebugLocked,
    )?;
    extend_u8(
        env.fuse_bank().map(|f| f.anti_rollback_disable()) as u8,
        PcrLogEntryId::AntiRollbackDisabled,
    )?;
    extend(
        env.fuse_bank().map(|f| f.vendor_pub_key_hash()),
        PcrLogEntryId::VendorPubKeyHash,
    )?;
    extend(
        env.data_vault().map(|d| d.owner_pk_hash()),
        PcrLogEntryId::OwnerPubKeyHash,
    )?;
    extend_u8(
        env.data_vault().map(|d| d.vendor_pk_index()) as u8,
        PcrLogEntryId::VendorPubKeyIndex,
    )?;
    extend(env.data_vault().map(|d| d.fmc_tci()), PcrLogEntryId::FmcTci)?;
    extend_u8(
        env.data_vault().map(|d| d.fmc_svn()) as u8,
        PcrLogEntryId::FmcSvn,
    )?;

    // TODO: Check PCR0 != 0
    Ok(())
}

/// Log PCR data
///
/// # Arguments
/// * `pcr_entry_id` - PCR log entry ID
/// * `pcr_id` - PCR ID
/// * `data` - PCR data
///
/// # Return Value
/// * `Ok(())` - Success
/// * `Err(GlobalErr::PcrLogInvalidEntryId)` - Invalid PCR log entry ID
/// * `Err(GlobalErr::PcrLogUpsupportedDataLength)` - Unsupported data length
///
pub fn log_pcr(pcr_entry_id: PcrLogEntryId, pcr_id: PcrId, data: &[u8]) -> CaliptraResult<()> {
    if pcr_entry_id == PcrLogEntryId::Invalid {
        raise_err!(PcrLogInvalidEntryId);
    }

    if data.len() > 48 {
        raise_err!(PcrLogUnsupportedDataLength);
    }

    // Create a PCR log entry
    let mut pcr_log_entry = PcrLogEntry {
        id: pcr_entry_id as u16,
        pcr_id: pcr_id as u16,
        ..Default::default()
    };
    pcr_log_entry.pcr_data.as_bytes_mut()[..data.len()].copy_from_slice(data);

    let dst = unsafe {
        let offset = core::mem::size_of::<PcrLogEntry>() * (pcr_entry_id as usize - 1);
        let ptr = (&mut PCR_LOG_ORG as *mut u8).add(offset);
        core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<PcrLogEntry>())
    };

    // Store log entry
    dst.copy_from_slice(pcr_log_entry.as_bytes());

    Ok(())
}
