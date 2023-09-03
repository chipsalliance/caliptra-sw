/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    File contains execution routines for extending current and journey PCRs.

Environment:

    FMC

Note:

    PCR2 - Journey PCR unlocked and cleared on cold reset
    PCR3 - Current PCR unlocked and cleared on any reset

--*/
use crate::flow::tci::Tci;
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_drivers::{
    cprintln,
    memory_layout::{PCR_LOG_ORG, PCR_LOG_SIZE},
    okref,
    pcr_log::{PcrLogEntry, PcrLogEntryId},
    CaliptraResult, PcrBank, PcrId,
};

use caliptra_common::{RT_FW_CURRENT_PCR, RT_FW_JOURNEY_PCR};
use caliptra_error::CaliptraError;
use zerocopy::AsBytes;

/// Extend current PCR
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn extend_current_pcr(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
    // Clear current PCR before extending it.
    if env.soc_ifc.reset_reason() == caliptra_drivers::ResetReason::UpdateReset {
        env.pcr_bank.erase_pcr(RT_FW_CURRENT_PCR)?;
    }
    extend_pcr_common(env, hand_off, RT_FW_CURRENT_PCR)
}

/// Extend journey PCR
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn extend_journey_pcr(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
    extend_pcr_common(env, hand_off, RT_FW_JOURNEY_PCR)
}

/// Extend common data into PCR
///
/// # Arguments
///
/// * `env` - FMC Environment
/// * `pcr_id` - PCR slot to extend the data into
fn extend_pcr_common(env: &mut FmcEnv, hand_off: &HandOff, pcr_id: PcrId) -> CaliptraResult<()> {
    // Extend RT TCI (Hash over runtime code)
    let rt_tci = Tci::rt_tci(env, hand_off);
    let rt_tci: [u8; 48] = okref(&rt_tci)?.into();
    env.pcr_bank.extend_pcr(pcr_id, &mut env.sha384, &rt_tci)?;

    log_pcr(
        &mut env.pcr_bank,
        PcrLogEntryId::RtTci,
        1 << pcr_id as u8,
        &rt_tci,
    )?;

    // Extend FW Image Manifest
    let manifest_digest = Tci::image_manifest_digest(env, hand_off);
    let manifest_digest: [u8; 48] = okref(&manifest_digest)?.into();
    env.pcr_bank
        .extend_pcr(pcr_id, &mut env.sha384, &manifest_digest)?;

    log_pcr(
        &mut env.pcr_bank,
        PcrLogEntryId::FwImageManifest,
        1 << pcr_id as u8,
        &manifest_digest,
    )
}

pub fn log_pcr(
    pcr_bank: &mut PcrBank,
    pcr_entry_id: PcrLogEntryId,
    pcr_ids: u32,
    data: &[u8],
) -> CaliptraResult<()> {
    if pcr_entry_id == PcrLogEntryId::Invalid {
        return Err(CaliptraError::FMC_PCR_LOG_INVALID_ENTRY_ID);
    }

    if data.len() > 48 {
        return Err(CaliptraError::FMC_PCR_LOG_UNSUPPORTED_DATA_LENGTH);
    }

    if pcr_bank.log_index * core::mem::size_of::<PcrLogEntry>() > PCR_LOG_SIZE {
        return Err(CaliptraError::FMC_GLOBAL_PCR_LOG_EXHAUSTED);
    }

    // Create a PCR log entry
    cprintln!("pcr_entry_id: {:?}", pcr_entry_id as u16);
    let mut pcr_log_entry = PcrLogEntry {
        id: pcr_entry_id as u16,
        pcr_ids,
        ..Default::default()
    };
    pcr_log_entry.pcr_data.as_bytes_mut()[..data.len()].copy_from_slice(data);

    let dst: &mut [PcrLogEntry] = unsafe {
        let ptr = PCR_LOG_ORG as *mut PcrLogEntry;
        let entry_ptr = ptr.add(pcr_bank.log_index);
        pcr_bank.log_index += 1;
        core::slice::from_raw_parts_mut(entry_ptr, 1)
    };

    // Store the log entry.
    dst[0] = pcr_log_entry;

    Ok(())
}
