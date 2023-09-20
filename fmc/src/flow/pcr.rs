/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    File contains execution routines for extending current and journey PCRs.

Environment:

    FMC

Note:

    PCR2 - Current PCR unlocked and cleared on any reset
    PCR3 - Journey PCR unlocked and cleared on cold reset

--*/
use crate::flow::tci::Tci;
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_drivers::{
    okref,
    pcr_log::{PcrLogEntry, PcrLogEntryId},
    CaliptraResult, PersistentData,
};

use caliptra_common::{RT_FW_CURRENT_PCR, RT_FW_JOURNEY_PCR};
use caliptra_error::CaliptraError;
use zerocopy::AsBytes;

/// Extend common data into the RT current and journey PCRs
///
/// # Arguments
///
/// * `env` - FMC Environment
/// * `pcr_id` - PCR slot to extend the data into
///
/// TODO: Add CFI instrumentation
pub fn extend_pcr_common(env: &mut FmcEnv) -> CaliptraResult<()> {
    // Calculate RT TCI (Hash over runtime code)
    let rt_tci: [u8; 48] = HandOff::rt_tci(env).into();

    // Calculate FW Image Manifest digest
    let manifest_digest = Tci::image_manifest_digest(env);
    let manifest_digest: [u8; 48] = okref(&manifest_digest)?.into();

    // Clear current PCR before extending it.
    env.pcr_bank.erase_pcr(RT_FW_CURRENT_PCR)?;

    extend_and_log(env, PcrLogEntryId::RtTci, &rt_tci)?;
    extend_and_log(env, PcrLogEntryId::FwImageManifest, &manifest_digest)?;

    Ok(())
}

/// Extend `data` into both the current and journey PCRs, and updates the PCR log.
/// TODO: Add CFI instrumentation
fn extend_and_log(env: &mut FmcEnv, entry_id: PcrLogEntryId, data: &[u8]) -> CaliptraResult<()> {
    env.pcr_bank
        .extend_pcr(RT_FW_CURRENT_PCR, &mut env.sha384, data)?;
    env.pcr_bank
        .extend_pcr(RT_FW_JOURNEY_PCR, &mut env.sha384, data)?;

    log_pcr(
        env.persistent_data.get_mut(),
        entry_id,
        (1 << RT_FW_CURRENT_PCR as u8) | (1 << RT_FW_JOURNEY_PCR as u8),
        data,
    )
}

// TODO: Add CFI instrumentation
fn log_pcr(
    persistent_data: &mut PersistentData,
    pcr_entry_id: PcrLogEntryId,
    pcr_ids: u32,
    data: &[u8],
) -> CaliptraResult<()> {
    let fht = &mut persistent_data.fht;

    let Some(dst) = persistent_data.pcr_log.get_mut(fht.pcr_log_index as usize) else {
        return Err(CaliptraError::FMC_GLOBAL_PCR_LOG_EXHAUSTED);
    };

    // Create a PCR log entry
    *dst = PcrLogEntry {
        id: pcr_entry_id as u16,
        pcr_ids,
        ..Default::default()
    };
    dst.pcr_data.as_bytes_mut()[..data.len()].copy_from_slice(data);
    fht.pcr_log_index += 1;

    Ok(())
}
