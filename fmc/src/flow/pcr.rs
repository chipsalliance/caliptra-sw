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
    cprintln, okref,
    pcr_log::{PcrLogEntry, PcrLogEntryId},
    CaliptraResult, PcrBank, PcrLogArray,
};

use caliptra_common::{RT_FW_CURRENT_PCR, RT_FW_JOURNEY_PCR};
use caliptra_error::CaliptraError;
use zerocopy::AsBytes;

/// Extend common data into the current and journey PCRs
///
/// # Arguments
///
/// * `env` - FMC Environment
/// * `pcr_id` - PCR slot to extend the data into
/// * `extend_journey` - Whether to extend into the journey PCR
///
/// TODO: Add CFI instrumentation
pub fn extend_pcr_common(
    env: &mut FmcEnv,
    hand_off: &mut HandOff,
    extend_journey: bool,
) -> CaliptraResult<()> {
    // Clear current PCR before extending it.
    if env.soc_ifc.reset_reason() == caliptra_drivers::ResetReason::UpdateReset {
        env.pcr_bank.erase_pcr(RT_FW_CURRENT_PCR)?;
    }

    // Calculate RT TCI (Hash over runtime code)
    let rt_tci = Tci::rt_tci(env, hand_off);
    let rt_tci: [u8; 48] = okref(&rt_tci)?.into();

    // Calculate FW Image Manifest digest
    let manifest_digest = Tci::image_manifest_digest(env, hand_off);
    let manifest_digest: [u8; 48] = okref(&manifest_digest)?.into();

    let mut pcr_ids: u32 = 1 << RT_FW_CURRENT_PCR as u8;

    env.pcr_bank
        .extend_pcr(RT_FW_CURRENT_PCR, &mut env.sha384, &rt_tci)?;
    env.pcr_bank
        .extend_pcr(RT_FW_CURRENT_PCR, &mut env.sha384, &manifest_digest)?;

    if extend_journey {
        pcr_ids |= 1 << RT_FW_JOURNEY_PCR as u8;
        env.pcr_bank
            .extend_pcr(RT_FW_JOURNEY_PCR, &mut env.sha384, &rt_tci)?;
        env.pcr_bank
            .extend_pcr(RT_FW_JOURNEY_PCR, &mut env.sha384, &manifest_digest)?;
    }

    log_pcr(
        &mut env.persistent_data.get_mut().pcr_log,
        &mut env.pcr_bank,
        PcrLogEntryId::RtTci,
        pcr_ids,
        &rt_tci,
    )?;

    log_pcr(
        &mut env.persistent_data.get_mut().pcr_log,
        &mut env.pcr_bank,
        PcrLogEntryId::FwImageManifest,
        pcr_ids,
        &manifest_digest,
    )?;

    Ok(())
}

// TODO: Add CFI instrumentation
fn log_pcr(
    pcr_log: &mut PcrLogArray,
    pcr_bank: &mut PcrBank,
    pcr_entry_id: PcrLogEntryId,
    pcr_ids: u32,
    data: &[u8],
) -> CaliptraResult<()> {
    let Some(dst) = pcr_log.get_mut(pcr_bank.log_index) else {
        return Err(CaliptraError::FMC_GLOBAL_PCR_LOG_EXHAUSTED);
    };

    // Create a PCR log entry
    cprintln!("pcr_entry_id: {:?}", pcr_entry_id as u16);
    cprintln!("FMC log_index: {:?}", pcr_bank.log_index as u16);
    let mut pcr_log_entry = PcrLogEntry {
        id: pcr_entry_id as u16,
        pcr_ids,
        ..Default::default()
    };
    pcr_log_entry.pcr_data.as_bytes_mut()[..data.len()].copy_from_slice(data);

    // TODO: Increment FHT log index on each call. Can't do that yet because
    // ROM does not touch the FHT's log index on update reset, which throws
    // off the count.
    pcr_bank.log_index += 1;

    *dst = pcr_log_entry;

    Ok(())
}
