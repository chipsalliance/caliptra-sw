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
use caliptra_drivers::{okref, CaliptraError, CaliptraResult, PcrBank, PcrId, Sha384};

use caliptra_common::{
    memory_layout::{PCR_LOG_ORG, PCR_LOG_SIZE},
    PcrLogEntry, PcrLogEntryId, RT_FW_CURRENT_PCR, RT_FW_JOURNEY_PCR,
};
use zerocopy::AsBytes;

struct PcrExtender<'a> {
    pcr_bank: &'a mut PcrBank,
    sha384: &'a mut Sha384,
}
impl PcrExtender<'_> {
    fn extend(
        &mut self,
        pcr_id: PcrId,
        bytes: &[u8],
        pcr_entry_id: PcrLogEntryId,
    ) -> CaliptraResult<()> {
        self.pcr_bank
            .extend_pcr(PcrId::PcrId0, self.sha384, bytes)?;
        log_pcr(pcr_entry_id, pcr_id, bytes)
    }
}

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
    let manifest_digest = Tci::image_manifest_digest(env, hand_off);
    let manifest_digest: [u8; 48] = okref(&manifest_digest)?.into();

    // Extend RT TCI (Hash over runtime code)
    let rt_tci = Tci::rt_tci(env, hand_off);
    let rt_tci_bytes: [u8; 48] = okref(&rt_tci)?.into();

    let mut extender = PcrExtender {
        pcr_bank: &mut env.pcr_bank,
        sha384: &mut env.sha384,
    };

    extender.extend(pcr_id, &rt_tci_bytes, PcrLogEntryId::RtTci)?;

    // Extend FW Image Manifest
    extender.extend(pcr_id, &manifest_digest, PcrLogEntryId::ManifestDigest)?;

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
        return Err(CaliptraError::FMC_PCR_LOG_INVALID_ENTRY_ID);
    }

    if data.len() > 48 {
        return Err(CaliptraError::FMC_PCR_LOG_UNSUPPORTED_DATA_LENGTH);
    }

    // Create a PCR log entry
    let mut pcr_log_entry = PcrLogEntry {
        id: pcr_entry_id as u16,
        pcr_id: pcr_id as u16,
        ..Default::default()
    };
    pcr_log_entry.pcr_data.as_bytes_mut()[..data.len()].copy_from_slice(data);

    let dst: &mut [PcrLogEntry] = unsafe {
        let ptr = PCR_LOG_ORG as *mut PcrLogEntry;
        core::slice::from_raw_parts_mut(ptr, PCR_LOG_SIZE / core::mem::size_of::<PcrLogEntry>())
    };

    // Store the log entry.
    dst[pcr_entry_id as usize - 1] = pcr_log_entry;

    Ok(())
}
