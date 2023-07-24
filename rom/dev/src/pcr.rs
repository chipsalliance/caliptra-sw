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

use crate::verifier::RomImageVerificationEnv;
use caliptra_common::{
    memory_layout::{PCR_LOG_ORG, PCR_LOG_SIZE},
    PcrLogEntry, PcrLogEntryId,
};
use caliptra_drivers::{Array4x12, CaliptraError, CaliptraResult, PcrBank, PcrId, Sha384};
use caliptra_image_verify::ImageVerificationInfo;

use zerocopy::AsBytes;

struct PcrExtender<'a> {
    pcr_bank: &'a mut PcrBank,
    sha384: &'a mut Sha384,
}
impl PcrExtender<'_> {
    fn extend(&mut self, data: Array4x12, pcr_entry_id: PcrLogEntryId) -> CaliptraResult<()> {
        let bytes: &[u8; 48] = &data.into();
        self.pcr_bank
            .extend_pcr(PcrId::PcrId0, self.sha384, bytes)?;
        log_pcr(pcr_entry_id, PcrId::PcrId0, bytes)
    }
    fn extend_u8(&mut self, data: u8, pcr_entry_id: PcrLogEntryId) -> CaliptraResult<()> {
        let bytes = &data.to_le_bytes();
        self.pcr_bank
            .extend_pcr(PcrId::PcrId0, self.sha384, bytes)?;
        log_pcr(pcr_entry_id, PcrId::PcrId0, bytes)
    }
}

/// Extend PCR0
///
/// # Arguments
///
/// * `env` - ROM Environment
pub(crate) fn extend_pcr0(
    env: &mut RomImageVerificationEnv,
    info: &ImageVerificationInfo,
) -> CaliptraResult<()> {
    // Clear the PCR
    env.pcr_bank.erase_pcr(caliptra_drivers::PcrId::PcrId0)?;

    let mut pcr = PcrExtender {
        pcr_bank: env.pcr_bank,
        sha384: env.sha384,
    };

    pcr.extend_u8(
        env.soc_ifc.lifecycle() as u8,
        PcrLogEntryId::DeviceLifecycle,
    )?;
    pcr.extend_u8(env.soc_ifc.debug_locked() as u8, PcrLogEntryId::DebugLocked)?;
    pcr.extend_u8(
        env.soc_ifc.fuse_bank().anti_rollback_disable() as u8,
        PcrLogEntryId::AntiRollbackDisabled,
    )?;
    pcr.extend(
        env.soc_ifc.fuse_bank().vendor_pub_key_hash(),
        PcrLogEntryId::VendorPubKeyHash,
    )?;
    pcr.extend(
        env.data_vault.owner_pk_hash(),
        PcrLogEntryId::OwnerPubKeyHash,
    )?;
    pcr.extend_u8(
        env.data_vault.vendor_pk_index() as u8,
        PcrLogEntryId::VendorPubKeyIndex,
    )?;
    pcr.extend(env.data_vault.fmc_tci(), PcrLogEntryId::FmcTci)?;
    pcr.extend_u8(env.data_vault.fmc_svn() as u8, PcrLogEntryId::FmcSvn)?;
    pcr.extend_u8(info.fmc.effective_fuse_svn as u8, PcrLogEntryId::FmcFuseSvn)?;

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
        return Err(CaliptraError::ROM_GLOBAL_PCR_LOG_INVALID_ENTRY_ID);
    }

    if data.len() > 48 {
        return Err(CaliptraError::ROM_GLOBAL_PCR_LOG_UNSUPPORTED_DATA_LENGTH);
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
