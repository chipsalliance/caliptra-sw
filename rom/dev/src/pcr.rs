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

use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_common::verifier::FirmwareImageVerificationEnv;
use caliptra_common::{
    pcr::{PCR_ID_FMC_CURRENT, PCR_ID_FMC_JOURNEY},
    PcrLogEntry, PcrLogEntryId,
};
use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, PcrBank, PcrLogArray, PersistentDataAccessor, Sha384,
};
use caliptra_image_verify::ImageVerificationInfo;

use zerocopy::AsBytes;

struct PcrExtender<'a> {
    pcr_log: &'a mut PcrLogArray,
    pcr_bank: &'a mut PcrBank,
    sha384: &'a mut Sha384,
}
impl PcrExtender<'_> {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn extend(&mut self, data: Array4x12, pcr_entry_id: PcrLogEntryId) -> CaliptraResult<()> {
        let bytes: &[u8; 48] = &data.into();
        self.extend_and_log(bytes, pcr_entry_id)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn extend_u8(&mut self, data: u8, pcr_entry_id: PcrLogEntryId) -> CaliptraResult<()> {
        let bytes = &data.to_le_bytes();
        self.extend_and_log(bytes, pcr_entry_id)
    }
    fn extend_and_log(&mut self, data: &[u8], pcr_entry_id: PcrLogEntryId) -> CaliptraResult<()> {
        self.pcr_bank
            .extend_pcr(PCR_ID_FMC_CURRENT, self.sha384, data)?;
        self.pcr_bank
            .extend_pcr(PCR_ID_FMC_JOURNEY, self.sha384, data)?;

        let pcr_ids: u32 = (1 << PCR_ID_FMC_CURRENT as u8) | (1 << PCR_ID_FMC_JOURNEY as u8);
        log_pcr(self.pcr_log, self.pcr_bank, pcr_entry_id, pcr_ids, data)
    }
}

/// Extend PCR0 and PCR1
///
/// # Arguments
///
/// * `env` - ROM Environment
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub(crate) fn extend_pcrs(
    env: &mut FirmwareImageVerificationEnv,
    info: &ImageVerificationInfo,
    persistent_data: &mut PersistentDataAccessor,
) -> CaliptraResult<()> {
    // Clear the Current PCR, but do not clear the Journey PCR
    env.pcr_bank.erase_pcr(PCR_ID_FMC_CURRENT)?;

    let mut pcr = PcrExtender {
        pcr_log: &mut persistent_data.get_mut().pcr_log,
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
        env.data_vault.ecc_vendor_pk_index() as u8,
        PcrLogEntryId::EccVendorPubKeyIndex,
    )?;
    pcr.extend(env.data_vault.fmc_tci(), PcrLogEntryId::FmcTci)?;
    pcr.extend_u8(env.data_vault.fmc_svn() as u8, PcrLogEntryId::FmcSvn)?;
    pcr.extend_u8(info.fmc.effective_fuse_svn as u8, PcrLogEntryId::FmcFuseSvn)?;
    pcr.extend_u8(
        env.data_vault.lms_vendor_pk_index() as u8,
        PcrLogEntryId::LmsVendorPubKeyIndex,
    )?;
    pcr.extend_u8(
        env.soc_ifc.fuse_bank().lms_verify() as u8,
        PcrLogEntryId::RomVerifyConfig,
    )?;

    Ok(())
}

/// Log PCR data
///
/// # Arguments
/// * `pcr_bank` - PCR bank
/// * `pcr_entry_id` - PCR log entry ID
/// * `pcr_ids` - bitmask of PCR indices
/// * `data` - PCR data
///
/// # Return Value
/// * `Ok(())` - Success
/// * `Err(GlobalErr::PcrLogInvalidEntryId)` - Invalid PCR log entry ID
/// * `Err(GlobalErr::PcrLogUpsupportedDataLength)` - Unsupported data length
///
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn log_pcr(
    pcr_log: &mut PcrLogArray,
    pcr_bank: &mut PcrBank,
    pcr_entry_id: PcrLogEntryId,
    pcr_ids: u32,
    data: &[u8],
) -> CaliptraResult<()> {
    if pcr_entry_id == PcrLogEntryId::Invalid {
        return Err(CaliptraError::ROM_GLOBAL_PCR_LOG_INVALID_ENTRY_ID);
    }

    let Some(dst) = pcr_log.get_mut(pcr_bank.log_index) else {
        return Err(CaliptraError::ROM_GLOBAL_PCR_LOG_EXHAUSTED);
    };

    // Create a PCR log entry
    let mut pcr_log_entry = PcrLogEntry {
        id: pcr_entry_id as u16,
        pcr_ids,
        ..Default::default()
    };
    let Some(dest_data) = pcr_log_entry.pcr_data.as_bytes_mut().get_mut(..data.len()) else {
        return Err(CaliptraError::ROM_GLOBAL_PCR_LOG_UNSUPPORTED_DATA_LENGTH);
    };
    dest_data.copy_from_slice(data);

    pcr_bank.log_index += 1;
    *dst = pcr_log_entry;

    Ok(())
}
