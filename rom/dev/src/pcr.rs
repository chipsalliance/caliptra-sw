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

#[cfg(feature = "cfi")]
use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_common::{
    pcr::{PCR_ID_FMC_CURRENT, PCR_ID_FMC_JOURNEY},
    PcrLogEntry, PcrLogEntryId,
};
use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, PcrBank, PersistentData, Sha2_512_384, SocIfc,
};
use zerocopy::IntoBytes;

struct PcrExtender<'a> {
    persistent_data: &'a mut PersistentData,
    pcr_bank: &'a mut PcrBank,
    sha2_512_384: &'a mut Sha2_512_384,
}
impl PcrExtender<'_> {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn extend(&mut self, data: &[u8], pcr_entry_id: PcrLogEntryId) -> CaliptraResult<()> {
        self.pcr_bank
            .extend_pcr(PCR_ID_FMC_CURRENT, self.sha2_512_384, data)?;
        self.pcr_bank
            .extend_pcr(PCR_ID_FMC_JOURNEY, self.sha2_512_384, data)?;

        let pcr_ids: u32 = (1 << PCR_ID_FMC_CURRENT as u8) | (1 << PCR_ID_FMC_JOURNEY as u8);
        log_pcr(self.persistent_data, pcr_entry_id, pcr_ids, data)
    }
}

/// Extend PCR0 and PCR1
///
/// # Arguments
///
/// * `persistent_data` - Persistent data
/// * `soc_ifc` - SOC Interface
/// * `pcr_bank` - PCR Bank
/// * `sha2_512_384` - SHA-512/384 Accelerator
/// * `info` - Image Verification Info
///
/// # Return Value
/// * `Ok(())` on success, error code on failure
///
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
#[inline(never)]
pub(crate) fn extend_pcrs(
    persistent_data: &mut PersistentData,
    soc_ifc: &SocIfc,
    pcr_bank: &mut PcrBank,
    sha2_512_384: &mut Sha2_512_384,
) -> CaliptraResult<()> {
    let data_vault = &persistent_data.rom.data_vault;
    let owner_pk_hash = <[u8; 48]>::from(&data_vault.owner_pk_hash());
    let fmc_tci = <[u8; 48]>::from(&data_vault.fmc_tci());

    // Reset the PCR log size to zero.
    persistent_data.rom.fht.pcr_log_index = 0;

    // Clear the Current PCR, but do not clear the Journey PCR
    pcr_bank.erase_pcr(PCR_ID_FMC_CURRENT)?;

    let lms_revocation_bytes = soc_ifc
        .fuse_bank()
        .vendor_lms_pub_key_revocation()
        .to_le_bytes();
    let owner_pub_keys_digest_in_fuses: bool =
        soc_ifc.fuse_bank().owner_pub_key_hash() != Array4x12::default();

    // NOTE: The contents of this PCR and the FMC Alias TCB info must stay in sync.
    //       Ordering and grouping is irrelevant but both must contain the same info
    let device_status: [u8; 17] = [
        owner_pub_keys_digest_in_fuses as u8,
        soc_ifc.fuse_bank().anti_rollback_disable() as u8,
        soc_ifc.fuse_bank().vendor_ecc_pub_key_revocation().bits() as u8,
        lms_revocation_bytes[0],
        lms_revocation_bytes[1],
        lms_revocation_bytes[2],
        lms_revocation_bytes[3],
        soc_ifc.fuse_bank().vendor_mldsa_pub_key_revocation() as u8,
        soc_ifc.fuse_bank().fw_fuse_svn() as u8,
        soc_ifc.fuse_bank().soc_manifest_fuse_svn() as u8,
        soc_ifc.fuse_bank().max_soc_manifest_fuse_svn() as u8,
        soc_ifc.fuse_bank().pqc_key_type() as u8,
        soc_ifc.lifecycle() as u8,
        soc_ifc.debug_locked() as u8,
        data_vault.cold_boot_fw_svn() as u8,
        data_vault.vendor_ecc_pk_index() as u8,
        data_vault.vendor_pqc_pk_index() as u8,
    ];

    let mut pcr = PcrExtender {
        persistent_data,
        pcr_bank,
        sha2_512_384,
    };

    pcr.extend(&device_status, PcrLogEntryId::DeviceStatus)?;

    pcr.extend(
        &<[u8; 48]>::from(&soc_ifc.fuse_bank().vendor_pub_key_info_hash()),
        PcrLogEntryId::VendorPubKeyInfoHash,
    )?;
    pcr.extend(&owner_pk_hash, PcrLogEntryId::OwnerPubKeyHash)?;
    pcr.extend(&fmc_tci, PcrLogEntryId::FmcTci)?;

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
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub fn log_pcr(
    persistent_data: &mut PersistentData,
    pcr_entry_id: PcrLogEntryId,
    pcr_ids: u32,
    data: &[u8],
) -> CaliptraResult<()> {
    if pcr_entry_id == PcrLogEntryId::Invalid {
        return Err(CaliptraError::ROM_GLOBAL_PCR_LOG_INVALID_ENTRY_ID);
    }

    let pcr_log = &mut persistent_data.rom.pcr_log;
    let fht = &mut persistent_data.rom.fht;

    let Some(dst) = pcr_log.get_mut(fht.pcr_log_index as usize) else {
        return Err(CaliptraError::ROM_GLOBAL_PCR_LOG_EXHAUSTED);
    };

    // Create a PCR log entry
    let mut pcr_log_entry = PcrLogEntry {
        id: pcr_entry_id as u16,
        pcr_ids,
        ..Default::default()
    };
    let Some(dest_data) = pcr_log_entry.pcr_data.as_mut_bytes().get_mut(..data.len()) else {
        return Err(CaliptraError::ROM_GLOBAL_PCR_LOG_UNSUPPORTED_DATA_LENGTH);
    };
    dest_data.copy_from_slice(data);

    fht.pcr_log_index += 1;
    *dst = pcr_log_entry;

    Ok(())
}
