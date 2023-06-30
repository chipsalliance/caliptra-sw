/*++

Licensed under the Apache-2.0 license.

File Name:

    fw_processor.rs

Abstract:

    File contains the code to download and validate the firmware.

--*/

use crate::fuse::log_fuse_data;
use crate::rom_env::RomEnv;
use crate::{cprintln, verifier::RomImageVerificationEnv};
use crate::{pcr, wdt};
use caliptra_common::{cprint, FuseLogEntryId, RomBootStatus::*};
use caliptra_drivers::*;
use caliptra_image_types::{ImageManifest, IMAGE_BYTE_SIZE};
use caliptra_image_verify::{ImageVerificationInfo, ImageVerificationLogInfo, ImageVerifier};
use caliptra_x509::{NotAfter, NotBefore};
use core::mem::ManuallyDrop;
use zerocopy::{AsBytes, FromBytes};

extern "C" {
    static mut MAN1_ORG: u32;
}

#[derive(Debug, Default)]
pub struct FwProcInfo {
    pub fmc_cert_valid_not_before: NotBefore,

    pub fmc_cert_valid_not_after: NotAfter,

    pub fmc_effective_fuse_svn: u32,
}

pub struct FirmwareProcessor {}

impl FirmwareProcessor {
    /// Download firmware mailbox command ID.
    const MBOX_DOWNLOAD_FIRMWARE_CMD_ID: u32 = 0x46574C44;

    pub fn process(env: &mut RomEnv) -> CaliptraResult<FwProcInfo> {
        // Disable the watchdog timer during firmware download.
        wdt::stop_wdt(&mut env.soc_ifc);

        // Download the image
        let mut txn = Self::download_image(&mut env.soc_ifc, &mut env.mbox)?;

        // Renable the watchdog timer.
        wdt::start_wdt(&mut env.soc_ifc);

        // Load the manifest
        let manifest = Self::load_manifest(&mut txn);
        let manifest = okref(&manifest)?;

        let mut venv = RomImageVerificationEnv {
            sha256: &mut env.sha256,
            sha384: &mut env.sha384,
            sha384_acc: &mut env.sha384_acc,
            soc_ifc: &mut env.soc_ifc,
            ecc384: &mut env.ecc384,
            data_vault: &mut env.data_vault,
            pcr_bank: &mut env.pcr_bank,
        };

        // Verify the image
        let info = Self::verify_image(&mut venv, manifest, txn.dlen());
        let info = okref(&info)?;

        Self::update_fuse_log(&info.log_info)?;

        // Populate data vault
        Self::populate_data_vault(venv.data_vault, info);

        // Extend PCR0
        pcr::extend_pcr0(&mut venv, info)?;
        report_boot_status(FwProcessorExtendPcrComplete.into());

        // Load the image
        Self::load_image(manifest, &mut txn)?;

        // Complete the mailbox transaction indicating success.
        txn.complete(true)?;
        report_boot_status(FwProcessorFirmwareDownloadTxComplete.into());

        // Get the certificate validity info
        let (nb, nf) = Self::get_cert_validity_info(manifest);

        report_boot_status(FwProcessorComplete.into());
        Ok(FwProcInfo {
            fmc_cert_valid_not_before: nb,
            fmc_cert_valid_not_after: nf,
            fmc_effective_fuse_svn: info.fmc.effective_fuse_svn,
        })
    }

    /// Download the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    ///
    /// # Returns
    ///
    /// Mailbox transaction handle. This transaction is ManuallyDrop because we
    /// don't want the transaction to be completed with failure until after
    /// report_error is called. This prevents a race condition where the SoC
    /// reads FW_ERROR_NON_FATAL immediately after the mailbox transaction
    /// fails, but before caliptra has set the FW_ERROR_NON_FATAL register.
    fn download_image<'a>(
        soc_ifc: &mut SocIfc,
        mbox: &'a mut Mailbox,
    ) -> CaliptraResult<ManuallyDrop<MailboxRecvTxn<'a>>> {
        soc_ifc.flow_status_set_ready_for_firmware();

        cprint!("[afmc] Waiting for Image ");
        loop {
            if let Some(txn) = mbox.peek_recv() {
                if txn.cmd() != Self::MBOX_DOWNLOAD_FIRMWARE_CMD_ID {
                    cprintln!("Invalid command 0x{:08x} received", txn.cmd());
                    txn.start_txn().complete(false)?;
                    continue;
                }

                // Re-borrow mailbox to work around https://github.com/rust-lang/rust/issues/54663
                let txn = mbox
                    .peek_recv()
                    .ok_or(CaliptraError::FW_PROC_MAILBOX_STATE_INCONSISTENT)?;

                // This is a download-firmware command; don't drop this, as the
                // transaction will be completed by either report_error() (on
                // failure) or by a manual complete call upon success.
                let txn = ManuallyDrop::new(txn.start_txn());
                if txn.dlen() == 0 || txn.dlen() > IMAGE_BYTE_SIZE as u32 {
                    cprintln!("Invalid Image of size {} bytes" txn.dlen());
                    return Err(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE);
                }

                cprintln!("");
                cprintln!("[afmc] Received Image of size {} bytes" txn.dlen());
                report_boot_status(FwProcessorDownloadImageComplete.into());
                return Ok(txn);
            }
        }
    }

    /// Load the manifest
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    fn load_manifest(txn: &mut MailboxRecvTxn) -> CaliptraResult<ImageManifest> {
        let slice = unsafe {
            let ptr = &mut MAN1_ORG as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        txn.copy_request(slice)?;

        if let Some(result) = ImageManifest::read_from(slice.as_bytes()) {
            report_boot_status(FwProcessorManifestLoadComplete.into());
            Ok(result)
        } else {
            Err(CaliptraError::FW_PROC_MANIFEST_READ_FAILURE)
        }
    }

    /// Verify the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    fn verify_image(
        venv: &mut RomImageVerificationEnv,
        manifest: &ImageManifest,
        img_bundle_sz: u32,
    ) -> CaliptraResult<ImageVerificationInfo> {
        let mut verifier = ImageVerifier::new(venv);
        let info = verifier.verify(manifest, img_bundle_sz, ResetReason::ColdReset)?;

        cprintln!(
            "[afmc] Image verified using Vendor ECC Key Index {}",
            info.vendor_ecc_pub_key_idx,
        );
        report_boot_status(FwProcessorImageVerificationComplete.into());
        Ok(info)
    }

    /// Update the fuse log
    ///
    /// # Arguments
    /// * `log_info` - Image Verification Log Info
    ///
    /// # Returns
    /// * CaliptraResult
    fn update_fuse_log(log_info: &ImageVerificationLogInfo) -> CaliptraResult<()> {
        // Log VendorPubKeyIndex
        log_fuse_data(
            FuseLogEntryId::VendorPubKeyIndex,
            log_info.vendor_ecc_pub_key_idx.as_bytes(),
        )?;

        // Log VendorPubKeyRevocation
        log_fuse_data(
            FuseLogEntryId::VendorPubKeyRevocation,
            log_info.fuse_vendor_pub_key_revocation.bits().as_bytes(),
        )?;

        // Log ManifestFmcSvn
        log_fuse_data(
            FuseLogEntryId::ManifestFmcSvn,
            log_info.fmc_log_info.manifest_svn.as_bytes(),
        )?;

        // Log ManifestFmcMinSvn
        log_fuse_data(
            FuseLogEntryId::ManifestFmcMinSvn,
            log_info.fmc_log_info.manifest_min_svn.as_bytes(),
        )?;

        // Log FuseFmcSvn
        log_fuse_data(
            FuseLogEntryId::FuseFmcSvn,
            log_info.fmc_log_info.fuse_svn.as_bytes(),
        )?;

        // Log ManifestRtSvn
        log_fuse_data(
            FuseLogEntryId::ManifestRtSvn,
            log_info.rt_log_info.manifest_svn.as_bytes(),
        )?;

        // Log ManifestRtMinSvn
        log_fuse_data(
            FuseLogEntryId::ManifestRtMinSvn,
            log_info.rt_log_info.manifest_min_svn.as_bytes(),
        )?;

        // Log FuseRtSvn
        log_fuse_data(
            FuseLogEntryId::FuseRtSvn,
            log_info.rt_log_info.fuse_svn.as_bytes(),
        )?;
        Ok(())
    }

    /// Load the image to ICCM & DCCM
    ///
    /// # Arguments
    ///
    /// * `env`      - ROM Environment
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    fn load_image(manifest: &ImageManifest, txn: &mut MailboxRecvTxn) -> CaliptraResult<()> {
        cprintln!(
            "[afmc] Loading FMC at address 0x{:08x} len {}",
            manifest.fmc.load_addr,
            manifest.fmc.size
        );

        let fmc_dest = unsafe {
            let addr = (manifest.fmc.load_addr) as *mut u32;
            core::slice::from_raw_parts_mut(addr, manifest.fmc.size as usize / 4)
        };

        txn.copy_request(fmc_dest)?;

        cprintln!(
            "[afmc] Loading Runtime at address 0x{:08x} len {}",
            manifest.runtime.load_addr,
            manifest.runtime.size
        );

        let runtime_dest = unsafe {
            let addr = (manifest.runtime.load_addr) as *mut u32;
            core::slice::from_raw_parts_mut(addr, manifest.runtime.size as usize / 4)
        };

        txn.copy_request(runtime_dest)?;

        report_boot_status(FwProcessorLoadImageComplete.into());
        Ok(())
    }

    /// Populate data vault
    ///
    /// # Arguments
    ///
    /// * `env`  - ROM Environment
    /// * `info` - Image Verification Info
    fn populate_data_vault(data_vault: &mut DataVault, info: &ImageVerificationInfo) {
        data_vault.write_cold_reset_entry48(ColdResetEntry48::FmcTci, &info.fmc.digest.into());

        data_vault.write_cold_reset_entry4(ColdResetEntry4::FmcSvn, info.fmc.svn);

        data_vault.write_cold_reset_entry4(ColdResetEntry4::FmcLoadAddr, info.fmc.load_addr);

        data_vault.write_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint, info.fmc.entry_point);

        data_vault.write_cold_reset_entry48(
            ColdResetEntry48::OwnerPubKeyHash,
            &info.owner_pub_keys_digest.into(),
        );

        data_vault.write_cold_reset_entry4(
            ColdResetEntry4::VendorPubKeyIndex,
            info.vendor_ecc_pub_key_idx,
        );

        data_vault.write_warm_reset_entry48(WarmResetEntry48::RtTci, &info.runtime.digest.into());

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtSvn, info.runtime.svn);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtLoadAddr, info.runtime.load_addr);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtEntryPoint, info.runtime.entry_point);

        // TODO: Need a better way to get the Manifest address
        let slice = unsafe {
            let ptr = &MAN1_ORG as *const u32;
            ptr as u32
        };

        data_vault.write_warm_reset_entry4(WarmResetEntry4::ManifestAddr, slice);
        report_boot_status(FwProcessorPopulateDataVaultComplete.into());
    }

    /// Process the certificate validity info
    ///
    /// # Arguments
    /// * `manifest` - Manifest
    ///
    /// # Returns
    /// * `NotBefore` - Valid Not Before Time
    /// * `NotAfter`  - Valid Not After Time
    ///
    fn get_cert_validity_info(manifest: &ImageManifest) -> (NotBefore, NotAfter) {
        // If there is a valid value in the manifest for the not_before and not_after times,
        // use those. Otherwise use the default values.
        let mut nb = NotBefore::default();
        let mut nf = NotAfter::default();
        let null_time = [0u8; 15];

        if manifest.header.vendor_data.vendor_not_after != null_time
            && manifest.header.vendor_data.vendor_not_before != null_time
        {
            nf.value = manifest.header.vendor_data.vendor_not_after;
            nb.value = manifest.header.vendor_data.vendor_not_before;
        }

        // Owner values take preference.
        if manifest.header.owner_data.owner_not_after != null_time
            && manifest.header.owner_data.owner_not_before != null_time
        {
            nf.value = manifest.header.owner_data.owner_not_after;
            nb.value = manifest.header.owner_data.owner_not_before;
        }

        (nb, nf)
    }
}
