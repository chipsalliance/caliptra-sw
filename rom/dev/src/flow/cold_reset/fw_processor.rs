/*++

Licensed under the Apache-2.0 license.

File Name:

    fw_processor.rs

Abstract:

    File contains the code to download and validate the firmware.

--*/
#[cfg(feature = "fake-rom")]
use crate::flow::fake::FakeRomImageVerificationEnv;
use crate::fuse::log_fuse_data;
use crate::rom_env::RomEnv;
use crate::{cprintln, verifier::RomImageVerificationEnv};
use crate::{pcr, wdt};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_eq, cfi_launder};
use caliptra_common::capabilities::Capabilities;
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::{cprint, memory_layout::MAN1_ORG, FuseLogEntryId, RomBootStatus::*};
use caliptra_drivers::*;
use caliptra_image_types::{ImageManifest, IMAGE_BYTE_SIZE};
use caliptra_image_verify::{ImageVerificationInfo, ImageVerificationLogInfo, ImageVerifier};
use caliptra_x509::{NotAfter, NotBefore};
use core::mem::ManuallyDrop;
use zerocopy::{AsBytes, FromBytes};

#[derive(Debug, Default)]
pub struct FwProcInfo {
    pub fmc_cert_valid_not_before: NotBefore,

    pub fmc_cert_valid_not_after: NotAfter,

    pub fmc_effective_fuse_svn: u32,
}

impl FwProcInfo {
    pub fn zeroize(&mut self) {
        self.fmc_cert_valid_not_before.value.fill(0);
        self.fmc_cert_valid_not_after.value.fill(0);
        self.fmc_effective_fuse_svn = 0;
    }
}

pub struct FirmwareProcessor {}

impl FirmwareProcessor {
    pub fn process(env: &mut RomEnv) -> CaliptraResult<FwProcInfo> {
        // Disable the watchdog timer during processing mailbox commands.
        wdt::stop_wdt(&mut env.soc_ifc);

        // Process mailbox commands.
        let mut txn = Self::process_mailbox_commands(&mut env.soc_ifc, &mut env.mbox)?;

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

        // Extend PCR0 and PCR1
        pcr::extend_pcrs(&mut venv, info)?;
        report_boot_status(FwProcessorExtendPcrComplete.into());

        // Load the image
        Self::load_image(manifest, &mut txn)?;

        // Complete the mailbox transaction indicating success.
        txn.complete(true)?;
        report_boot_status(FwProcessorFirmwareDownloadTxComplete.into());

        // Update FW version registers
        env.soc_ifc.set_fmc_fw_rev_id(manifest.fmc.version);
        env.soc_ifc.set_rt_fw_rev_id(manifest.runtime.version);

        // Get the certificate validity info
        let (nb, nf) = Self::get_cert_validity_info(manifest);

        report_boot_status(FwProcessorComplete.into());
        Ok(FwProcInfo {
            fmc_cert_valid_not_before: nb,
            fmc_cert_valid_not_after: nf,
            fmc_effective_fuse_svn: info.fmc.effective_fuse_svn,
        })
    }

    /// Process mailbox commands
    ///
    /// # Arguments
    ///
    /// * `soc_ifc` - SOC Interface
    /// * `mbox` - Mailbox
    ///
    /// # Returns
    ///
    /// Mailbox transaction handle (returned only for the FIRMWARE_LOAD command).
    /// This transaction is ManuallyDrop because we don't want the transaction
    /// to be completed with failure until after handle_fatal_error is called.
    /// This prevents a race condition where the SoC reads FW_ERROR_NON_FATAL
    /// immediately after the mailbox transaction fails,
    ///  but before caliptra has set the FW_ERROR_NON_FATAL register.
    fn process_mailbox_commands<'a>(
        soc_ifc: &mut SocIfc,
        mbox: &'a mut Mailbox,
    ) -> CaliptraResult<ManuallyDrop<MailboxRecvTxn<'a>>> {
        soc_ifc.flow_status_set_ready_for_firmware();

        cprint!("[afmc] Waiting for Commands...");
        loop {
            if let Some(txn) = mbox.peek_recv() {
                report_fw_error_non_fatal(0);
                match CommandId::from(txn.cmd()) {
                    CommandId::SELF_TEST | CommandId::VERSION | CommandId::SHUTDOWN => {
                        // [TODO] Placeholder for FIPS ROM commands.
                        txn.start_txn().complete(false)?;
                        continue;
                    }
                    CommandId::CAPABILITIES => {
                        let mut capabilities = Capabilities::default();
                        capabilities |= Capabilities::ROM_BASE;

                        txn.start_txn().send_response(&capabilities.to_bytes())?;
                        continue;
                    }
                    CommandId::FIRMWARE_LOAD => {
                        // Re-borrow mailbox to work around https://github.com/rust-lang/rust/issues/54663
                        let txn = mbox
                            .peek_recv()
                            .ok_or(CaliptraError::FW_PROC_MAILBOX_STATE_INCONSISTENT)?;

                        // This is a download-firmware command; don't drop this, as the
                        // transaction will be completed by either handle_fatal_error() (on
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
                    _ => {
                        cprintln!("Invalid command 0x{:08x} received", txn.cmd());
                        txn.start_txn().complete(false)?;
                        return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND);
                    }
                }
            }
        }
    }

    /// Load the manifest
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest(txn: &mut MailboxRecvTxn) -> CaliptraResult<ImageManifest> {
        let slice = unsafe {
            let ptr = MAN1_ORG as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        txn.copy_request(slice)?;

        let opt = ImageManifest::read_from(slice.as_bytes());
        let result = opt.is_some();
        if cfi_launder(result) {
            cfi_assert!(opt.is_some());
            report_boot_status(FwProcessorManifestLoadComplete.into());
            Ok(opt.unwrap())
        } else {
            cfi_assert!(opt.is_none());
            Err(CaliptraError::FW_PROC_MANIFEST_READ_FAILURE)
        }
    }

    /// Verify the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn verify_image(
        venv: &mut RomImageVerificationEnv,
        manifest: &ImageManifest,
        img_bundle_sz: u32,
    ) -> CaliptraResult<ImageVerificationInfo> {
        #[cfg(feature = "fake-rom")]
        let venv = &mut FakeRomImageVerificationEnv {
            sha384_acc: venv.sha384_acc,
            soc_ifc: venv.soc_ifc,
            data_vault: venv.data_vault,
        };

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
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn update_fuse_log(log_info: &ImageVerificationLogInfo) -> CaliptraResult<()> {
        // Log VendorPubKeyIndex
        log_fuse_data(
            FuseLogEntryId::VendorEccPubKeyIndex,
            log_info.vendor_ecc_pub_key_idx.as_bytes(),
        )?;

        // Log VendorPubKeyRevocation
        log_fuse_data(
            FuseLogEntryId::VendorEccPubKeyRevocation,
            log_info
                .fuse_vendor_ecc_pub_key_revocation
                .bits()
                .as_bytes(),
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

        // Log VendorLmsPubKeyIndex
        if let Some(vendor_lms_pub_key_idx) = log_info.vendor_lms_pub_key_idx {
            log_fuse_data(
                FuseLogEntryId::VendorLmsPubKeyIndex,
                vendor_lms_pub_key_idx.as_bytes(),
            )?;
        }

        // Log VendorLmsPubKeyRevocation
        if let Some(fuse_vendor_lms_pub_key_revocation) =
            log_info.fuse_vendor_lms_pub_key_revocation
        {
            log_fuse_data(
                FuseLogEntryId::VendorLmsPubKeyRevocation,
                fuse_vendor_lms_pub_key_revocation.as_bytes(),
            )?;
        }

        Ok(())
    }

    /// Load the image to ICCM & DCCM
    ///
    /// # Arguments
    ///
    /// * `env`      - ROM Environment
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    // Inlined to reduce ROM size
    #[inline(always)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
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
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn populate_data_vault(data_vault: &mut DataVault, info: &ImageVerificationInfo) {
        data_vault.write_cold_reset_entry48(ColdResetEntry48::FmcTci, &info.fmc.digest.into());

        data_vault.write_cold_reset_entry4(ColdResetEntry4::FmcSvn, info.fmc.svn);

        data_vault.write_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint, info.fmc.entry_point);

        data_vault.write_cold_reset_entry48(
            ColdResetEntry48::OwnerPubKeyHash,
            &info.owner_pub_keys_digest.into(),
        );

        data_vault.write_cold_reset_entry4(
            ColdResetEntry4::EccVendorPubKeyIndex,
            info.vendor_ecc_pub_key_idx,
        );

        // If LMS is not enabled, write the max value to the data vault
        // to indicate the index is invalid.
        data_vault.write_cold_reset_entry4(
            ColdResetEntry4::LmsVendorPubKeyIndex,
            info.vendor_lms_pub_key_idx.unwrap_or(u32::MAX),
        );

        data_vault.write_warm_reset_entry48(WarmResetEntry48::RtTci, &info.runtime.digest.into());

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtSvn, info.runtime.svn);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtEntryPoint, info.runtime.entry_point);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::ManifestAddr, MAN1_ORG);
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
