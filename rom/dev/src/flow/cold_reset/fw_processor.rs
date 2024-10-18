/*++

Licensed under the Apache-2.0 license.

File Name:

    fw_processor.rs

Abstract:

    File contains the code to download and validate the firmware.

--*/
#![allow(dead_code)]

#[cfg(feature = "fake-rom")]
use crate::flow::fake::FakeRomImageVerificationEnv;
use crate::fuse::log_fuse_data;
use crate::pcr;
use crate::rom_env::RomEnv;
use crate::run_fips_tests;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::CfiCounter;
use caliptra_common::capabilities::Capabilities;
use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::{
    CapabilitiesResp, CommandId, MailboxReqHeader, MailboxRespHeader, Response,
    StashMeasurementReq, StashMeasurementResp,
};
use caliptra_common::pcr::PCR_ID_STASH_MEASUREMENT;
use caliptra_common::verifier::FirmwareImageVerificationEnv;
use caliptra_common::PcrLogEntry;
use caliptra_common::PcrLogEntryId;
use caliptra_common::{FuseLogEntryId, RomBootStatus::*};
use caliptra_drivers::pcr_log::MeasurementLogEntry;
use caliptra_drivers::*;
use caliptra_image_types::{ImageManifest, IMAGE_BYTE_SIZE};
use caliptra_image_verify::{ImageVerificationInfo, ImageVerificationLogInfo, ImageVerifier};
use caliptra_kat::KatsEnv;
use caliptra_x509::{NotAfter, NotBefore};
use core::mem::ManuallyDrop;
use zerocopy::{AsBytes, LayoutVerified};
use zeroize::Zeroize;

const ACTIVE_MODE: bool = true;
const PAYLOAD_AVAILABLE: bool = true;
const RECOVERY_INTERFACE_ADDRESS: u32 = 0x0;
const PROT_CAP_OFFSET: u32 = 0x0;
const PROT_CAP_AGENT_BYTE_10_OFFSET: u32 = PROT_CAP_OFFSET + 10;
const PROT_CAP_AGENT_BYTE_11_OFFSET: u32 = PROT_CAP_OFFSET + 11;
const DEVICE_ID_OFFSET: u32 = PROT_CAP_OFFSET + 0x10;
const DEVICE_STATUS_OFFSET: u32 = PROT_CAP_OFFSET + 0x28;
const DEVICE_RESET_OFFSET: u32 = PROT_CAP_OFFSET + 0x30;
const RECOVERY_CTRL_OFFSET: u32 = PROT_CAP_OFFSET + 0x34;
const RECOVERY_STATUS_OFFSET: u32 = PROT_CAP_OFFSET + 0x38;
const HW_STATUS_OFFSET: u32 = PROT_CAP_OFFSET + 0x3C;
const INDIRECT_FIFO_CTRL_OFFSET: u32 = PROT_CAP_OFFSET + 0x40;
const INDIRECT_FIFO_STATUS_OFFSET: u32 = PROT_CAP_OFFSET + 0x48;
const INDIRECT_FIFO_DATA_OFFSET: u32 = PROT_CAP_OFFSET + 0x6C;

#[derive(Debug, Default, Zeroize)]
pub struct FwProcInfo {
    pub fmc_cert_valid_not_before: NotBefore,

    pub fmc_cert_valid_not_after: NotAfter,

    pub fmc_effective_fuse_svn: u32,

    pub owner_pub_keys_digest_in_fuses: bool,
}

pub struct FirmwareProcessor {}

impl FirmwareProcessor {
    pub fn process(env: &mut RomEnv) -> CaliptraResult<FwProcInfo> {
        let mut kats_env = caliptra_kat::KatsEnv {
            // SHA1 Engine
            sha1: &mut env.sha1,

            // sha256
            sha256: &mut env.sha256,

            // SHA2-384 Engine
            sha384: &mut env.sha384,

            // SHA2-512/384 Accelerator
            sha2_512_384_acc: &mut env.sha2_512_384_acc,

            // Hmac384 Engine
            hmac384: &mut env.hmac384,

            /// Cryptographically Secure Random Number Generator
            trng: &mut env.trng,

            // LMS Engine
            lms: &mut env.lms,

            /// Ecc384 Engine
            ecc384: &mut env.ecc384,

            /// SHA Acc lock state
            sha_acc_lock_state: ShaAccLockState::NotAcquired,
        };
        // Process mailbox commands.
        let (mut txn, image_size_bytes) = Self::process_mailbox_commands(
            &mut env.soc_ifc,
            &mut env.mbox,
            &mut env.pcr_bank,
            &mut env.dma,
            &mut kats_env,
            env.persistent_data.get_mut(),
        )?;

        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            caliptra_drivers::FipsTestHook::halt_if_hook_set(
                caliptra_drivers::FipsTestHook::HALT_FW_LOAD,
            )
        };

        // Load the manifest
        let manifest = Self::load_manifest(&mut env.persistent_data, &mut txn);
        let manifest = okref(&manifest)?;

        let mut venv = FirmwareImageVerificationEnv {
            sha256: &mut env.sha256,
            sha384: &mut env.sha384,
            soc_ifc: &mut env.soc_ifc,
            ecc384: &mut env.ecc384,
            data_vault: &mut env.data_vault,
            pcr_bank: &mut env.pcr_bank,
            image: txn.raw_mailbox_contents(),
        };

        // Verify the image
        let info = Self::verify_image(&mut venv, manifest, image_size_bytes);
        let info = okref(&info)?;

        Self::update_fuse_log(&mut env.persistent_data.get_mut().fuse_log, &info.log_info)?;

        // Populate data vault
        Self::populate_data_vault(venv.data_vault, info, &env.persistent_data);

        // Extend PCR0 and PCR1
        pcr::extend_pcrs(&mut venv, info, &mut env.persistent_data)?;
        report_boot_status(FwProcessorExtendPcrComplete.into());

        // Load the image
        Self::load_image(manifest, &mut txn)?;

        // Complete the mailbox transaction indicating success.
        txn.complete(true)?;
        report_boot_status(FwProcessorFirmwareDownloadTxComplete.into());

        // Update FW version registers
        // Truncate FMC version to 16 bits (no error for 31:16 != 0)
        env.soc_ifc.set_fmc_fw_rev_id(manifest.fmc.version as u16);
        env.soc_ifc.set_rt_fw_rev_id(manifest.runtime.version);

        // Get the certificate validity info
        let (nb, nf) = Self::get_cert_validity_info(manifest);

        report_boot_status(FwProcessorComplete.into());
        Ok(FwProcInfo {
            fmc_cert_valid_not_before: nb,
            fmc_cert_valid_not_after: nf,
            fmc_effective_fuse_svn: info.fmc.effective_fuse_svn,
            owner_pub_keys_digest_in_fuses: info.owner_pub_keys_digest_in_fuses,
        })
    }

    /// Process mailbox commands
    ///
    /// # Arguments
    ///
    /// * `soc_ifc` - SOC Interface
    /// * `mbox` - Mailbox
    /// * `pcr_bank` - PCR Bank
    /// * `sha384` - SHA384
    /// * `persistent_data` - Persistent data
    ///
    /// # Returns
    /// * `MailboxRecvTxn` - Mailbox Receive Transaction
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
        pcr_bank: &mut PcrBank,
        dma: &mut Dma,
        env: &mut KatsEnv,
        persistent_data: &mut PersistentData,
    ) -> CaliptraResult<(ManuallyDrop<MailboxRecvTxn<'a>>, u32)> {
        let mut self_test_in_progress = false;

        cprintln!("[fwproc] Waiting for Commands...");
        loop {
            // Random delay for CFI glitch protection.
            CfiCounter::delay();

            if let Some(txn) = mbox.peek_recv() {
                report_fw_error_non_fatal(0);
                cprintln!("[fwproc] Received command 0x{:08x}", txn.cmd());

                // Handle FW load as a separate case due to the re-borrow explained below
                if txn.cmd() == CommandId::FIRMWARE_LOAD.into() {
                    if ACTIVE_MODE {
                        return Err(CaliptraError::FW_PROC_MAILBOX_FW_LOAD_CMD_IN_ACTIVE_MODE);
                    }
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

                    let image_size_bytes = txn.dlen();
                    cprintln!("[fwproc] Received Image of size {} bytes", image_size_bytes);
                    report_boot_status(FwProcessorDownloadImageComplete.into());
                    return Ok((txn, image_size_bytes));
                }

                // NOTE: We use ManuallyDrop here because any error here becomes a fatal error
                //       See note above about race condition
                let mut txn = ManuallyDrop::new(txn.start_txn());
                match CommandId::from(txn.cmd()) {
                    CommandId::VERSION => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_bytes_mut())?;

                        let mut resp = FipsVersionCmd::execute(soc_ifc)?;
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;
                    }
                    CommandId::SELF_TEST_START => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_bytes_mut())?;

                        if self_test_in_progress {
                            // TODO: set non-fatal error register?
                            txn.complete(false)?;
                        } else {
                            run_fips_tests(env)?;
                            let mut resp = MailboxRespHeader::default();
                            resp.populate_chksum();
                            txn.send_response(resp.as_bytes())?;
                            self_test_in_progress = true;
                        }
                    }
                    CommandId::SELF_TEST_GET_RESULTS => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_bytes_mut())?;

                        if !self_test_in_progress {
                            // TODO: set non-fatal error register?
                            txn.complete(false)?;
                        } else {
                            let mut resp = MailboxRespHeader::default();
                            resp.populate_chksum();
                            txn.send_response(resp.as_bytes())?;
                            self_test_in_progress = false;
                        }
                    }
                    CommandId::SHUTDOWN => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_bytes_mut())?;

                        let mut resp = MailboxRespHeader::default();
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;

                        // Causing a ROM Fatal Error will zeroize the module
                        return Err(CaliptraError::RUNTIME_SHUTDOWN);
                    }
                    CommandId::CAPABILITIES => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_bytes_mut())?;

                        let mut capabilities = Capabilities::default();
                        capabilities |= Capabilities::ROM_BASE;

                        let mut resp = CapabilitiesResp {
                            hdr: MailboxRespHeader::default(),
                            capabilities: capabilities.to_bytes(),
                        };
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;
                        continue;
                    }
                    CommandId::STASH_MEASUREMENT => {
                        if persistent_data.fht.meas_log_index == MEASUREMENT_MAX_COUNT as u32 {
                            cprintln!(
                                "[fwproc] Maximum supported number of measurements already received."
                            );
                            txn.complete(false)?;

                            // Raise a fatal error on hitting the max. limit.
                            // This ensures that any SOC ROM/FW couldn't send a stash measurement
                            // that wasn't properly stored within Caliptra.
                            return Err(CaliptraError::FW_PROC_MAILBOX_STASH_MEASUREMENT_MAX_LIMIT);
                        }

                        Self::stash_measurement(pcr_bank, env.sha384, persistent_data, &mut txn)?;

                        // Generate and send response (with FIPS approved status)
                        let mut resp = StashMeasurementResp {
                            hdr: MailboxRespHeader::default(),
                            dpe_result: 0, // DPE_STATUS_SUCCESS
                        };
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;
                    }
                    CommandId::RI_DOWNLOAD_FIRMWARE => {
                        // This command is not supported in passive mode.
                        if ACTIVE_MODE == false {
                            cprintln!("[fwproc] RI_DOWNLOAD_FIRMWARE cmd not supported in passive mode");
                            txn.complete(false)?;
                            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND);
                        }

                        txn.complete(true)?;

                        // Download the firmware image from the recovery interface.
                        let image_size_bytes = Self::retrieve_image_from_ri(dma)?;

                        let txn = ManuallyDrop::new(mbox.raw_recv_txn());
                        cprintln!("[fwproc] Received Image from Recovery Interface of size {} bytes", image_size_bytes);
                        report_boot_status(FwProcessorDownloadImageComplete.into());
                        return Ok((txn, image_size_bytes));
                    }
                    _ => {
                        cprintln!("[fwproc] Invalid command received");
                        // Don't complete the transaction here; let the fatal
                        // error handler do it to prevent a race condition
                        // setting the error code.
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
    fn load_manifest(
        persistent_data: &mut PersistentDataAccessor,
        txn: &mut MailboxRecvTxn,
    ) -> CaliptraResult<ImageManifest> {
        let manifest = &mut persistent_data.get_mut().manifest1;
        if ACTIVE_MODE {
            let raw_image = txn.raw_mailbox_contents();
            let buf = manifest.as_bytes_mut();
            buf.copy_from_slice(&raw_image[..buf.len()]);
        }
        else {
            txn.copy_request(manifest.as_bytes_mut())?;
        }
        report_boot_status(FwProcessorManifestLoadComplete.into());
        Ok(*manifest)
    }

    /// Verify the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn verify_image(
        venv: &mut FirmwareImageVerificationEnv,
        manifest: &ImageManifest,
        img_bundle_sz: u32,
    ) -> CaliptraResult<ImageVerificationInfo> {
        #[cfg(feature = "fake-rom")]
        let venv = &mut FakeRomImageVerificationEnv {
            sha256: venv.sha256,
            sha384: venv.sha384,
            soc_ifc: venv.soc_ifc,
            data_vault: venv.data_vault,
            ecc384: venv.ecc384,
            image: venv.image,
        };

        // Random delay for CFI glitch protection.
        CfiCounter::delay();
        CfiCounter::delay();
        CfiCounter::delay();
        CfiCounter::delay();

        let mut verifier = ImageVerifier::new(venv);
        let info = verifier.verify(manifest, img_bundle_sz, ResetReason::ColdReset)?;

        cprintln!(
            "[fwproc] Image verified using Vendor ECC Key Index {}",
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
    fn update_fuse_log(
        log: &mut FuseLogArray,
        log_info: &ImageVerificationLogInfo,
    ) -> CaliptraResult<()> {
        // Log VendorPubKeyIndex
        log_fuse_data(
            log,
            FuseLogEntryId::VendorEccPubKeyIndex,
            log_info.vendor_ecc_pub_key_idx.as_bytes(),
        )?;

        // Log VendorPubKeyRevocation
        log_fuse_data(
            log,
            FuseLogEntryId::VendorEccPubKeyRevocation,
            log_info
                .fuse_vendor_ecc_pub_key_revocation
                .bits()
                .as_bytes(),
        )?;

        // Log ManifestFmcSvn
        log_fuse_data(
            log,
            FuseLogEntryId::ManifestFmcSvn,
            log_info.fmc_log_info.manifest_svn.as_bytes(),
        )?;

        // Log ManifestReserved0
        log_fuse_data(
            log,
            FuseLogEntryId::ManifestReserved0,
            log_info.fmc_log_info.reserved.as_bytes(),
        )?;

        // Log FuseFmcSvn
        log_fuse_data(
            log,
            FuseLogEntryId::FuseFmcSvn,
            log_info.fmc_log_info.fuse_svn.as_bytes(),
        )?;

        // Log ManifestRtSvn
        log_fuse_data(
            log,
            FuseLogEntryId::ManifestRtSvn,
            log_info.rt_log_info.manifest_svn.as_bytes(),
        )?;

        // Log ManifestReserved1
        log_fuse_data(
            log,
            FuseLogEntryId::ManifestReserved1,
            log_info.rt_log_info.reserved.as_bytes(),
        )?;

        // Log FuseRtSvn
        log_fuse_data(
            log,
            FuseLogEntryId::FuseRtSvn,
            log_info.rt_log_info.fuse_svn.as_bytes(),
        )?;

        // Log VendorLmsPubKeyIndex
        if let Some(vendor_lms_pub_key_idx) = log_info.vendor_lms_pub_key_idx {
            log_fuse_data(
                log,
                FuseLogEntryId::VendorLmsPubKeyIndex,
                vendor_lms_pub_key_idx.as_bytes(),
            )?;
        }

        // Log VendorLmsPubKeyRevocation
        if let Some(fuse_vendor_lms_pub_key_revocation) =
            log_info.fuse_vendor_lms_pub_key_revocation
        {
            log_fuse_data(
                log,
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
            "[fwproc] Loading FMC at address 0x{:08x} len {}",
            manifest.fmc.load_addr,
            manifest.fmc.size
        );

        let fmc_dest = unsafe {
            let addr = (manifest.fmc.load_addr) as *mut u32;
            core::slice::from_raw_parts_mut(addr, manifest.fmc.size as usize / 4)
        };

        txn.copy_request(fmc_dest.as_bytes_mut())?;

        cprintln!(
            "[fwproc] Loading Runtime at address 0x{:08x} len {}",
            manifest.runtime.load_addr,
            manifest.runtime.size
        );

        let runtime_dest = unsafe {
            let addr = (manifest.runtime.load_addr) as *mut u32;
            core::slice::from_raw_parts_mut(addr, manifest.runtime.size as usize / 4)
        };

        txn.copy_request(runtime_dest.as_bytes_mut())?;

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
    fn populate_data_vault(
        data_vault: &mut DataVault,
        info: &ImageVerificationInfo,
        persistent_data: &PersistentDataAccessor,
    ) {
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

        data_vault.write_warm_reset_entry4(
            WarmResetEntry4::ManifestAddr,
            &persistent_data.get().manifest1 as *const _ as u32,
        );
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

    /// Read request from mailbox and verify the checksum
    ///
    /// # Arguments
    /// * `txn` - Mailbox Receive Transaction
    /// * `data` - Data buffer for the expected request
    ///
    /// # Returns
    /// * `()` - Ok
    ///    Error code on failure.
    fn copy_req_verify_chksum(txn: &mut MailboxRecvTxn, data: &mut [u8]) -> CaliptraResult<()> {
        // NOTE: Currently ROM only supports commands with a fixed request size
        //       This check will need to be updated if any commands are added with a variable request size
        if txn.dlen() as usize != data.len() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }

        // Read the data in from the mailbox HW
        txn.copy_request(data)?;

        // Extract header out from the rest of the request
        let req_hdr: &MailboxReqHeader = LayoutVerified::<&[u8], MailboxReqHeader>::new(
            &data[..core::mem::size_of::<MailboxReqHeader>()],
        )
        .ok_or(CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE)?
        .into_ref();

        // Verify checksum
        if !caliptra_common::checksum::verify_checksum(
            req_hdr.chksum,
            txn.cmd(),
            &data[core::mem::size_of_val(&req_hdr.chksum)..],
        ) {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_CHECKSUM);
        };

        Ok(())
    }

    /// Read measurement from mailbox and extends it into PCR31
    ///
    /// # Arguments
    /// * `pcr_bank` - PCR Bank
    /// * `sha384` - SHA384
    /// * `persistent_data` - Persistent data
    /// * `txn` - Mailbox Receive Transaction
    ///
    /// # Returns
    /// * `()` - Ok
    ///     Err - StashMeasurementReadFailure
    fn stash_measurement(
        pcr_bank: &mut PcrBank,
        sha384: &mut Sha384,
        persistent_data: &mut PersistentData,
        txn: &mut MailboxRecvTxn,
    ) -> CaliptraResult<()> {
        let mut measurement = StashMeasurementReq::default();
        Self::copy_req_verify_chksum(txn, measurement.as_bytes_mut())?;

        // Extend measurement into PCR31.
        Self::extend_measurement(pcr_bank, sha384, persistent_data, &measurement)?;

        Ok(())
    }

    /// Extends measurement into PCR31 and logs it to PCR log.
    ///
    /// # Arguments
    /// * `pcr_bank` - PCR Bank
    /// * `sha384` - SHA384
    /// * `persistent_data` - Persistent data
    /// * `stash_measurement` - Measurement
    ///
    /// # Returns
    /// * `()` - Ok
    ///    Error code on failure.
    fn extend_measurement(
        pcr_bank: &mut PcrBank,
        sha384: &mut Sha384,
        persistent_data: &mut PersistentData,
        stash_measurement: &StashMeasurementReq,
    ) -> CaliptraResult<()> {
        // Extend measurement into PCR31.
        pcr_bank.extend_pcr(
            PCR_ID_STASH_MEASUREMENT,
            sha384,
            stash_measurement.measurement.as_bytes(),
        )?;

        // Log measurement to the measurement log.
        Self::log_measurement(persistent_data, stash_measurement)
    }

    /// Log measurement data to the Stash Measurement log
    ///
    /// # Arguments
    /// * `persistent_data` - Persistent data
    /// * `stash_measurement` - Measurement
    ///
    /// # Return Value
    /// * `Ok(())` - Success
    /// * `Err(GlobalErr::MeasurementLogExhausted)` - Measurement log exhausted
    ///
    pub fn log_measurement(
        persistent_data: &mut PersistentData,
        stash_measurement: &StashMeasurementReq,
    ) -> CaliptraResult<()> {
        let fht = &mut persistent_data.fht;
        let Some(dst) = persistent_data.measurement_log.get_mut(fht.meas_log_index as usize) else {
            return Err(CaliptraError::ROM_GLOBAL_MEASUREMENT_LOG_EXHAUSTED);
        };

        *dst = MeasurementLogEntry {
            pcr_entry: PcrLogEntry {
                id: PcrLogEntryId::StashMeasurement as u16,
                reserved0: [0u8; 2],
                pcr_ids: 1 << (PCR_ID_STASH_MEASUREMENT as u8),
                pcr_data: zerocopy::transmute!(stash_measurement.measurement),
            },
            metadata: stash_measurement.metadata,
            context: zerocopy::transmute!(stash_measurement.context),
            svn: stash_measurement.svn,
            reserved0: [0u8; 4],
        };

        fht.meas_log_index += 1;

        Ok(())
    }

    /// Retireve the fw image from the recovery interface and store it in the mailbox sram.
    /// 
    /// # Arguments
    /// * `dma` - DMA driver
    /// 
    /// # Returns
    /// * `()` - Ok
    ///   Error code on failure.
    fn retrieve_image_from_ri(
        dma: &mut Dma,
    ) -> CaliptraResult<u32> {
        // 1. Set PROT_CAP:Byte11 bit3 to 1 ('Flashless boot').
        let mut prot_cap_byte_11_val = dma.read_dword(PROT_CAP_AGENT_BYTE_11_OFFSET as usize)?;
        prot_cap_byte_11_val |= 1 << 1; // Set bit 1
        dma.write_dword(PROT_CAP_AGENT_BYTE_11_OFFSET as usize, prot_cap_byte_11_val)?;

        // 2. Set DEVICE_STATUS:Byte0 to 0x3 ('Recovery mode - ready to accept recovery image').
        dma.write_dword(DEVICE_STATUS_OFFSET as usize, 0x3)?;

        // 3. Set DEVICE_STATUS:Byte[2:3] to 0x12 ('Recovery Reason Codes' 0x12 = 0 Flashless/Streaming Boot (FSB)).
        dma.write_dword((DEVICE_RESET_OFFSET + 2) as usize, 0x12)?;

        // 4. Set RECOVERY_STATUS register:Byte0 Bit[3:0] to 0x1 ('Awaiting recovery image') & 
        // Byte0 Bit[7:4] to 0 (Recovery image index).
        let mut recovery_status_val = dma.read_dword(RECOVERY_STATUS_OFFSET as usize)?;
        recovery_status_val = (recovery_status_val & 0xFFFFFF00) | 0x1;
        dma.write_dword(RECOVERY_STATUS_OFFSET as usize, recovery_status_val)?;

        // 5. Loop on the 'payload_available' signal for the recovery image details to be available.
        while PAYLOAD_AVAILABLE == false {
            // Wait for the payload available signal.
        }

        // 6. Read the image size from INDIRECT_FIFO_CTRL register:Byte[2:5]. Image size in DWORDs.
        let image_size_dword = dma.read_dword((INDIRECT_FIFO_CTRL_OFFSET + 2) as usize)?;

        // 7. Transfer the image from the recovery interface to the mailbox SRAM.
        let image_size_bytes = image_size_dword * 4;
        dma.transfer_payload_to_mbox(image_size_bytes)?;

        Ok(image_size_bytes)
    }
}
