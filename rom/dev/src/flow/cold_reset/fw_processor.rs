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
use crate::key_ladder;
use crate::pcr;
use crate::rom_env::RomEnv;
use crate::run_fips_tests;
use caliptra_api::mailbox::{
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmHmacResp, CmKeyUsage, CmRandomGenerateReq,
    CmRandomGenerateResp, CmStableKeyType, InstallOwnerPkHashReq, InstallOwnerPkHashResp,
    CM_STABLE_KEY_INFO_SIZE_BYTES,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert_bool, cfi_assert_ne, CfiCounter};
use caliptra_common::{
    capabilities::Capabilities,
    crypto::{Crypto, EncryptedCmk, UnencryptedCmk},
    fips::FipsVersionCmd,
    hmac_cm::hmac,
    keyids::{KEY_ID_STABLE_IDEV, KEY_ID_STABLE_LDEV},
    mailbox_api::{
        CapabilitiesResp, CommandId, GetIdevCsrResp, MailboxReqHeader, MailboxRespHeader,
        MailboxRespHeaderVarSize, StashMeasurementReq, StashMeasurementResp,
    },
    pcr::PCR_ID_STASH_MEASUREMENT,
    verifier::FirmwareImageVerificationEnv,
    FuseLogEntryId, PcrLogEntry, PcrLogEntryId,
    RomBootStatus::*,
};
use caliptra_drivers::{pcr_log::MeasurementLogEntry, *};

use caliptra_image_types::{FwVerificationPqcKeyType, ImageManifest, IMAGE_BYTE_SIZE};
use caliptra_image_verify::{
    ImageVerificationInfo, ImageVerificationLogInfo, ImageVerifier, MAX_FIRMWARE_SVN,
};
use caliptra_kat::KatsEnv;
use caliptra_x509::{NotAfter, NotBefore};
use core::mem::{size_of, ManuallyDrop};
use zerocopy::{transmute, FromBytes, IntoBytes};
use zeroize::Zeroize;

const RESERVED_PAUSER: u32 = 0xFFFFFFFF;

#[derive(PartialEq)]
enum FwProcessorErr {
    Fatal(CaliptraError),
    NonFatal(Option<CaliptraError>), // TODO make an error non optional
}

/// Get payload data from mailbox with checksum validation
pub fn get_checksummed_payload<'a>(txn: &'a MailboxRecvTxn<'a>) -> CaliptraResult<&'a [u8]> {
    let cmd = txn.cmd();
    let dlen = txn.dlen() as usize;
    let raw_data = txn.raw_mailbox_contents();

    // Verify payload is large enough for checksum header
    if dlen < core::mem::size_of::<MailboxReqHeader>() {
        return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
    }

    // Verify checksum
    let req_hdr = MailboxReqHeader::ref_from_bytes(
        raw_data
            .get(..core::mem::size_of::<MailboxReqHeader>())
            .ok_or(CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE)?,
    )
    .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

    if !caliptra_common::checksum::verify_checksum(
        req_hdr.chksum,
        cmd,
        raw_data
            .get(core::mem::size_of_val(&req_hdr.chksum)..dlen)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?,
    ) {
        return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_CHECKSUM);
    }

    raw_data
        .get(..dlen)
        .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)
}

#[derive(Debug, Default, Zeroize)]
pub struct FwProcInfo {
    pub fmc_cert_valid_not_before: NotBefore,

    pub fmc_cert_valid_not_after: NotAfter,

    pub effective_fuse_svn: u32,

    pub owner_pub_keys_digest_in_fuses: bool,

    pub pqc_key_type: u8,
}

pub struct FirmwareProcessor {}

impl FirmwareProcessor {
    pub fn process(env: &mut RomEnv) -> CaliptraResult<FwProcInfo> {
        let mut kats_env = caliptra_kat::KatsEnv {
            // SHA1 Engine
            sha1: &mut env.sha1,

            // sha256
            sha256: &mut env.sha256,

            // SHA2-512/384 Engine
            sha2_512_384: &mut env.sha2_512_384,

            // SHA2-512/384 Accelerator
            sha2_512_384_acc: &mut env.sha2_512_384_acc,

            // Hmac-512/384 Engine
            hmac: &mut env.hmac,

            // Cryptographically Secure Random Number Generator
            trng: &mut env.trng,

            // LMS Engine
            lms: &mut env.lms,

            // Mldsa87 Engine
            mldsa87: &mut env.mldsa87,

            // Ecc384 Engine
            ecc384: &mut env.ecc384,

            // AES Engine
            aes: &mut env.aes,

            // SHA Acc lock state
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

        // Load the manifest into DCCM.
        let manifest = Self::load_manifest(&mut env.persistent_data, &mut txn);
        let manifest = okref(&manifest)?;

        let mut venv = FirmwareImageVerificationEnv {
            sha256: &mut env.sha256,
            sha2_512_384: &mut env.sha2_512_384,
            sha2_512_384_acc: &mut env.sha2_512_384_acc,
            soc_ifc: &mut env.soc_ifc,
            ecc384: &mut env.ecc384,
            mldsa87: &mut env.mldsa87,
            data_vault: &env.persistent_data.get().data_vault,
            pcr_bank: &mut env.pcr_bank,
            image: txn.raw_mailbox_contents(),
            dma: &mut env.dma,
            persistent_data: env.persistent_data.get(),
        };

        // Verify the image
        let info = Self::verify_image(&mut venv, manifest, image_size_bytes);
        let info = okref(&info)?;

        Self::update_fuse_log(&mut env.persistent_data.get_mut().fuse_log, &info.log_info)?;

        // Populate data vault
        Self::populate_data_vault(info, &mut env.persistent_data);

        // Extend PCR0 and PCR1
        pcr::extend_pcrs(
            env.persistent_data.get_mut(),
            &env.soc_ifc,
            &mut env.pcr_bank,
            &mut env.sha2_512_384,
            info,
        )?;
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

        Self::populate_fw_key_ladder(env)?;

        report_boot_status(FwProcessorComplete.into());
        Ok(FwProcInfo {
            fmc_cert_valid_not_before: nb,
            fmc_cert_valid_not_after: nf,
            effective_fuse_svn: info.effective_fuse_svn,
            owner_pub_keys_digest_in_fuses: info.owner_pub_keys_digest_in_fuses,
            pqc_key_type: info.pqc_key_type as u8,
        })
    }

    /// Process mailbox commands
    ///
    /// # Arguments
    ///
    /// * `soc_ifc` - SOC Interface
    /// * `mbox` - Mailbox
    /// * `pcr_bank` - PCR Bank
    /// * `dma` - DMA engine
    /// * `env` - KAT Environment
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
        let subsystem_mode = soc_ifc.subsystem_mode();

        cprintln!("[fwproc] Wait for Commands...");
        loop {
            // Random delay for CFI glitch protection.
            CfiCounter::delay();

            if let Some(txn) = mbox.peek_recv() {
                report_fw_error_non_fatal(0);

                // Drop all commands for invalid PAUSER
                if txn.id() == RESERVED_PAUSER {
                    return Err(CaliptraError::FW_PROC_MAILBOX_RESERVED_PAUSER);
                }
                cfi_assert_ne(txn.id(), RESERVED_PAUSER);

                cprintln!("[fwproc] Recv command 0x{:08x}", txn.cmd());

                // Handle FW load as a separate case due to the re-borrow explained below
                if txn.cmd() == CommandId::FIRMWARE_LOAD.into() {
                    if subsystem_mode {
                        Err(CaliptraError::FW_PROC_MAILBOX_FW_LOAD_CMD_IN_SUBSYSTEM_MODE)?;
                    }
                    cfi_assert_bool(!subsystem_mode);

                    // Re-borrow mailbox to work around https://github.com/rust-lang/rust/issues/54663
                    let txn = mbox
                        .peek_recv()
                        .ok_or(CaliptraError::FW_PROC_MAILBOX_STATE_INCONSISTENT)?;

                    // This is a download-firmware command; don't drop this, as the
                    // transaction will be completed by either handle_fatal_error() (on
                    // failure) or by a manual complete call upon success.
                    let txn = ManuallyDrop::new(txn.start_txn());
                    let image_size_bytes = txn.dlen();
                    if image_size_bytes == 0 || image_size_bytes > IMAGE_BYTE_SIZE as u32 {
                        cprintln!("Invalid Image of size {} bytes", image_size_bytes);
                        return Err(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE);
                    }

                    cprintln!("[fwproc] Received Image of size {} bytes", image_size_bytes);
                    report_boot_status(FwProcessorDownloadImageComplete.into());
                    return Ok((txn, image_size_bytes));
                }

                // Handle RI_DOWNLOAD_FIRMWARE as a separate case since it's special
                if txn.cmd() == CommandId::RI_DOWNLOAD_FIRMWARE.into() {
                    if !subsystem_mode {
                        cprintln!(
                            "[fwproc] RI_DOWNLOAD_FIRMWARE cmd not supported in passive mode"
                        );
                        return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND);
                    }
                    cfi_assert_bool(subsystem_mode);

                    // Re-borrow mailbox to work around https://github.com/rust-lang/rust/issues/54663
                    let txn = mbox
                        .peek_recv()
                        .ok_or(CaliptraError::FW_PROC_MAILBOX_STATE_INCONSISTENT)?;

                    let mut txn = ManuallyDrop::new(txn.start_txn());
                    // Complete the command indicating success.
                    cprintln!("[fwproc] Completing RI_DOWNLOAD_FIRMWARE command");
                    txn.complete(true)?;

                    // Create a transaction to facilitate the download of the firmware image
                    // from the recovery interface. This dummy transaction is necessary to
                    // obtain and subsequently release the lock required to gain exclusive
                    // access to the mailbox sram by the DMA engine, enabling it to write the
                    // firmware image into the mailbox sram.
                    let txn = ManuallyDrop::new(mbox.recovery_recv_txn());

                    // Download the firmware image from the recovery interface.
                    let image_size_bytes =
                        Self::retrieve_image_from_recovery_interface(dma, soc_ifc)?;
                    cprintln!(
                        "[fwproc] Received image from the Recovery Interface of size {} bytes",
                        image_size_bytes
                    );
                    report_boot_status(FwProcessorDownloadImageComplete.into());
                    return Ok((txn, image_size_bytes));
                }

                // NOTE: We use ManuallyDrop here because any error here becomes a fatal error
                //       See note above about race condition
                let mut txn = ManuallyDrop::new(txn.start_txn());

                cprintln!("[fwproc] Processing command=0x{:x}", txn.cmd());

                // Stage the response buffer
                let resp = &mut [0u8; caliptra_common::mailbox_api::MAX_ROM_RESP_SIZE][..];

                // Get payload with checksum validation
                let cmd_bytes = get_checksummed_payload(&txn)?;

                let res = match CommandId::from(txn.cmd()) {
                    CommandId::VERSION => Self::handle_version_cmd(soc_ifc, resp),
                    CommandId::SELF_TEST_START => {
                        Self::handle_self_test_start_cmd(env, &mut self_test_in_progress, resp)
                    }
                    CommandId::SELF_TEST_GET_RESULTS => {
                        Self::handle_self_test_get_results_cmd(&mut self_test_in_progress, resp)
                    }
                    CommandId::ECDSA384_SIGNATURE_VERIFY => {
                        Self::handle_ecdsa_verify(cmd_bytes, env.ecc384, resp)
                    }
                    CommandId::MLDSA87_SIGNATURE_VERIFY => {
                        Self::handle_mldsa_verify(cmd_bytes, env.mldsa87, resp)
                    }
                    CommandId::SHUTDOWN => {
                        // This command is a bit special. We want a Fatal Error to happen to zeroize
                        // the module but also send a success report before that.
                        let mut header_resp = MailboxRespHeader::default();
                        // Generate response checksum
                        caliptra_common::mailbox_api::populate_checksum(header_resp.as_mut_bytes());
                        // Send the payload
                        txn.send_response(header_resp.as_bytes())?;

                        // Note: Response will be sent before this error causes shutdown
                        Err(FwProcessorErr::Fatal(CaliptraError::RUNTIME_SHUTDOWN))
                    }
                    CommandId::CAPABILITIES => Self::handle_capabilities_cmd(resp),
                    CommandId::STASH_MEASUREMENT => Self::handle_stash_measurement_cmd(
                        pcr_bank,
                        env,
                        persistent_data,
                        cmd_bytes,
                        resp,
                    ),
                    CommandId::GET_IDEV_ECC384_CSR => {
                        Self::handle_get_idev_ecc384_csr_cmd(persistent_data, resp)
                    }
                    CommandId::GET_IDEV_MLDSA87_CSR => {
                        Self::handle_get_idev_mldsa87_csr_cmd(persistent_data, resp)
                    }
                    CommandId::CM_DERIVE_STABLE_KEY => {
                        Self::handle_derive_stable_key_cmd(env, persistent_data, cmd_bytes, resp)
                    }
                    CommandId::CM_RANDOM_GENERATE => {
                        Self::handle_cm_random_generate_cmd(env, cmd_bytes, resp)
                    }
                    CommandId::CM_HMAC => {
                        Self::handle_cm_hmac_cmd(env, persistent_data, cmd_bytes, resp)
                    }
                    CommandId::INSTALL_OWNER_PK_HASH => {
                        Self::handle_install_owner_pk_hash_cmd(persistent_data, cmd_bytes, resp)
                    }
                    _ => {
                        cprintln!("[fwproc] Invalid command received");
                        // Don't complete the transaction here; let the fatal
                        // error handler do it to prevent a race condition
                        // setting the error code.
                        return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND);
                    }
                };

                match res {
                    Ok(len) => {
                        let resp = resp
                            .get_mut(..len)
                            .ok_or(CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE)?;
                        // Generate response checksum
                        caliptra_common::mailbox_api::populate_checksum(resp);
                        // Send the payload
                        txn.send_response(resp)?;
                        // zero the original resp buffer so as not to leak sensitive data
                        resp.fill(0);
                    }
                    Err(err) => match err {
                        FwProcessorErr::Fatal(e) => Err(e)?,
                        FwProcessorErr::NonFatal(e) => {
                            if let Some(err) = e {
                                report_fw_error_non_fatal(err.into());
                            }
                            txn.complete(false)?
                        }
                    },
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
        let mbox_sram = txn.raw_mailbox_contents();
        let manifest_buf = manifest.as_mut_bytes();
        if mbox_sram.len() < manifest_buf.len() {
            Err(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE)?;
        }
        let src_slice = mbox_sram
            .get(..manifest_buf.len())
            .ok_or(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE)?;
        manifest_buf.copy_from_slice(src_slice);
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
            sha2_512_384: venv.sha2_512_384,
            sha2_512_384_acc: venv.sha2_512_384_acc,
            soc_ifc: venv.soc_ifc,
            data_vault: venv.data_vault,
            ecc384: venv.ecc384,
            mldsa87: venv.mldsa87,
            image: venv.image,
            dma: venv.dma,
        };

        // Random delay for CFI glitch protection.
        CfiCounter::delay();
        CfiCounter::delay();
        CfiCounter::delay();
        CfiCounter::delay();

        let dma = venv.dma;
        let recovery_interface_base_addr = venv.soc_ifc.recovery_interface_base_addr().into();

        let mci_base_addr = venv.soc_ifc.mci_base_addr().into();
        let caliptra_base_addr = venv.soc_ifc.caliptra_base_axi_addr().into();
        let subsystem_mode = venv.soc_ifc.subsystem_mode();

        let mut verifier = ImageVerifier::new(venv);
        let info = verifier.verify(manifest, img_bundle_sz, ResetReason::ColdReset);

        // If running in subsystem mode, set the recovery status.
        if subsystem_mode {
            let dma_recovery = DmaRecovery::new(
                recovery_interface_base_addr,
                caliptra_base_addr,
                mci_base_addr,
                dma,
            );

            // Reset the RECOVERY_CTRL register Activate Recovery Image field by writing 0x1.
            dma_recovery.reset_recovery_ctrl_activate_rec_img()?;

            let (recovery_status, next_image_idx, device_status) = if info.is_err() {
                (
                    DmaRecovery::RECOVERY_STATUS_IMAGE_AUTHENTICATION_ERROR,
                    0,
                    DmaRecovery::DEVICE_STATUS_FATAL_ERROR,
                )
            } else {
                // we still have to do the SoC and MCU images
                // we pre-emptively set the next image index to 1 so that the recovery interface
                // will receive the right index so that no matter what order the recovery registers
                // are read, we will send the right image next
                (
                    DmaRecovery::RECOVERY_STATUS_AWAITING_RECOVERY_IMAGE,
                    1,
                    DmaRecovery::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE,
                )
            };

            cprintln!(
                "[fwproc] Setting device recovery status to 0x{:x}, image index 0x{:x}, device status 0x{:x}",
                recovery_status,
                next_image_idx,
                device_status
            );
            dma_recovery.set_recovery_status(recovery_status, next_image_idx)?;
            dma_recovery.set_device_status(device_status)?;
        }

        let info = match info {
            Ok(value) => value,
            Err(e) => Err(e)?,
        };

        cprintln!(
            "[fwproc] Img verified w/ Vendor ECC Key Idx {}, PQC Key Type: {}, PQC Key Idx {}, with SVN {} and effective fuse SVN {}",
            info.vendor_ecc_pub_key_idx,
            if FwVerificationPqcKeyType::from_u8(manifest.pqc_key_type) == Some(FwVerificationPqcKeyType::MLDSA)  { "MLDSA" } else { "LMS" },
            info.vendor_pqc_pub_key_idx,
            info.fw_svn,
            info.effective_fuse_svn,
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

        // Log cold-boot FW SVN
        log_fuse_data(
            log,
            FuseLogEntryId::ColdBootFwSvn,
            log_info.fw_log_info.manifest_svn.as_bytes(),
        )?;

        // Log ManifestReserved0
        log_fuse_data(
            log,
            FuseLogEntryId::ManifestReserved0,
            log_info.fw_log_info.reserved.as_bytes(),
        )?;

        // Log DeprecatedFuseFmcSvn (which is now the same as FuseFwSvn)
        #[allow(deprecated)]
        log_fuse_data(
            log,
            FuseLogEntryId::_DeprecatedFuseFmcSvn,
            log_info.fw_log_info.fuse_svn.as_bytes(),
        )?;

        // Log ManifestFwSvn
        log_fuse_data(
            log,
            FuseLogEntryId::ManifestFwSvn,
            log_info.fw_log_info.manifest_svn.as_bytes(),
        )?;

        // Log ManifestReserved1
        log_fuse_data(
            log,
            FuseLogEntryId::ManifestReserved1,
            log_info.fw_log_info.reserved.as_bytes(),
        )?;

        // Log FuseFwSvn
        log_fuse_data(
            log,
            FuseLogEntryId::FuseFwSvn,
            log_info.fw_log_info.fuse_svn.as_bytes(),
        )?;

        // Log VendorPqcPubKeyIndex
        log_fuse_data(
            log,
            FuseLogEntryId::VendorPqcPubKeyIndex,
            log_info.vendor_pqc_pub_key_idx.as_bytes(),
        )?;

        // Log VendorPqcPubKeyRevocation
        log_fuse_data(
            log,
            FuseLogEntryId::VendorPqcPubKeyRevocation,
            log_info.fuse_vendor_pqc_pub_key_revocation.as_bytes(),
        )?;

        Ok(())
    }

    /// Load the image to ICCM
    ///
    /// # Arguments
    ///
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    ///
    // Inlined to reduce ROM size
    #[inline(always)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_image(manifest: &ImageManifest, txn: &mut MailboxRecvTxn) -> CaliptraResult<()> {
        cprintln!(
            "[fwproc] Load FMC at address 0x{:08x} len {}",
            manifest.fmc.load_addr,
            manifest.fmc.size
        );

        let mbox_sram = txn.raw_mailbox_contents();
        let fmc_dest = unsafe {
            let addr = (manifest.fmc.load_addr) as *mut u8;
            core::slice::from_raw_parts_mut(addr, manifest.fmc.size as usize)
        };
        let start = size_of::<ImageManifest>();
        let end = start + fmc_dest.len();
        if start > end || mbox_sram.len() < end {
            Err(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE)?;
        }
        let src_slice = mbox_sram
            .get(start..end)
            .ok_or(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE)?;
        fmc_dest.copy_from_slice(src_slice);

        cprintln!(
            "[fwproc] Load Runtime at address 0x{:08x} len {}",
            manifest.runtime.load_addr,
            manifest.runtime.size
        );

        let mbox_sram = txn.raw_mailbox_contents();
        let runtime_dest = unsafe {
            let addr = (manifest.runtime.load_addr) as *mut u8;
            core::slice::from_raw_parts_mut(addr, manifest.runtime.size as usize)
        };
        let start = size_of::<ImageManifest>() + manifest.fmc.size as usize;
        let end = start + runtime_dest.len();
        if start > end || mbox_sram.len() < end {
            Err(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE)?;
        }
        let src_slice = mbox_sram
            .get(start..end)
            .ok_or(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE)?;
        runtime_dest.copy_from_slice(src_slice);

        report_boot_status(FwProcessorLoadImageComplete.into());
        Ok(())
    }

    /// Populate data vault
    ///
    /// # Arguments
    ///
    /// * `info` - Image Verification Info
    /// * `persistent_data` - Persistent data accessor
    ///
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn populate_data_vault(
        info: &ImageVerificationInfo,
        persistent_data: &mut PersistentDataAccessor,
    ) {
        let manifest_address = &persistent_data.get().manifest1 as *const _ as u32;
        let data_vault = &mut persistent_data.get_mut().data_vault;
        data_vault.set_fmc_tci(&info.fmc.digest.into());
        data_vault.set_cold_boot_fw_svn(info.fw_svn);
        data_vault.set_fmc_entry_point(info.fmc.entry_point);
        data_vault.set_owner_pk_hash(&info.owner_pub_keys_digest.into());
        data_vault.set_vendor_ecc_pk_index(info.vendor_ecc_pub_key_idx);
        data_vault.set_vendor_pqc_pk_index(info.vendor_pqc_pub_key_idx);
        data_vault.set_rt_tci(&info.runtime.digest.into());
        data_vault.set_fw_svn(info.fw_svn);
        data_vault.set_fw_min_svn(info.fw_svn);
        data_vault.set_rt_entry_point(info.runtime.entry_point);
        data_vault.set_manifest_addr(manifest_address);

        report_boot_status(FwProcessorPopulateDataVaultComplete.into());
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn populate_fw_key_ladder(env: &mut RomEnv) -> CaliptraResult<()> {
        let svn = env.persistent_data.get().data_vault.fw_svn();

        if svn > MAX_FIRMWARE_SVN {
            // If this occurs it is an internal programming error.
            Err(CaliptraError::FW_PROC_SVN_TOO_LARGE)?;
        }

        let chain_len = MAX_FIRMWARE_SVN - svn;

        cprintln!(
            "[fwproc] Initializing chain, length {} (max {})",
            chain_len,
            MAX_FIRMWARE_SVN
        );

        key_ladder::initialize_key_ladder(env, chain_len)?;

        cprintln!("[fwproc] Chain initialized");

        report_boot_status(FwProcessorCalculateKeyLadderComplete.into());

        Ok(())
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

    /// Read measurement from mailbox and extends it into PCR31
    ///
    /// # Arguments
    /// * `pcr_bank` - PCR Bank
    /// * `sha384` - SHA384
    /// * `persistent_data` - Persistent data
    /// * `cmd_bytes` - Command bytes
    ///
    /// # Returns
    /// * `()` - Ok
    ///     Err - StashMeasurementReadFailure
    fn stash_measurement(
        pcr_bank: &mut PcrBank,
        sha2: &mut Sha2_512_384,
        persistent_data: &mut PersistentData,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<()> {
        let measurement: &StashMeasurementReq = StashMeasurementReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        // Extend measurement into PCR31.
        Self::extend_measurement(pcr_bank, sha2, persistent_data, measurement)?;

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
        sha2: &mut Sha2_512_384,
        persistent_data: &mut PersistentData,
        stash_measurement: &StashMeasurementReq,
    ) -> CaliptraResult<()> {
        // Extend measurement into PCR31.
        pcr_bank.extend_pcr(
            PCR_ID_STASH_MEASUREMENT,
            sha2,
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
        let Some(dst) = persistent_data
            .measurement_log
            .get_mut(fht.meas_log_index as usize)
        else {
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

    /// Retrieve the fw image from the recovery interface and store it in the mailbox sram.
    ///
    /// # Arguments
    /// * `dma` - DMA driver
    /// * `soc_ifc` - SOC Interface
    ///
    /// # Returns
    /// * `CaliptraResult<u32>` - Size of the image downloaded
    ///   Error code on failure.
    fn retrieve_image_from_recovery_interface(
        dma: &mut Dma,
        soc_ifc: &mut SocIfc,
    ) -> CaliptraResult<u32> {
        let rri_base_addr = soc_ifc.recovery_interface_base_addr().into();
        let caliptra_base_addr = soc_ifc.caliptra_base_axi_addr().into();
        let mci_base_addr = soc_ifc.mci_base_addr().into();
        const FW_IMAGE_INDEX: u32 = 0x0;
        let dma_recovery = DmaRecovery::new(rri_base_addr, caliptra_base_addr, mci_base_addr, dma);
        dma_recovery.download_image_to_mbox(FW_IMAGE_INDEX)
    }

    fn derive_stable_key(
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        persistent_data: &mut PersistentData,
        request: &CmDeriveStableKeyReq,
    ) -> CaliptraResult<EncryptedCmk> {
        let key_type: CmStableKeyType = request.key_type.into();

        let aes_key = match key_type {
            CmStableKeyType::IDevId => AesKey::KV(KeyReadArgs::new(KEY_ID_STABLE_IDEV)),
            CmStableKeyType::LDevId => AesKey::KV(KeyReadArgs::new(KEY_ID_STABLE_LDEV)),
            CmStableKeyType::Reserved => Err(CaliptraError::DOT_INVALID_KEY_TYPE)?,
        };
        let k0 = cmac_kdf(aes, aes_key, &request.info, None, 4)?;

        // Prepend "DOT Final" to info and use as label for HMAC KDF
        const PREFIX: &[u8] = b"DOT Final";
        let mut data = [0u8; CM_STABLE_KEY_INFO_SIZE_BYTES + PREFIX.len()];
        data[..PREFIX.len()].copy_from_slice(PREFIX);
        data[PREFIX.len()..].copy_from_slice(&request.info);

        let mut tag: Array4x16 = Array4x16::default();
        hmac_kdf(
            hmac,
            HmacKey::Array4x16(&Array4x16::from(k0)),
            &data[..],
            None,
            trng,
            HmacTag::Array4x16(&mut tag),
            HmacMode::Hmac512,
        )?;

        let mut key_material = [0u8; 64];
        for (i, word) in tag.0.iter().enumerate() {
            key_material[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        // Convert the tag to CMK
        let unencrypted_cmk = UnencryptedCmk {
            version: 1,
            length: key_material.len() as u16,
            key_usage: CmKeyUsage::Hmac as u32 as u8,
            id: [0u8; 3],
            usage_counter: 0,
            key_material,
        };

        let random = trng.generate()?;
        let kek_iv: [u8; 12] = random.0.as_bytes()[..12].try_into().unwrap();
        let encrypted_cmk = Crypto::encrypt_cmk(
            aes,
            trng,
            &unencrypted_cmk,
            kek_iv,
            Crypto::get_cmb_aes_key(persistent_data),
        )?;

        Ok(encrypted_cmk)
    }

    fn handle_version_cmd(soc_ifc: &mut SocIfc, resp: &mut [u8]) -> Result<usize, FwProcessorErr> {
        let version_resp = FipsVersionCmd::execute(soc_ifc);
        let len = core::mem::size_of_val(&version_resp);
        resp.get_mut(..len)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(version_resp.as_bytes());
        Ok(len)
    }

    fn handle_self_test_start_cmd(
        env: &mut KatsEnv,
        self_test_in_progress: &mut bool,
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        if *self_test_in_progress {
            // TODO: set non-fatal error register?
            Err(FwProcessorErr::NonFatal(None))
        } else {
            run_fips_tests(env).map_err(FwProcessorErr::Fatal)?;
            let header_resp = MailboxRespHeader::default();
            let len = core::mem::size_of_val(&header_resp);
            resp.get_mut(..len)
                .ok_or(FwProcessorErr::Fatal(
                    CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
                ))?
                .copy_from_slice(header_resp.as_bytes());
            *self_test_in_progress = true;
            Ok(len)
        }
    }

    fn handle_self_test_get_results_cmd(
        self_test_in_progress: &mut bool,
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        if !*self_test_in_progress {
            // TODO: set non-fatal error register?
            Err(FwProcessorErr::NonFatal(None))
        } else {
            let header_resp = MailboxRespHeader::default();
            let len = core::mem::size_of_val(&header_resp);
            resp.get_mut(..len)
                .ok_or(FwProcessorErr::Fatal(
                    CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
                ))?
                .copy_from_slice(header_resp.as_bytes());
            *self_test_in_progress = false;
            Ok(len)
        }
    }

    fn handle_capabilities_cmd(resp: &mut [u8]) -> Result<usize, FwProcessorErr> {
        let mut capabilities = Capabilities::default();
        capabilities |= Capabilities::ROM_BASE;

        let capabilities_resp = CapabilitiesResp {
            hdr: MailboxRespHeader::default(),
            capabilities: capabilities.to_bytes(),
        };
        let len = core::mem::size_of_val(&capabilities_resp);
        resp.get_mut(..len)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(capabilities_resp.as_bytes());
        Ok(len)
    }

    fn handle_stash_measurement_cmd(
        pcr_bank: &mut PcrBank,
        env: &mut KatsEnv,
        persistent_data: &mut PersistentData,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        if persistent_data.fht.meas_log_index == MEASUREMENT_MAX_COUNT as u32 {
            cprintln!("[fwproc] Max # of measurements received.");

            // Raise a fatal error on hitting the max. limit.
            // This ensures that any SOC ROM/FW couldn't send a stash measurement
            // that wasn't properly stored within Caliptra.
            return Err(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_STASH_MEASUREMENT_MAX_LIMIT,
            ));
        }

        Self::stash_measurement(pcr_bank, env.sha2_512_384, persistent_data, cmd_bytes)
            .map_err(FwProcessorErr::Fatal)?;

        // Generate response (with FIPS approved status)
        let stash_resp = StashMeasurementResp {
            hdr: MailboxRespHeader::default(),
            dpe_result: 0, // DPE_STATUS_SUCCESS
        };
        let len = core::mem::size_of_val(&stash_resp);
        resp.get_mut(..len)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(stash_resp.as_bytes());
        Ok(len)
    }

    fn handle_get_idev_ecc384_csr_cmd(
        persistent_data: &mut PersistentData,
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        let csr_persistent_mem = &persistent_data.idevid_csr_envelop.ecc_csr;

        if csr_persistent_mem.is_unprovisioned() {
            // CSR was never written to DCCM. This means the gen_idev_id_csr
            // manufacturing flag was not set before booting into ROM.
            return Err(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR,
            ));
        }

        let csr = csr_persistent_mem
            .get()
            .ok_or(FwProcessorErr::Fatal(CaliptraError::ROM_IDEVID_INVALID_CSR))?;

        let full_struct_size = core::mem::size_of::<GetIdevCsrResp>();

        // Zero the response buffer first
        let resp = resp
            .get_mut(..full_struct_size)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?;
        resp.fill(0);

        // Get a mutable reference to the response struct in the buffer
        let csr_resp = GetIdevCsrResp::mut_from_bytes(resp)
            .map_err(|_| FwProcessorErr::Fatal(CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE))?;

        // Set the fields directly in the response buffer
        csr_resp.hdr = MailboxRespHeader::default();
        csr_resp.data_size = csr.len() as u32;
        csr_resp
            .data
            .get_mut(..csr.len())
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(csr);

        Ok(size_of::<MailboxRespHeaderVarSize>() + csr.len())
    }

    fn handle_get_idev_mldsa87_csr_cmd(
        persistent_data: &mut PersistentData,
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        let csr_persistent_mem = &persistent_data.idevid_csr_envelop.mldsa_csr;

        if csr_persistent_mem.is_unprovisioned() {
            // CSR was never written to DCCM. This means the gen_idev_id_csr
            // manufacturing flag was not set before booting into ROM.
            return Err(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR,
            ));
        }

        let csr = csr_persistent_mem
            .get()
            .ok_or(FwProcessorErr::Fatal(CaliptraError::ROM_IDEVID_INVALID_CSR))?;

        let full_struct_size = core::mem::size_of::<GetIdevCsrResp>();

        // Zero the response buffer first
        let resp = resp
            .get_mut(..full_struct_size)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?;

        // Get a mutable reference to the response struct in the buffer
        let csr_resp = GetIdevCsrResp::mut_from_bytes(resp)
            .map_err(|_| FwProcessorErr::Fatal(CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE))?;

        // Set the fields directly in the response buffer
        csr_resp.hdr = MailboxRespHeader::default();
        csr_resp.data_size = csr.len() as u32;
        csr_resp
            .data
            .get_mut(..csr.len())
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(csr);

        Ok(size_of::<MailboxRespHeaderVarSize>() + csr.len())
    }

    fn handle_derive_stable_key_cmd(
        env: &mut KatsEnv,
        persistent_data: &mut PersistentData,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        let request: &CmDeriveStableKeyReq = CmDeriveStableKeyReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| {
                FwProcessorErr::Fatal(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)
            })?;

        let encrypted_cmk =
            Self::derive_stable_key(env.aes, env.hmac, env.trng, persistent_data, request)
                .map_err(FwProcessorErr::Fatal)?;

        let key_resp = CmDeriveStableKeyResp {
            cmk: transmute!(encrypted_cmk),
            ..Default::default()
        };
        let len = core::mem::size_of_val(&key_resp);
        resp.get_mut(..len)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(key_resp.as_bytes());
        Ok(len)
    }

    fn handle_cm_hmac_cmd(
        env: &mut KatsEnv,
        persistent_data: &mut PersistentData,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        let mut hmac_resp = CmHmacResp::default();
        hmac(
            env.hmac,
            env.aes,
            env.trng,
            Crypto::get_cmb_aes_key(persistent_data),
            cmd_bytes,
            hmac_resp.as_mut_bytes(),
        )
        .map_err(FwProcessorErr::Fatal)?;

        let len = core::mem::size_of_val(&hmac_resp);
        resp.get_mut(..len)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(hmac_resp.as_bytes());
        Ok(len)
    }

    fn handle_install_owner_pk_hash_cmd(
        persistent_data: &mut PersistentData,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        let request: &InstallOwnerPkHashReq = InstallOwnerPkHashReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| {
                FwProcessorErr::Fatal(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)
            })?;

        // Save the owner public key hash in persistent data.
        persistent_data
            .dot_owner_pk_hash
            .owner_pk_hash
            .copy_from_slice(&request.digest);
        persistent_data.dot_owner_pk_hash.valid = true;

        // Generate response (with FIPS approved status)
        let hash_resp = InstallOwnerPkHashResp {
            hdr: MailboxRespHeader::default(),
            dpe_result: 0, // DPE_STATUS_SUCCESS
        };
        let len = core::mem::size_of_val(&hash_resp);
        resp.get_mut(..len)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(hash_resp.as_bytes());
        Ok(len)
    }

    fn handle_ecdsa_verify(
        cmd_bytes: &[u8],
        ecc384: &mut Ecc384,
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        let result = caliptra_common::verify::EcdsaVerifyCmd::execute(ecc384, cmd_bytes);
        if let Err(e) = result {
            Err(FwProcessorErr::NonFatal(Some(e)))?
        }
        let header_resp = MailboxRespHeader::default();
        let len = core::mem::size_of_val(&header_resp);
        resp.get_mut(..len)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(header_resp.as_bytes());
        Ok(len)
    }

    fn handle_mldsa_verify(
        cmd_bytes: &[u8],
        mldsa87: &mut Mldsa87,
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        let result = caliptra_common::verify::MldsaVerifyCmd::execute(mldsa87, cmd_bytes);
        if let Err(e) = result {
            Err(FwProcessorErr::NonFatal(Some(e)))?
        }
        let header_resp = MailboxRespHeader::default();
        let len = core::mem::size_of_val(&header_resp);
        resp.get_mut(..len)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?
            .copy_from_slice(header_resp.as_bytes());
        Ok(len)
    }

    fn handle_cm_random_generate_cmd(
        env: &mut KatsEnv,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> Result<usize, FwProcessorErr> {
        let request: &CmRandomGenerateReq = CmRandomGenerateReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| {
                FwProcessorErr::Fatal(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)
            })?;

        let size = request.size as usize;
        let full_struct_size = core::mem::size_of::<CmRandomGenerateResp>();

        // Zero the response buffer first
        let resp = resp
            .get_mut(..full_struct_size)
            .ok_or(FwProcessorErr::Fatal(
                CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE,
            ))?;
        resp.fill(0);

        // Get a mutable reference to the response struct in the buffer
        let rand_resp = CmRandomGenerateResp::mut_from_bytes(resp)
            .map_err(|_| FwProcessorErr::Fatal(CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE))?;

        let resp_data = rand_resp
            .data
            .get_mut(..size)
            .ok_or(FwProcessorErr::NonFatal(None))?;
        rand_resp.hdr.data_len = size as u32;

        for chunk in resp_data.chunks_mut(48) {
            let rand = env.trng.generate().map_err(FwProcessorErr::Fatal)?;
            let rand_bytes = rand.as_bytes();
            chunk.copy_from_slice(
                rand_bytes
                    .get(..chunk.len())
                    .ok_or(FwProcessorErr::NonFatal(None))?,
            );
        }

        Ok(size_of::<MailboxRespHeaderVarSize>() + size)
    }
}
