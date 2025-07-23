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
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmHmacReq, CmHmacResp, CmKeyUsage,
    CmRandomGenerateReq, CmRandomGenerateResp, CmStableKeyType, InstallOwnerPkHashReq,
    InstallOwnerPkHashResp, ResponseVarSize, CM_STABLE_KEY_INFO_SIZE_BYTES,
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
        CapabilitiesResp, CommandId, GetIdevCsrResp, MailboxReqHeader, MailboxRespHeader, Response,
        StashMeasurementReq, StashMeasurementResp,
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

    fn ecdsa_verify(
        txn: &mut ManuallyDrop<MailboxRecvTxn<'_>>,
        ecc384: &mut Ecc384,
    ) -> Result<(), CaliptraError> {
        let raw_data = txn.raw_mailbox_contents();
        let dlen = txn.dlen() as usize;

        if dlen > raw_data.len() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }

        let cmd_bytes = &raw_data[..dlen];

        // Extract header and verify checksum
        if cmd_bytes.len() < core::mem::size_of::<MailboxReqHeader>() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }

        let req_hdr = MailboxReqHeader::ref_from_bytes(
            &cmd_bytes[..core::mem::size_of::<MailboxReqHeader>()],
        )
        .map_err(|_| CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE)?;

        if !caliptra_common::checksum::verify_checksum(
            req_hdr.chksum,
            txn.cmd(),
            &cmd_bytes[core::mem::size_of_val(&req_hdr.chksum)..],
        ) {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_CHECKSUM);
        }

        let result = caliptra_common::verify::EcdsaVerifyCmd::execute(ecc384, cmd_bytes);
        let mut resp = MailboxRespHeader::default();
        match result {
            Ok(_) => {
                resp.populate_chksum();
                txn.send_response(resp.as_bytes())?;
            }
            Err(e) => {
                caliptra_drivers::report_fw_error_non_fatal(e.into());
                txn.complete(false)?;
            }
        }

        Ok(())
    }

    fn mldsa_verify(
        txn: &mut ManuallyDrop<MailboxRecvTxn<'_>>,
        mldsa87: &mut Mldsa87,
    ) -> Result<(), CaliptraError> {
        let raw_data = txn.raw_mailbox_contents();
        let dlen = txn.dlen() as usize;

        if dlen > raw_data.len() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }

        let cmd_bytes = &raw_data[..dlen];

        // Extract header and verify checksum
        if cmd_bytes.len() < core::mem::size_of::<MailboxReqHeader>() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }

        let req_hdr = MailboxReqHeader::ref_from_bytes(
            &cmd_bytes[..core::mem::size_of::<MailboxReqHeader>()],
        )
        .map_err(|_| CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE)?;

        if !caliptra_common::checksum::verify_checksum(
            req_hdr.chksum,
            txn.cmd(),
            &cmd_bytes[core::mem::size_of_val(&req_hdr.chksum)..],
        ) {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_CHECKSUM);
        }

        let result = caliptra_common::verify::MldsaVerifyCmd::execute(mldsa87, cmd_bytes);
        let mut resp = MailboxRespHeader::default();
        match result {
            Ok(_) => {
                resp.populate_chksum();
                txn.send_response(resp.as_bytes())?;
            }
            Err(e) => {
                caliptra_drivers::report_fw_error_non_fatal(e.into());
                txn.complete(false)?;
            }
        }

        Ok(())
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

                // NOTE: We use ManuallyDrop here because any error here becomes a fatal error
                //       See note above about race condition
                let mut txn = ManuallyDrop::new(txn.start_txn());
                match CommandId::from(txn.cmd()) {
                    CommandId::VERSION => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;

                        let mut resp = FipsVersionCmd::execute(soc_ifc);
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;
                    }
                    CommandId::SELF_TEST_START => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;

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
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;

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
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;

                        let mut resp = MailboxRespHeader::default();
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;

                        // Causing a ROM Fatal Error will zeroize the module
                        return Err(CaliptraError::RUNTIME_SHUTDOWN);
                    }
                    CommandId::CAPABILITIES => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;

                        let mut capabilities = Capabilities::default();
                        capabilities |= Capabilities::ROM_BASE;

                        if Self::supports_ocp_lock(&soc_ifc) {
                            capabilities |= Capabilities::ROM_OCP_LOCK;
                        }

                        let mut resp = CapabilitiesResp {
                            hdr: MailboxRespHeader::default(),
                            capabilities: capabilities.to_bytes(),
                        };
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;
                        continue;
                    }
                    CommandId::ECDSA384_SIGNATURE_VERIFY => {
                        Self::ecdsa_verify(&mut txn, env.ecc384)?
                    }
                    CommandId::MLDSA87_SIGNATURE_VERIFY => {
                        Self::mldsa_verify(&mut txn, env.mldsa87)?
                    }
                    CommandId::STASH_MEASUREMENT => {
                        if persistent_data.fht.meas_log_index == MEASUREMENT_MAX_COUNT as u32 {
                            cprintln!("[fwproc] Max # of measurements received.");
                            txn.complete(false)?;

                            // Raise a fatal error on hitting the max. limit.
                            // This ensures that any SOC ROM/FW couldn't send a stash measurement
                            // that wasn't properly stored within Caliptra.
                            return Err(CaliptraError::FW_PROC_MAILBOX_STASH_MEASUREMENT_MAX_LIMIT);
                        }

                        Self::stash_measurement(
                            pcr_bank,
                            env.sha2_512_384,
                            persistent_data,
                            &mut txn,
                        )?;

                        // Generate and send response (with FIPS approved status)
                        let mut resp = StashMeasurementResp {
                            hdr: MailboxRespHeader::default(),
                            dpe_result: 0, // DPE_STATUS_SUCCESS
                        };
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;
                    }
                    CommandId::GET_IDEV_ECC384_CSR => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;

                        let csr_persistent_mem = &persistent_data.idevid_csr_envelop.ecc_csr;
                        let mut resp = GetIdevCsrResp::default();

                        if csr_persistent_mem.is_unprovisioned() {
                            // CSR was never written to DCCM. This means the gen_idev_id_csr
                            // manufacturing flag was not set before booting into ROM.
                            return Err(
                                CaliptraError::FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR,
                            );
                        }

                        let csr = csr_persistent_mem
                            .get()
                            .ok_or(CaliptraError::ROM_IDEVID_INVALID_CSR)?;

                        resp.data_size = csr_persistent_mem.get_csr_len();
                        resp.data[..resp.data_size as usize].copy_from_slice(csr);

                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes_partial()?)?;
                    }
                    CommandId::GET_IDEV_MLDSA87_CSR => {
                        let mut request = MailboxReqHeader::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;

                        let csr_persistent_mem = &persistent_data.idevid_csr_envelop.mldsa_csr;
                        let mut resp = GetIdevCsrResp::default();

                        if csr_persistent_mem.is_unprovisioned() {
                            // CSR was never written to DCCM. This means the gen_idev_id_csr
                            // manufacturing flag was not set before booting into ROM.
                            return Err(
                                CaliptraError::FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR,
                            );
                        }

                        let csr = csr_persistent_mem
                            .get()
                            .ok_or(CaliptraError::ROM_IDEVID_INVALID_CSR)?;

                        resp.data_size = csr_persistent_mem.get_csr_len();
                        resp.data[..resp.data_size as usize].copy_from_slice(csr);

                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;
                    }
                    CommandId::RI_DOWNLOAD_FIRMWARE => {
                        if !subsystem_mode {
                            cprintln!(
                                "[fwproc] RI_DOWNLOAD_FIRMWARE cmd not supported in passive mode"
                            );
                            txn.complete(false)?;
                            Err(CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND)?;
                        }
                        cfi_assert_bool(subsystem_mode);
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
                    CommandId::CM_DERIVE_STABLE_KEY => {
                        let mut request = CmDeriveStableKeyReq::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;

                        let encrypted_cmk = Self::derive_stable_key(
                            env.aes,
                            env.hmac,
                            env.trng,
                            persistent_data,
                            &request,
                        )?;

                        let mut resp = CmDeriveStableKeyResp {
                            cmk: transmute!(encrypted_cmk),
                            ..Default::default()
                        };
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;
                    }
                    CommandId::CM_RANDOM_GENERATE => {
                        let mut request = CmRandomGenerateReq::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;
                        let size = request.size as usize;
                        let mut resp = CmRandomGenerateResp::default();
                        if size > resp.data.len() {
                            txn.complete(false)?;
                        } else {
                            for i in (0..size).step_by(48) {
                                let rand: [u8; 48] = env.trng.generate()?.into();
                                let len = rand.len().min(resp.data.len() - i);
                                // check to prevent panic even though this is impossible
                                if i > resp.data.len() {
                                    break;
                                }
                                resp.data[i..i + len].copy_from_slice(&rand[..len]);
                            }
                            resp.hdr.data_len = size as u32;
                            resp.populate_chksum();
                            txn.send_response(resp.as_bytes_partial()?)?;
                        }
                    }
                    CommandId::CM_HMAC => {
                        let mut request = CmHmacReq::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), true)?;
                        let mut resp = CmHmacResp::default();
                        hmac(
                            env.hmac,
                            env.aes,
                            env.trng,
                            Crypto::get_cmb_aes_key(persistent_data),
                            request.as_bytes(),
                            resp.as_mut_bytes(),
                        )?;

                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes_partial()?)?;
                    }
                    CommandId::INSTALL_OWNER_PK_HASH => {
                        let mut request = InstallOwnerPkHashReq::default();
                        Self::copy_req_verify_chksum(&mut txn, request.as_mut_bytes(), false)?;

                        // Save the owner public key hash in persistent data.
                        persistent_data
                            .dot_owner_pk_hash
                            .owner_pk_hash
                            .copy_from_slice(&request.digest);
                        persistent_data.dot_owner_pk_hash.valid = true;

                        // Generate and send response (with FIPS approved status)
                        let mut resp = InstallOwnerPkHashResp {
                            hdr: MailboxRespHeader::default(),
                            dpe_result: 0, // DPE_STATUS_SUCCESS
                        };
                        resp.populate_chksum();
                        txn.send_response(resp.as_bytes())?;
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
        let mbox_sram = txn.raw_mailbox_contents();
        let manifest_buf = manifest.as_mut_bytes();
        if mbox_sram.len() < manifest_buf.len() {
            Err(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE)?;
        }
        manifest_buf.copy_from_slice(&mbox_sram[..manifest_buf.len()]);
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
        fmc_dest.copy_from_slice(&mbox_sram[start..end]);

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
        runtime_dest.copy_from_slice(&mbox_sram[start..end]);

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

    /// Read request from mailbox and verify the checksum
    ///
    /// # Arguments
    /// * `txn` - Mailbox Receive Transaction
    /// * `data` - Data buffer for the expected request
    ///
    /// # Returns
    /// * `()` - Ok
    ///    Error code on failure.
    pub fn copy_req_verify_chksum(
        txn: &mut MailboxRecvTxn,
        mut data: &mut [u8],
        partial_allowed: bool,
    ) -> CaliptraResult<()> {
        let txn_dlen = txn.dlen() as usize;
        if partial_allowed {
            if txn_dlen > data.len() {
                return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
            }
            // handle requests that are smaller than the expected size for certain
            // variable-sized requests
            data = &mut data[..txn_dlen];
        }
        if txn_dlen != data.len() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }
        if data.len() < core::mem::size_of::<MailboxReqHeader>() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }

        // Read the data in from the mailbox HW
        txn.copy_request(data)?;

        // Extract header out from the rest of the request
        let req_hdr =
            MailboxReqHeader::ref_from_bytes(&data[..core::mem::size_of::<MailboxReqHeader>()])
                .map_err(|_| CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE)?;

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
        sha2: &mut Sha2_512_384,
        persistent_data: &mut PersistentData,
        txn: &mut MailboxRecvTxn,
    ) -> CaliptraResult<()> {
        let mut measurement = StashMeasurementReq::default();
        Self::copy_req_verify_chksum(txn, measurement.as_mut_bytes(), false)?;

        // Extend measurement into PCR31.
        Self::extend_measurement(pcr_bank, sha2, persistent_data, &measurement)?;

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

    /// Checks if ROM supports OCP LOCK.
    ///
    /// ROM needs to be compiled with `ocp-lock` feature and the hardware needs to support OCP
    /// LOCK.
    ///
    /// # Arguments
    /// * `soc_ifc` - SOC Interface
    ///
    /// # Returns true if OCP lock is supported.
    fn supports_ocp_lock(soc_ifc: &SocIfc) -> bool {
        #[cfg(feature = "ocp-lock")]
        if soc_ifc.ocp_lock_mode() {
            return true;
        }

        false
    }
}
