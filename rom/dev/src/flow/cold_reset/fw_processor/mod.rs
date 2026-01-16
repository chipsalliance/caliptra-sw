/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the code to download and validate the firmware.

--*/

#[cfg(feature = "fake-rom")]
use crate::flow::fake::FakeRomImageVerificationEnv;
use crate::fuse::log_fuse_data;
use crate::key_ladder;
use crate::pcr;
use crate::rom_env::RomEnv;
use caliptra_api::mailbox;
use caliptra_api::mailbox::MailboxRespHeader;
use caliptra_api::mailbox::{
    AlgorithmType, CmDeriveStableKeyReq, CmKeyUsage, CmStableKeyType, CM_STABLE_KEY_INFO_SIZE_BYTES,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert_bool, cfi_assert_ne, CfiCounter};
use caliptra_common::{
    crypto::{Crypto, EncryptedCmk, UnencryptedCmk},
    mailbox_api::{CommandId, MailboxReqHeader, ZeroizeUdsFeResp},
    verifier::FirmwareImageVerificationEnv,
    FuseLogEntryId,
    RomBootStatus::*,
};
use caliptra_drivers::*;

use caliptra_image_types::{FwVerificationPqcKeyType, ImageManifest, IMAGE_BYTE_SIZE};
use caliptra_image_verify::{
    ImageVerificationInfo, ImageVerificationLogInfo, ImageVerifier, MAX_FIRMWARE_SVN,
};
use caliptra_kat::KatsEnv;
use caliptra_x509::{NotAfter, NotBefore};
use core::mem::{size_of, ManuallyDrop};
use dma::AesDmaMode;
use zerocopy::{FromBytes, IntoBytes};
use zeroize::Zeroize;

use crate::flow::cold_reset::ocp_lock;

mod capabilities;
mod cm_derive_stable_key;
mod cm_hmac;
mod cm_random_generate;
mod ecdsa_verify;
mod get_idev_csr;
mod get_ldev_cert;
mod install_owner_pk_hash;
mod mldsa_verify;
mod report_hek_metadata;
mod ri_download_firmware;
mod self_test;
mod shutdown;
mod stash_measurement;
mod version;
mod zeroize_uds_fe;

use capabilities::CapabilitiesCmd;
use cm_derive_stable_key::CmDeriveStableKeyCmd;
use cm_hmac::CmHmacCmd;
use cm_random_generate::CmRandomGenerateCmd;
use ecdsa_verify::EcdsaVerifyCmd;
use get_idev_csr::{GetIdevEcc384CsrCmd, GetIdevMldsa87CsrCmd};
use get_ldev_cert::GetLdevCertCmd;
use install_owner_pk_hash::InstallOwnerPkHashCmd;
use mldsa_verify::MldsaVerifyCmd;
use report_hek_metadata::OcpLockReportHekMetadataCmd;
use ri_download_firmware::RiDownloadFirmwareCmd;
use self_test::{SelfTestGetResultsCmd, SelfTestStartCmd};
use shutdown::ShutdownCmd;
use stash_measurement::StashMeasurementCmd;
use version::VersionCmd;
use zeroize_uds_fe::ZeroizeUdsFeCmd;

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

            // SHA3/SHAKE Engine
            sha3: &mut env.sha3,

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

        // After processing commands but before booting into the next stage we need to complete the OCP LOCK flow.
        if env.soc_ifc.ocp_lock_enabled() {
            ocp_lock::complete_ocp_lock_flow(
                &mut env.soc_ifc,
                env.persistent_data.get_mut(),
                &mut env.key_vault,
            )?;
        }

        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            caliptra_drivers::FipsTestHook::halt_if_hook_set(
                caliptra_drivers::FipsTestHook::HALT_FW_LOAD,
            )
        };

        let mci_base = env.soc_ifc.mci_base_addr();
        // Load the manifest into DCCM.
        let manifest = Self::load_manifest(
            &mut env.persistent_data,
            txn.as_deref_mut(),
            &mut env.soc_ifc,
            &mut env.dma,
        );
        let manifest = okref(&manifest)?;

        let image_source = if let Some(ref txn) = txn {
            caliptra_common::verifier::ImageSource::MboxMemory(txn.raw_mailbox_contents())
        } else {
            caliptra_common::verifier::ImageSource::Axi {
                dma: &env.dma,
                axi_start: AxiAddr::from(mci_base + caliptra_drivers::dma::MCU_SRAM_OFFSET),
            }
        };
        let mut venv = FirmwareImageVerificationEnv {
            sha256: &mut env.sha256,
            sha2_512_384: &mut env.sha2_512_384,
            sha2_512_384_acc: &mut env.sha2_512_384_acc,
            soc_ifc: &mut env.soc_ifc,
            ecc384: &mut env.ecc384,
            mldsa87: &mut env.mldsa87,
            data_vault: &env.persistent_data.get().rom.data_vault,
            pcr_bank: &mut env.pcr_bank,
            image_source,
            persistent_data: env.persistent_data.get(),
        };

        // Verify the image
        let info = Self::verify_image(&mut venv, manifest, image_size_bytes);
        let info = okref(&info)?;

        Self::update_fuse_log(
            &mut env.persistent_data.get_mut().rom.fuse_log,
            &info.log_info,
        )?;

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
        Self::load_image(manifest, txn.as_deref_mut(), &mut env.soc_ifc, &mut env.dma)?;

        // Complete the mailbox transaction indicating success.
        if let Some(ref mut txn) = txn {
            txn.complete(true)?;
        }

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
    /// * `Option<MailboxRecvTxn>` - Mailbox Receive Transaction (Some in passive mode, None in subsystem mode)
    /// * `u32` - Image size in bytes
    ///
    /// In passive mode, the mailbox transaction handle is returned for the FIRMWARE_LOAD command.
    /// In subsystem mode, firmware is loaded via the recovery interface and None is returned.
    /// This transaction is ManuallyDrop because we don't want the transaction
    /// to be completed with failure until after handle_fatal_error is called.
    /// This prevents a race condition where the SoC reads FW_ERROR_NON_FATAL
    /// immediately after the mailbox transaction fails,
    /// but before caliptra has set the FW_ERROR_NON_FATAL register.
    fn process_mailbox_commands<'a>(
        soc_ifc: &mut SocIfc,
        mbox: &'a mut Mailbox,
        pcr_bank: &mut PcrBank,
        dma: &mut Dma,
        env: &mut KatsEnv,
        persistent_data: &mut PersistentData,
    ) -> CaliptraResult<(Option<ManuallyDrop<MailboxRecvTxn<'a>>>, u32)> {
        let mut self_test_in_progress = false;
        let subsystem_mode = soc_ifc.subsystem_mode();

        cprintln!("[fwproc] Wait for Commands...");
        loop {
            // Random delay for CFI glitch protection.
            CfiCounter::delay();

            if let Some(txn) = mbox.peek_recv() {
                clear_fw_error_non_fatal(persistent_data);

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
                    return Ok((Some(txn), image_size_bytes));
                }

                // Handle RI_DOWNLOAD_FIRMWARE and RI_DOWNLOAD_ENCRYPTED_FIRMWARE
                // Both commands download firmware from recovery interface, but encrypted variant
                // sets boot_mode so runtime knows not to activate MCU firmware after downloading
                let encrypted = txn.cmd() == CommandId::RI_DOWNLOAD_ENCRYPTED_FIRMWARE.into();
                if txn.cmd() == CommandId::RI_DOWNLOAD_FIRMWARE.into() || encrypted {
                    if !subsystem_mode {
                        cprintln!(
                            "[fwproc] RI_DOWNLOAD_FIRMWARE cmd not supported in passive mode"
                        );
                        // Start and complete the transaction with error
                        let txn = mbox
                            .peek_recv()
                            .ok_or(CaliptraError::FW_PROC_MAILBOX_STATE_INCONSISTENT)?;
                        let mut txn = txn.start_txn();
                        txn.complete(false)?;
                        Err(CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND)?;
                    }
                    cfi_assert_bool(subsystem_mode);

                    // Set boot mode based on command type
                    if encrypted {
                        persistent_data.rom.boot_mode = BootMode::EncryptedFirmware;
                    }

                    // Complete the command indicating success
                    cprintln!("[fwproc] Completing RI_DOWNLOAD_FIRMWARE command");
                    let txn = mbox
                        .peek_recv()
                        .ok_or(CaliptraError::FW_PROC_MAILBOX_STATE_INCONSISTENT)?;
                    let mut txn = txn.start_txn();
                    txn.complete(true)?;
                    // Explicitly drop to release the borrow on mbox
                    drop(txn);

                    // Now we can access mbox again since the transaction is complete
                    return Ok((None, RiDownloadFirmwareCmd::execute(dma, soc_ifc)?));
                }

                // NOTE: We use ManuallyDrop here because any error here becomes a fatal error
                //       See note above about race condition
                let mut txn = ManuallyDrop::new(txn.start_txn());

                // Get command bytes and verify checksum
                let cmd_bytes = FirmwareProcessor::get_and_verify_cmd_bytes(&txn)?;

                // Response buffer
                let resp = &mut [0u8; caliptra_common::mailbox_api::MAX_ROM_RESP_SIZE][..];

                // Don't read CMD again in the same loop execution is it might already have changed
                // to the next CMD
                let cmd = txn.cmd();
                let resp_len = match CommandId::from(cmd) {
                    CommandId::VERSION => VersionCmd::execute(cmd_bytes, soc_ifc, resp)?,
                    CommandId::SELF_TEST_START => {
                        let (in_progress, len) =
                            SelfTestStartCmd::execute(cmd_bytes, env, self_test_in_progress, resp)?;
                        self_test_in_progress = in_progress;
                        len
                    }
                    CommandId::SELF_TEST_GET_RESULTS => {
                        let (in_progress, len) =
                            SelfTestGetResultsCmd::execute(cmd_bytes, self_test_in_progress, resp)?;
                        self_test_in_progress = in_progress;
                        len
                    }
                    CommandId::SHUTDOWN => ShutdownCmd::execute(cmd_bytes, resp)?,
                    CommandId::CAPABILITIES => CapabilitiesCmd::execute(cmd_bytes, soc_ifc, resp)?,
                    CommandId::ECDSA384_SIGNATURE_VERIFY => {
                        EcdsaVerifyCmd::execute(cmd_bytes, env.ecc384, resp)?
                    }
                    CommandId::MLDSA87_SIGNATURE_VERIFY => {
                        MldsaVerifyCmd::execute(cmd_bytes, env.mldsa87, resp)?
                    }
                    CommandId::STASH_MEASUREMENT => {
                        if persistent_data.rom.fht.meas_log_index == MEASUREMENT_MAX_COUNT as u32 {
                            cprintln!("[fwproc] Max # of measurements received.");
                            txn.complete(false)?;

                            // Raise a fatal error on hitting the max. limit.
                            // This ensures that any SOC ROM/FW couldn't send a stash measurement
                            // that wasn't properly stored within Caliptra.
                            return Err(CaliptraError::FW_PROC_MAILBOX_STASH_MEASUREMENT_MAX_LIMIT);
                        }

                        StashMeasurementCmd::execute(
                            cmd_bytes,
                            pcr_bank,
                            env.sha2_512_384,
                            persistent_data,
                            resp,
                        )?
                    }
                    CommandId::GET_IDEV_ECC384_CSR => {
                        GetIdevEcc384CsrCmd::execute(cmd_bytes, persistent_data, resp)?
                    }
                    CommandId::GET_IDEV_MLDSA87_CSR => {
                        GetIdevMldsa87CsrCmd::execute(cmd_bytes, persistent_data, resp)?
                    }
                    CommandId::CM_DERIVE_STABLE_KEY => CmDeriveStableKeyCmd::execute(
                        cmd_bytes,
                        env.aes,
                        env.hmac,
                        env.trng,
                        persistent_data,
                        resp,
                    )?,
                    CommandId::CM_RANDOM_GENERATE => {
                        CmRandomGenerateCmd::execute(cmd_bytes, env.trng, resp)?
                    }
                    CommandId::CM_HMAC => CmHmacCmd::execute(
                        cmd_bytes,
                        env.aes,
                        env.hmac,
                        env.trng,
                        persistent_data,
                        resp,
                    )?,
                    CommandId::OCP_LOCK_REPORT_HEK_METADATA => {
                        OcpLockReportHekMetadataCmd::execute(
                            cmd_bytes,
                            soc_ifc,
                            persistent_data,
                            resp,
                        )?
                    }
                    CommandId::INSTALL_OWNER_PK_HASH => {
                        InstallOwnerPkHashCmd::execute(cmd_bytes, persistent_data, resp)?
                    }
                    CommandId::GET_LDEV_ECC384_CERT => GetLdevCertCmd::execute(
                        cmd_bytes,
                        persistent_data,
                        AlgorithmType::Ecc384,
                        resp,
                    )?,
                    CommandId::GET_LDEV_MLDSA87_CERT => GetLdevCertCmd::execute(
                        cmd_bytes,
                        persistent_data,
                        AlgorithmType::Mldsa87,
                        resp,
                    )?,
                    CommandId::ZEROIZE_UDS_FE => {
                        ZeroizeUdsFeCmd::execute(cmd_bytes, soc_ifc, dma, resp)?
                    }
                    _ => {
                        cprintln!("[fwproc] Invalid command received");
                        // Don't complete the transaction here; let the fatal
                        // error handler do it to prevent a race condition
                        // setting the error code.
                        return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND);
                    }
                };

                // Send response or complete with failure
                if resp_len >= core::mem::size_of::<MailboxRespHeader>() {
                    let response = resp
                        .get_mut(..resp_len)
                        .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
                    mailbox::populate_checksum(response);

                    txn.send_response(response)?;
                } else {
                    // Response length of 0 indicates failure (e.g., self test commands)
                    txn.complete(false)?;
                }

                match CommandId::from(cmd) {
                    // ZEROIZE_UDS_FE sends both a response as well as an error after that.
                    // Shutdown after zeroization as UDS and/or FE values and its derived keys are no longer valid.
                    CommandId::ZEROIZE_UDS_FE => {
                        let resp = ZeroizeUdsFeResp::ref_from_bytes(&resp[..resp_len])
                            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE)?;
                        // Use the response to figure out if we succeeded or failed
                        if resp.dpe_result == 0 {
                            Err(CaliptraError::UDS_FE_PROGRAMMING_ZEROIZATION_SUCCESS)?
                        } else {
                            Err(CaliptraError::UDS_FE_PROGRAMMING_ZEROIZATION_FAILED)?
                        }
                    }
                    CommandId::SHUTDOWN =>
                    // Causing a ROM Fatal Error will zeroize the module
                    {
                        Err(CaliptraError::RUNTIME_SHUTDOWN)?
                    }
                    _ => (),
                };
            }
        }
    }

    /// Load the manifest
    ///
    /// # Arguments
    ///
    /// * `persistent_data` - Persistent data accessor
    /// * `txn` - Mailbox transaction (Some in passive mode, None in subsystem mode)
    /// * `soc_ifc` - SoC Interface
    /// * `dma` - DMA engine
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest(
        persistent_data: &mut PersistentDataAccessor,
        txn: Option<&mut MailboxRecvTxn>,
        soc_ifc: &mut SocIfc,
        dma: &mut Dma,
    ) -> CaliptraResult<ImageManifest> {
        if let Some(txn) = txn {
            Self::load_manifest_from_mbox(persistent_data, txn)
        } else {
            Self::load_manifest_from_mcu(persistent_data, soc_ifc, dma)
        }
    }

    /// Load the manifest from mailbox SRAM
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest_from_mbox(
        persistent_data: &mut PersistentDataAccessor,
        txn: &mut MailboxRecvTxn,
    ) -> CaliptraResult<ImageManifest> {
        let manifest = &mut persistent_data.get_mut().rom.manifest1;
        let mbox_sram = txn.raw_mailbox_contents();
        let manifest_buf = manifest.as_mut_bytes();
        if mbox_sram.len() < manifest_buf.len() {
            Err(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE)?;
        }
        manifest_buf.copy_from_slice(&mbox_sram[..manifest_buf.len()]);
        report_boot_status(FwProcessorManifestLoadComplete.into());
        Ok(*manifest)
    }

    /// Load the manifest from MCU SRAM using DMA
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest_from_mcu(
        persistent_data: &mut PersistentDataAccessor,
        soc_ifc: &mut SocIfc,
        dma: &mut Dma,
    ) -> CaliptraResult<ImageManifest> {
        let manifest = &mut persistent_data.get_mut().rom.manifest1;
        let manifest_buf = manifest.as_mut_bytes();

        // Get MCU SRAM address
        let mci_base_addr: AxiAddr = soc_ifc.mci_base_addr().into();
        let recovery_interface_base_addr: AxiAddr = soc_ifc.recovery_interface_base_addr().into();
        let caliptra_base_addr: AxiAddr = soc_ifc.caliptra_base_axi_addr().into();

        // Read manifest from MCU SRAM using DMA directly into manifest buffer
        let (manifest_words, _) = <[u32]>::mut_from_prefix(manifest_buf).unwrap();

        let dma_recovery = DmaRecovery::new(
            recovery_interface_base_addr,
            caliptra_base_addr,
            mci_base_addr,
            dma,
        );
        dma_recovery.load_from_mcu_to_buffer(0, manifest_words)?;

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
        let dma = if let caliptra_common::verifier::ImageSource::Axi { dma, axi_start: _ } =
            &venv.image_source
        {
            Some(*dma)
        } else {
            None
        };

        #[cfg(feature = "fake-rom")]
        let venv = &mut FakeRomImageVerificationEnv {
            sha256: venv.sha256,
            sha2_512_384: venv.sha2_512_384,
            sha2_512_384_acc: venv.sha2_512_384_acc,
            soc_ifc: venv.soc_ifc,
            data_vault: venv.data_vault,
            ecc384: venv.ecc384,
            mldsa87: venv.mldsa87,
            image_source: match &venv.image_source {
                caliptra_common::verifier::ImageSource::MboxMemory(img) => {
                    crate::flow::fake::ImageSource::Memory(img)
                }
                caliptra_common::verifier::ImageSource::Axi { dma, axi_start: _ } => {
                    crate::flow::fake::ImageSource::McuSram(dma)
                }
                _ => panic!("Image source cannot be fips test"),
            },
        };

        // Random delay for CFI glitch protection.
        CfiCounter::delay();
        CfiCounter::delay();
        CfiCounter::delay();
        CfiCounter::delay();

        let recovery_interface_base_addr = venv.soc_ifc.recovery_interface_base_addr().into();
        let mci_base_addr = venv.soc_ifc.mci_base_addr().into();
        let caliptra_base_addr = venv.soc_ifc.caliptra_base_axi_addr().into();

        let mut verifier = ImageVerifier::new(venv);
        let info = verifier.verify(manifest, img_bundle_sz, ResetReason::ColdReset);

        // If running in subsystem mode, set the recovery status.
        if let Some(dma) = dma {
            let dma_recovery = DmaRecovery::new(
                recovery_interface_base_addr,
                caliptra_base_addr,
                mci_base_addr,
                dma,
            );

            // Reset the RECOVERY_CTRL register Activate Recovery Image field by writing 0x1.
            dma_recovery.reset_recovery_ctrl_activate_rec_img()?;
            // Reset the Indirect FIFO control so that payload_available is reset.
            dma_recovery.reset_indirect_fifo_ctrl()?;

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
    /// * `txn`      - Mailbox Receive Transaction (Some in passive mode, None in subsystem mode)
    /// * `soc_ifc`  - SoC Interface
    /// * `dma`      - DMA engine
    ///
    // Inlined to reduce ROM size
    #[inline(always)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_image(
        manifest: &ImageManifest,
        txn: Option<&mut MailboxRecvTxn>,
        soc_ifc: &mut SocIfc,
        dma: &mut Dma,
    ) -> CaliptraResult<()> {
        if let Some(txn) = txn {
            Self::load_image_from_mbox(manifest, txn)
        } else {
            Self::load_image_from_mcu(manifest, soc_ifc, dma)
        }
    }

    /// Load the image from mailbox SRAM to ICCM
    ///
    /// # Arguments
    ///
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    ///
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_image_from_mbox(
        manifest: &ImageManifest,
        txn: &mut MailboxRecvTxn,
    ) -> CaliptraResult<()> {
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

    /// Load the image from MCU SRAM to ICCM using DMA
    ///
    /// # Arguments
    ///
    /// * `manifest` - Manifest
    /// * `soc_ifc`  - SoC Interface
    /// * `dma`      - DMA engine
    ///
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_image_from_mcu(
        manifest: &ImageManifest,
        soc_ifc: &mut SocIfc,
        dma: &mut Dma,
    ) -> CaliptraResult<()> {
        // Get MCU SRAM address
        let mci_base_addr: AxiAddr = soc_ifc.mci_base_addr().into();
        let recovery_interface_base_addr: AxiAddr = soc_ifc.recovery_interface_base_addr().into();
        let caliptra_base_addr: AxiAddr = soc_ifc.caliptra_base_axi_addr().into();

        let dma_recovery = DmaRecovery::new(
            recovery_interface_base_addr,
            caliptra_base_addr,
            mci_base_addr,
            dma,
        );

        cprintln!(
            "[fwproc] Load FMC at address 0x{:08x} len {}",
            manifest.fmc.load_addr,
            manifest.fmc.size
        );

        // Load FMC from MCU SRAM
        let fmc_size_words = manifest.fmc.size.div_ceil(4) as usize;
        let fmc_words = unsafe {
            core::slice::from_raw_parts_mut(manifest.fmc.load_addr as *mut u32, fmc_size_words)
        };
        let fmc_offset = size_of::<ImageManifest>();
        dma_recovery.load_from_mcu_to_buffer(fmc_offset as u64, fmc_words)?;

        cprintln!(
            "[fwproc] Load Runtime at address 0x{:08x} len {}",
            manifest.runtime.load_addr,
            manifest.runtime.size
        );

        // Load Runtime from MCU SRAM
        let runtime_size_words = manifest.runtime.size.div_ceil(4) as usize;
        let runtime_words = unsafe {
            core::slice::from_raw_parts_mut(
                manifest.runtime.load_addr as *mut u32,
                runtime_size_words,
            )
        };
        let runtime_offset = size_of::<ImageManifest>() + manifest.fmc.size as usize;
        dma_recovery.load_from_mcu_to_buffer(runtime_offset as u64, runtime_words)?;

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
        let manifest_address = &persistent_data.get().rom.manifest1 as *const _ as u32;
        let data_vault = &mut persistent_data.get_mut().rom.data_vault;
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
        let svn = env.persistent_data.get().rom.data_vault.fw_svn();

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

    /// Get command bytes from mailbox and verify checksum
    ///
    /// # Arguments
    /// * `txn` - Mailbox transaction
    ///
    /// # Returns
    /// * `&[u8]` - Command bytes slice
    ///    Error code on failure.
    pub fn get_and_verify_cmd_bytes<'a>(txn: &'a MailboxRecvTxn<'a>) -> CaliptraResult<&'a [u8]> {
        // Get command bytes from mailbox
        let raw_data = txn.raw_mailbox_contents();
        let dlen = txn.dlen() as usize;

        if dlen > raw_data.len() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }

        let cmd_bytes = &raw_data[..dlen];

        // Verify checksum
        Self::verify_chksum(txn.cmd(), cmd_bytes)?;

        Ok(cmd_bytes)
    }

    /// Verify the checksum of a mailbox request
    ///
    /// # Arguments
    /// * `cmd` - Command ID from the mailbox transaction
    /// * `data` - Raw data from the mailbox
    ///
    /// # Returns
    /// * `()` - Ok
    ///    Error code on failure.
    pub fn verify_chksum(cmd: u32, data: &[u8]) -> CaliptraResult<()> {
        if data.len() < core::mem::size_of::<MailboxReqHeader>() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }

        // Extract header out from the rest of the request
        let req_hdr =
            MailboxReqHeader::ref_from_bytes(&data[..core::mem::size_of::<MailboxReqHeader>()])
                .map_err(|_| CaliptraError::FW_PROC_MAILBOX_PROCESS_FAILURE)?;

        // Verify checksum
        if !caliptra_common::checksum::verify_checksum(
            req_hdr.chksum,
            cmd,
            &data[core::mem::size_of_val(&req_hdr.chksum)..],
        ) {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_CHECKSUM);
        };

        Ok(())
    }

    /// Retrieve the fw image from the recovery interface and download it to MCU.
    ///
    /// # Arguments
    /// * `dma` - DMA driver
    /// * `soc_ifc` - SOC Interface
    ///
    /// # Returns
    /// * `CaliptraResult<u32>` - Size of the image downloaded
    ///   Error code on failure.
    pub(crate) fn retrieve_image_from_recovery_interface_to_mcu(
        dma: &mut Dma,
        soc_ifc: &mut SocIfc,
    ) -> CaliptraResult<u32> {
        const FW_IMAGE_INDEX: u32 = 0x0;
        let recovery_interface_base_addr = soc_ifc.recovery_interface_base_addr().into();

        let mci_base_addr = soc_ifc.mci_base_addr().into();
        let caliptra_base_addr = soc_ifc.caliptra_base_axi_addr().into();

        let dma_recovery = DmaRecovery::new(
            recovery_interface_base_addr,
            caliptra_base_addr,
            mci_base_addr,
            dma,
        );
        dma_recovery.download_image_to_mcu(FW_IMAGE_INDEX, AesDmaMode::None)
    }

    pub(crate) fn derive_stable_key(
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        persistent_data: &mut PersistentData,
        request: &CmDeriveStableKeyReq,
    ) -> CaliptraResult<EncryptedCmk> {
        let key_type: CmStableKeyType = request.key_type.into();

        let aes_key = match key_type {
            CmStableKeyType::IDevId => AesKey::KV(KeyReadArgs::new(
                caliptra_common::keyids::KEY_ID_STABLE_IDEV,
            )),
            CmStableKeyType::LDevId => AesKey::KV(KeyReadArgs::new(
                caliptra_common::keyids::KEY_ID_STABLE_LDEV,
            )),
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
        let kek_iv: [u32; 3] = random.0[..3].try_into().unwrap();
        let encrypted_cmk = Crypto::encrypt_cmk(
            aes,
            trng,
            &unencrypted_cmk,
            kek_iv.into(),
            Crypto::get_cmb_aes_key(persistent_data),
        )?;

        Ok(encrypted_cmk)
    }
}
