/*++

Licensed under the Apache-2.0 license.

File Name:

    update_reset.rs

Abstract:

    File contains the implementation of update reset flow.

--*/
#[cfg(feature = "fake-rom")]
use crate::flow::fake::FakeRomImageVerificationEnv;
use crate::key_ladder;
use crate::{cprintln, pcr, rom_env::RomEnv};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::verifier::FirmwareImageVerificationEnv;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::{okref, report_boot_status, MailboxRecvTxn, ResetReason};
use caliptra_drivers::{report_fw_error_non_fatal, Hmac, Trng};
use caliptra_drivers::{AxiAddr, DataVault, Dma, PersistentData};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::ImageManifest;
use caliptra_image_verify::{ImageVerificationInfo, ImageVerifier};
use core::mem::size_of;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Default)]
pub struct UpdateResetFlow {}

impl UpdateResetFlow {
    /// Execute update reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn run(env: &mut RomEnv) -> CaliptraResult<()> {
        cprintln!("[update-reset] ++");
        report_boot_status(UpdateResetStarted.into());

        let data_vault = &mut env.persistent_data.get_mut().data_vault;

        // Indicate that Update-Reset flow has started.
        // This is used by the next Warm-Reset flow to confirm that the Update-Reset was successful.
        // Success status is set at the end of the flow.
        data_vault.set_rom_update_reset_status(UpdateResetStarted.into());

        let Some(mut recv_txn) = env.mbox.try_start_recv_txn() else {
            cprintln!("Failed To Get Mailbox Txn");
            return Err(CaliptraError::ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE);
        };

        let mut process_txn = || -> CaliptraResult<()> {
            // Parse command, staging address, and image size
            let (actual_cmd, staging_addr, img_bundle_sz) = if recv_txn.cmd()
                == CommandId::EXTERNAL_MAILBOX_CMD.into()
                && crate::subsystem_mode()
            {
                // Parse ExternalMailboxCmdReq to get actual command and staging address
                let mbox_contents = recv_txn.raw_mailbox_contents();
                if mbox_contents.len()
                    < core::mem::size_of::<caliptra_common::mailbox_api::ExternalMailboxCmdReq>()
                {
                    cprintln!("External mailbox command too small");
                    return Err(CaliptraError::ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE);
                }

                let external_cmd =
                    caliptra_common::mailbox_api::ExternalMailboxCmdReq::ref_from_bytes(
                        &mbox_contents[..core::mem::size_of::<
                            caliptra_common::mailbox_api::ExternalMailboxCmdReq,
                        >()],
                    )
                    .map_err(|_| CaliptraError::ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE)?;

                let staging_addr = ((external_cmd.axi_address_start_high as u64) << 32)
                    | (external_cmd.axi_address_start_low as u64);
                (
                    external_cmd.command_id,
                    Some(staging_addr),
                    external_cmd.command_size,
                )
            } else {
                (recv_txn.cmd(), None, recv_txn.dlen())
            };

            if actual_cmd != CommandId::FIRMWARE_LOAD.into() {
                cprintln!("Invalid command 0x{:08x} recv", actual_cmd);
                return Err(CaliptraError::ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND);
            }

            Self::load_manifest(
                env.persistent_data.get_mut(),
                &mut recv_txn,
                &mut env.soc_ifc,
                &mut env.dma,
                staging_addr,
            )?;
            report_boot_status(UpdateResetLoadManifestComplete.into());

            let image_in_mcu = env.soc_ifc.has_ss_staging_area();
            let mut venv = FirmwareImageVerificationEnv {
                sha256: &mut env.sha256,
                sha2_512_384: &mut env.sha2_512_384,
                sha2_512_384_acc: &mut env.sha2_512_384_acc,
                soc_ifc: &mut env.soc_ifc,
                ecc384: &mut env.ecc384,
                mldsa87: &mut env.mldsa87,
                data_vault: &env.persistent_data.get().data_vault,
                pcr_bank: &mut env.pcr_bank,
                image: recv_txn.raw_mailbox_contents(),
                dma: &env.dma,
                persistent_data: env.persistent_data.get(),
                image_in_mcu,
                staging_addr,
            };

            let info = {
                let manifest = &env.persistent_data.get().manifest2;
                Self::verify_image(&mut venv, manifest, img_bundle_sz)
            };
            let info = okref(&info)?;
            report_boot_status(UpdateResetImageVerificationComplete.into());

            // Populate data vault
            let data_vault = &mut env.persistent_data.get_mut().data_vault;
            Self::populate_data_vault(data_vault, info, &mut env.hmac, &mut env.trng)?;

            // Extend PCR0 and PCR1
            pcr::extend_pcrs(
                env.persistent_data.get_mut(),
                &env.soc_ifc,
                &mut env.pcr_bank,
                &mut env.sha2_512_384,
                info,
            )?;
            report_boot_status(UpdateResetExtendPcrComplete.into());

            cprintln!(
                "[update-reset] Img verified w/ Vendor ECC Key Index {}",
                info.vendor_ecc_pub_key_idx
            );

            let manifest = &env.persistent_data.get().manifest2;
            Self::load_image(
                manifest,
                &mut recv_txn,
                &mut env.soc_ifc,
                &mut env.dma,
                staging_addr,
            )?;
            Ok(())
        };
        if let Err(e) = process_txn() {
            // To prevent a race condition where the SoC sees the mailbox
            // transaction fail and reads the non-fatal error register before it
            // gets populated, report the non-fatal error code now.
            report_fw_error_non_fatal(e.into());
            return Err(e);
        }

        // Drop the transaction and release the Mailbox lock after the image
        // has been successfully verified and loaded in memory
        drop(recv_txn);
        report_boot_status(UpdateResetLoadImageComplete.into());

        let persistent_data = env.persistent_data.get_mut();
        cprintln!("[update-reset] Copying MAN_2 To MAN_1");
        persistent_data.manifest1 = persistent_data.manifest2;
        report_boot_status(UpdateResetOverwriteManifestComplete.into());

        // Set RT version. FMC does not change.
        env.soc_ifc
            .set_rt_fw_rev_id(persistent_data.manifest1.runtime.version);

        let data_vault = &mut env.persistent_data.get_mut().data_vault;
        data_vault.set_rom_update_reset_status(UpdateResetComplete.into());

        cprintln!("[update-reset Success] --");
        report_boot_status(UpdateResetComplete.into());

        Ok(())
    }

    /// Verify the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * 'manifest'- Manifest
    ///
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn verify_image(
        env: &mut FirmwareImageVerificationEnv,
        manifest: &ImageManifest,
        img_bundle_sz: u32,
    ) -> CaliptraResult<ImageVerificationInfo> {
        #[cfg(feature = "fake-rom")]
        let env = &mut FakeRomImageVerificationEnv {
            sha256: env.sha256,
            sha2_512_384: env.sha2_512_384,
            sha2_512_384_acc: env.sha2_512_384_acc,
            soc_ifc: env.soc_ifc,
            data_vault: env.data_vault,
            ecc384: env.ecc384,
            mldsa87: env.mldsa87,
            image: env.image,
            dma: env.dma,
        };

        let mut verifier = ImageVerifier::new(env);

        let info = verifier.verify(manifest, img_bundle_sz, ResetReason::UpdateReset)?;

        Ok(info)
    }

    /// Load the image to ICCM & DCCM
    ///
    /// # Arguments
    ///
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    /// * `soc_ifc`  - SoC Interface
    /// * `dma`      - DMA engine
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_image(
        manifest: &ImageManifest,
        txn: &mut MailboxRecvTxn,
        soc_ifc: &mut caliptra_drivers::SocIfc,
        dma: &mut Dma,
        staging_addr: Option<u64>,
    ) -> CaliptraResult<()> {
        if soc_ifc.has_ss_staging_area() {
            let addr =
                staging_addr.ok_or(CaliptraError::ROM_UPDATE_RESET_FLOW_IMAGE_NOT_IN_MCU_SRAM)?;
            Self::load_image_from_mcu(manifest, dma, addr)?;
        } else {
            Self::load_image_from_mbox(manifest, txn)?;
        }
        // Call the complete here to reset the execute bit
        txn.complete(true)?;
        Ok(())
    }

    /// Load the image from mailbox SRAM to ICCM
    ///
    /// # Arguments
    ///
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_image_from_mbox(
        manifest: &ImageManifest,
        txn: &mut MailboxRecvTxn,
    ) -> CaliptraResult<()> {
        cprintln!(
            "[update-reset] Loading Runtime at addr 0x{:08x} len {}",
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
            Err(CaliptraError::ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE)?;
        }
        runtime_dest.copy_from_slice(&mbox_sram[start..end]);

        Ok(())
    }

    /// Load the image from MCU SRAM to ICCM using DMA
    ///
    /// # Arguments
    ///
    /// * `manifest` - Manifest
    /// * `soc_ifc`  - SoC Interface
    /// * `dma`      - DMA engine
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_image_from_mcu(
        manifest: &ImageManifest,
        dma: &mut Dma,
        staging_addr: u64,
    ) -> CaliptraResult<()> {
        cprintln!(
            "[update-reset] Loading Runtime at addr 0x{:08x} len {} from staging 0x{:016x}",
            manifest.runtime.load_addr,
            manifest.runtime.size,
            staging_addr
        );

        // Load Runtime from staging area
        let runtime_dest = unsafe {
            let addr = (manifest.runtime.load_addr) as *mut u8;
            core::slice::from_raw_parts_mut(addr, manifest.runtime.size as usize)
        };
        let runtime_size_words = runtime_dest.len().div_ceil(4);
        let runtime_words = unsafe {
            core::slice::from_raw_parts_mut(
                runtime_dest.as_mut_ptr() as *mut u32,
                runtime_size_words,
            )
        };
        let runtime_offset = size_of::<ImageManifest>() + manifest.fmc.size as usize;
        let source_addr = AxiAddr::from(staging_addr + runtime_offset as u64);
        dma.read_buffer(source_addr, runtime_words);

        Ok(())
    }

    /// Load the manifest
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest(
        persistent_data: &mut PersistentData,
        txn: &mut MailboxRecvTxn,
        soc_ifc: &mut caliptra_drivers::SocIfc,
        dma: &mut Dma,
        staging_addr: Option<u64>,
    ) -> CaliptraResult<()> {
        if soc_ifc.has_ss_staging_area() {
            let addr =
                staging_addr.ok_or(CaliptraError::ROM_UPDATE_RESET_FLOW_IMAGE_NOT_IN_MCU_SRAM)?;
            Self::load_manifest_from_mcu(persistent_data, dma, addr)
        } else {
            Self::load_manifest_from_mbox(persistent_data, txn)
        }
    }

    /// Load the manifest from mailbox SRAM
    ///
    /// # Returns
    ///
    /// * `()` - Success
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest_from_mbox(
        persistent_data: &mut PersistentData,
        txn: &mut MailboxRecvTxn,
    ) -> CaliptraResult<()> {
        let manifest = &mut persistent_data.manifest2;
        let mbox_sram = txn.raw_mailbox_contents();
        let manifest_buf = manifest.as_mut_bytes();
        if mbox_sram.len() < manifest_buf.len() {
            Err(CaliptraError::ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE)?;
        }
        manifest_buf.copy_from_slice(&mbox_sram[..manifest_buf.len()]);
        Ok(())
    }

    /// Load the manifest from MCU SRAM using DMA
    ///
    /// # Returns
    ///
    /// * `()` - Success
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest_from_mcu(
        persistent_data: &mut PersistentData,
        dma: &mut Dma,
        staging_addr: u64,
    ) -> CaliptraResult<()> {
        let manifest = &mut persistent_data.manifest2;
        let manifest_buf = manifest.as_mut_bytes();

        // Read manifest from staging area using DMA directly into manifest buffer
        let manifest_size_words = manifest_buf.len().div_ceil(4); // Round up to word boundary
        let manifest_words = unsafe {
            core::slice::from_raw_parts_mut(
                manifest_buf.as_mut_ptr() as *mut u32,
                manifest_size_words,
            )
        };

        let source_addr = AxiAddr::from(staging_addr);
        dma.read_buffer(source_addr, manifest_words);

        Ok(())
    }

    /// Populate data vault
    ///
    /// # Arguments
    ///
    /// * `env`  - ROM Environment
    /// * `info` - Image Verification Info
    /// * `hmac` - HMAC helper
    /// * `trng` - TRNG helper
    fn populate_data_vault(
        data_vault: &mut DataVault,
        info: &ImageVerificationInfo,
        hmac: &mut Hmac,
        trng: &mut Trng,
    ) -> CaliptraResult<()> {
        data_vault.set_rt_tci(&info.runtime.digest.into());

        let old_min_svn = data_vault.fw_min_svn();
        let new_min_svn = core::cmp::min(old_min_svn, info.fw_svn);

        data_vault.set_fw_svn(info.fw_svn);
        data_vault.set_fw_min_svn(new_min_svn);
        data_vault.set_rt_entry_point(info.runtime.entry_point);

        report_boot_status(UpdateResetPopulateDataVaultComplete.into());

        // Extend the key ladder if the min-SVN is being decremented.
        let decrement_by = old_min_svn - new_min_svn;
        cprintln!("[update-reset] Extending key ladder by {}", decrement_by);

        key_ladder::extend_key_ladder(hmac, trng, decrement_by)?;
        report_boot_status(UpdateResetExtendKeyLadderComplete.into());

        Ok(())
    }
}
