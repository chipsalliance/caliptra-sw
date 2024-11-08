/*++

Licensed under the Apache-2.0 license.

File Name:

    update_reset.rs

Abstract:

    File contains the implementation of update reset flow.

--*/
#[cfg(feature = "fake-rom")]
use crate::flow::fake::FakeRomImageVerificationEnv;
use crate::{cprintln, pcr, rom_env::RomEnv};
use caliptra_common::verifier::FirmwareImageVerificationEnv;

use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::report_fw_error_non_fatal;
use caliptra_drivers::{
    okref, report_boot_status, MailboxRecvTxn, ResetReason, WarmResetEntry4, WarmResetEntry48,
};
use caliptra_drivers::{DataVault, PersistentData};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::ImageManifest;
use caliptra_image_verify::{ImageVerificationInfo, ImageVerifier};
use zerocopy::AsBytes;

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

        // Indicate that Update-Reset flow has started.
        // This is used by the next Warm-Reset flow to confirm that the Update-Reset was successful.
        // Success status is set at the end of the flow.
        env.data_vault.write_warm_reset_entry4(
            WarmResetEntry4::RomUpdateResetStatus,
            UpdateResetStarted.into(),
        );

        let Some(mut recv_txn) = env.mbox.try_start_recv_txn() else {
            cprintln!("Failed To Get Mailbox Txn");
            return Err(CaliptraError::ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE);
        };

        let mut process_txn = || -> CaliptraResult<()> {
            if recv_txn.cmd() != CommandId::FIRMWARE_LOAD.into() {
                cprintln!("Invalid command 0x{:08x} recv", recv_txn.cmd());
                return Err(CaliptraError::ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND);
            }

            Self::load_manifest(env.persistent_data.get_mut(), &mut recv_txn)?;
            report_boot_status(UpdateResetLoadManifestComplete.into());

            let mut venv = FirmwareImageVerificationEnv {
                sha256: &mut env.sha256,
                sha384: &mut env.sha384,
                soc_ifc: &mut env.soc_ifc,
                ecc384: &mut env.ecc384,
                data_vault: &mut env.data_vault,
                pcr_bank: &mut env.pcr_bank,
                image: recv_txn.raw_mailbox_contents(),
            };

            let info = {
                let manifest = &env.persistent_data.get().manifest2;
                Self::verify_image(&mut venv, manifest, recv_txn.dlen())
            };
            let info = okref(&info)?;
            report_boot_status(UpdateResetImageVerificationComplete.into());

            // Populate data vault
            Self::populate_data_vault(venv.data_vault, info);

            // Extend PCR0 and PCR1
            pcr::extend_pcrs(&mut venv, info, &mut env.persistent_data)?;
            report_boot_status(UpdateResetExtendPcrComplete.into());

            cprintln!(
                "[update-reset] Img verified w/ Vendor ECC Key Index {}",
                info.vendor_ecc_pub_key_idx
            );

            let manifest = &env.persistent_data.get().manifest2;
            Self::load_image(manifest, &mut recv_txn)?;
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

        env.data_vault.write_lock_warm_reset_entry4(
            WarmResetEntry4::RomUpdateResetStatus,
            UpdateResetComplete.into(),
        );

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
            sha384: env.sha384,
            soc_ifc: env.soc_ifc,
            data_vault: env.data_vault,
            ecc384: env.ecc384,
            image: env.image,
        };

        let mut verifier = ImageVerifier::new(env);

        let info = verifier.verify(manifest, img_bundle_sz, ResetReason::UpdateReset)?;

        Ok(info)
    }

    /// Load the image to ICCM & DCCM
    ///
    /// # Arguments
    ///
    /// * `env`      - ROM Environment
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_image(manifest: &ImageManifest, txn: &mut MailboxRecvTxn) -> CaliptraResult<()> {
        cprintln!(
            "[update-reset] Loading Runtime at addr 0x{:08x} len {}",
            manifest.runtime.load_addr,
            manifest.runtime.size
        );

        // Throw away the FMC portion of the image
        txn.drop_words(manifest.fmc.size as usize / 4)?;

        let runtime_dest = unsafe {
            let addr = (manifest.runtime.load_addr) as *mut u32;
            core::slice::from_raw_parts_mut(addr, manifest.runtime.size as usize / 4)
        };

        txn.copy_request(runtime_dest.as_bytes_mut())?;

        //Call the complete here to reset the execute bit
        txn.complete(true)?;

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
    ) -> CaliptraResult<()> {
        txn.copy_request(persistent_data.manifest2.as_bytes_mut())?;
        Ok(())
    }

    /// Populate data vault
    ///
    /// # Arguments
    ///
    /// * `env`  - ROM Environment
    /// * `info` - Image Verification Info
    fn populate_data_vault(data_vault: &mut DataVault, info: &ImageVerificationInfo) {
        data_vault.write_warm_reset_entry48(WarmResetEntry48::RtTci, &info.runtime.digest.into());

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtSvn, info.runtime.svn);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtEntryPoint, info.runtime.entry_point);

        report_boot_status(UpdateResetPopulateDataVaultComplete.into());
    }
}
