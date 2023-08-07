/*++

Licensed under the Apache-2.0 license.

File Name:

    update_reset.rs

Abstract:

    File contains the implementation of update reset flow.

--*/
use crate::{cprintln, rom_env::RomEnv, verifier::RomImageVerificationEnv};

use caliptra_common::memory_layout::{MAN1_ORG, MAN2_ORG};
use caliptra_common::FirmwareHandoffTable;

use caliptra_common::RomBootStatus::*;
use caliptra_drivers::DataVault;
use caliptra_drivers::{
    report_boot_status, MailboxRecvTxn, ResetReason, WarmResetEntry4, WarmResetEntry48,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::ImageManifest;
use caliptra_image_verify::{ImageVerificationInfo, ImageVerifier};
use zerocopy::{AsBytes, FromBytes};

#[derive(Default)]
pub struct UpdateResetFlow {}

impl UpdateResetFlow {
    const MBOX_DOWNLOAD_FIRMWARE_CMD_ID: u32 = 0x46574C44;

    /// Execute update reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    pub fn run(env: &mut RomEnv) -> CaliptraResult<Option<FirmwareHandoffTable>> {
        cprintln!("[update-reset] ++");
        report_boot_status(UpdateResetStarted.into());

        let Some(mut recv_txn) = env.mbox.try_start_recv_txn() else {
            cprintln!("Failed To Get Mailbox Transaction");
            return Err(CaliptraError::ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE);
        };

        if recv_txn.cmd() != Self::MBOX_DOWNLOAD_FIRMWARE_CMD_ID {
            cprintln!("Invalid command 0x{:08x} received", recv_txn.cmd());
            return Err(CaliptraError::ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND);
        }

        let manifest = Self::load_manifest(&mut recv_txn)?;
        report_boot_status(UpdateResetLoadManifestComplete.into());

        let mut venv = RomImageVerificationEnv {
            sha256: &mut env.sha256,
            sha384: &mut env.sha384,
            sha384_acc: &mut env.sha384_acc,
            soc_ifc: &mut env.soc_ifc,
            ecc384: &mut env.ecc384,
            data_vault: &mut env.data_vault,
            pcr_bank: &mut env.pcr_bank,
        };

        let info = Self::verify_image(&mut venv, &manifest, recv_txn.dlen())?;
        report_boot_status(UpdateResetImageVerificationComplete.into());

        cprintln!(
            "[update-reset] Image verified using Vendor ECC Key Index {}",
            info.vendor_ecc_pub_key_idx
        );

        // Populate data vault
        Self::populate_data_vault(venv.data_vault, &info);

        Self::load_image(&manifest, recv_txn)?;
        report_boot_status(UpdateResetLoadImageComplete.into());

        Self::copy_regions();
        report_boot_status(UpdateResetOverwriteManifestComplete.into());

        cprintln!("[update-reset Success] --");
        report_boot_status(UpdateResetComplete.into());

        Ok(None)
    }

    /// Verify the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * 'manifest'- Manifest
    ///
    fn verify_image(
        env: &mut RomImageVerificationEnv,
        manifest: &ImageManifest,
        img_bundle_sz: u32,
    ) -> CaliptraResult<ImageVerificationInfo> {
        let mut verifier = ImageVerifier::new(env);

        let info = verifier.verify(manifest, img_bundle_sz, ResetReason::UpdateReset)?;

        Ok(info)
    }

    ///
    /// Copy the verified MAN_2 region to MAN_1
    ///
    /// # Arguments
    ///
    /// * `manifest` - Manifest
    ///
    fn copy_regions() {
        cprintln!("[update-reset] Copying MAN_2 To MAN_1");

        let dst = unsafe {
            let ptr = MAN1_ORG as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        let src = unsafe {
            let ptr = MAN2_ORG as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        dst.clone_from_slice(src);
    }

    /// Load the image to ICCM & DCCM
    ///
    /// # Arguments
    ///
    /// * `env`      - ROM Environment
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    fn load_image(manifest: &ImageManifest, mut txn: MailboxRecvTxn) -> CaliptraResult<()> {
        cprintln!(
            "[update-reset] Loading Runtime at address 0x{:08x} len {}",
            manifest.runtime.load_addr,
            manifest.runtime.size
        );

        // Throw away the FMC portion of the image
        txn.drop_words(manifest.fmc.size as usize / 4)?;

        let runtime_dest = unsafe {
            let addr = (manifest.runtime.load_addr) as *mut u32;
            core::slice::from_raw_parts_mut(addr, manifest.runtime.size as usize / 4)
        };

        txn.copy_request(runtime_dest)?;

        //Call the complete here to reset the execute bit
        txn.complete(true)?;

        // Drop the transaction and release the Mailbox lock after the image
        // has been successfully verified and loaded in memory
        drop(txn);

        Ok(())
    }

    /// Load the manifest
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    fn load_manifest(txn: &mut MailboxRecvTxn) -> CaliptraResult<ImageManifest> {
        let slice = unsafe {
            let ptr = MAN2_ORG as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        txn.copy_request(slice)?;

        ImageManifest::read_from(slice.as_bytes())
            .ok_or(CaliptraError::ROM_UPDATE_RESET_FLOW_MANIFEST_READ_FAILURE)
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
