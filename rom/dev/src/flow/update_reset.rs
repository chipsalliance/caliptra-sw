/*++

Licensed under the Apache-2.0 license.

File Name:

    update_reset.rs

Abstract:

    File contains the implementation of update reset flow.

--*/
use crate::{cprintln, fht, rom_env::RomEnv, rom_err_def, verifier::RomImageVerificationEnv};

use caliptra_common::FirmwareHandoffTable;
use caliptra_drivers::{CaliptraResult, MailboxRecvTxn, ResetReason};
use caliptra_image_types::ImageManifest;
use caliptra_image_verify::{ImageVerificationInfo, ImageVerifier};
use zerocopy::{AsBytes, FromBytes};

extern "C" {
    static mut MAN2_ORG: u32;
    static mut MAN1_ORG: u32;
}

rom_err_def! {
    UpdateReset,
    UpdateResetErr
    {
        ManifestReadFailure = 0x2,
        InvalidFirmwareCommand = 0x03,
        MailboxAccessFailure = 0x04,
    }
}

#[derive(Default)]
pub struct UpdateResetFlow {}

impl UpdateResetFlow {
    const MBOX_DOWNLOAD_FIRMWARE_CMD_ID: u32 = 0x46574C44;

    /// Execute update reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    pub fn run(env: &RomEnv) -> CaliptraResult<FirmwareHandoffTable> {
        cprintln!("[update-reset] ++");

        let Some(recv_txn) = env.mbox().map(|m| m.try_start_recv_txn()) else {
            cprintln!("Failed To Get Mailbox Txn");            
            raise_err!(MailboxAccessFailure)
        };

        let cmd = recv_txn.cmd();

        if cmd != Self::MBOX_DOWNLOAD_FIRMWARE_CMD_ID {
            cprintln!("Invalid cmd 0x{:08x} received", cmd);
            raise_err!(InvalidFirmwareCommand)
        }

        let manifest = Self::load_manifest(&recv_txn)?;

        let info = Self::verify_image(env, &manifest)?;

        cprintln!(
            "[update-reset] Img verified using Vendor ECC Key Idx {}",
            info.vendor_ecc_pub_key_idx
        );

        Self::load_image(env, &manifest, recv_txn)?;

        Self::copy_regions(&manifest);
        cprintln!("[update-reset Success] --");
        Ok(fht::make_fht(env))
    }

    /// Verify the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * 'manifest'- Manifest
    ///
    fn verify_image(
        env: &RomEnv,
        manifest: &ImageManifest,
    ) -> CaliptraResult<ImageVerificationInfo> {
        let venv = RomImageVerificationEnv::new(env);

        let verifier = ImageVerifier::new(venv);

        let info = verifier.verify(manifest, (), ResetReason::UpdateReset)?;

        Ok(info)
    }

    ///
    /// Copy the verified MAN_2 region to MAN_1
    ///
    /// # Arguments
    ///
    /// * `manifest` - Manifest
    ///
    fn copy_regions(manifest: &ImageManifest) {
        cprintln!("[update-reset] Copying MAN_2 To MAN_1");

        let dst = unsafe {
            let ptr = &mut MAN1_ORG as *mut u32;
            core::slice::from_raw_parts_mut(
                ptr,
                (core::mem::size_of::<ImageManifest>()
                    + manifest.fmc.size as usize
                    + manifest.runtime.size as usize
                    + 3)
                    / 4,
            )
        };

        let src = unsafe {
            let ptr = &mut MAN2_ORG as *mut u32;

            core::slice::from_raw_parts_mut(
                ptr,
                (core::mem::size_of::<ImageManifest>()
                    + manifest.fmc.size as usize
                    + manifest.runtime.size as usize
                    + 3)
                    / 4,
            )
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
    fn load_image(
        _env: &RomEnv,
        manifest: &ImageManifest,
        txn: MailboxRecvTxn,
    ) -> CaliptraResult<()> {
        cprintln!(
            "[update-reset] Loading Runtime at address 0x{:08x} len {}",
            manifest.runtime.load_addr,
            manifest.runtime.size
        );

        let runtime_dest = unsafe {
            let addr = (manifest.runtime.load_addr) as *mut u32;
            core::slice::from_raw_parts_mut(addr, manifest.runtime.size as usize / 4)
        };

        // Read data and complete the request.
        txn.read_data(runtime_dest);

        // Drop the tranaction and release the Mailbox lock after the image
        // has been successfully verified and loaded in memory
        drop(txn);

        Ok(())
    }

    /// Load the manifest
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    fn load_manifest(txn: &MailboxRecvTxn) -> CaliptraResult<ImageManifest> {
        let slice = unsafe {
            let ptr = &mut MAN2_ORG as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        txn.read_data(slice);

        ImageManifest::read_from(slice.as_bytes()).ok_or(err_u32!(ManifestReadFailure))
    }
}
