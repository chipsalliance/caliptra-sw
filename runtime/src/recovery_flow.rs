/*++

Licensed under the Apache-2.0 license.

File Name:

    recovery_flow.rs

Abstract:

    File contains the implementation of the recovery flow for MCU firmware and SoC manifest.

--*/

use crate::{
    authorize_and_stash::AuthorizeAndStashCmd, set_auth_manifest::AuthManifestSource, Drivers,
    SetAuthManifestCmd, IMAGE_AUTHORIZED,
};
use caliptra_auth_man_types::AuthorizationManifest;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::{
    cprintln,
    mailbox_api::{AuthorizeAndStashReq, ImageHashSource},
};
use caliptra_drivers::{printer::HexBytes, AesDmaMode, DmaRecovery};
use caliptra_kat::{CaliptraError, CaliptraResult};
use zerocopy::IntoBytes;

pub enum RecoveryFlow {}

impl RecoveryFlow {
    /// Load the SoC Manifest and MCU firwmare
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn recovery_flow(drivers: &mut Drivers) -> CaliptraResult<()> {
        const SOC_MANIFEST_INDEX: u32 = 1;
        const MCU_FIRMWARE_INDEX: u32 = 2;

        // we need to hold the mailbox lock since we are downloading to it
        if drivers.mbox.lock() {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }
        // use different scopes since we need to borrow drivers mutably and immutably
        let mut buffer = [0; size_of::<AuthorizationManifest>() / 4];
        let source = {
            let dma = &drivers.dma;
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.caliptra_base_axi_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                dma,
            );
            // need to make sure the device status is correct to load the next image
            dma_recovery.set_device_status(
                DmaRecovery::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE,
            )?;

            // download SoC manifest
            if drivers.soc_ifc.has_ss_staging_area() {
                dma_recovery.download_image_to_caliptra(SOC_MANIFEST_INDEX, &mut buffer)?;
                AuthManifestSource::Slice(buffer.as_bytes())
            } else {
                dma_recovery.download_image_to_mbox(SOC_MANIFEST_INDEX)?;
                AuthManifestSource::Mailbox
            }
        };

        SetAuthManifestCmd::set_auth_manifest(drivers, source, false)?;
        drivers.mbox.unlock();

        let digest = {
            let dma = &drivers.dma;
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.caliptra_base_axi_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                dma,
            );
            // need to make sure the device status is correct to load the next image
            dma_recovery.set_device_status(
                DmaRecovery::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE,
            )?;
            cprintln!("[rt] Uploading MCU firmware");
            let mcu_size_bytes =
                dma_recovery.download_image_to_mcu(MCU_FIRMWARE_INDEX, AesDmaMode::None)?;
            let mcu_size_bytes =
                dma_recovery.download_image_to_mcu(MCU_FIRMWARE_INDEX, AesDmaMode::None)?;
            cprintln!("[rt] Calculating MCU digest");
            dma_recovery.sha384_mcu_sram(
                &mut drivers.sha2_512_384_acc,
                0,
                mcu_size_bytes,
                AesDmaMode::None,
            )?
        };

        let digest: [u8; 48] = digest.into();
        cprintln!("[rt] Verifying MCU digest: {}", HexBytes(&digest));
        // verify the digest
        let auth_and_stash_req = AuthorizeAndStashReq {
            fw_id: [2, 0, 0, 0],
            measurement: digest,
            source: ImageHashSource::InRequest.into(),
            ..Default::default()
        };

        let auth_result = AuthorizeAndStashCmd::authorize_and_stash(drivers, &auth_and_stash_req)?;

        {
            let dma = &drivers.dma;
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.caliptra_base_axi_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                dma,
            );

            if auth_result != IMAGE_AUTHORIZED {
                dma_recovery.set_recovery_status(
                    DmaRecovery::RECOVERY_STATUS_IMAGE_AUTHENTICATION_ERROR,
                    0,
                )?;
                return Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH);
            }

            // notify MCU that it can boot its firmware
            //            drivers.soc_ifc.set_mcu_firmware_ready();

            // we're done with recovery
            dma_recovery.set_recovery_status(DmaRecovery::RECOVERY_STATUS_SUCCESSFUL, 0)?;
        }

        Ok(())
    }
}
