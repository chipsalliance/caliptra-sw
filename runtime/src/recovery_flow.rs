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
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::{
    cprintln,
    mailbox_api::{AuthorizeAndStashReq, ImageHashSource},
};
use caliptra_drivers::{printer::HexBytes, DmaRecovery};
use caliptra_kat::{CaliptraError, CaliptraResult};

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
        let result = {
            let dma = &drivers.dma;
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                dma,
            );
            // need to make sure the device status is correct to load the next image
            dma_recovery.set_device_status(DmaRecovery::DEVICE_STATUS_RUNNING_RECOVERY_IMAGE)?;

            // download SoC manifest
            dma_recovery.download_image_to_mbox(SOC_MANIFEST_INDEX, false)
        };
        drivers.mbox.unlock();
        result?;

        SetAuthManifestCmd::set_auth_manifest(drivers, AuthManifestSource::Mailbox)?;

        let digest = {
            let dma = &drivers.dma;
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                dma,
            );
            // need to make sure the device status is correct to load the next image
            dma_recovery.set_device_status(DmaRecovery::DEVICE_STATUS_RUNNING_RECOVERY_IMAGE)?;
            cprintln!("[rt] Uploading MCU firmware");
            let mcu_size_bytes = dma_recovery.download_image_to_mcu(MCU_FIRMWARE_INDEX, false)?;
            cprintln!("[rt] Calculating MCU digest");
            dma_recovery.sha384_mcu_sram(&mut drivers.sha2_512_384_acc, mcu_size_bytes)?
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

            // notify MCU that it can boot
            // [TODO][CAP2]: get the correct value for this
            dma_recovery.set_mci_flow_status(123)?;

            // we're done with recovery
            dma_recovery.set_recovery_status(DmaRecovery::RECOVERY_STATUS_SUCCESSFUL, 0)?;
        }

        Ok(())
    }
}
