/*++

Licensed under the Apache-2.0 license.

File Name:

    recovery_flow.rs

Abstract:

    File contains the implementation of the recovery flow for MCU firmware and SoC manifest.

--*/

use crate::{
    authorize_and_stash::AuthorizeAndStashCmd,
    drivers::{McuFwStatus, McuResetReason},
    set_auth_manifest::AuthManifestSource,
    Drivers, SetAuthManifestCmd, IMAGE_AUTHORIZED,
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
    fn dma_recovery(drivers: &Drivers) -> DmaRecovery<'_> {
        DmaRecovery::new(
            drivers.soc_ifc.recovery_interface_base_addr().into(),
            drivers.soc_ifc.caliptra_base_axi_addr().into(),
            drivers.soc_ifc.mci_base_addr().into(),
            &drivers.dma,
        )
    }

    fn set_recovery_boot_failure(
        drivers: &Drivers,
        image_idx: u32,
        recovery_reason: u32,
    ) -> CaliptraResult<()> {
        let dma_recovery = Self::dma_recovery(drivers);
        dma_recovery.set_recovery_status(
            DmaRecovery::RECOVERY_STATUS_IMAGE_AUTHENTICATION_ERROR,
            image_idx,
        )?;
        dma_recovery.set_boot_failure_reason(recovery_reason)
    }

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
                drivers.soc_ifc.caliptra_base_axi_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                dma,
            );
            // need to make sure the device status is correct to load the next image
            dma_recovery.set_device_status(
                DmaRecovery::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE,
            )?;

            // download SoC manifest
            dma_recovery.download_image_to_mbox(SOC_MANIFEST_INDEX)
        };
        result?;

        if let Err(err) =
            SetAuthManifestCmd::set_auth_manifest(drivers, AuthManifestSource::Mailbox, false)
        {
            let recovery_reason = DmaRecovery::recovery_reason_from_auth_manifest_error(err);
            Self::set_recovery_boot_failure(drivers, SOC_MANIFEST_INDEX, recovery_reason)?;
            return Err(err);
        }
        drivers.mbox.unlock();

        let digest = {
            let dma = &drivers.dma;
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.caliptra_base_axi_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                dma,
            );
            // Reset the RECOVERY_CTRL register Activate Recovery Image field by writing 0x1.
            dma_recovery.reset_recovery_ctrl_activate_rec_img()?;
            // Reset the Indirect FIFO control so that payload_available is reset.
            dma_recovery.reset_indirect_fifo_ctrl()?;

            // need to make sure the device status is correct to load the next image
            dma_recovery.set_device_status(
                DmaRecovery::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE,
            )?;
            cprintln!("[rt] Uploading MCU firmware");
            let mcu_size_bytes = dma_recovery.download_image_to_mcu(MCU_FIRMWARE_INDEX)?;
            cprintln!("[rt] Calculating MCU digest");
            dma_recovery.sha384_mcu_sram(&mut drivers.sha2_512_384_acc, mcu_size_bytes)?
        };

        let pl0_pauser_locality = drivers.persistent_data.get().manifest1.header.pl0_pauser;

        let digest: [u8; 48] = digest.into();
        cprintln!("[rt] Verifying MCU digest: {}", HexBytes(&digest));
        // verify the digest
        let auth_and_stash_req = AuthorizeAndStashReq {
            fw_id: [2, 0, 0, 0],
            measurement: digest,
            source: ImageHashSource::InRequest.into(),
            // We want to make sure this measurement is not skipped.
            flags: 0,
            ..Default::default()
        };

        let auth_result = match AuthorizeAndStashCmd::authorize_and_stash(
            drivers,
            &auth_and_stash_req,
            pl0_pauser_locality,
        ) {
            Ok(auth_result) => auth_result,
            Err(err) => {
                Self::set_recovery_boot_failure(
                    drivers,
                    MCU_FIRMWARE_INDEX,
                    DmaRecovery::RECOVERY_REASON_MAIN_FIRMWARE_AUTHENTICATION_FAILURE,
                )?;
                return Err(err);
            }
        };

        {
            let dma = &drivers.dma;
            let mci_base_addr = drivers.soc_ifc.mci_base_addr().into();
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.caliptra_base_axi_addr().into(),
                mci_base_addr,
                dma,
            );

            if auth_result != IMAGE_AUTHORIZED {
                Self::set_recovery_boot_failure(
                    drivers,
                    MCU_FIRMWARE_INDEX,
                    DmaRecovery::RECOVERY_REASON_MAIN_FIRMWARE_AUTHENTICATION_FAILURE,
                )?;
                return Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH);
            }

            // we're done with recovery
            dma_recovery.set_recovery_status(DmaRecovery::RECOVERY_STATUS_SUCCESSFUL, 0)?;
        }

        // notify MCU that it can boot its firmware
        drivers.persistent_data.get_mut().mcu_firmware_loaded = McuFwStatus::Loaded.into();
        Drivers::request_mcu_reset(drivers, McuResetReason::FwBoot);

        Ok(())
    }
}
