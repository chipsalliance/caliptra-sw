/*++

Licensed under the Apache-2.0 license.

File Name:

    recovery_flow.rs

Abstract:

    File contains the implementation of the recovery flow for MCU firmware and SoC manifest.

--*/

use crate::{
    activate_firmware::MCI_TOP_REG_RESET_REASON_OFFSET,
    authorize_and_stash::AuthorizeAndStashCmd,
    drivers::{McuFwStatus, McuResetReason},
    Drivers, SetAuthManifestCmd, IMAGE_AUTHORIZED,
};
use caliptra_auth_man_types::AuthorizationManifest;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::{
    cprintln,
    mailbox_api::{AuthorizeAndStashReq, ImageHashSource},
};
use caliptra_drivers::{printer::HexBytes, AesDmaMode, BootMode, DmaMmio, DmaRecovery};
use caliptra_kat::{CaliptraError, CaliptraResult};
use ureg::MmioMut;
use zerocopy::IntoBytes;

const FW_BOOT_UPD_RESET: u32 = 0b1 << 1;

pub enum RecoveryFlow {}

impl RecoveryFlow {
    /// Load the SoC Manifest and MCU firwmare
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn recovery_flow(drivers: &mut Drivers) -> CaliptraResult<()> {
        const SOC_MANIFEST_INDEX: u32 = 1;
        const MCU_FIRMWARE_INDEX: u32 = 2;

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
            dma_recovery.download_image_to_caliptra(SOC_MANIFEST_INDEX, &mut buffer)?;
            buffer.as_bytes()
        };

        SetAuthManifestCmd::set_auth_manifest(drivers, source, false)?;

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
            let mci_base_addr = drivers.soc_ifc.mci_base_addr().into();
            let dma = &drivers.dma;
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.caliptra_base_axi_addr().into(),
                mci_base_addr,
                dma,
            );

            if auth_result != IMAGE_AUTHORIZED {
                dma_recovery.set_recovery_status(
                    DmaRecovery::RECOVERY_STATUS_IMAGE_AUTHENTICATION_ERROR,
                    0,
                )?;
                return Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH);
            }

            // Check if firmware was loaded encrypted - if so, skip MCU activation
            // MCU ROM will decrypt the firmware and send CM_ACTIVATE_FIRMWARE command
            let boot_mode = drivers.persistent_data.get().rom.boot_mode;
            if boot_mode == BootMode::EncryptedFirmware {
                cprintln!("[rt] Encrypted firmware boot mode - skipping MCU activation");
                // we're done with recovery, but MCU will handle its own boot after decryption
                dma_recovery.set_recovery_status(DmaRecovery::RECOVERY_STATUS_SUCCESSFUL, 0)?;
                return Ok(());
            }

            // Caliptra sets RESET_REASON.FW_BOOT_UPD_RESET
            let mmio = &DmaMmio::new(mci_base_addr, dma);
            unsafe {
                mmio.write_volatile(
                    MCI_TOP_REG_RESET_REASON_OFFSET as *mut u32,
                    FW_BOOT_UPD_RESET,
                )
            };

            cprintln!("[rt] Setting MCU firmware ready");
            // notify MCU that it can boot its firmware
            drivers.soc_ifc.set_mcu_firmware_ready();
            cprintln!(
                "[rt] Setting MCU firmware ready: {:08x}{:08x}{:08x}{:08x}",
                drivers.soc_ifc.fw_ctrl(0),
                drivers.soc_ifc.fw_ctrl(1),
                drivers.soc_ifc.fw_ctrl(2),
                drivers.soc_ifc.fw_ctrl(3)
            );

            // we're done with recovery
            dma_recovery.set_recovery_status(DmaRecovery::RECOVERY_STATUS_SUCCESSFUL, 0)?;
        }

        // notify MCU that it can boot its firmware
        drivers.persistent_data.get_mut().fw.mcu_firmware_loaded = McuFwStatus::Loaded.into();
        Drivers::request_mcu_reset(drivers, McuResetReason::FwBoot);

        Ok(())
    }
}
