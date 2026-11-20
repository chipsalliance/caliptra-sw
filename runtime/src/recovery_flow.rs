/*++

Licensed under the Apache-2.0 license.

File Name:

    recovery_flow.rs

Abstract:

    File contains the implementation of the recovery flow for MCU firmware and SoC manifest.

--*/

use crate::{
    activate_firmware::MCI_TOP_REG_RESET_REASON_OFFSET,
    authorize_and_stash::{
        AuthorizeAndStashCmd, IMAGE_AUTHORIZED_OWNER_ONLY, IMAGE_AUTHORIZED_VENDOR_OWNER,
    },
    drivers::{McuFwStatus, McuResetReason},
    set_auth_manifest::AuthManifestUpdateMode,
    stash_measurement::MCU_RT_RESERVED_FW_ID,
    Drivers, SetAuthManifestCmd,
};
use caliptra_auth_man_types::AuthorizationManifest;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::{
    cprintln,
    mailbox_api::{AuthorizeAndStashReq, ImageHashSource},
};
use caliptra_drivers::{
    printer::HexBytes, AesDmaMode, BootMode, Dma, DmaMmio, DmaRecovery, SocIfc,
};
use caliptra_kat::{CaliptraError, CaliptraResult};
use caliptra_ureg::MmioMut;
use zerocopy::IntoBytes;

const FW_BOOT_UPD_RESET: u32 = 0b1 << 1;

const SOC_MANIFEST_INDEX: u32 = 1;
const MCU_FIRMWARE_INDEX: u32 = 2;

/// Error from a recovery flow stage. `recovery_flow` passes the index of the
/// image the stage worked on to `report_failure`, and `report_failure` writes
/// the matching RECOVERY_STATUS.
enum RecoveryFailure {
    /// `report_failure` writes `RECOVERY_STATUS_FAILED` ('Recovery failed').
    Other(CaliptraError),
    /// `report_failure` writes `RECOVERY_STATUS_IMAGE_AUTHENTICATION_ERROR`,
    /// then `recovery_reason` as the boot failure reason in DEVICE_STATUS.
    Authentication {
        error: CaliptraError,
        recovery_reason: u32,
    },
}

/// A `CaliptraError` that a stage propagates with `?` is not an
/// authentication failure, so `report_failure` writes `RECOVERY_STATUS_FAILED`.
impl From<CaliptraError> for RecoveryFailure {
    fn from(err: CaliptraError) -> Self {
        RecoveryFailure::Other(err)
    }
}

pub enum RecoveryFlow {}

impl RecoveryFlow {
    /// Builds a `DmaRecovery` over the recovery interface, Caliptra and MCI
    /// base addresses. Takes the two fields it needs rather than all of
    /// `Drivers`, so a caller can still borrow another field mutably while the
    /// handle is alive.
    fn dma_recovery<'a>(soc_ifc: &SocIfc, dma: &'a Dma) -> DmaRecovery<'a> {
        DmaRecovery::new(
            soc_ifc.recovery_interface_base_addr().into(),
            soc_ifc.caliptra_base_axi_addr().into(),
            soc_ifc.mci_base_addr().into(),
            dma,
        )
    }

    /// Writes the failure status to RECOVERY_STATUS, so the Recovery Agent
    /// stops polling a device that has stopped, and returns the error for
    /// CPTRA_FW_ERROR_FATAL.
    ///
    /// For `RecoveryFailure::Other`, the stage error says why the recovery
    /// failed, so `report_failure` returns the stage error whether the 0xC
    /// 'Recovery failed' write succeeds or fails.
    ///
    /// For `RecoveryFailure::Authentication`, `report_failure` returns the
    /// authentication error, or the error of a failed RECOVERY_STATUS or
    /// DEVICE_STATUS write. When the 0xD 'Recovery image authentication error'
    /// write fails, RECOVERY_STATUS still shows 0x2 'Booting recovery image',
    /// so `report_failure` writes 0xC 'Recovery failed' as a fallback, and the
    /// Recovery Agent stops polling when that write succeeds.
    fn report_failure(
        drivers: &Drivers,
        image_idx: u32,
        failure: RecoveryFailure,
    ) -> CaliptraError {
        let dma_recovery = Self::dma_recovery(&drivers.soc_ifc, &drivers.dma);
        match failure {
            RecoveryFailure::Other(error) => {
                let _ = dma_recovery
                    .set_recovery_status(DmaRecovery::RECOVERY_STATUS_FAILED, image_idx);
                error
            }
            RecoveryFailure::Authentication {
                error,
                recovery_reason,
            } => {
                if let Err(write_err) = dma_recovery.set_recovery_status(
                    DmaRecovery::RECOVERY_STATUS_IMAGE_AUTHENTICATION_ERROR,
                    image_idx,
                ) {
                    let _ = dma_recovery
                        .set_recovery_status(DmaRecovery::RECOVERY_STATUS_FAILED, image_idx);
                    return write_err;
                }
                match dma_recovery.set_boot_failure_reason(recovery_reason) {
                    Ok(()) => error,
                    Err(write_err) => write_err,
                }
            }
        }
    }

    /// Loads the SoC manifest and the MCU firmware. Each stage works on one
    /// image, so `recovery_flow` passes the index of that image to
    /// `report_failure` when the stage fails.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub(crate) fn recovery_flow(drivers: &mut Drivers) -> CaliptraResult<()> {
        Self::load_soc_manifest(drivers)
            .map_err(|failure| Self::report_failure(drivers, SOC_MANIFEST_INDEX, failure))?;
        Self::load_mcu_firmware(drivers)
            .map_err(|failure| Self::report_failure(drivers, MCU_FIRMWARE_INDEX, failure))
    }

    /// Downloads the SoC manifest and sets it as the authorization manifest.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn load_soc_manifest(drivers: &mut Drivers) -> Result<(), RecoveryFailure> {
        // use different scopes since we need to borrow drivers mutably and immutably
        let mut buffer = [0; size_of::<AuthorizationManifest>() / 4];
        let source = {
            let dma_recovery = Self::dma_recovery(&drivers.soc_ifc, &drivers.dma);
            // need to make sure the device status is correct to load the next image
            dma_recovery.set_device_status(
                DmaRecovery::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE,
            )?;

            // download SoC manifest
            dma_recovery.download_image_to_caliptra(SOC_MANIFEST_INDEX, &mut buffer)?;
            buffer.as_bytes()
        };

        SetAuthManifestCmd::set_auth_manifest(
            drivers,
            source,
            false,
            AuthManifestUpdateMode::CreateMissingDpeContexts,
        )
        .map_err(|error| RecoveryFailure::Authentication {
            error,
            recovery_reason: DmaRecovery::recovery_reason_from_auth_manifest_error(error),
        })
    }

    /// Downloads the MCU firmware into MCU SRAM and authorizes its digest. For
    /// plain firmware, `load_mcu_firmware` then requests an MCU reset to boot
    /// the firmware. For encrypted firmware, `load_mcu_firmware` records the
    /// ciphertext size and digest and returns, and the MCU ROM decrypts the
    /// image and sends ACTIVATE_FIRMWARE.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn load_mcu_firmware(drivers: &mut Drivers) -> Result<(), RecoveryFailure> {
        let (digest, mcu_size_bytes) = {
            let dma_recovery = Self::dma_recovery(&drivers.soc_ifc, &drivers.dma);
            // Reset the RECOVERY_CTRL register Activate Recovery Image field by writing 0x1.
            dma_recovery.reset_recovery_ctrl_activate_rec_img()?;
            // Reset the Indirect FIFO control so that payload_available is reset.
            dma_recovery.reset_indirect_fifo_ctrl()?;

            // need to make sure the device status is correct to load the next image
            dma_recovery.set_device_status(
                DmaRecovery::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE,
            )?;

            // Signal that we are awaiting the MCU firmware image. and wait
            // for payload_available to deassert. This helps avoid a race
            // condition in the MCU ROM AXI bypass mode where MCU ROM needs
            // to clear REC_PAYLOAD_DONE.
            dma_recovery.set_recovery_status(
                DmaRecovery::RECOVERY_STATUS_AWAITING_RECOVERY_IMAGE,
                MCU_FIRMWARE_INDEX,
            )?;
            dma_recovery.wait_for_payload_not_available();

            let mcu_size_bytes =
                dma_recovery.download_image_to_mcu(MCU_FIRMWARE_INDEX, AesDmaMode::None)?;
            let digest = dma_recovery.sha384_mcu_sram(
                &mut drivers.sha2_512_384_acc,
                0,
                mcu_size_bytes,
                AesDmaMode::None,
            )?;
            (digest, mcu_size_bytes)
        };

        let pl0_pauser_locality = drivers
            .persistent_data
            .get()
            .rom
            .manifest1
            .header
            .pl0_pauser;

        let digest: [u8; 48] = digest.into();
        cprintln!("[rt] Verifying MCU digest: {}", HexBytes(&digest));
        // verify the digest
        let soc_manifest_svn = drivers.persistent_data.get().fw.dpe.soc_manifest_svn;
        let auth_and_stash_req = AuthorizeAndStashReq {
            fw_id: MCU_RT_RESERVED_FW_ID,
            measurement: digest,
            source: ImageHashSource::InRequest.into(),
            // We want to make sure this measurement is not skipped.
            flags: 0,
            svn: soc_manifest_svn,
            ..Default::default()
        };

        let auth_result = AuthorizeAndStashCmd::authorize_and_stash(
            drivers,
            &auth_and_stash_req,
            pl0_pauser_locality,
        )
        .map_err(|error| RecoveryFailure::Authentication {
            error,
            recovery_reason: DmaRecovery::RECOVERY_REASON_MAIN_FIRMWARE_AUTHENTICATION_FAILURE,
        })?;

        {
            let mci_base_addr = drivers.soc_ifc.mci_base_addr().into();
            let dma = &drivers.dma;
            let dma_recovery = Self::dma_recovery(&drivers.soc_ifc, dma);

            if auth_result != IMAGE_AUTHORIZED_VENDOR_OWNER
                && auth_result != IMAGE_AUTHORIZED_OWNER_ONLY
            {
                return Err(RecoveryFailure::Authentication {
                    error: CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH,
                    recovery_reason:
                        DmaRecovery::RECOVERY_REASON_MAIN_FIRMWARE_AUTHENTICATION_FAILURE,
                });
            }

            // Check if firmware was loaded encrypted - if so, skip MCU activation
            // MCU ROM will decrypt the firmware and send the ACTIVATE_FIRMWARE
            // mailbox command with the INITIAL_ACTIVATE flag once it is ready
            // for Caliptra to publish FW_EXEC_CTRL[MCU].
            let boot_mode = drivers.persistent_data.get().rom.boot_mode;
            if boot_mode == BootMode::EncryptedFirmware {
                // The image in MCU SRAM is ciphertext || 16-byte GCM tag.
                // CM_AES_GCM_DECRYPT_DMA expects the tag as a separate field
                // and verifies the SHA-384 against only the ciphertext portion,
                // so strip the tag from both the size and the digest.
                const GCM_TAG_SIZE: u32 = 16;
                let ciphertext_size = mcu_size_bytes
                    .checked_sub(GCM_TAG_SIZE)
                    .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
                let ciphertext_digest = dma_recovery.sha384_mcu_sram(
                    &mut drivers.sha2_512_384_acc,
                    0,
                    ciphertext_size,
                    AesDmaMode::None,
                )?;
                drivers.mcu_fw_info.size = ciphertext_size;
                drivers.mcu_fw_info.sha384 = ciphertext_digest.into();

                // we're done with recovery, but MCU will handle its own boot after decryption
                dma_recovery.set_recovery_status(DmaRecovery::RECOVERY_STATUS_SUCCESSFUL, 0)?;
                dma_recovery.set_device_status_with_recovery_reason(
                    DmaRecovery::DEVICE_STATUS_HEALTHY,
                    0,
                )?;
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

            // notify MCU that it can boot its firmware
            drivers.soc_ifc.set_mcu_firmware_ready();

            // leave recovery status open in case MCU wants to load additional images
        }

        // notify MCU that it can boot its firmware
        drivers.persistent_data.get_mut().fw.mcu_firmware_loaded = McuFwStatus::Loaded.into();
        Drivers::request_mcu_reset(drivers, McuResetReason::FwBoot);

        Ok(())
    }
}
