/*++

Licensed under the Apache-2.0 license.

File Name:

    activate_firmware.rs

Abstract:

    File contains ACTIVATE_FIRMWARE mailbox command.

--*/

use core::mem::offset_of;

use crate::authorize_and_stash::AuthorizeAndStashCmd;
use crate::drivers::{McuFwStatus, McuResetReason};
use crate::Drivers;
use crate::{manifest::find_metadata_entry, mutrefbytes};
use caliptra_api::mailbox::{
    ActivateFirmwareFlags, AuthAndStashFlags, AuthorizeAndStashReq, ImageHashSource,
};
use caliptra_auth_man_types::ImageMetadataFlags;
use caliptra_common::mailbox_api::{ActivateFirmwareReq, ActivateFirmwareResp, MailboxRespHeader};
use caliptra_drivers::dma::MCU_SRAM_OFFSET;
use caliptra_drivers::{
    AesDmaMode, AxiAddr, BootMode, CaliptraError, CaliptraResult, DmaMmio, DmaRecovery,
};
use caliptra_ureg::Mmio;

pub const MCI_TOP_REG_RESET_REASON_OFFSET: u32 = 0x38;
const MCI_TOP_REG_INTR_RF_BLOCK_OFFSET: u32 = 0x1000;
const NOTIF0_INTERNAL_INTR_R_OFFSET: u32 = MCI_TOP_REG_INTR_RF_BLOCK_OFFSET + 0x24;
const NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK: u32 = 0x2;
const RESET_STATUS_R_OFFSET: u32 = 0x3c;
const RESET_STATUS_MCU_RESET_MASK: u32 = 0x2;
const MAX_EXEC_GO_BIT_INDEX: u8 = 127;

pub struct ActivateFirmwareCmd;
impl ActivateFirmwareCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let fw_id_count: usize = {
            let err = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
            let offset = offset_of!(ActivateFirmwareReq, fw_id_count);
            u32::from_le_bytes(
                cmd_args
                    .get(offset..offset + 4)
                    .ok_or(err)?
                    .try_into()
                    .map_err(|_| err)?,
            )
            .try_into()
            .unwrap()
        };

        if (fw_id_count == 0) || (fw_id_count > ActivateFirmwareReq::MAX_FW_ID_COUNT) {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let mcu_image_size: usize = {
            let err = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
            let offset = offset_of!(ActivateFirmwareReq, mcu_fw_image_size);
            u32::from_le_bytes(
                cmd_args
                    .get(offset..offset + 4)
                    .ok_or(err)?
                    .try_into()
                    .map_err(|_| err)?,
            )
            .try_into()
            .unwrap()
        };

        let flags_raw: u32 = if cmd_args.len() >= core::mem::size_of::<ActivateFirmwareReq>() {
            // `flags` is the last field; older callers that pre-date this
            // field send a shorter buffer, in which case it defaults to zero.
            let err = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
            let offset = offset_of!(ActivateFirmwareReq, flags);
            u32::from_le_bytes(
                cmd_args
                    .get(offset..offset + 4)
                    .ok_or(err)?
                    .try_into()
                    .map_err(|_| err)?,
            )
        } else {
            0
        };
        // Reject unknown flag bits explicitly — `from_bits_truncate` (used by
        // our `From<u32>` impl below) would silently drop them.
        if flags_raw & !ActivateFirmwareFlags::all().bits() != 0 {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }
        let flags: ActivateFirmwareFlags = flags_raw.into();

        let mut images_to_activate_bitmap: [u32; 4] = [0; 4];
        for i in 0..fw_id_count {
            let err = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
            let offset = offset_of!(ActivateFirmwareReq, fw_ids) + (i * 4);
            let fw_id = u32::from_le_bytes(
                cmd_args
                    .get(offset..offset + 4)
                    .ok_or(err)?
                    .try_into()
                    .map_err(|_| err)?,
            );
            if fw_id == ActivateFirmwareReq::RESERVED0_IMAGE_ID
                || fw_id == ActivateFirmwareReq::RESERVED1_IMAGE_ID
            {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            if fw_id == ActivateFirmwareReq::MCU_IMAGE_ID && mcu_image_size == 0 {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            let image_metadata = find_metadata_entry(
                &drivers
                    .persistent_data
                    .get()
                    .fw
                    .auth_manifest_image_metadata_col,
                fw_id,
            )
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
            let exec_bit = ImageMetadataFlags(image_metadata.flags).exec_bit() as u8;
            // Check if exec_bit is valid
            // Note that bits 0 and 1 are reserved. Refer to
            // https://chipsalliance.github.io/caliptra-rtl/main/external-regs/?p=caliptra_top_reg.generic_and_fuse_reg.SS_GENERIC_FW_EXEC_CTRL%5B0%5D
            if exec_bit == 0 || exec_bit == 1 || exec_bit > MAX_EXEC_GO_BIT_INDEX {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            Self::set_bit(&mut images_to_activate_bitmap, exec_bit as usize);
        }

        Self::activate_fw(
            drivers,
            &images_to_activate_bitmap,
            mcu_image_size as u32,
            flags,
        )
        .map_err(|_| CaliptraError::IMAGE_VERIFIER_ACTIVATION_FAILED)?;

        let resp = mutrefbytes::<ActivateFirmwareResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        Ok(core::mem::size_of::<ActivateFirmwareResp>())
    }

    #[inline(never)]
    pub(crate) fn activate_fw(
        drivers: &mut Drivers,
        activate_bitmap: &[u32; 4],
        mcu_image_size: u32,
        flags: ActivateFirmwareFlags,
    ) -> Result<(), ()> {
        let mci_base_addr: AxiAddr = drivers.soc_ifc.mci_base_addr().into();
        let mut go_bitmap: [u32; 4] = [0; 4];

        // Get the current value of FW_EXEC_CTRL
        drivers.soc_ifc.get_ss_generic_fw_exec_ctrl(&mut go_bitmap);

        let mut temp_bitmap: [u32; 4] = [0; 4];

        let mcu_activate_requested =
            Self::is_bit_set(activate_bitmap, ActivateFirmwareReq::MCU_IMAGE_ID as usize);

        // INITIAL_ACTIVATE is the first-boot path after encrypted firmware:
        // MCU ROM has already loaded firmware into MCU SRAM via
        // RI_DOWNLOAD_ENCRYPTED_FIRMWARE and decrypted it in place via
        // CM_AES_GCM_DECRYPT_DMA. Skip the hitless-update dance and just
        // publish FW_EXEC_CTRL so MCI releases MCU from reset after MCU ROM
        // triggers its own warm reset.
        //
        // Gated on two conditions that together prove the SRAM contents are
        // trusted and that no hitless update is in flight:
        //   * BootMode::EncryptedFirmware was set by ROM (cannot be forged
        //     from a mailbox client).
        //   * FW_EXEC_CTRL[MCU] is currently 0 (MCU has not been activated
        //     yet — otherwise the caller is masquerading a real hitless
        //     update as an initial activation).
        let initial_activate = flags.contains(ActivateFirmwareFlags::INITIAL_ACTIVATE);
        if initial_activate {
            if !mcu_activate_requested {
                // The flag only makes sense paired with the MCU image.
                return Err(());
            }
            if drivers.persistent_data.get().rom.boot_mode != BootMode::EncryptedFirmware {
                return Err(());
            }
            if Self::is_bit_set(&go_bitmap, ActivateFirmwareReq::MCU_IMAGE_ID as usize) {
                return Err(());
            }
        }

        if mcu_activate_requested && !initial_activate {
            // If MCU image is being activated, set the RESET_REASON first before clearing the FW_EXEC_CTRL
            // to ensure the correct reset reason is captured after the reset.
            drivers.persistent_data.get_mut().fw.mcu_firmware_loaded =
                McuFwStatus::HitlessUpdateStarted.into();
            Drivers::set_mcu_reset_reason(drivers, McuResetReason::FwHitlessUpd);
        } else if mcu_activate_requested && initial_activate {
            // Tell MCI to record this as a firmware-boot reset (bit
            // `FwBootUpdReset`) so that after MCU ROM triggers its warm
            // reset and MCI releases MCU from BOOT_RST_MCU, MCU ROM reads
            // `RESET_REASON.FwBootUpdReset = 1` and dispatches to the
            // FwBoot flow (which jumps to the decrypted firmware in SRAM)
            // instead of re-running cold boot in a loop.
            Drivers::set_mcu_reset_reason(drivers, McuResetReason::FwBoot);
        }

        // Caliptra clears FW_EXEC_CTRL for all affected images. On
        // INITIAL_ACTIVATE the bits are already clear (we verified
        // FW_EXEC_CTRL[MCU] == 0 above), so this is a no-op and no
        // notif_cptra_mcu_reset_req_sts interrupt is raised toward MCU.
        for i in 0..4 {
            temp_bitmap[i] = go_bitmap[i] & !activate_bitmap[i];
        }

        drivers.soc_ifc.set_ss_generic_fw_exec_ctrl(&temp_bitmap);

        if mcu_activate_requested && !initial_activate {
            // MCU sees request from Caliptra and shall clear the interrupt status.
            // MCU sets RESET_REQUEST.mcu_req in MCI to request a reset.
            // MCI does an MCU halt req/ack handshake to ensure the MCU is idle
            // MCI asserts MCU reset (min reset time for MCU is until MIN_MCU_RST_COUNTER overflows)

            let dma = &drivers.dma;
            let mmio = &DmaMmio::new(mci_base_addr, dma);
            // Wait for MCU to clear interrupt
            let mut intr_status: u32 = 1;
            while intr_status != 0 {
                intr_status =
                    unsafe { mmio.read_volatile(NOTIF0_INTERNAL_INTR_R_OFFSET as *const u32) }
                        & NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK;
            }

            // Wait for MCI to assert reset
            let mut reset_status: u32 = 0;
            while reset_status == 0 {
                reset_status = unsafe { mmio.read_volatile(RESET_STATUS_R_OFFSET as *const u32) }
                    & RESET_STATUS_MCU_RESET_MASK;
            }

            // Caliptra will then have access to MCU SRAM Updatable Execution Region and update the FW image.
            let image_metadata = find_metadata_entry(
                &drivers
                    .persistent_data
                    .get()
                    .fw
                    .auth_manifest_image_metadata_col,
                ActivateFirmwareReq::MCU_IMAGE_ID,
            )
            .ok_or(())?;
            let dma_image = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.caliptra_base_axi_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                &drivers.dma,
            );
            let mcu_sram_addr: u64 =
                ((mci_base_addr.hi as u64) << 32) + (mci_base_addr.lo as u64) + MCU_SRAM_OFFSET;
            dma_image
                .transfer_payload_to_axi(
                    AxiAddr {
                        hi: image_metadata.image_staging_address.hi,
                        lo: image_metadata.image_staging_address.lo,
                    },
                    mcu_image_size,
                    AxiAddr {
                        hi: (mcu_sram_addr >> 32) as u32,
                        lo: mcu_sram_addr as u32,
                    },
                    false,
                    false,
                    AesDmaMode::None,
                )
                .map_err(|_| ())?;

            // Verify MCU after loading
            let auth_and_stash_req = AuthorizeAndStashReq {
                fw_id: ActivateFirmwareReq::MCU_IMAGE_ID.to_le_bytes(),
                measurement: [0; 48],
                source: ImageHashSource::LoadAddress.into(),
                flags: AuthAndStashFlags::SKIP_STASH.bits(),
                ..Default::default()
            };

            let pl0_pauser_locality = drivers
                .persistent_data
                .get()
                .rom
                .manifest1
                .header
                .pl0_pauser;
            AuthorizeAndStashCmd::authorize_and_stash(
                drivers,
                &auth_and_stash_req,
                pl0_pauser_locality,
            )
            .map(|_| ())
            .map_err(|_| ())?;

            drivers.persistent_data.get_mut().fw.mcu_firmware_loaded = McuFwStatus::Loaded.into();
        } else if mcu_activate_requested && initial_activate {
            // INITIAL_ACTIVATE: firmware is already in MCU SRAM and was
            // integrity-checked end-to-end during the encrypted-boot flow:
            //   * recovery_flow::sha384_mcu_sram verified the ciphertext
            //     against the auth-manifest digest before MCU ROM saw it.
            //   * CM_AES_GCM_DECRYPT_DMA verified the GCM tag before MCU
            //     ROM returned successfully from the decrypt mailbox call.
            // Skip reload + AuthorizeAndStash; just mark as loaded.
            drivers.persistent_data.get_mut().fw.mcu_firmware_loaded = McuFwStatus::Loaded.into();
        }

        for i in 0..4 {
            temp_bitmap[i] = go_bitmap[i] | activate_bitmap[i];
        }

        // Caliptra sets FW_EXEC_CTRL. On INITIAL_ACTIVATE this is the only
        // hardware effect of the entire command: it asserts
        // mcu_sram_fw_exec_region_lock so MCI's BOOT_RST_MCU state will
        // release MCU when MCU ROM next triggers its warm reset.
        drivers.soc_ifc.set_ss_generic_fw_exec_ctrl(&temp_bitmap);
        Ok(())
    }

    fn set_bit(bitmap: &mut [u32; 4], bit: usize) {
        if bit < core::mem::size_of_val(bitmap) * 8 {
            let idx = bit / 32;
            let offset = bit % 32;
            bitmap[idx] |= 1 << offset;
        }
    }

    fn is_bit_set(bitmap: &[u32; 4], bit: usize) -> bool {
        if bit < core::mem::size_of_val(bitmap) * 8 {
            let idx = bit / 32;
            let offset = bit % 32;
            (bitmap[idx] & (1 << offset)) != 0
        } else {
            false
        }
    }
}
