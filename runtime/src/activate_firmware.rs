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
use caliptra_api::mailbox::{AuthAndStashFlags, AuthorizeAndStashReq, ImageHashSource};
use caliptra_auth_man_types::ImageMetadataFlags;
use caliptra_common::mailbox_api::{ActivateFirmwareReq, ActivateFirmwareResp, MailboxRespHeader};
use caliptra_drivers::dma::MCU_SRAM_OFFSET;
use caliptra_drivers::{AxiAddr, CaliptraError, CaliptraResult, DmaMmio, DmaRecovery};
use ureg::{Mmio, MmioMut};

const MCI_TOP_REG_INTR_RF_BLOCK_OFFSET: u32 = 0x1000;
const NOTIF0_INTERNAL_INTR_R_OFFSET: u32 = MCI_TOP_REG_INTR_RF_BLOCK_OFFSET + 0x24;
const NOTIF0_INTR_TRIG_R_OFFSET: u32 = MCI_TOP_REG_INTR_RF_BLOCK_OFFSET + 0x34;
const NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK: u32 = 0x2;
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

        let mut images_to_activate_bitmap: [u32; 4] = [0; 4];
        for i in 0..fw_id_count {
            let offset = offset_of!(ActivateFirmwareReq, fw_ids) + (i * 4);
            if cmd_args.len() < offset + 4 {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            let fw_id = u32::from_le_bytes(
                cmd_args[offset..offset + 4]
                    .try_into()
                    .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
            );
            if fw_id == ActivateFirmwareReq::RESERVED0_IMAGE_ID
                || fw_id == ActivateFirmwareReq::RESERVED1_IMAGE_ID
            {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            if fw_id == ActivateFirmwareReq::MCU_IMAGE_ID && mcu_image_size == 0 {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            let exec_bit = Self::get_exec_bit(drivers, fw_id)
                .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
            // Check if exec_bit is valid
            // Note that bits 0 and 1 are reserved. Refer to
            // https://chipsalliance.github.io/caliptra-rtl/main/external-regs/?p=caliptra_top_reg.generic_and_fuse_reg.SS_GENERIC_FW_EXEC_CTRL%5B0%5D
            if exec_bit == 0 || exec_bit == 1 || exec_bit > MAX_EXEC_GO_BIT_INDEX {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            Self::set_bit(&mut images_to_activate_bitmap, fw_id as usize);
        }

        Self::activate_fw(drivers, &images_to_activate_bitmap, mcu_image_size as u32)
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
    ) -> Result<(), ()> {
        let mci_base_addr: AxiAddr = drivers.soc_ifc.mci_base_addr().into();
        let mut go_bitmap: [u32; 4] = [0; 4];

        // Get the current value of FW_EXEC_CTRL
        drivers.soc_ifc.get_ss_generic_fw_exec_ctrl(&mut go_bitmap);

        let mut temp_bitmap: [u32; 4] = [0; 4];

        // Caliptra clears FW_EXEC_CTRL for all affected images
        for i in 0..4 {
            temp_bitmap[i] = go_bitmap[i] & !activate_bitmap[i];
        }

        // Leave MCU image bit as is, we will set it later after the reset_reason is set to avoid race condition
        // between Caliptra and MCU
        if Self::is_bit_set(&go_bitmap, ActivateFirmwareReq::MCU_IMAGE_ID as usize) {
            Self::set_bit(&mut temp_bitmap, ActivateFirmwareReq::MCU_IMAGE_ID as usize);
        }

        drivers.soc_ifc.set_ss_generic_fw_exec_ctrl(&temp_bitmap);

        if Self::is_bit_set(activate_bitmap, ActivateFirmwareReq::MCU_IMAGE_ID as usize) {
            // MCU sees request from Caliptra and shall clear the interrupt status.
            // MCU sets RESET_REQUEST.mcu_req in MCI to request a reset.
            // MCI does an MCU halt req/ack handshake to ensure the MCU is idle
            // MCI asserts MCU reset (min reset time for MCU is until MIN_MCU_RST_COUNTER overflows)

            drivers.persistent_data.get_mut().mcu_firmware_loaded =
                McuFwStatus::HitlessUpdateStarted.into();
            Drivers::set_mcu_reset_reason(drivers, McuResetReason::FwHitlessUpd);

            let dma = &drivers.dma;
            let mmio = &DmaMmio::new(mci_base_addr, dma);

            // Trigger MCU reset request
            unsafe {
                mmio.write_volatile(
                    NOTIF0_INTR_TRIG_R_OFFSET as *mut u32,
                    NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK,
                );
            }

            // Wait for MCU to clear interrupt
            let mut intr_status: u32 = 1;
            while intr_status != 0 {
                intr_status =
                    unsafe { mmio.read_volatile(NOTIF0_INTERNAL_INTR_R_OFFSET as *const u32) }
                        & NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK;
            }

            // Clear FW_EXEC_CTRL[2]
            Self::clear_bit(&mut temp_bitmap, ActivateFirmwareReq::MCU_IMAGE_ID as usize);
            drivers.soc_ifc.set_ss_generic_fw_exec_ctrl(&temp_bitmap);

            // Wait for MCU to clear interrupt
            let mut intr_status: u32 = 1;
            while intr_status != 0 {
                intr_status =
                    unsafe { mmio.read_volatile(NOTIF0_INTERNAL_INTR_R_OFFSET as *const u32) }
                        & NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK;
            }

            // Caliptra will then have access to MCU SRAM Updatable Execution Region and update the FW image.
            let (_, image_staging_address) =
                Self::get_loading_staging_address(drivers, ActivateFirmwareReq::MCU_IMAGE_ID)?;
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
                        hi: image_staging_address.hi,
                        lo: image_staging_address.lo,
                    },
                    mcu_image_size,
                    AxiAddr {
                        hi: (mcu_sram_addr >> 32) as u32,
                        lo: mcu_sram_addr as u32,
                    },
                    false,
                    false,
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

            AuthorizeAndStashCmd::authorize_and_stash(drivers, &auth_and_stash_req)
                .map(|_| ())
                .map_err(|_| ())?;

            drivers.persistent_data.get_mut().mcu_firmware_loaded = McuFwStatus::Loaded.into();
        }

        for i in 0..4 {
            temp_bitmap[i] = go_bitmap[i] | activate_bitmap[i];
        }

        // Caliptra sets FW_EXEC_CTRL
        drivers.soc_ifc.set_ss_generic_fw_exec_ctrl(&temp_bitmap);
        Ok(())
    }

    #[inline(never)]
    pub(crate) fn get_exec_bit(drivers: &Drivers, image_id: u32) -> Result<u8, ()> {
        // Get the exec bit for the given image ID
        let persistent_data = drivers.persistent_data.get();
        let auth_manifest_image_metadata_col = &persistent_data.auth_manifest_image_metadata_col;
        if let Some(metadata_entry) =
            find_metadata_entry(auth_manifest_image_metadata_col, image_id)
        {
            Ok(ImageMetadataFlags(metadata_entry.flags).exec_bit() as u8)
        } else {
            Err(())
        }
    }

    #[inline(never)]
    pub(crate) fn get_loading_staging_address(
        drivers: &Drivers,
        image_id: u32,
    ) -> Result<(AxiAddr, AxiAddr), ()> {
        // Get the staging address for the given image ID
        let persistent_data = drivers.persistent_data.get();
        let auth_manifest_image_metadata_col = &persistent_data.auth_manifest_image_metadata_col;
        if let Some(metadata_entry) =
            find_metadata_entry(auth_manifest_image_metadata_col, image_id)
        {
            Ok((
                AxiAddr {
                    hi: metadata_entry.image_load_address.hi,
                    lo: metadata_entry.image_load_address.lo,
                },
                AxiAddr {
                    hi: metadata_entry.image_staging_address.hi,
                    lo: metadata_entry.image_staging_address.lo,
                },
            ))
        } else {
            Err(())
        }
    }

    fn set_bit(bitmap: &mut [u32; 4], bit: usize) {
        if bit < core::mem::size_of_val(bitmap) * 8 {
            let idx = bit / 32;
            let offset = bit % 32;
            bitmap[idx] |= 1 << offset;
        }
    }

    fn clear_bit(bitmap: &mut [u32; 4], bit: usize) {
        if bit < core::mem::size_of_val(bitmap) * 8 {
            let idx = bit / 32;
            let offset = bit % 32;
            bitmap[idx] &= !(1 << offset);
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
