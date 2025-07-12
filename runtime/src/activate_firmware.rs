/*++

Licensed under the Apache-2.0 license.

File Name:

    activate_firmware.rs

Abstract:

    File contains ACTIVATE_FIRMWARE mailbox command.

--*/

use core::mem::offset_of;

use crate::Drivers;
use crate::{manifest::find_metadata_entry, mutrefbytes};
use caliptra_common::cprintln;
use caliptra_common::mailbox_api::{ActivateFirmwareReq, ActivateFirmwareResp, MailboxRespHeader};
use caliptra_drivers::{AxiAddr, CaliptraError, CaliptraResult, DmaMmio, DmaRecovery};
use ureg::{Mmio, MmioMut};

const MCI_TOP_REG_RESET_REASON_OFFSET: u32 = 0x38;
const FW_HITLESS_UPD_RESET_MASK: u32 = 0x1;
const MCI_TOP_REG_INTR_RF_BLOCK_OFFSET: u32 = 0x1000;
const NOTIF0_INTERNAL_INTR_R_OFFSET: u32 = MCI_TOP_REG_INTR_RF_BLOCK_OFFSET + 0x24;
const NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK: u32 = 0x2;
const SOC_MCI_TOP_MCI_REG_RESET_STATUS_OFFSET: u32 = 0x3c;
const MCU_RESET_REQ_STS_MASK: u32 = 0x2;

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
            if fw_id > ActivateFirmwareReq::MAX_FW_ID_VAL {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            if fw_id == ActivateFirmwareReq::RESERVED0_IMAGE_ID
                || fw_id == ActivateFirmwareReq::RESERVED1_IMAGE_ID
            {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            if fw_id == ActivateFirmwareReq::MCU_IMAGE_ID && mcu_image_size == 0 {
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
        cprintln!(
            "ActivateFirmwareCmd::activate_fw: activate_bitmap={:?}, mcu_image_size={}",
            activate_bitmap, mcu_image_size
        );
        let mci_base_addr: AxiAddr = drivers.soc_ifc.mci_base_addr().into();
        let dma = &drivers.dma;
        let mut go_bitmap: [u32; 4] = [0; 4];

        // Get the current value of FW_EXEC_CTRL
        drivers.soc_ifc.get_ss_generic_fw_exec_ctrl(&mut go_bitmap);

        let mut temp_bitmap: [u32; 4] = [0; 4];

        // Caliptra clears FW_EXEC_CTRL[2] for all affected images.
        for i in 0..4 {
            temp_bitmap[i] = go_bitmap[i] & !activate_bitmap[i];
        }

        drivers.soc_ifc.set_ss_generic_fw_exec_ctrl(&temp_bitmap);

        if Self::is_bit_set(activate_bitmap, ActivateFirmwareReq::MCU_IMAGE_ID as usize) {
            // MCU sees request from Caliptra and shall clear the interrupt status.
            // MCU sets RESET_REQUEST.mcu_req in MCI to request a reset.
            // MCI does an MCU halt req/ack handshake to ensure the MCU is idle
            // MCI asserts MCU reset (min reset time for MCU is until MIN_MCU_RST_COUNTER overflows)

            let mmio = &DmaMmio::new(mci_base_addr, dma);

            // Wait for MCU to clear interrupt
            let mut intr_status: u32 = 1;
            while intr_status != 0 {
                intr_status =
                    unsafe { mmio.read_volatile(NOTIF0_INTERNAL_INTR_R_OFFSET as *const u32) }
                        & NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK;
            }

            // Wait until RESET_STATUS.MCU_RESET_STS is set
            let mut reset_status: u32 = 0;
            while reset_status == 0 {
                reset_status = unsafe {
                    mmio.read_volatile(SOC_MCI_TOP_MCI_REG_RESET_STATUS_OFFSET as *const u32)
                        & MCU_RESET_REQ_STS_MASK
                };
            }

            cprintln!(
                "ActivateFirmwareCmd::activate_fw: MCU reset requested, resetting MCU..."
            );

            // Caliptra will then have access to MCU SRAM Updatable Execution Region and update the FW image.
            let (image_load_address, image_staging_address) =
                Self::get_loading_staging_address(drivers, ActivateFirmwareReq::MCU_IMAGE_ID)?;

            cprintln!(
                "ActivateFirmwareCmd::activate_fw: MCU image load address: hi={:#x}, lo={:#x}; staging address: hi={:#x}, lo={:#x}",
                image_load_address.hi, image_load_address.lo, image_staging_address.hi, image_staging_address.lo
            );
            let dma_image = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.caliptra_base_axi_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                &drivers.dma,
            );
            dma_image
                .transfer_payload_to_axi(
                    AxiAddr {
                        hi: image_staging_address.hi,
                        lo: image_staging_address.lo,
                    },
                    mcu_image_size,
                    AxiAddr {
                        hi: image_load_address.hi,
                        lo: image_load_address.lo,
                    },
                    false,
                    true,
                )
                .map_err(|_| ())?;

            // Caliptra sets RESET_REASON.FW_HITLESS_UPD_RESET
            unsafe {
                mmio.write_volatile(
                    MCI_TOP_REG_RESET_REASON_OFFSET as *mut u32,
                    FW_HITLESS_UPD_RESET_MASK,
                )
            };
        }

        for i in 0..4 {
            temp_bitmap[i] = go_bitmap[i] | activate_bitmap[i];
        }

        // Caliptra sets FW_EXEC_CTRL
        drivers.soc_ifc.set_ss_generic_fw_exec_ctrl(&temp_bitmap);
        Ok(())
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
