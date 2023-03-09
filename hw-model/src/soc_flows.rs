// Licensed under the Apache-2.0 license

use crate as caliptra_hw_model;
use caliptra_emu_types::RvSize;

/// Firmware Load Command Opcode
const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

pub struct SocFlows;
impl SocFlows {
    /// Upload firmware to the mailbox.
    pub fn upload_firmware(model: &mut impl caliptra_hw_model::HwModel, firmware: &Vec<u8>) {
        assert_eq!(model.soc_mbox().lock().read().lock(), false);

        assert_eq!(model.soc_mbox().lock().read().lock(), true);

        model.soc_mbox().cmd().write(|_| FW_LOAD_CMD_OPCODE);

        model.soc_mbox().dlen().write(|_| firmware.len() as u32);

        let word_size = RvSize::Word as usize;
        let remainder = firmware.len() % word_size;
        let n = firmware.len() - remainder;

        for idx in (0..n).step_by(word_size) {
            let val = u32::from_le_bytes(firmware[idx..idx + word_size].try_into().unwrap());
            model.soc_mbox().datain().write(|_| val);
        }

        // Handle the remainder bytes.
        if remainder > 0 {
            let mut last_word = firmware[n] as u32;
            for idx in 1..remainder {
                last_word |= (firmware[n + idx] as u32) << (idx << 3);
            }
            model.soc_mbox().datain().write(|_| last_word);
        }

        // Set the status as DATA_READY.
        model
            .soc_mbox()
            .status()
            .write(|w| w.status(|w| w.data_ready()));

        // Set Execute Bit
        model.soc_mbox().execute().write(|w| w.execute(true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HwModel, InitParams};

    #[test]
    pub fn test_upload_firmware() {
        let firmware: Vec<u8> = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ]
        .into();

        // Same as test_apb, but uses higher-level register interface
        let mut model = caliptra_hw_model::create(InitParams {
            ..Default::default()
        })
        .unwrap();

        SocFlows::upload_firmware(&mut model, &firmware);

        assert_eq!(model.soc_mbox().cmd().read(), FW_LOAD_CMD_OPCODE);
        assert_eq!(model.soc_mbox().dlen().read(), firmware.len() as u32);
        assert!(model.soc_mbox().status().read().status().data_ready());

        // Read the data out of the mailbox.
        let mut temp: Vec<u32> = Vec::new();
        let mut word_count = (firmware.len() + 3) >> 2;
        while word_count > 0 {
            let word = model.soc_mbox().dataout().read();
            temp.push(word);
            word_count -= 1;
        }
        let fw_img_from_mb: Vec<u8> = temp.iter().flat_map(|val| val.to_le_bytes()).collect();
        assert_eq!(firmware, fw_img_from_mb[..firmware.len()]);
    }
}
