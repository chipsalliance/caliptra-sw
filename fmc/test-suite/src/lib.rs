// Licensed under the Apache-2.0 license

#[cfg(test)]
mod tests {
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use caliptra_hw_model::{HwModel, InitParams};

    use std::fs::File;
    use std::io::Read;

    /// Firmware Load Command Opcode
    const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

    pub fn upload_firmware(model: &mut impl HwModel, path: &str) {
        let mut fmc = File::open(path).unwrap();
        let mut firmware_buffer = Vec::new();
        fmc.read_to_end(&mut firmware_buffer).unwrap();

        assert_eq!(model.soc_mbox().lock().read().lock(), false);

        assert_eq!(model.soc_mbox().lock().read().lock(), true);

        model.soc_mbox().cmd().write(|_| FW_LOAD_CMD_OPCODE);

        model
            .soc_mbox()
            .dlen()
            .write(|_| firmware_buffer.len() as u32);

        let word_size = RvSize::Word as usize;
        let remainder = firmware_buffer.len() % word_size;
        let n = firmware_buffer.len() - remainder;

        for idx in (0..n).step_by(word_size) {
            let val = u32::from_le_bytes(firmware_buffer[idx..idx + word_size].try_into().unwrap());
            model.soc_mbox().datain().write(|_| val);
        }

        // Handle the remainder bytes.
        if remainder > 0 {
            let mut last_word = firmware_buffer[n] as u32;
            for idx in 1..remainder {
                last_word |= (firmware_buffer[n + idx] as u32) << (idx << 3);
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

    #[test]
    fn it_works() {
        let mut rom = File::open("/tmp/test-rom.bin").unwrap();
        let mut rom_buffer = Vec::new();
        rom.read_to_end(&mut rom_buffer).unwrap();

        let mut model = caliptra_hw_model::create(InitParams {
            rom: &rom_buffer,
            ..Default::default()
        })
        .unwrap();

        // Wait for ROM to request firmware.
        model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

        upload_firmware(&mut model, "/tmp/fmc.bin");

        //model.step_until(|m|
        //    m.output().exit_requested()
        //);
    }
}
