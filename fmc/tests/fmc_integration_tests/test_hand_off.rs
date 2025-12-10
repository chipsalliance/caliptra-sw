// Licensed under the Apache-2.0 license
use crate::helpers;
use caliptra_builder::{firmware, ImageOptions};
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams};

#[test]
fn test_hand_off() {
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let fuses = Fuses {
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };

        let rom =
            caliptra_builder::rom_for_fw_integration_tests_fpga(cfg!(feature = "fpga_subsystem"))
                .unwrap();

        let image = caliptra_builder::build_and_sign_image(
            &firmware::FMC_WITH_UART,
            &firmware::runtime_tests::BOOT,
            image_options,
        )
        .unwrap();

        let mut hw = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                fuses,
                ..Default::default()
            },
            BootParams {
                fw_image: Some(&image.to_bytes().unwrap()),
                ..Default::default()
            },
        )
        .unwrap();

        let mut output = vec![];
        hw.copy_output_until_exit_success(&mut output).unwrap();
    }
}
