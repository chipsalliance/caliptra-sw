// Licensed under the Apache-2.0 license

use caliptra_api::soc_mgr::SocManager;
use caliptra_builder::{
    firmware::{APP_ZEROS, FMC_ZEROS},
    ImageOptions,
};
use caliptra_drivers::memory_layout::ICCM_ORG;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, HwModel, InitParams};

#[test]
fn test_zeros() {
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let init_params = InitParams {
        rom: &rom,
        ..Default::default()
    };

    let image =
        caliptra_builder::build_and_sign_image(&FMC_ZEROS, &APP_ZEROS, ImageOptions::default())
            .unwrap();

    let mut model = caliptra_hw_model::new(
        init_params,
        BootParams {
            fw_image: Some(&image.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    // 0 is an ilegal instruction in risc-v. Image should immediately NMI.
    model.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);
    assert_eq!(
        model.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::ROM_GLOBAL_EXCEPTION)
    );

    let ext_info = model.soc_ifc().cptra_fw_extended_error_info().read();
    let mcause = ext_info[0];
    let mepc = ext_info[2];

    // Invalid Instruction error
    assert_eq!(mcause, 2);
    assert_eq!(mepc, ICCM_ORG);
}
