// Licensed under the Apache-2.0 license

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::DefaultHwModel;
use caliptra_hw_model::{BootParams, Fuses, InitParams, SecurityState};
use caliptra_image_types::ImageBundle;

pub fn build_hw_model_and_image_bundle(
    fuses: Fuses,
    image_options: ImageOptions,
) -> (DefaultHwModel, ImageBundle) {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        fw_image: None,
    })
    .unwrap();

    let image_bundle =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
            .unwrap();

    (hw, image_bundle)
}
