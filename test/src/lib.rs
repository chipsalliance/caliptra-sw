// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART},
    FwId, ImageOptions,
};
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams};

pub mod crypto;
pub mod derive;
pub mod x509;

pub fn swap_word_bytes(words: &[u32]) -> Vec<u32> {
    words.iter().map(|word| word.swap_bytes()).collect()
}
pub fn swap_word_bytes_inplace(words: &mut [u32]) {
    for word in words.iter_mut() {
        *word = word.swap_bytes()
    }
}

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
pub fn run_test(
    test_fwid: Option<&'static FwId>,
    test_image_options: Option<ImageOptions>,
    init_params: Option<InitParams>,
) -> DefaultHwModel {
    let runtime_fwid = test_fwid.unwrap_or(&APP_WITH_UART);

    let image_options = test_image_options.unwrap_or_else(|| {
        let mut opts = ImageOptions::default();
        opts.vendor_config.pl0_pauser = Some(0x1);
        opts.fmc_version = 0xaaaaaaaa;
        opts.app_version = 0xbbbbbbbb;
        opts
    });

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let init_params = match init_params {
        Some(init_params) => init_params,
        None => InitParams {
            rom: &rom,
            ..Default::default()
        },
    };

    let image = caliptra_builder::build_and_sign_image(&FMC_WITH_UART, runtime_fwid, image_options)
        .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params,
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    model
}
