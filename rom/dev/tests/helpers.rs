// Licensed under the Apache-2.0 license

use std::mem;

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
use caliptra_hw_model::{DefaultHwModel, ModelError};
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

/// This function matches the to_match string in the haystack string and returns the data
/// after the match until the next newline character.
///
/// # Arguments
///
/// * `to_match` - String to search for
/// * `haystack` - String to search in
pub fn get_data(to_match: &str, haystack: &str) -> String {
    let mut index = haystack.find(to_match).unwrap();
    index += to_match.len();
    let mut str = String::new();
    while haystack.chars().nth(index).unwrap() != '\n' {
        str.push(haystack.chars().nth(index).unwrap());
        index += 1;
    }

    str
}

pub fn get_csr(hw: &mut DefaultHwModel) -> Result<Vec<u8>, ModelError> {
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().status() == 0x0800_0000);
    let mut txn = hw.wait_for_mailbox_receive()?;
    let result = mem::take(&mut txn.req.data);
    txn.respond_success();
    hw.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| 0);
    Ok(result)
}
