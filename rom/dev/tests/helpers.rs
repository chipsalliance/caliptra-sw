// Licensed under the Apache-2.0 license

use std::mem;

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_common::RomBootStatus;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
use caliptra_hw_model::{DefaultHwModel, ModelError};
use caliptra_image_types::ImageBundle;

pub const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

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
        ..Default::default()
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
pub fn get_data<'a>(to_match: &str, haystack: &'a str) -> &'a str {
    let index = haystack
        .find(to_match)
        .unwrap_or_else(|| panic!("unable to find substr {to_match:?}"));
    haystack[index + to_match.len()..]
        .split('\n')
        .next()
        .unwrap_or("")
}

pub fn get_csr(hw: &mut DefaultHwModel) -> Result<Vec<u8>, ModelError> {
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().status() == 0x0800_0000);
    let mut txn = hw.wait_for_mailbox_receive()?;
    let result = mem::take(&mut txn.req.data);
    txn.respond_success();
    hw.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| 0);
    Ok(result)
}

pub fn change_dword_endianess(data: &mut [u8]) {
    for idx in (0..data.len()).step_by(4) {
        data.swap(idx, idx + 3);
        data.swap(idx + 1, idx + 2);
    }
}

#[track_caller]
pub fn step_until_boot_status(
    hw: &mut DefaultHwModel,
    expected_status: RomBootStatus,
    ignore_intermediate_status: bool,
) {
    // Since the boot takes less than 20M cycles, we know something is wrong if
    // we're stuck at the same state for that duration.
    const MAX_WAIT_CYCLES: u32 = 20_000_000;

    let mut cycle_count = 0u32;
    let expected_status_u32: u32 = expected_status.into();
    let initial_boot_status_u32 = hw.soc_ifc().cptra_boot_status().read();
    loop {
        let actual_status_u32 = hw.soc_ifc().cptra_boot_status().read();
        if expected_status_u32 == actual_status_u32 {
            break;
        }

        if !ignore_intermediate_status && actual_status_u32 != initial_boot_status_u32 {
            panic!(
                "Expected the next boot_status to be {expected_status:?} \
                    ({expected_status_u32}), but status changed from \
                    {initial_boot_status_u32} to {actual_status_u32})"
            );
        }
        hw.step();
        cycle_count += 1;
        if cycle_count >= MAX_WAIT_CYCLES {
            panic!(
                "Expected boot_status to be {expected_status:?} \
                    ({expected_status_u32}), but was stuck at ({actual_status_u32})"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "Foo bar baz \n\
                       [idev] CSR = foo bar\n\
                       [idev] CSR = wrong";

    #[test]
    fn test_get_data() {
        assert_eq!("foo bar", get_data("[idev] CSR = ", LOG));

        assert_eq!("", get_data("CSR = wrong", LOG));
    }

    #[test]
    #[should_panic(expected = "unable to find substr \"[idev] FOO = \"")]
    fn test_get_data_not_found() {
        assert_eq!("", get_data("[idev] FOO = ", LOG));
    }
}
