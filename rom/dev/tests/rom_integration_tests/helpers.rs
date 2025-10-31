// Licensed under the Apache-2.0 license

use std::mem;

use caliptra_api::SocManager;
use caliptra_builder::{firmware, ImageOptions};
use caliptra_common::{
    memory_layout::{ROM_ORG, ROM_SIZE, ROM_STACK_ORG, ROM_STACK_SIZE, STACK_ORG, STACK_SIZE},
    FMC_ORG, FMC_SIZE, RUNTIME_ORG, RUNTIME_SIZE,
};
use caliptra_drivers::InitDevIdCsrEnvelope;
use caliptra_hw_model::{
    BootParams, CodeRange, Fuses, HwModel, ImageInfo, InitParams, SecurityState, StackInfo,
    StackRange,
};
use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, ModelError};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageBundle};
use zerocopy::TryFromBytes;

pub const PQC_KEY_TYPE: [FwVerificationPqcKeyType; 2] = [
    FwVerificationPqcKeyType::LMS,
    FwVerificationPqcKeyType::MLDSA,
];

pub const LIFECYCLES_PROVISIONED: [DeviceLifecycle; 2] =
    [DeviceLifecycle::Manufacturing, DeviceLifecycle::Production];

pub const LIFECYCLES_ALL: [DeviceLifecycle; 3] = [
    DeviceLifecycle::Unprovisioned,
    DeviceLifecycle::Manufacturing,
    DeviceLifecycle::Production,
];

pub fn build_hw_model_and_image_bundle(
    fuses: Fuses,
    image_options: ImageOptions,
) -> (DefaultHwModel, ImageBundle) {
    let image = build_image_bundle(image_options);
    (build_hw_model(fuses), image)
}

pub fn build_hw_model(fuses: Fuses) -> DefaultHwModel {
    let subsystem_mode = cfg!(feature = "fpga_subsystem");
    let rom = caliptra_builder::rom_for_fw_integration_tests_mode(subsystem_mode).unwrap();
    let image_info = vec![
        ImageInfo::new(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
        ),
    ];
    let mut security_state = SecurityState::from(fuses.life_cycle as u32);
    security_state.set_debug_locked(fuses.debug_locked);
    caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            stack_info: Some(StackInfo::new(image_info)),
            ..Default::default()
        },
        BootParams {
            fuses,
            ..Default::default()
        },
    )
    .unwrap()
}

pub fn build_image_bundle(image_options: ImageOptions) -> ImageBundle {
    caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::APP_WITH_UART,
        image_options,
    )
    .unwrap()
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

pub fn get_csr_envelop(hw: &mut DefaultHwModel) -> Result<InitDevIdCsrEnvelope, ModelError> {
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().idevid_csr_ready());
    let mut txn = hw.wait_for_mailbox_receive()?;
    let result = mem::take(&mut txn.req.data);
    txn.respond_success();
    hw.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| 0);
    let (csr_envelop, _) = InitDevIdCsrEnvelope::try_read_from_prefix(&result).unwrap();
    Ok(csr_envelop)
}

pub fn change_dword_endianess(data: &mut [u8]) {
    for idx in (0..data.len()).step_by(4) {
        data.swap(idx, idx + 3);
        data.swap(idx + 1, idx + 2);
    }
}

pub fn model_supports_subsystem_mode(subsystem_mode: bool) -> bool {
    let fpga_subsystem = cfg!(feature = "fpga_subsystem");
    let fpga_realtime = cfg!(feature = "fpga_realtime");
    let fpga = fpga_subsystem || fpga_realtime;
    let emulator = !fpga;
    emulator || (subsystem_mode && fpga_subsystem) || ((!subsystem_mode) && fpga_realtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "Foo bar baz \n\
                       [idev] ECC CSR = foo bar\n\
                       [idev] ECC CSR = wrong";

    #[test]
    fn test_get_data() {
        assert_eq!("foo bar", get_data("[idev] ECC CSR = ", LOG));

        assert_eq!("", get_data("CSR = wrong", LOG));
    }

    #[test]
    #[should_panic(expected = "unable to find substr \"[idev] FOO = \"")]
    fn test_get_data_not_found() {
        assert_eq!("", get_data("[idev] FOO = ", LOG));
    }
}
