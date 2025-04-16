// Licensed under the Apache-2.0 license

use crate::common::fips_test_init_to_rom;
use caliptra_hw_model::OpenOcdError;
use caliptra_hw_model::{InitParams, SecurityState};
use caliptra_hw_model_types::DeviceLifecycle;

fn check_jtag_accessible(
    rom: &[u8],
    debug_locked: bool,
    device_lifecycle: DeviceLifecycle,
    expect_result: Result<(), OpenOcdError>,
) {
    let security_state = *SecurityState::default()
        .set_debug_locked(debug_locked)
        .set_device_lifecycle(device_lifecycle);

    let mut hw = fips_test_init_to_rom(
        Some(InitParams {
            rom,
            security_state,
            ..Default::default()
        }),
        None,
    );

    #[cfg(feature = "fpga_realtime")]
    assert_eq!(
        expect_result,
        hw.launch_openocd(),
        " for {device_lifecycle:?}:{debug_locked}"
    );
}

#[test]
fn jtag_locked() {
    #![cfg_attr(not(feature = "fpga_realtime"), ignore)]

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    // When debug is locked JTAG is only accesisble in Manufacturing mode.
    check_jtag_accessible(
        &rom,
        true,
        DeviceLifecycle::Unprovisioned,
        Err(OpenOcdError::CaliptraNotAccessible),
    );
    check_jtag_accessible(
        &rom,
        true,
        DeviceLifecycle::Manufacturing,
        Err(OpenOcdError::VeerNotAccessible),
    );
    check_jtag_accessible(
        &rom,
        true,
        DeviceLifecycle::Reserved2,
        Err(OpenOcdError::CaliptraNotAccessible),
    );
    check_jtag_accessible(
        &rom,
        true,
        DeviceLifecycle::Production,
        Err(OpenOcdError::CaliptraNotAccessible),
    );

    // When debug not locked JTAG is accessible in any mode.
    check_jtag_accessible(&rom, false, DeviceLifecycle::Unprovisioned, Ok(()));
    check_jtag_accessible(&rom, false, DeviceLifecycle::Manufacturing, Ok(()));
    check_jtag_accessible(&rom, false, DeviceLifecycle::Reserved2, Ok(()));
    check_jtag_accessible(&rom, false, DeviceLifecycle::Production, Ok(()));
}
