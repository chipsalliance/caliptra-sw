// Licensed under the Apache-2.0 license

use crate::common::fips_test_init_to_rom;
use caliptra_builder::firmware;
use caliptra_hw_model::{BootParams, InitParams, SecurityState};
use caliptra_hw_model_types::DeviceLifecycle;

fn check_jtag_accessible(
    rom: &Vec<u8>,
    debug_locked: bool,
    device_lifecycle: DeviceLifecycle,
    _expect_pass: bool,
) {
    let security_state = *SecurityState::default()
        .set_debug_locked(debug_locked)
        .set_device_lifecycle(device_lifecycle);

    let mut _hw = fips_test_init_to_rom(Some(BootParams {
        init_params: InitParams {
            rom,
            security_state,
            ..Default::default()
        },
        ..Default::default()
    }));

    #[cfg(feature = "fpga_realtime")]
    match _hw.launch_openocd() {
        Ok(()) => assert!(
            _expect_pass,
            "Result Ok when expected to fail for debug_locked {debug_locked} {device_lifecycle:?}"
        ),
        Err(caliptra_hw_model::OpenOcdError::NotAccessible) => assert!(
            !_expect_pass,
            "Result NotAccessible when expected to pass for debug_locked {debug_locked} {device_lifecycle:?}"
        ),
        Err(e) => panic!("OpenOCD failed with an unexpected error: {e:?}"),
    }
}

#[test]
fn jtag_locked() {
    #![cfg_attr(not(feature = "fpga_realtime"), ignore)]

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    // When debug is locked JTAG is only accesisble in Manufacturing mode.
    check_jtag_accessible(&rom, true, DeviceLifecycle::Unprovisioned, false);
    check_jtag_accessible(&rom, true, DeviceLifecycle::Manufacturing, true);
    check_jtag_accessible(&rom, true, DeviceLifecycle::Reserved2, false);
    check_jtag_accessible(&rom, true, DeviceLifecycle::Production, false);

    // When debug not locked JTAG is accessible in any mode.
    check_jtag_accessible(&rom, false, DeviceLifecycle::Unprovisioned, true);
    check_jtag_accessible(&rom, false, DeviceLifecycle::Manufacturing, true);
    check_jtag_accessible(&rom, false, DeviceLifecycle::Reserved2, true);
    check_jtag_accessible(&rom, false, DeviceLifecycle::Production, true);
}
