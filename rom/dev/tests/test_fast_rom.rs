// Licensed under the Apache-2.0 license

use caliptra_builder::ROM_FAST_WITH_UART;
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{BootParams, DeviceLifecycle, HwModel, InitParams, SecurityState};

#[test]
fn test_skip_kats() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_FAST_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    // If KatStarted boot status is posted before ColResetStarted, the statement below will trigger panic.
    hw.step_until_boot_status(
        caliptra_common::RomBootStatus::ColdResetStarted.into(),
        false,
    );
}

#[test]
fn test_fast_rom_production_error() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_FAST_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    // Let it run until a fatal error (should fail very early)
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);

    // Make sure we see the right fatal error
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        CaliptraError::ROM_GLOBAL_FAST_ROM_IN_PRODUCTION.into()
    );
}
