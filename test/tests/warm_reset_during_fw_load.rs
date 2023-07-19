// Licensed under the Apache-2.0 license

use caliptra_builder::ROM_WITH_UART;
use caliptra_hw_model::{BootParams, HwModel, InitParams, SecurityState};
use caliptra_hw_model_types::{DeviceLifecycle, Fuses};

#[cfg(any(feature = "verilator", feature = "fpga_realtime"))]
#[test]
fn warm_reset_during_fw_load() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        fuses: Fuses {
            owner_pk_hash: [0xffff_ffff; 12],
            fmc_key_manifest_svn: 0b1111111,
            ..Default::default()
        },
        fw_image: None,
        ..Default::default()
    })
    .unwrap();

    // Wait for rom to be ready for firmware
    while !hw.ready_for_fw() {
        hw.step();
    }

    // Perform warm reset
    hw.warm_reset_flow();

    // Wait for error
    while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
        hw.step();
    }
    assert_ne!(hw.soc_ifc().cptra_fw_error_fatal().read(), 0);
}
