/*++

Licensed under the Apache-2.0 license.

File Name:

    uds_programming.rs

Abstract:

    File contains the implementation of UDS programming flow test.
--*/

use caliptra_api::SocManager;
use caliptra_builder::firmware::ROM_WITH_UART;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DbgManufServiceRegReq, DeviceLifecycle, HwModel, SecurityState};

#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_uds_programming_no_active_mode() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_uds_program_req(true);
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            subsystem_mode: false,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Wait for fatal error
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);

    // Verify fatal code is correct
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::ROM_UDS_PROG_IN_PASSIVE_MODE)
    );
}

#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_uds_programming_granularity_64bit() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_uds_program_req(true);
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            subsystem_mode: true,
            uds_granularity_64: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Wait for ROM to complete
    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_service_reg_rsp().read();
        resp.uds_program_success()
    });

    let config_val = hw.soc_ifc().cptra_generic_input_wires().read()[0];
    assert_eq!((config_val >> 31) & 1, 0);
}

#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_uds_programming_granularity_32bit() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_uds_program_req(true);
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            subsystem_mode: true,
            uds_granularity_64: false,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Wait for ROM to complete
    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_service_reg_rsp().read();
        resp.uds_program_success()
    });

    let config_val = hw.soc_ifc().cptra_generic_input_wires().read()[0];
    assert_eq!((config_val >> 31) & 1, 1);
}
