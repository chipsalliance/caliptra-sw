// Licensed under the Apache-2.0 license
use crate::common;

use caliptra_builder::firmware::ROM_WITH_UART_FIPS_TEST_HOOKS;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::FipsTestHook;
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use common::*;

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_halt_check_no_output() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART_FIPS_TEST_HOOKS).unwrap();

    let mut hw = fips_test_init_to_boot_start(
        Some(InitParams {
            rom: &rom,
            ..Default::default()
        }),
        Some(BootParams {
            initial_dbg_manuf_service_reg: (FipsTestHook::HALT_SELF_TESTS as u32)
                << HOOK_CODE_OFFSET,
            ..Default::default()
        }),
    );

    // Wait for ACK that ROM reached halt point
    hook_wait_for_complete(&mut hw);

    // Check output is inhibited
    verify_output_inhibited(&mut hw);

    // TODO: Remove continuing if it's not needed
    // Tell ROM to continue
    hook_code_write(&mut hw, FipsTestHook::CONTINUE);

    // Wait for ACK that ROM continued
    hook_wait_for_complete(&mut hw);

    // Step to ready for FW in ROM
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha384_error() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART_FIPS_TEST_HOOKS).unwrap();

    let mut hw = fips_test_init_to_boot_start(
        Some(InitParams {
            rom: &rom,
            ..Default::default()
        }),
        Some(BootParams {
            initial_dbg_manuf_service_reg: (FipsTestHook::SHA384_ERROR as u32) << HOOK_CODE_OFFSET,
            ..Default::default()
        }),
    );

    // Wait for fatal error
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);

    // Verify fatal code is correct
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::KAT_SHA384_DIGEST_MISMATCH)
    );

    // TODO: Verify we cannot use the algorithm
    // TODO: Attempt to clear the error in an undocumented way
    // TODO: Restart Caliptra
    // TODO: Verify crypto operations can be performed
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_lms_error() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART_FIPS_TEST_HOOKS).unwrap();

    let mut hw = fips_test_init_to_boot_start(
        Some(InitParams {
            rom: &rom,
            ..Default::default()
        }),
        Some(BootParams {
            initial_dbg_manuf_service_reg: (FipsTestHook::LMS_ERROR as u32) << HOOK_CODE_OFFSET,
            ..Default::default()
        }),
    );

    // Wait for fatal error
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);

    // Verify fatal code is correct
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::KAT_LMS_DIGEST_MISMATCH)
    );

    // TODO: Verify we cannot use the algorithm
    // TODO: Attempt to clear the error in an undocumented way
    // TODO: Restart Caliptra
    // TODO: Verify crypto operations can be performed
}
