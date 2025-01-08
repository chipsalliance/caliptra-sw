// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::rom_tests::TEST_FMC_INTERACTIVE,
    firmware::{self, APP_WITH_UART},
    ImageOptions,
};
use caliptra_common::RomBootStatus::{self, KatStarted};
use caliptra_hw_model::{DeviceLifecycle, HwModel, SecurityState};

#[test]
fn test_wdt_activation_and_stoppage() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Unprovisioned);

    // Build the image we are going to send to ROM to load
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let rom =
        caliptra_builder::build_firmware_rom(caliptra_builder::firmware::rom_from_env()).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    if cfg!(feature = "fpga_realtime") {
        // timer1_restart is only high for a few cycles; the realtime model
        // timing is too imprecise that sort of check.
        hw.step_until(|m| m.ready_for_fw());
    } else {
        // Ensure we are starting to count from zero.
        hw.step_until(|m| m.soc_ifc().cptra_wdt_timer1_ctrl().read().timer1_restart());
    }

    // Make sure the wdt1 timer is enabled.
    assert!(hw.soc_ifc().cptra_wdt_timer1_en().read().timer1_en());

    // Upload the FW once ROM is at the right point
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    // Keep going until we jump to fake FMC
    hw.step_until_output_contains("Running Caliptra FMC")
        .unwrap();

    // Make sure the wdt1 timer is enabled.
    assert!(hw.soc_ifc().cptra_wdt_timer1_en().read().timer1_en());
}

#[test]
fn test_wdt_not_enabled_on_debug_part() {
    let security_state = *SecurityState::default()
        .set_debug_locked(false)
        .set_device_lifecycle(DeviceLifecycle::Unprovisioned);

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Confirm security state is as expected.
    assert!(!hw.soc_ifc().cptra_security_state().read().debug_locked());

    hw.step_until_boot_status(RomBootStatus::CfiInitialized.into(), false);
    hw.step_until_boot_status(KatStarted.into(), false);

    // Make sure the wdt1 timer is disabled.
    assert!(!hw.soc_ifc().cptra_wdt_timer1_en().read().timer1_en());
}

#[test]
fn test_rom_wdt_timeout() {
    const WDT_EXPIRED: u32 = 0x0105000C;

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Unprovisioned);

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        caliptra_hw_model::BootParams {
            wdt_timeout_cycles: u64::MAX,
            ..Default::default()
        },
    )
    .unwrap();

    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() == WDT_EXPIRED);

    let mcause = hw.soc_ifc().cptra_fw_extended_error_info().at(0).read();
    let mscause = hw.soc_ifc().cptra_fw_extended_error_info().at(1).read();
    let mepc = hw.soc_ifc().cptra_fw_extended_error_info().at(2).read();
    let ra = hw.soc_ifc().cptra_fw_extended_error_info().at(3).read();
    let error_internal_intr_r = hw.soc_ifc().cptra_fw_extended_error_info().at(4).read();

    println!(
        "WDT Expiry mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X} ra=0x{:08X} error_internal_intr_r={:08X}",
        mcause,
        mscause,
        mepc,
        ra,
        error_internal_intr_r,
    );

    // no mcause if wdt times out
    assert_eq!(mcause, 0);
    // no mscause if wdt times out
    assert_eq!(mscause, 0);
    // mepc is a memory address so won't be 0
    assert_ne!(mepc, 0);
    // return address won't be 0
    assert_ne!(ra, 0);
    // error_internal_intr_r must be 0b01000000 since the error_wdt_timer1_timeout_sts bit must be set
    assert_eq!(error_internal_intr_r, 0b01000000);
}
