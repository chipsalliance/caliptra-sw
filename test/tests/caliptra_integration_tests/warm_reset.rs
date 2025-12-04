// Licensed under the Apache-2.0 license

use caliptra_api::soc_mgr::SocManager;
use caliptra_api_types::{DeviceLifecycle, Fuses};
use caliptra_builder::{
    firmware::{APP_WITH_UART, APP_WITH_UART_FPGA, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::CommandId;
use caliptra_hw_model::{mbox_write_fifo, BootParams, HwModel, InitParams, SecurityState};
use caliptra_test::image_pk_desc_hash;

#[test]
fn warm_reset_basic() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests_fpga(cfg!(feature = "fpga_subsystem"))
        .unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &if cfg!(feature = "fpga_subsystem") {
            APP_WITH_UART_FPGA
        } else {
            APP_WITH_UART
        },
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut hw = caliptra_hw_model::new(
        InitParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                fw_svn: [0x7F, 0, 0, 0], // Equals 7
                ..Default::default()
            },
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }

    // Perform warm reset
    hw.warm_reset_flow().unwrap();

    // Wait for boot
    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }
}

#[test]
fn warm_reset_during_fw_load() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests_fpga(cfg!(feature = "fpga_subsystem"))
        .unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &if cfg!(feature = "fpga_subsystem") {
            APP_WITH_UART_FPGA
        } else {
            APP_WITH_UART
        },
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let boot_params = BootParams {
        fw_image: None,
        ..Default::default()
    };

    let mut hw = caliptra_hw_model::new(
        InitParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                fw_svn: [0x7F, 0, 0, 0], // Equals 7
                ..Default::default()
            },
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Start the FW load
    // Wait for rom to be ready for firmware
    while !hw.ready_for_fw() {
        hw.step();
    }
    // Lock the mailbox
    assert!(!hw.soc_mbox().lock().read().lock());
    // Write load firmware command and data
    hw.soc_mbox()
        .cmd()
        .write(|_| CommandId::FIRMWARE_LOAD.into());
    let buf = &image.to_bytes().unwrap();
    assert!(mbox_write_fifo(&hw.soc_mbox(), buf).is_ok());
    // Ask the microcontroller to execute this command
    hw.soc_mbox().execute().write(|w| w.execute(true));

    // Perform warm reset while ROM is executing the firmware load
    hw.warm_reset_flow().unwrap();

    // Wait for error
    while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
        hw.step();
    }
    assert_ne!(hw.soc_ifc().cptra_fw_error_fatal().read(), 0);
}
