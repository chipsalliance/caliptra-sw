// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{self, APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::CommandId;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;

use crate::common::run_rt_test;

#[test]
fn test_standard() {
    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    let mut model = run_rt_test(None, None, None);

    model
        .step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();
}

#[test]
fn test_boot() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::BOOT), None, None);

    model.step_until_exit_success().unwrap();
}

#[test]
fn test_fw_version() {
    let mut model = run_rt_test(None, None, None);
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let fw_rev = model.soc_ifc().cptra_fw_rev_id().read();
    assert_eq!(fw_rev[0], 0xaaaaaaaa);
    assert_eq!(fw_rev[1], 0xbbbbbbbb);
}

#[test]
fn test_update() {
    let image_options = ImageOptions {
        app_version: 0xaabbccdd,
        ..Default::default()
    };
    // Make image to update to. On the FPGA this needs to be done before executing the test,
    // otherwise the test will fail because processor is too busy building to be able to respond to
    // the TRNG call during the initial boot.
    let image =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
            .unwrap()
            .to_bytes()
            .unwrap();

    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
        .unwrap();

    model
        .step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();

    let fw_rev = model.soc_ifc().cptra_fw_rev_id().read();
    assert_eq!(fw_rev[0], 0xaaaaaaaa);
    assert_eq!(fw_rev[1], 0xaabbccdd);
}
