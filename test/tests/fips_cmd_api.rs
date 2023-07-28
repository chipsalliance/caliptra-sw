// Licensed under the Apache-2.0 license

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::ModelError;
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use caliptra_runtime::{CommandId, VersionResponse};
use zerocopy::{AsBytes, FromBytes};

#[test]
fn test_fips_cmd_api() {
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    hw.step_until(|m| m.ready_for_fw());

    let resp = hw.mailbox_execute(u32::from(CommandId::VERSION), &[]);
    assert!(resp.is_ok());
    let fips_version_resp = hw
        .mailbox_execute(u32::from(CommandId::VERSION), &[])
        .unwrap()
        .unwrap();

    // Check command size
    let fips_version_bytes: &[u8] = fips_version_resp.as_bytes();

    // Check values against expected.
    let fips_version = VersionResponse::read_from(fips_version_bytes.as_bytes()).unwrap();
    assert_eq!(fips_version.mode, VersionResponse::MODE);
    assert_eq!(fips_version.fips_rev, [0x01, 0x00, 0x00]);
    let name = &fips_version.name[..];
    assert_eq!(name, VersionResponse::NAME.as_bytes());

    let resp = hw.mailbox_execute(u32::from(CommandId::SELF_TEST), &[]);
    assert!(resp.is_ok());

    let resp = hw.mailbox_execute(u32::from(CommandId::SHUTDOWN), &[]);
    assert!(resp.is_ok());

    // Check we are rejecting additional commands with the shutdown error code.
    let expected_err = Err(ModelError::MailboxCmdFailed(0x000E0008));
    let resp = hw.mailbox_execute(u32::from(CommandId::VERSION), &[]);
    assert_eq!(resp, expected_err);
}
