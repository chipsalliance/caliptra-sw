// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{Fuses, HwModel, ModelError};

pub mod helpers;

#[test]
fn test_unknown_command_is_not_fatal() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // This command does not exist
    assert_eq!(
        hw.mailbox_execute(0xabcd_1234, &[]),
        Err(ModelError::MailboxCmdFailed(0))
    );

    // The ROM does not currently report an error for this
    // TODO: Is this right?
    assert_eq!(hw.soc_ifc().cptra_fw_error_non_fatal().read(), 0);

    // Make sure we can still upload new firmware after the unknown
    // command.
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
}

#[test]
fn test_mailbox_command_aborted_after_report_error() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    assert_eq!(
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_INVALID_IMAGE_SIZE.into()
        )),
        hw.upload_firmware(&[])
    );

    // Make sure a new attempt to upload firmware is rejected (even though this
    // command would otherwise succeed)
    //
    // The original failure reason should still be in the register
    assert_eq!(
        hw.upload_firmware(&image_bundle.to_bytes().unwrap()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_INVALID_IMAGE_SIZE.into()
        ))
    );
}
