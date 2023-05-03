// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_hw_model::{Fuses, HwModel, ModelError};

pub mod helpers;

// [TODO] Use the error codes from the common library.
const INVALID_IMAGE_SIZE: u32 = 0x02000003;

#[test]
fn test_unknown_command_is_not_fatal() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // This command does not exist
    assert_eq!(
        hw.mailbox_execute(0xabcd_1234, &[]),
        Err(ModelError::MailboxCmdFailed)
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
    assert_eq!(Err(ModelError::MailboxCmdFailed), hw.upload_firmware(&[]));

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        INVALID_IMAGE_SIZE
    );

    // Make sure a new attempt to upload firmware is rejected (even though this
    // command would otherwise succeed)
    assert_eq!(
        hw.upload_firmware(&image_bundle.to_bytes().unwrap()),
        Err(ModelError::MailboxCmdFailed)
    );

    // The original failure reason should still be in the register
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        INVALID_IMAGE_SIZE
    );
}
