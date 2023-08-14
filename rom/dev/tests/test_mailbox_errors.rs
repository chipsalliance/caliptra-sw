// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{Fuses, HwModel, ModelError};

pub mod helpers;

// Since the boot takes less than 30M cycles, we know something is wrong if
// we're stuck at the same state for that duration.
const MAX_WAIT_CYCLES: u32 = 30_000_000;

#[test]
fn test_unknown_command_is_fatal() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // This command does not exist
    assert_eq!(
        hw.mailbox_execute(0xabcd_1234, &[]),
        Err(ModelError::MailboxCmdFailed(0))
    );

    hw.step_until_fatal_error(
        CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND.into(),
        MAX_WAIT_CYCLES,
    );
}

#[test]
fn test_mailbox_command_aborted_after_handle_fatal_error() {
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
