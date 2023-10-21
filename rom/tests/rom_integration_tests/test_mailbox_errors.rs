// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, StashMeasurementReq};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{Fuses, HwModel, ModelError};
use zerocopy::AsBytes;

use crate::helpers;

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
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND.into()
        ))
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

#[test]
fn test_mailbox_invalid_checksum() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Upload measurement.
    let payload = StashMeasurementReq {
        measurement: [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap(),
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0xAB; 4],
        context: [0xCD; 48],
        svn: 0xEF01,
    };

    // Calc and update checksum
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::STASH_MEASUREMENT),
        &payload.as_bytes()[4..],
    );

    // Corrupt the checksum
    let checksum = checksum - 1;

    let payload = StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..payload
    };

    assert_eq!(
        hw.mailbox_execute(CommandId::STASH_MEASUREMENT.into(), payload.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_CHECKSUM.into()
        ))
    );
}

#[test]
fn test_mailbox_invalid_req_size_large() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Upload measurement.
    let payload = StashMeasurementReq {
        measurement: [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap(),
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0xAB; 4],
        context: [0xCD; 48],
        svn: 0xEF01,
    };

    // Send too much data (stash measurement is bigger than capabilities)
    assert_eq!(
        hw.mailbox_execute(CommandId::CAPABILITIES.into(), payload.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH.into()
        ))
    );
}

#[test]
fn test_mailbox_invalid_req_size_small() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Upload measurement.
    let payload = StashMeasurementReq {
        measurement: [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap(),
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0xAB; 4],
        context: [0xCD; 48],
        svn: 0xEF01,
    };

    // Drop a dword
    assert_eq!(
        hw.mailbox_execute(
            CommandId::STASH_MEASUREMENT.into(),
            &payload.as_bytes()[4..]
        ),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH.into()
        ))
    );
}

#[test]
fn test_mailbox_invalid_req_size_zero() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    assert_eq!(
        hw.mailbox_execute(CommandId::CAPABILITIES.into(), &[]),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH.into()
        ))
    );
}
