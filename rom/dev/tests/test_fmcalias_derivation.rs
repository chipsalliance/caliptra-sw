use caliptra_builder::ImageOptions;
// Licensed under the Apache-2.0 license
use caliptra_hw_model::{Fuses, HwModel, ModelError};
use caliptra_image_types::IMAGE_BYTE_SIZE;

mod helpers;

// [TODO] Use the error codes from the common library.
const INVALID_IMAGE_SIZE: u32 = 0x02000003;

#[test]
fn test_zero_firmware_size() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let mut output = vec![];

    // Zero-sized firmware.
    assert_eq!(
        hw.upload_firmware(&[]).unwrap_err(),
        ModelError::MailboxCmdFailed
    );
    let result = hw.copy_output_until_non_fatal_error(INVALID_IMAGE_SIZE, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_firmware_gt_max_size() {
    const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

    // Firmware size > 128 KB.

    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let mut output = vec![];

    // Manually put the oversize data in the mailbox because
    // HwModel::upload_firmware won't let us.
    assert!(!hw.soc_mbox().lock().read().lock());
    hw.soc_mbox().cmd().write(|_| FW_LOAD_CMD_OPCODE);
    hw.soc_mbox().dlen().write(|_| (IMAGE_BYTE_SIZE + 1) as u32);
    for i in 0..((IMAGE_BYTE_SIZE + 1 + 3) / 4) {
        hw.soc_mbox().datain().write(|_| i as u32);
    }
    hw.soc_mbox().execute().write(|w| w.execute(true));
    let result = hw.copy_output_until_non_fatal_error(INVALID_IMAGE_SIZE, &mut output);
    assert!(result.is_ok());
}
