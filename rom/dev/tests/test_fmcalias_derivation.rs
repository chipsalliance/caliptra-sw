// Licensed under the Apache-2.0 license
use caliptra_hw_model::{Fuses, HwModel};
use caliptra_image_types::IMAGE_BYTE_SIZE;

mod helpers;

// [TODO] Use the error codes from the common library.
const INVALID_IMAGE_SIZE: u32 = 0x02000003;

#[test]
fn test_zero_firmware_size() {
    let (mut hw, _image_bundle) = helpers::build_hw_model_and_image_bundle(Fuses::default());
    let mut output = vec![];

    // Zero-sized firmware.
    hw.upload_firmware(&[]).unwrap();
    let result = hw.copy_output_until_non_fatal_error(INVALID_IMAGE_SIZE, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_firmware_gt_max_size() {
    let (mut hw, _image_bundle) = helpers::build_hw_model_and_image_bundle(Fuses::default());
    let mut output = vec![];

    // Firmware size > 128 KB.
    hw.upload_firmware(&vec![0u8; IMAGE_BYTE_SIZE + 1]).unwrap();
    let result = hw.copy_output_until_non_fatal_error(INVALID_IMAGE_SIZE, &mut output);
    assert!(result.is_ok());
}
