// Licensed under the Apache-2.0 license
use caliptra_builder::{firmware, ImageOptions};

// FMC and Runtime FW binaries should run on both RTL 1.1+ and RTL 1.0
// The hw-1.0 feature is still necessary but should not be used in a way it impacts the binary
// (Skip this test when hw-1.0 feature is enabled globally since it would be enabled for both image builds)
#[cfg(not(feature = "hw-1.0"))]
#[test]
fn test_hw_1_0_bin_identical() {
    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let image_hw_1_0 = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART_HW_1_0,
        &firmware::APP_WITH_UART_HW_1_0,
        ImageOptions::default(),
    )
    .unwrap();

    assert!(image.runtime == image_hw_1_0.runtime);
    assert!(image.fmc == image_hw_1_0.fmc);
}
