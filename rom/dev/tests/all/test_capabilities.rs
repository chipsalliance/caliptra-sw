// Licensed under the Apache-2.0 license

use crate::helpers;
use caliptra_builder::ImageOptions;
use caliptra_common::{capabilities::Capabilities, mailbox_api::CommandId};
use caliptra_hw_model::{Fuses, HwModel};
use zerocopy::AsBytes;

#[test]
fn test_capabilities() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let response = hw
        .mailbox_execute(CommandId::CAPABILITIES.into(), &[])
        .unwrap()
        .unwrap();

    let caps = Capabilities::try_from(response.as_bytes()).unwrap();

    assert!(caps.contains(Capabilities::ROM_BASE));
}
