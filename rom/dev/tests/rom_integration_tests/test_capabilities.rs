// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_common::capabilities::Capabilities;
use caliptra_common::mailbox_api::{
    CapabilitiesResp, CommandId, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_hw_model::{Fuses, HwModel};
use zerocopy::{AsBytes, FromBytes};

use crate::helpers;

#[test]
fn test_capabilities() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    hw.step_until(|hw| hw.ready_for_fw());

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };

    let response = hw
        .mailbox_execute(CommandId::CAPABILITIES.into(), payload.as_bytes())
        .unwrap()
        .unwrap();

    let capabilities_resp = CapabilitiesResp::read_from(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        capabilities_resp.hdr.chksum,
        0x0,
        &capabilities_resp.as_bytes()[core::mem::size_of_val(&capabilities_resp.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(
        capabilities_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Verify Capabilities
    let caps = Capabilities::try_from(capabilities_resp.capabilities.as_bytes()).unwrap();
    assert!(caps.contains(Capabilities::ROM_BASE));
}
