// Licensed under the Apache-2.0 license

use caliptra_builder::{version, ImageOptions};
use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::{
    CommandId, FipsVersionResp, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_hw_model::{Fuses, HwModel};
use zerocopy::{AsBytes, FromBytes};

use crate::helpers;

// TODO: Find a better way to get this or make it a don't-care for this test
//       This is not going to work when we start testing against multiple hw revs
const HW_REV_ID: u32 = 0x1;

#[test]
fn test_version() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };

    let response = hw
        .mailbox_execute(CommandId::VERSION.into(), payload.as_bytes())
        .unwrap()
        .unwrap();

    let version_resp = FipsVersionResp::read_from(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        version_resp.hdr.chksum,
        0x0,
        &version_resp.as_bytes()[core::mem::size_of_val(&version_resp.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(
        version_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Verify Version Info
    assert_eq!(version_resp.mode, FipsVersionCmd::MODE);
    // fw_rev[0] is FMC version at 31:16 and ROM version at 15:0
    // fw_rev[1] is app (fw) version
    // FMC and FW version are expected to be 0x0 before FW load
    assert_eq!(
        version_resp.fips_rev,
        [HW_REV_ID, (version::get_rom_version() as u32), 0x0]
    );
    let name = &version_resp.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());
}
