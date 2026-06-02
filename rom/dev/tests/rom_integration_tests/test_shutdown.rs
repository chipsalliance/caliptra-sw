// Licensed under the Apache-2.0 license

use caliptra_api::{
    mailbox::{CommandId, MailboxReqHeader, MailboxRespHeader},
    SocManager,
};
use caliptra_hw_model::{Fuses, HwModel};
use caliptra_kat::CaliptraError;
use zerocopy::{FromBytes, IntoBytes};

use crate::helpers;

#[test]
fn test_shutdown_cmd() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), Default::default());

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SHUTDOWN), &[]),
    };

    let response = hw
        .mailbox_execute(CommandId::SHUTDOWN.into(), payload.as_bytes())
        .unwrap()
        .unwrap();
    let resp_hdr = MailboxRespHeader::ref_from_bytes(response.as_bytes()).unwrap();

    assert!(caliptra_common::checksum::verify_checksum(
        resp_hdr.chksum,
        0x0,
        &response.as_bytes()[core::mem::size_of_val(&resp_hdr.chksum)..],
    ));

    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::RUNTIME_SHUTDOWN)
    );
}
