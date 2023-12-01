// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader};
use caliptra_hw_model::HwModel;
use zerocopy::{AsBytes, FromBytes};

use crate::common::run_rt_test;

#[test]
fn test_disable_attestation_cmd() {
    let mut model = run_rt_test(None, None, None);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };
    // once DPE APIs are enabled, ensure that the RT alias key in the cert is different from the key that signs DPE certs
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();

    let resp_hdr = MailboxRespHeader::read_from(resp.as_bytes()).unwrap();
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
}
