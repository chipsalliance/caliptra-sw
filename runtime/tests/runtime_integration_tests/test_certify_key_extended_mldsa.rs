// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{
    CertifyKeyExtendedFlags, CertifyKeyExtendedMldsa87Req, CommandId, MailboxReq, MailboxReqHeader,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;

use crate::common::{assert_error, run_pqc_rt_test};

#[test]
fn test_certify_key_extended_mldsa87_unimplemented() {
    let mut model = run_pqc_rt_test();

    let mut cmd = MailboxReq::CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        flags: CertifyKeyExtendedFlags::empty(),
        certify_key_req: [0u8; CertifyKeyExtendedMldsa87Req::CERTIFY_KEY_REQ_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED_MLDSA87),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND,
        resp,
    );
}
