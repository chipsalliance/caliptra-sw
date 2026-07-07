// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{CommandId, InvokeDpeMldsa87Req, MailboxReq};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;

use crate::common::{assert_error, run_pqc_rt_test};

#[test]
fn test_invoke_dpe_mldsa87_unimplemented() {
    let mut model = run_pqc_rt_test();

    let mut cmd = MailboxReq::InvokeDpeMldsa87Command(InvokeDpeMldsa87Req::default());
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::INVOKE_DPE_MLDSA87),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND,
        resp,
    );
}
