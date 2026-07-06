// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use zerocopy::IntoBytes;

use crate::common::{assert_error, run_pqc_rt_test};

#[test]
fn test_get_pq_csr_unimplemented() {
    let mut model = run_pqc_rt_test();

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_PQ_CSR), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_CSR), payload.as_bytes())
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND,
        resp,
    );
}
