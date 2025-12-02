/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa_verify.rs

Abstract:

    File contains MLDSA87_SIGNATURE_VERIFY mailbox command.

--*/

use caliptra_common::mailbox_api::{MailboxRespHeader, Response};
use caliptra_drivers::{report_fw_error_non_fatal, CaliptraResult, Mldsa87};
use zerocopy::IntoBytes;

pub struct MldsaVerifyCmd;
impl MldsaVerifyCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        mldsa87: &mut Mldsa87,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let result = caliptra_common::verify::MldsaVerifyCmd::execute(mldsa87, cmd_bytes);

        match result {
            Ok(_) => {
                let mut verify_resp = MailboxRespHeader::default();
                verify_resp.populate_chksum();

                let resp_bytes = verify_resp.as_bytes();
                resp[..resp_bytes.len()].copy_from_slice(resp_bytes);
                Ok(resp_bytes.len())
            }
            Err(e) => {
                report_fw_error_non_fatal(e.into());
                // Return 0 to indicate failure
                Ok(0)
            }
        }
    }
}
