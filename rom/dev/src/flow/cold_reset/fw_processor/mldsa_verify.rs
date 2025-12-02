/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa_verify.rs

Abstract:

    File contains MLDSA87_SIGNATURE_VERIFY mailbox command.

--*/

use caliptra_common::mailbox_api::{MailboxRespHeader, Response};
use caliptra_drivers::{report_fw_error_non_fatal, CaliptraError, CaliptraResult, Mldsa87};
use zerocopy::{FromBytes, IntoBytes};

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
                // Use the response buffer directly as MailboxRespHeader.
                // The buffer is zeroized at the start of the loop
                let resp_buffer_size = core::mem::size_of::<MailboxRespHeader>();
                let resp = resp
                    .get_mut(..resp_buffer_size)
                    .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
                let verify_resp = MailboxRespHeader::mut_from_bytes(resp)
                    .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

                verify_resp.populate_chksum();

                let resp_bytes = verify_resp.as_bytes();
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
