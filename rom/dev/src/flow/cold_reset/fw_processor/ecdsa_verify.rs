/*++

Licensed under the Apache-2.0 license.

File Name:

    ecdsa_verify.rs

Abstract:

    File contains ECDSA384_SIGNATURE_VERIFY mailbox command.

--*/

use caliptra_common::mailbox_api::MailboxRespHeader;
use caliptra_drivers::{report_fw_error_non_fatal, CaliptraResult, Ecc384};

pub struct EcdsaVerifyCmd;
impl EcdsaVerifyCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        ecc384: &mut Ecc384,
        _resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let result = caliptra_common::verify::EcdsaVerifyCmd::execute(ecc384, cmd_bytes);

        match result {
            Ok(_) => {
                // Zero value of response buffer is good
                Ok(core::mem::size_of::<MailboxRespHeader>())
            }
            Err(e) => {
                report_fw_error_non_fatal(e.into());
                // Return 0 to indicate failure
                Ok(0)
            }
        }
    }
}
