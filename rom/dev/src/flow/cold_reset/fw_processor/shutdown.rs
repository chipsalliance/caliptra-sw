/*++

Licensed under the Apache-2.0 license.

File Name:

    shutdown.rs

Abstract:

    File contains SHUTDOWN mailbox command.

--*/

use caliptra_common::mailbox_api::MailboxReqHeader;
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

pub struct ShutdownCmd;
impl ShutdownCmd {
    #[inline(always)]
    pub(crate) fn execute(cmd_bytes: &[u8], _resp: &mut [u8]) -> CaliptraResult<usize> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        // Zero value of response buffer is good

        // Causing a ROM Fatal Error will zeroize the module
        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }
}
