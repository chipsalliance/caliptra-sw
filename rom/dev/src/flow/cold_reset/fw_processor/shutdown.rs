/*++

Licensed under the Apache-2.0 license.

File Name:

    shutdown.rs

Abstract:

    File contains SHUTDOWN mailbox command.

--*/

use caliptra_common::mailbox_api::{MailboxReqHeader, MailboxRespHeader, Response};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::{FromBytes, IntoBytes};

pub struct ShutdownCmd;
impl ShutdownCmd {
    #[inline(always)]
    pub(crate) fn execute(cmd_bytes: &[u8], resp: &mut [u8]) -> CaliptraResult<usize> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        // Use the response buffer directly as MailboxRespHeader.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<MailboxRespHeader>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let shutdown_resp = MailboxRespHeader::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        shutdown_resp.populate_chksum();

        let _resp_bytes = shutdown_resp.as_bytes();

        // Causing a ROM Fatal Error will zeroize the module
        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }
}
