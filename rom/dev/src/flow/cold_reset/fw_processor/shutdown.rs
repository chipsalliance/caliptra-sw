/*++

Licensed under the Apache-2.0 license.

File Name:

    shutdown.rs

Abstract:

    File contains SHUTDOWN mailbox command.

--*/

use caliptra_common::mailbox_api::{MailboxRespHeader, Response};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::IntoBytes;

pub struct ShutdownCmd;
impl ShutdownCmd {
    #[inline(always)]
    pub(crate) fn execute(_cmd_bytes: &[u8], resp: &mut [u8]) -> CaliptraResult<usize> {
        let mut shutdown_resp = MailboxRespHeader::default();
        shutdown_resp.populate_chksum();

        let resp_bytes = shutdown_resp.as_bytes();
        resp[..resp_bytes.len()].copy_from_slice(resp_bytes);

        // Causing a ROM Fatal Error will zeroize the module
        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }
}
