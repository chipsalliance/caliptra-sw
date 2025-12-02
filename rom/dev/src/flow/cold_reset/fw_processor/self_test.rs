/*++

Licensed under the Apache-2.0 license.

File Name:

    self_test.rs

Abstract:

    File contains SELF_TEST_START and SELF_TEST_GET_RESULTS mailbox commands.

--*/

use caliptra_common::mailbox_api::{MailboxReqHeader, MailboxRespHeader};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use caliptra_kat::KatsEnv;
use zerocopy::{FromBytes, IntoBytes};

use crate::run_fips_tests;

pub struct SelfTestStartCmd;
impl SelfTestStartCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        env: &mut KatsEnv,
        self_test_in_progress: bool,
        resp: &mut [u8],
    ) -> CaliptraResult<(bool, usize)> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        if self_test_in_progress {
            // TODO: set non-fatal error register?
            // Return 0 for response length, will cause txn.complete(false)
            Ok((false, 0))
        } else {
            run_fips_tests(env)?;
            // Use the response buffer directly as MailboxRespHeader.
            // The buffer is zeroized at the start of the loop
            let resp_buffer_size = core::mem::size_of::<MailboxRespHeader>();
            let resp = resp
                .get_mut(..resp_buffer_size)
                .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
            let test_resp = MailboxRespHeader::mut_from_bytes(resp)
                .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

            let resp_bytes = test_resp.as_bytes();
            Ok((true, resp_bytes.len()))
        }
    }
}

pub struct SelfTestGetResultsCmd;
impl SelfTestGetResultsCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        self_test_in_progress: bool,
        resp: &mut [u8],
    ) -> CaliptraResult<(bool, usize)> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        if !self_test_in_progress {
            // TODO: set non-fatal error register?
            // Return 0 for response length, will cause txn.complete(false)
            Ok((false, 0))
        } else {
            // Use the response buffer directly as MailboxRespHeader.
            // The buffer is zeroized at the start of the loop
            let resp_buffer_size = core::mem::size_of::<MailboxRespHeader>();
            let resp = resp
                .get_mut(..resp_buffer_size)
                .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
            let test_resp = MailboxRespHeader::mut_from_bytes(resp)
                .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

            let resp_bytes = test_resp.as_bytes();
            Ok((false, resp_bytes.len()))
        }
    }
}
