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
use zerocopy::FromBytes;

use crate::run_fips_tests;

pub struct SelfTestStartCmd;
impl SelfTestStartCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        env: &mut KatsEnv<'_, '_>,
        self_test_in_progress: bool,
        _resp: &mut [u8],
    ) -> CaliptraResult<(bool, usize)> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        if self_test_in_progress {
            // TODO: set non-fatal error register?
            // Return 0 for response length, will cause txn.complete(false)
            Ok((false, 0))
        } else {
            run_fips_tests(env)?;
            // Zero value of response buffer is good
            Ok((true, core::mem::size_of::<MailboxRespHeader>()))
        }
    }
}

pub struct SelfTestGetResultsCmd;
impl SelfTestGetResultsCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        self_test_in_progress: bool,
        _resp: &mut [u8],
    ) -> CaliptraResult<(bool, usize)> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        if !self_test_in_progress {
            // TODO: set non-fatal error register?
            // Return 0 for response length, will cause txn.complete(false)
            Ok((false, 0))
        } else {
            // Zero value of response buffer is good
            Ok((false, core::mem::size_of::<MailboxRespHeader>()))
        }
    }
}
