/*++

Licensed under the Apache-2.0 license.

File Name:

    get_ldev_cert.rs

Abstract:

    File contains GET_LDEV_ECC384_CERT and GET_LDEV_MLDSA87_CERT mailbox commands.

--*/

use caliptra_api::mailbox::{AlgorithmType, GetLdevCertResp};
use caliptra_common::dice::GetLdevCertCmd as CommonGetLdevCertCmd;
use caliptra_common::mailbox_api::{MailboxReqHeader, ResponseVarSize};
use caliptra_drivers::{CaliptraError, CaliptraResult, PersistentData};
use zerocopy::{FromBytes, IntoBytes};

pub struct GetLdevCertCmd;
impl GetLdevCertCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        persistent_data: &mut PersistentData,
        algorithm_type: AlgorithmType,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        // Use the response buffer directly as GetLdevCertResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<GetLdevCertResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let ldev_resp = GetLdevCertResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        CommonGetLdevCertCmd::execute(persistent_data, algorithm_type, ldev_resp.as_mut_bytes())?;

        let resp_bytes = ldev_resp.as_bytes_partial()?;
        Ok(resp_bytes.len())
    }
}
