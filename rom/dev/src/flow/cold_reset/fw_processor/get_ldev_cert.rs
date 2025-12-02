/*++

Licensed under the Apache-2.0 license.

File Name:

    get_ldev_cert.rs

Abstract:

    File contains GET_LDEV_ECC384_CERT and GET_LDEV_MLDSA87_CERT mailbox commands.

--*/

use caliptra_api::mailbox::{AlgorithmType, GetLdevCertResp};
use caliptra_common::dice::GetLdevCertCmd as CommonGetLdevCertCmd;
use caliptra_common::mailbox_api::{MailboxReqHeader, Response, ResponseVarSize};
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

        let mut ldev_resp = GetLdevCertResp::default();
        CommonGetLdevCertCmd::execute(persistent_data, algorithm_type, ldev_resp.as_mut_bytes())?;

        ldev_resp.populate_chksum();
        let resp_bytes = ldev_resp.as_bytes_partial()?;
        resp[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok(resp_bytes.len())
    }
}
