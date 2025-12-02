/*++

Licensed under the Apache-2.0 license.

File Name:

    install_owner_pk_hash.rs

Abstract:

    File contains INSTALL_OWNER_PK_HASH mailbox command.

--*/

use caliptra_api::mailbox::{InstallOwnerPkHashReq, InstallOwnerPkHashResp};
use caliptra_common::mailbox_api::{MailboxRespHeader, Response};
use caliptra_drivers::{CaliptraError, CaliptraResult, PersistentData};
use zerocopy::{FromBytes, IntoBytes};

pub struct InstallOwnerPkHashCmd;
impl InstallOwnerPkHashCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        persistent_data: &mut PersistentData,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let request = InstallOwnerPkHashReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        // Save the owner public key hash in persistent data.
        persistent_data
            .dot_owner_pk_hash
            .owner_pk_hash
            .copy_from_slice(&request.digest);
        persistent_data.dot_owner_pk_hash.valid = true;

        // Generate and send response (with FIPS approved status)
        let mut install_resp = InstallOwnerPkHashResp {
            hdr: MailboxRespHeader::default(),
            dpe_result: 0, // DPE_STATUS_SUCCESS
        };
        install_resp.populate_chksum();

        let resp_bytes = install_resp.as_bytes();
        resp[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok(resp_bytes.len())
    }
}
