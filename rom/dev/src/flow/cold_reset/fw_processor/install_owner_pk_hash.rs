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

        // Use the response buffer directly as InstallOwnerPkHashResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<InstallOwnerPkHashResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let install_resp = InstallOwnerPkHashResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        install_resp.hdr = MailboxRespHeader::default();
        install_resp.dpe_result = 0; // DPE_STATUS_SUCCESS
        install_resp.populate_chksum();

        let resp_bytes = install_resp.as_bytes();
        Ok(resp_bytes.len())
    }
}
