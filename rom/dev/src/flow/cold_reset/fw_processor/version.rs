/*++

Licensed under the Apache-2.0 license.

File Name:

    version.rs

Abstract:

    File contains VERSION mailbox command.

--*/

use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::{FipsVersionResp, MailboxReqHeader, Response};
use caliptra_drivers::{CaliptraError, CaliptraResult, SocIfc};
use zerocopy::{FromBytes, IntoBytes};

pub struct VersionCmd;
impl VersionCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        soc_ifc: &mut SocIfc,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        // Use the response buffer directly as FipsVersionResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<FipsVersionResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let version_resp = FipsVersionResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let version_data = FipsVersionCmd::execute(soc_ifc);
        version_resp.hdr = version_data.hdr;
        version_resp.mode = version_data.mode;
        version_resp.fips_rev = version_data.fips_rev;
        version_resp.name = version_data.name;
        version_resp.populate_chksum();

        let resp_bytes = version_resp.as_bytes();
        Ok(resp_bytes.len())
    }
}
