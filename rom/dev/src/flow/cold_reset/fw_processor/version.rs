/*++

Licensed under the Apache-2.0 license.

File Name:

    version.rs

Abstract:

    File contains VERSION mailbox command.

--*/

use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::{MailboxReqHeader, Response};
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

        let mut version_resp = FipsVersionCmd::execute(soc_ifc);
        version_resp.populate_chksum();

        let resp_bytes = version_resp.as_bytes();
        resp[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok(resp_bytes.len())
    }
}
