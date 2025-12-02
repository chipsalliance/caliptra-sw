/*++

Licensed under the Apache-2.0 license.

File Name:

    version.rs

Abstract:

    File contains VERSION mailbox command.

--*/

use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::Response;
use caliptra_drivers::{CaliptraResult, SocIfc};
use zerocopy::IntoBytes;

pub struct VersionCmd;
impl VersionCmd {
    #[inline(always)]
    pub(crate) fn execute(
        _cmd_bytes: &[u8],
        soc_ifc: &mut SocIfc,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let mut version_resp = FipsVersionCmd::execute(soc_ifc);
        version_resp.populate_chksum();

        let resp_bytes = version_resp.as_bytes();
        resp[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok(resp_bytes.len())
    }
}
