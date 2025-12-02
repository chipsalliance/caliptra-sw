/*++

Licensed under the Apache-2.0 license.

File Name:

    capabilities.rs

Abstract:

    File contains CAPABILITIES mailbox command.

--*/

use caliptra_common::capabilities::Capabilities;
use caliptra_common::mailbox_api::{
    CapabilitiesResp, MailboxReqHeader, MailboxRespHeader, Response,
};
use caliptra_drivers::{CaliptraError, CaliptraResult, SocIfc};
use zerocopy::{FromBytes, IntoBytes};

pub struct CapabilitiesCmd;
impl CapabilitiesCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        soc_ifc: &mut SocIfc,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let mut capabilities = Capabilities::default();
        capabilities |= Capabilities::ROM_BASE;

        if soc_ifc.ocp_lock_enabled() {
            capabilities |= Capabilities::ROM_OCP_LOCK;
        }

        let mut capabilities_resp = CapabilitiesResp {
            hdr: MailboxRespHeader::default(),
            capabilities: capabilities.to_bytes(),
        };
        capabilities_resp.populate_chksum();

        let resp_bytes = capabilities_resp.as_bytes();
        resp[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok(resp_bytes.len())
    }
}
