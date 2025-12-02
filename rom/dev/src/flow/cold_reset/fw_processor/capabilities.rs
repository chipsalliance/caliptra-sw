/*++

Licensed under the Apache-2.0 license.

File Name:

    capabilities.rs

Abstract:

    File contains CAPABILITIES mailbox command.

--*/

use caliptra_common::capabilities::Capabilities;
use caliptra_common::mailbox_api::{CapabilitiesResp, MailboxReqHeader, MailboxRespHeader};
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

        // Use the response buffer directly as CapabilitiesResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<CapabilitiesResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let capabilities_resp = CapabilitiesResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let mut capabilities = Capabilities::default();
        capabilities |= Capabilities::ROM_BASE;

        if soc_ifc.ocp_lock_enabled() {
            capabilities |= Capabilities::ROM_OCP_LOCK;
        }

        capabilities_resp.hdr = MailboxRespHeader::default();
        capabilities_resp.capabilities = capabilities.to_bytes();
        let resp_bytes = capabilities_resp.as_bytes();
        Ok(resp_bytes.len())
    }
}
