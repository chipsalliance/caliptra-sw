/*++

Licensed under the Apache-2.0 license.

File Name:

    capabilities.rs

Abstract:

    File contains Capabilities mailbox command.

--*/

use crate::{mutrefbytes, Drivers};
use caliptra_common::{
    capabilities::Capabilities,
    mailbox_api::{CapabilitiesResp, MailboxRespHeader},
};
use caliptra_drivers::CaliptraResult;

pub struct CapabilitiesCmd;
impl CapabilitiesCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, resp: &mut [u8]) -> CaliptraResult<usize> {
        let mut capabilities = Capabilities::default();
        capabilities |= Capabilities::RT_BASE;

        if drivers.ocp_lock_context.available() {
            capabilities |= Capabilities::RT_OCP_LOCK;
        }

        let resp = mutrefbytes::<CapabilitiesResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.capabilities = capabilities.to_bytes();
        Ok(core::mem::size_of::<CapabilitiesResp>())
    }
}
