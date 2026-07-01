/*++

Licensed under the Apache-2.0 license.

File Name:

    capabilities.rs

Abstract:

    File contains Capabilities mailbox command.

--*/

use caliptra_common::{
    capabilities::Capabilities,
    mailbox_api::{CapabilitiesResp, MailboxRespHeader},
};
use caliptra_error::CaliptraResult;
use zerocopy::IntoBytes;

use crate::Drivers;

pub struct CapabilitiesCmd;
impl CapabilitiesCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut capabilities = Capabilities::default();
        capabilities |= Capabilities::RT_BASE;

        let mut resp = CapabilitiesResp {
            hdr: MailboxRespHeader::default(),
            capabilities: capabilities.to_bytes(),
        };
        crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}
