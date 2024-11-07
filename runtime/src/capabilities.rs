/*++

Licensed under the Apache-2.0 license.

File Name:

    capabilities.rs

Abstract:

    File contains Capabilities mailbox command.

--*/

use caliptra_common::{
    capabilities::Capabilities,
    mailbox_api::{CapabilitiesResp, MailboxResp, MailboxRespHeader},
};
use caliptra_error::CaliptraResult;

pub struct CapabilitiesCmd;
impl CapabilitiesCmd {
    #[inline(never)]
    pub(crate) fn execute() -> CaliptraResult<MailboxResp> {
        let mut capabilities = Capabilities::default();
        capabilities |= Capabilities::RT_BASE;

        Ok(MailboxResp::Capabilities(CapabilitiesResp {
            hdr: MailboxRespHeader::default(),
            capabilities: capabilities.to_bytes(),
        }))
    }
}
