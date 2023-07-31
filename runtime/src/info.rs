// Licensed under the Apache-2.0 license

use caliptra_drivers::CaliptraResult;
use crate::{Drivers, MailboxResp, MailboxRespHeader, FwInfoResp};

pub struct FwInfoCmd;
impl FwInfoCmd {
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        Ok(MailboxResp::FwInfo(FwInfoResp {
            hdr: MailboxRespHeader::default(),
            pl0_pauser: drivers.manifest.header.pl0_pauser,
        }))
    }
}