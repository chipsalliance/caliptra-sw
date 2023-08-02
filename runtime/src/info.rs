// Licensed under the Apache-2.0 license

use crate::{Drivers, FwInfoResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::CaliptraResult;

pub struct FwInfoCmd;
impl FwInfoCmd {
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        Ok(MailboxResp::FwInfo(FwInfoResp {
            hdr: MailboxRespHeader::default(),
            pl0_pauser: drivers.manifest.header.pl0_pauser,
        }))
    }
}
