// Licensed under the Apache-2.0 license

use crate::cprintln;
use crate::mailbox_api::{FipsVersionResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::CaliptraResult;
use caliptra_drivers::SocIfc;

pub struct FipsVersionCmd;
impl FipsVersionCmd {
    pub const NAME: [u8; 12] = *b"Caliptra RTM";
    pub const MODE: u32 = 0x46495053;

    pub fn execute(soc_ifc: &SocIfc) -> CaliptraResult<MailboxResp> {
        cprintln!("[rt] FIPS Version");

        let resp = FipsVersionResp {
            hdr: MailboxRespHeader::default(),
            mode: Self::MODE,
            fips_rev: soc_ifc.get_version(),
            name: Self::NAME,
        };

        Ok(MailboxResp::FipsVersion(resp))
    }
}
