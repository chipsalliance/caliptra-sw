// Licensed under the Apache-2.0 license

use crate::cprintln;
use crate::mailbox_api::{FipsVersionResp, MailboxRespHeader};
use caliptra_drivers::SocIfc;

pub struct FipsVersionCmd;
impl FipsVersionCmd {
    pub const NAME: [u8; 12] = *b"Caliptra RTM";
    pub const NAME_ROT: [u8; 12] = *b"Caliptra ROT";
    pub const MODE: u32 = 0x46495053;

    #[cfg_attr(feature = "runtime", inline(never))]
    pub fn execute(soc_ifc: &SocIfc) -> FipsVersionResp {
        cprintln!("[rt] FIPS Version");

        let name = if soc_ifc.subsystem_mode() {
            Self::NAME_ROT
        } else {
            Self::NAME
        };

        FipsVersionResp {
            hdr: MailboxRespHeader::default(),
            mode: Self::MODE,
            fips_rev: soc_ifc.get_version(),
            name,
        }
    }
}
