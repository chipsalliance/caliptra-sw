// Licensed under the Apache-2.0 license

use crate::{Drivers, FwInfoResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::CaliptraResult;

pub struct FwInfoCmd;
impl FwInfoCmd {
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        let fuse_bank = drivers.soc_ifc.fuse_bank();

        let runtime_svn = fuse_bank.runtime_fuse_svn();
        let fmc_manifest_svn = fuse_bank.fmc_fuse_svn();

        Ok(MailboxResp::FwInfo(FwInfoResp {
            hdr: MailboxRespHeader::default(),
            pl0_pauser: drivers.manifest.header.pl0_pauser,
            runtime_svn,
            fmc_manifest_svn,
        }))
    }
}
