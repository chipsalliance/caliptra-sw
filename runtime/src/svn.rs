use caliptra_drivers::CaliptraResult;

use crate::{mailbox_api::GetSvnResp, Drivers, MailboxResp};

pub fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
    let fuse_bank = drivers.soc_ifc.fuse_bank();

    let runtime_svn = fuse_bank.runtime_fuse_svn();
    let fmc_manifest_svn = fuse_bank.fmc_fuse_svn();

    Ok(MailboxResp::GetSvn(GetSvnResp {
        runtime_svn,
        fmc_manifest_svn,
    }))
}
