use caliptra_drivers::CaliptraResult;

use crate::{mailbox_api::GetSvnResp, Drivers, MailboxResp};

pub fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
    let registers = drivers.soc_ifc.regs();

    let runtime_svn = registers.fuse_runtime_svn().read();
    let fmc_manifest_svn = registers.fuse_fmc_key_manifest_svn().read();

    Ok(MailboxResp::GetSvn(GetSvnResp {
        runtime_svn,
        fmc_manifest_svn,
    }))
}
