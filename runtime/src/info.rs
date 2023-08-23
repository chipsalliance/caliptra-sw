// Licensed under the Apache-2.0 license

use crate::{handoff::RtHandoff, Drivers};
use caliptra_common::mailbox_api::{FwInfoResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::CaliptraResult;

pub struct FwInfoCmd;
impl FwInfoCmd {
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        let handoff = RtHandoff {
            data_vault: &drivers.data_vault,
            fht: drivers.fht,
        };

        let runtime_svn = handoff.rt_svn()?;
        let min_runtime_svn = handoff.rt_min_svn()?;
        let fmc_manifest_svn = handoff.fmc_svn()?;

        Ok(MailboxResp::FwInfo(FwInfoResp {
            hdr: MailboxRespHeader::default(),
            pl0_pauser: drivers.manifest.header.pl0_pauser,
            runtime_svn,
            min_runtime_svn,
            fmc_manifest_svn,
        }))
    }
}
