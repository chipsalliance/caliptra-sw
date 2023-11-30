// Licensed under the Apache-2.0 license

use crate::{handoff::RtHandoff, Drivers};
use caliptra_common::mailbox_api::{FwInfoResp, GetIdevInfoResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::CaliptraResult;

pub struct FwInfoCmd;
impl FwInfoCmd {
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        let pdata = drivers.persistent_data.get();

        let handoff = RtHandoff {
            data_vault: &drivers.data_vault,
            fht: &pdata.fht,
        };

        let runtime_svn = handoff.rt_svn()?;
        let min_runtime_svn = handoff.rt_min_svn()?;
        let fmc_manifest_svn = handoff.fmc_svn()?;

        Ok(MailboxResp::FwInfo(FwInfoResp {
            hdr: MailboxRespHeader::default(),
            pl0_pauser: pdata.manifest1.header.pl0_pauser,
            runtime_svn,
            min_runtime_svn,
            fmc_manifest_svn,
            attestation_disabled: drivers.attestation_disabled.into(),
        }))
    }
}

pub struct IDevIdInfoCmd;
impl IDevIdInfoCmd {
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        let pdata = drivers.persistent_data.get();
        let pub_key = pdata.fht.idev_dice_pub_key;

        Ok(MailboxResp::GetIdevInfo(GetIdevInfoResp {
            hdr: MailboxRespHeader::default(),
            idev_pub_x: pub_key.x.into(),
            idev_pub_y: pub_key.y.into(),
        }))
    }
}
