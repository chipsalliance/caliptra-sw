/*++

Licensed under the Apache-2.0 license.

File Name:

    info.rs

Abstract:

    File contains mailbox commands to retrieve info about state of the Runtime firmware.

--*/

use crate::{handoff::RtHandoff, Drivers};
use caliptra_common::mailbox_api::{FwInfoResp, GetIdevInfoResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::CaliptraResult;
use caliptra_image_types::RomInfo;

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
        let rom_info = handoff.fht.rom_info_addr.get()?;

        Ok(MailboxResp::FwInfo(FwInfoResp {
            hdr: MailboxRespHeader::default(),
            pl0_pauser: pdata.manifest1.header.pl0_pauser,
            runtime_svn,
            min_runtime_svn,
            fmc_manifest_svn,
            attestation_disabled: pdata.attestation_disabled.get().into(),
            rom_revision: rom_info.revision.0,
            fmc_revision: pdata.manifest1.fmc.revision.0,
            runtime_revision: pdata.manifest1.runtime.revision.0,
            rom_sha256_digest: rom_info.sha256_digest,
            fmc_sha384_digest: pdata.manifest1.fmc.digest.0,
            runtime_sha384_digest: pdata.manifest1.runtime.digest.0,
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
