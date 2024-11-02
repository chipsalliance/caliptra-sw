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
    #[inline(never)]
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        let pdata = drivers.persistent_data.get();

        let handoff = RtHandoff {
            data_vault: &drivers.data_vault,
            fht: &pdata.fht,
        };

        let fw_svn = handoff.fw_svn()?;
        let min_fw_svn = handoff.fw_min_svn()?;
        let cold_boot_fw_svn = handoff.cold_boot_fw_svn()?;
        let rom_info = handoff.fht.rom_info_addr.get()?;

        Ok(MailboxResp::FwInfo(FwInfoResp {
            hdr: MailboxRespHeader::default(),
            pl0_pauser: pdata.manifest1.header.pl0_pauser,
            fw_svn,
            min_fw_svn,
            cold_boot_fw_svn,
            attestation_disabled: pdata.attestation_disabled.get().into(),
            rom_revision: rom_info.revision,
            fmc_revision: pdata.manifest1.fmc.revision,
            runtime_revision: pdata.manifest1.runtime.revision,
            rom_sha256_digest: rom_info.sha256_digest,
            fmc_sha384_digest: pdata.manifest1.fmc.digest,
            runtime_sha384_digest: pdata.manifest1.runtime.digest,
        }))
    }
}

pub struct IDevIdInfoCmd;
impl IDevIdInfoCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        let pdata = drivers.persistent_data.get();
        let pub_key = pdata.fht.idev_dice_ecdsa_pub_key;

        Ok(MailboxResp::GetIdevInfo(GetIdevInfoResp {
            hdr: MailboxRespHeader::default(),
            idev_pub_x: pub_key.x.into(),
            idev_pub_y: pub_key.y.into(),
        }))
    }
}
