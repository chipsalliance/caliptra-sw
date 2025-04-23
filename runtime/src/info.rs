/*++

Licensed under the Apache-2.0 license.

File Name:

    info.rs

Abstract:

    File contains mailbox commands to retrieve info about state of the Runtime firmware.

--*/

use crate::{handoff::RtHandoff, Drivers};
use caliptra_common::mailbox_api::{
    AlgorithmType, FwInfoResp, GetIdevInfoResp, GetIdevMldsa87InfoResp, MailboxResp,
    MailboxRespHeader,
};
use caliptra_drivers::CaliptraResult;

pub struct FwInfoCmd;
impl FwInfoCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        let pdata = drivers.persistent_data.get();

        let handoff = RtHandoff {
            data_vault: &pdata.data_vault,
            fht: &pdata.fht,
        };

        let fw_svn = handoff.fw_svn();
        let min_fw_svn = handoff.fw_min_svn();
        let cold_boot_fw_svn = handoff.cold_boot_fw_svn();
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
            owner_pub_key_hash: pdata.data_vault.owner_pk_hash().into(),
        }))
    }
}

pub struct IDevIdInfoCmd;
impl IDevIdInfoCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &Drivers,
        alg_type: AlgorithmType,
    ) -> CaliptraResult<MailboxResp> {
        let pdata = drivers.persistent_data.get();
        match alg_type {
            AlgorithmType::Ecc384 => {
                let pub_key = pdata.fht.idev_dice_ecdsa_pub_key;

                Ok(MailboxResp::GetIdevInfo(GetIdevInfoResp {
                    hdr: MailboxRespHeader::default(),
                    idev_pub_x: pub_key.x.into(),
                    idev_pub_y: pub_key.y.into(),
                }))
            }
            AlgorithmType::Mldsa87 => {
                let pub_key = pdata.idevid_mldsa_pub_key;

                Ok(MailboxResp::GetIdevMldsa87Info(GetIdevMldsa87InfoResp {
                    hdr: MailboxRespHeader::default(),
                    idev_pub_key: pub_key.into(),
                }))
            }
        }
    }
}
