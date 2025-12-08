/*++

Licensed under the Apache-2.0 license.

File Name:

    info.rs

Abstract:

    File contains mailbox commands to retrieve info about state of the Runtime firmware.

--*/

use crate::{handoff::RtHandoff, mutrefbytes, Drivers};
use caliptra_common::mailbox_api::{
    AlgorithmType, FwInfoResp, GetIdevEcc384InfoResp, GetIdevMldsa87InfoResp, MailboxRespHeader,
};
use caliptra_drivers::{get_fw_error_non_fatal, CaliptraResult};

pub struct FwInfoCmd;
impl FwInfoCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &Drivers, resp: &mut [u8]) -> CaliptraResult<usize> {
        let pdata = drivers.persistent_data.get();

        let handoff = RtHandoff {
            data_vault: &pdata.data_vault,
            fht: &pdata.fht,
        };
        let rom_info = handoff.fht.rom_info_addr.get()?;

        let resp = mutrefbytes::<FwInfoResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();

        resp.pl0_pauser = pdata.manifest1.header.pl0_pauser;
        resp.fw_svn = handoff.fw_svn();
        resp.min_fw_svn = handoff.fw_min_svn();
        resp.cold_boot_fw_svn = handoff.cold_boot_fw_svn();
        resp.attestation_disabled = pdata.dpe.attestation_disabled.get().into();
        resp.rom_revision = rom_info.revision;
        resp.fmc_revision = pdata.manifest1.fmc.revision;
        resp.runtime_revision = pdata.manifest1.runtime.revision;
        resp.rom_sha256_digest = rom_info.sha256_digest;
        resp.fmc_sha384_digest = pdata.manifest1.fmc.digest;
        resp.runtime_sha384_digest = pdata.manifest1.runtime.digest;
        resp.owner_pub_key_hash = pdata.data_vault.owner_pk_hash().into();
        resp.authman_sha384_digest = pdata.auth_manifest_digest;
        resp.most_recent_fw_error = match get_fw_error_non_fatal() {
            0 => drivers.persistent_data.get().cleared_non_fatal_fw_error,
            e => e,
        };
        Ok(core::mem::size_of::<FwInfoResp>())
    }
}

pub struct IDevIdInfoCmd;
impl IDevIdInfoCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &Drivers,
        alg_type: AlgorithmType,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let pdata = drivers.persistent_data.get();
        match alg_type {
            AlgorithmType::Ecc384 => {
                let pub_key = pdata.fht.idev_dice_ecdsa_pub_key;

                let resp = mutrefbytes::<GetIdevEcc384InfoResp>(resp)?;
                resp.hdr = MailboxRespHeader::default();
                resp.idev_pub_x = pub_key.x.into();
                resp.idev_pub_y = pub_key.y.into();
                Ok(core::mem::size_of::<GetIdevEcc384InfoResp>())
            }
            AlgorithmType::Mldsa87 => {
                let pub_key = pdata.idevid_mldsa_pub_key;

                let resp = mutrefbytes::<GetIdevMldsa87InfoResp>(resp)?;
                resp.hdr = MailboxRespHeader::default();
                resp.idev_pub_key = pub_key.into();
                Ok(core::mem::size_of::<GetIdevMldsa87InfoResp>())
            }
        }
    }
}
