/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains CertifyKeyExtended mailbox command.

--*/

use crate::{
    mutrefbytes, CptraDpeTypes, DpeCrypto, DpeEnv, DpePlatform, Drivers, PauserPrivileges,
};
use caliptra_common::mailbox_api::{
    CertifyKeyExtendedFlags, CertifyKeyExtendedReq, CertifyKeyExtendedResp, MailboxRespHeader,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use dpe::{
    commands::{CertifyKeyP384Cmd as CertifyKeyCmd, CommandExecution},
    response::Response,
    DpeInstance, DpeProfile,
};
use zerocopy::{FromBytes, IntoBytes};

pub struct CertifyKeyExtendedCmd;
impl CertifyKeyExtendedCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = CertifyKeyExtendedReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        match drivers.caller_privilege_level() {
            // CERTIFY_KEY_EXTENDED MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        let pdata = drivers.persistent_data.get_mut();
        let crypto = DpeCrypto::new(
            &mut drivers.sha2_512_384,
            &mut drivers.trng,
            &mut drivers.ecc384,
            &mut drivers.hmac,
            &mut drivers.key_vault,
            &mut pdata.rom.fht.rt_dice_ecc_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            &mut pdata.fw.dpe.exported_cdi_slots,
        );
        let pl0_pauser = pdata.rom.manifest1.header.pl0_pauser;
        let (nb, nf) = Drivers::get_cert_validity_info(&pdata.rom.manifest1);
        // Populate the otherName only if requested and provided by ADD_SUBJECT_ALT_NAME
        let dmtf_device_info = if cmd.flags.contains(CertifyKeyExtendedFlags::DMTF_OTHER_NAME) {
            drivers
                .dmtf_device_info
                .as_ref()
                .map(|dmtf_device_info| dmtf_device_info.as_bytes())
        } else {
            None
        };
        let mut env = DpeEnv::<CptraDpeTypes> {
            crypto,
            platform: DpePlatform::new(
                pl0_pauser,
                &hashed_rt_pub_key,
                &drivers.ecc_cert_chain,
                &nb,
                &nf,
                dmtf_device_info,
                None,
            ),
            state: &mut pdata.fw.dpe.state,
        };

        let certify_key_cmd = CertifyKeyCmd::ref_from_bytes(&cmd.certify_key_req[..]).or(Err(
            CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED,
        ))?;
        let locality = drivers.mbox.id();
        let dpe = &mut DpeInstance::initialized(DpeProfile::P384Sha384);
        let resp = certify_key_cmd.execute(dpe, &mut env, locality);

        let certify_key_resp = match resp {
            Ok(Response::CertifyKey(certify_key_resp)) => certify_key_resp,
            Ok(_) => return Err(CaliptraError::RUNTIME_CERTIFY_KEY_EXTENDED_FAILED),
            Err(e) => {
                // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                if let Some(ext_err) = e.get_error_detail() {
                    drivers.soc_ifc.set_fw_extended_error(ext_err);
                }
                return Err(CaliptraError::RUNTIME_CERTIFY_KEY_EXTENDED_FAILED);
            }
        };

        let certify_key_extended_resp = mutrefbytes::<CertifyKeyExtendedResp>(mbox_resp)?;
        certify_key_extended_resp.hdr = MailboxRespHeader::default();
        certify_key_extended_resp.certify_key_resp = certify_key_resp
            .as_bytes()
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_DPE_RESPONSE_SERIALIZATION_FAILED)?;
        Ok(core::mem::size_of::<CertifyKeyExtendedResp>())
    }
}
