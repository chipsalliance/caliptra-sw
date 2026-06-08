/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains CertifyKeyExtended mailbox command.

--*/

use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::{
    CertifyKeyExtendedFlags, CertifyKeyExtendedReq, InvokeDpeResp, MailboxResp, MailboxRespHeader,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use dpe::commands::{CertifyKeyP384Cmd, Command};
use zerocopy::{FromBytes, TryFromBytes};

use crate::{invoke_dpe::invoke_dpe_cmd, Drivers, EcDpeView, PauserPrivileges};

pub struct CertifyKeyExtendedCmd;
impl CertifyKeyExtendedCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = CertifyKeyExtendedReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        match drivers.caller_privilege_level() {
            // CERTIFY_KEY_EXTENDED MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        // Populate the otherName only if requested and provided by ADD_SUBJECT_ALT_NAME
        let dmtf_device_info = if cmd.flags.contains(CertifyKeyExtendedFlags::DMTF_OTHER_NAME) {
            drivers.dmtf_device_info.as_ref().and_then(|info| {
                let mut dmtf_device_info = ArrayVec::new();
                dmtf_device_info.try_extend_from_slice(info).ok()?;
                Some(dmtf_device_info)
            })
        } else {
            None
        };
        let certify_key_cmd = CertifyKeyP384Cmd::ref_from_bytes(&cmd.certify_key_req[..])
            .map_err(|_| CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED)?;
        let command = Command::from(certify_key_cmd);

        let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        let locality = drivers.mbox.user();
        let ec_dpe_view = EcDpeView {
            sha384: &mut drivers.sha384,
            trng: &mut drivers.trng,
            ecc384: &mut drivers.ecc384,
            hmac384: &mut drivers.hmac384,
            key_vault: &mut drivers.key_vault,
            cert_chain: &drivers.cert_chain,
            persistent_data: drivers.persistent_data.get_mut(),
        };
        let (_, resp_buf) = drivers
            .mbox
            .raw_mailbox_contents_mut()?
            .split_at_mut(core::mem::offset_of!(InvokeDpeResp, data));
        let result = invoke_dpe_cmd(
            &command,
            ec_dpe_view,
            hashed_rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            dmtf_device_info,
            None,
            locality,
            resp_buf,
        );
        let (dpe_resp, _) =
            InvokeDpeResp::try_mut_from_prefix(drivers.mbox.raw_mailbox_contents_mut()?)
                .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        dpe_resp.hdr = MailboxRespHeader::default();

        result
            .inspect(|data_size| {
                dpe_resp.data_size = *data_size as u32;
            })
            .map_err(|e| {
                // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                if let Some(ext_err) = e.get_error_detail() {
                    drivers.soc_ifc.set_fw_extended_error(ext_err);
                }
                CaliptraError::RUNTIME_CERTIFY_KEY_EXTENDED_FAILED
            })?;

        let total_size = core::mem::size_of::<InvokeDpeResp>()
            - core::mem::size_of_val(&dpe_resp.data)
            + dpe_resp.data_size as usize;

        Ok(MailboxResp::InPlace(total_size))
    }
}
