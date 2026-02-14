/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains CertifyKeyExtended mailbox command.

--*/

use crate::{
    invoke_dpe::invoke_dpe_cmd, mutrefbytes, CaliptraDpeProfile, Drivers, PauserPrivileges,
};
use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::{
    CertifyKeyExtendedFlags, CertifyKeyExtendedReq, CertifyKeyExtendedResp, MailboxRespHeader,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use dpe::commands::{CertifyKeyP384Cmd as CertifyKeyCmd, Command};
use zerocopy::FromBytes;

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

        let certify_key_cmd = CertifyKeyCmd::ref_from_bytes(&cmd.certify_key_req[..]).or(Err(
            CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED,
        ))?;
        let resp = mutrefbytes::<CertifyKeyExtendedResp>(mbox_resp)?;
        resp.hdr = MailboxRespHeader::default();
        let profile = CaliptraDpeProfile::Ecc384;
        let cmd = &Command::from(certify_key_cmd);
        let result = invoke_dpe_cmd(
            profile,
            drivers,
            cmd,
            dmtf_device_info,
            None,
            &mut resp.certify_key_resp,
        );

        match result {
            Ok(dpe_resp_len) => Ok(size_of::<CertifyKeyExtendedResp>()
                - CertifyKeyExtendedResp::CERTIFY_KEY_RESP_SIZE
                + dpe_resp_len),
            Err(e) => {
                // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                if let Some(ext_err) = e.get_error_detail() {
                    drivers.soc_ifc.set_fw_extended_error(ext_err);
                }
                Err(CaliptraError::RUNTIME_CERTIFY_KEY_EXTENDED_FAILED)
            }
        }
    }
}
