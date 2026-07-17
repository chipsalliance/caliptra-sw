/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains CertifyKeyExtended mailbox command.

--*/

use crate::{
    invoke_dpe::invoke_dpe_cmd, CaliptraDpeProfile, Drivers, MboxResponseWriter, PauserPrivileges,
};
use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::{
    CertifyKeyExtendedFlags, CertifyKeyExtendedReq, MailboxRespHeader, MailboxRespHeaderVarSize,
};
use caliptra_dpe_response_buffer::{OffsetResponseBuffer, ResponseBuffer};
use caliptra_drivers::{CaliptraError, CaliptraResult};
#[cfg(feature = "mldsa_attestation")]
use dpe::commands::CertifyKeyMldsa87Cmd;
use dpe::commands::{CertifyKeyP384Cmd, Command};
use zerocopy::{FromBytes, FromZeros, IntoBytes};

pub struct CertifyKeyExtendedCmd;
impl CertifyKeyExtendedCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = CertifyKeyExtendedReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;
        Self::certify_key(
            drivers,
            cmd.flags,
            &cmd.certify_key_req,
            CaliptraDpeProfile::Ecc384,
        )
    }

    /// CERTIFY_KEY_EXTENDED logic generic to the cryptographic algorithm in use.
    pub(crate) fn certify_key(
        drivers: &mut Drivers,
        flags: CertifyKeyExtendedFlags,
        certify_key_req: &[u8],
        profile: CaliptraDpeProfile,
    ) -> CaliptraResult<()> {
        match drivers.caller_privilege_level() {
            // CERTIFY_KEY_EXTENDED MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        // Populate the otherName only if requested and provided by ADD_SUBJECT_ALT_NAME
        let dmtf_device_info = if flags.contains(CertifyKeyExtendedFlags::DMTF_OTHER_NAME) {
            drivers.dmtf_device_info.as_ref().and_then(|info| {
                let mut dmtf_device_info = ArrayVec::new();
                dmtf_device_info.try_extend_from_slice(info).ok()?;
                Some(dmtf_device_info)
            })
        } else {
            None
        };

        let command = match profile {
            CaliptraDpeProfile::Ecc384 => Command::from(
                CertifyKeyP384Cmd::ref_from_bytes(certify_key_req)
                    .map_err(|_| CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED)?,
            ),
            #[cfg(feature = "mldsa_attestation")]
            CaliptraDpeProfile::Mldsa => Command::from(
                CertifyKeyMldsa87Cmd::ref_from_bytes(certify_key_req)
                    .map_err(|_| CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED)?,
            ),
        };

        let mut writer = MboxResponseWriter::from_mbox_base();
        let mut w = OffsetResponseBuffer::new(&mut writer, size_of::<MailboxRespHeaderVarSize>());

        let resp_size = invoke_dpe_cmd(
            profile,
            drivers,
            &command,
            dmtf_device_info,
            None,
            None,
            &mut w,
        )
        .map_err(|e| {
            drivers.soc_ifc.set_fw_extended_error(e.get_error_code());
            // The Mbox writer cannot encounter an error during clear, and the Certify Key
            // extended error is more important.
            let _ = writer.clear();
            CaliptraError::RUNTIME_CERTIFY_KEY_EXTENDED_FAILED
        })?;

        let header = MailboxRespHeaderVarSize {
            hdr: MailboxRespHeader::default(),
            data_len: resp_size as u32,
        };
        crate::packet::finalize_mbox_buffer(&mut drivers.mbox, &mut writer, header)?;
        Ok(())
    }
}
