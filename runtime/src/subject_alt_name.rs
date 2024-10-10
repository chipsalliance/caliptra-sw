/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains AddSubjectAltName mailbox command.

--*/

use core::str::from_utf8;

use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::{AddSubjectAltNameReq, MailboxResp};
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::IntoBytes;

use crate::{Drivers, MAX_CERT_CHAIN_SIZE, PL0_PAUSER_FLAG};

pub struct AddSubjectAltNameCmd;
impl AddSubjectAltNameCmd {
    // https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.3.0.pdf 1.3.6.1.4.1.412.274.1
    pub const DMTF_OID: &'static [u8] =
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01];

    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if cmd_args.len() <= core::mem::size_of::<AddSubjectAltNameReq>() {
            let mut cmd = AddSubjectAltNameReq::default();
            cmd.as_mut_bytes()[..cmd_args.len()].copy_from_slice(cmd_args);

            let dmtf_device_info_size = cmd.dmtf_device_info_size as usize;
            if dmtf_device_info_size > cmd.dmtf_device_info.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            Self::validate_dmtf_device_info(&cmd.dmtf_device_info[..dmtf_device_info_size])?;

            let mut dmtf_device_info = ArrayVec::new();
            dmtf_device_info
                .try_extend_from_slice(&cmd.dmtf_device_info[..dmtf_device_info_size])
                .map_err(|_| CaliptraError::RUNTIME_STORE_DMTF_DEVICE_INFO_FAILED)?;
            drivers.dmtf_device_info = Some(dmtf_device_info);

            Ok(MailboxResp::default())
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }

    fn validate_dmtf_device_info(dmtf_device_info: &[u8]) -> CaliptraResult<()> {
        let dmtf_device_info_utf8 = from_utf8(dmtf_device_info)
            .map_err(|_| CaliptraError::RUNTIME_DMTF_DEVICE_INFO_VALIDATION_FAILED)?;
        // dmtf_device_info_utf8 must match ^[^:]*:[^:]*:[^:]*$
        if dmtf_device_info_utf8.chars().filter(|c| *c == ':').count() != 2 {
            Err(CaliptraError::RUNTIME_DMTF_DEVICE_INFO_VALIDATION_FAILED)
        } else {
            Ok(())
        }
    }
}
