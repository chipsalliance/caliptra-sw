/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains AddSubjectAltName mailbox command.

--*/

use crate::Drivers;
use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::AddSubjectAltNameReq;
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::IntoBytes;

pub struct AddSubjectAltNameCmd;
impl AddSubjectAltNameCmd {
    // https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.3.0.pdf 1.3.6.1.4.1.412.274.1
    pub const DMTF_OID: &'static [u8] =
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01];

    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
        if cmd_args.len() <= core::mem::size_of::<AddSubjectAltNameReq>() {
            let mut cmd = AddSubjectAltNameReq::default();
            cmd.as_mut_bytes()[..cmd_args.len()].copy_from_slice(cmd_args);

            let dmtf_device_info_size = cmd.dmtf_device_info_size as usize;
            if dmtf_device_info_size > cmd.dmtf_device_info.len() {
                return Err(CaliptraError::MAILBOX_INVALID_PARAMS);
            }

            Self::validate_dmtf_device_info(&cmd.dmtf_device_info[..dmtf_device_info_size])?;

            let mut dmtf_device_info = ArrayVec::new();
            dmtf_device_info
                .try_extend_from_slice(&cmd.dmtf_device_info[..dmtf_device_info_size])
                .map_err(|_| CaliptraError::RUNTIME_STORE_DMTF_DEVICE_INFO_FAILED)?;
            drivers.dmtf_device_info = Some(dmtf_device_info);

            Ok(0)
        } else {
            Err(CaliptraError::MBOX_PAYLOAD_INVALID_SIZE)
        }
    }

    /// Verifies that `dmtf_device_info` only contains ascii characters and contains exactly 2 ':'
    /// characters.
    ///
    /// dmtf_device_info_utf8 must match ^[^:]*:[^:]*:[^:]*$
    fn validate_dmtf_device_info(dmtf_device_info: &[u8]) -> CaliptraResult<()> {
        let mut colon_count = 0;
        for c in dmtf_device_info.iter() {
            if !c.is_ascii() {
                Err(CaliptraError::RUNTIME_DMTF_DEVICE_INFO_VALIDATION_FAILED)?
            }

            if *c == b':' {
                colon_count += 1;
            }
        }
        if colon_count != 2 {
            Err(CaliptraError::RUNTIME_DMTF_DEVICE_INFO_VALIDATION_FAILED)?
        }
        Ok(())
    }
}
