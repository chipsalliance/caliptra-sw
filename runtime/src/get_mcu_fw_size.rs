/*++

Licensed under the Apache-2.0 license.

File Name:

    get_mcu_fw_size.rs

Abstract:

    File contains GET_MCU_FW_SIZE mailbox command.

--*/

use crate::{mutrefbytes, Drivers};
use caliptra_common::mailbox_api::{GetMcuFwSizeResp, MailboxRespHeader};
use caliptra_drivers::CaliptraResult;

/// Metadata about the MCU firmware image downloaded during the recovery flow.
/// Populated by the recovery flow and returned to MCU ROM via the
/// GET_MCU_FW_SIZE mailbox command so it can issue CM_AES_GCM_DECRYPT_DMA
/// without recomputing the digest.
#[derive(Clone, Copy)]
pub struct McuFwInfo {
    /// Size of the MCU firmware image in bytes.
    pub size: u32,
    /// SHA-384 digest of the MCU firmware image (ciphertext).
    pub sha384: [u8; 48],
}

impl Default for McuFwInfo {
    fn default() -> Self {
        Self {
            size: 0,
            sha384: [0u8; 48],
        }
    }
}

pub struct GetMcuFwSizeCmd;
impl GetMcuFwSizeCmd {
    /// Returns the size and SHA-384 digest of the MCU firmware image downloaded
    /// during the recovery flow.  Used by MCU ROM during encrypted boot so it
    /// can issue CM_AES_GCM_DECRYPT_DMA without recomputing the digest.
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, resp: &mut [u8]) -> CaliptraResult<usize> {
        let resp = mutrefbytes::<GetMcuFwSizeResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.size = drivers.mcu_fw_info.size;
        resp.sha384 = drivers.mcu_fw_info.sha384;
        Ok(core::mem::size_of::<GetMcuFwSizeResp>())
    }
}
