/*++

Licensed under the Apache-2.0 license.

File Name:

    cm_derive_stable_key.rs

Abstract:

    File contains CM_DERIVE_STABLE_KEY mailbox command.

--*/

use caliptra_api::mailbox::{CmDeriveStableKeyReq, CmDeriveStableKeyResp};
use caliptra_common::mailbox_api::Response;
use caliptra_drivers::{Aes, CaliptraResult, Hmac, PersistentData, Trng};
use zerocopy::{transmute, FromBytes, IntoBytes};

use super::FirmwareProcessor;

pub struct CmDeriveStableKeyCmd;
impl CmDeriveStableKeyCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        persistent_data: &mut PersistentData,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let request = CmDeriveStableKeyReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| caliptra_drivers::CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let encrypted_cmk =
            FirmwareProcessor::derive_stable_key(aes, hmac, trng, persistent_data, request)?;

        // Use the response buffer directly as CmDeriveStableKeyResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<CmDeriveStableKeyResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(caliptra_drivers::CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let derive_resp = CmDeriveStableKeyResp::mut_from_bytes(resp)
            .map_err(|_| caliptra_drivers::CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        derive_resp.cmk = transmute!(encrypted_cmk);
        derive_resp.populate_chksum();

        let resp_bytes = derive_resp.as_bytes();
        Ok(resp_bytes.len())
    }
}
