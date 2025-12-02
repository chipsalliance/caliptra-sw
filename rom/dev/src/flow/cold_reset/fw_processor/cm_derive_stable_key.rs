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

        let mut derive_resp = CmDeriveStableKeyResp {
            cmk: transmute!(encrypted_cmk),
            ..Default::default()
        };
        derive_resp.populate_chksum();

        let resp_bytes = derive_resp.as_bytes();
        resp[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok(resp_bytes.len())
    }
}
