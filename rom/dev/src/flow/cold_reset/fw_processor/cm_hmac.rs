/*++

Licensed under the Apache-2.0 license.

File Name:

    cm_hmac.rs

Abstract:

    File contains CM_HMAC mailbox command.

--*/

use caliptra_api::mailbox::CmHmacResp;
use caliptra_common::crypto::Crypto;
use caliptra_common::hmac_cm::hmac;
use caliptra_common::mailbox_api::ResponseVarSize;
use caliptra_drivers::{Aes, CaliptraError, CaliptraResult, Hmac, PersistentData, Trng};
use zerocopy::{FromBytes, IntoBytes};

pub struct CmHmacCmd;
impl CmHmacCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        aes: &mut Aes,
        hmac_engine: &mut Hmac,
        trng: &mut Trng,
        persistent_data: &mut PersistentData,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // Use the response buffer directly as CmHmacResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<CmHmacResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let hmac_resp = CmHmacResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        hmac(
            hmac_engine,
            aes,
            trng,
            Crypto::get_cmb_aes_key(persistent_data),
            cmd_bytes,
            hmac_resp.as_mut_bytes(),
        )?;

        let resp_bytes = hmac_resp.as_bytes_partial()?;
        Ok(resp_bytes.len())
    }
}
