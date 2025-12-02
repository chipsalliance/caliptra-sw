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
use caliptra_common::mailbox_api::{Response, ResponseVarSize};
use caliptra_drivers::{Aes, CaliptraResult, Hmac, PersistentData, Trng};
use zerocopy::IntoBytes;

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
        let mut hmac_resp = CmHmacResp::default();
        hmac(
            hmac_engine,
            aes,
            trng,
            Crypto::get_cmb_aes_key(persistent_data),
            cmd_bytes,
            hmac_resp.as_mut_bytes(),
        )?;

        hmac_resp.populate_chksum();
        let resp_bytes = hmac_resp.as_bytes_partial()?;
        resp[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok(resp_bytes.len())
    }
}
