// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    AccessKeySizes, EndorsementAlgorithms, HpkeAlgorithms, OcpLockGetAlgorithmsResp,
};
use caliptra_error::{CaliptraError, CaliptraResult};

use crate::mutrefbytes;

use super::OcpLockContext;

pub struct GetAlgorithmsCmd;
impl GetAlgorithmsCmd {
    #[cfg_attr(not(feature = "no-cfi"), caliptra_cfi_derive_git::cfi_impl_fn)]
    #[inline(never)]
    pub fn execute(context: &mut OcpLockContext, resp: &mut [u8]) -> CaliptraResult<usize> {
        if !context.available() {
            Err(CaliptraError::RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND)?;
        }
        let resp = mutrefbytes::<OcpLockGetAlgorithmsResp>(resp)?;
        resp.access_key_sizes = AccessKeySizes::LEN_256;
        resp.endorsement_algorithms = EndorsementAlgorithms::all();
        resp.hpke_algorithms = HpkeAlgorithms::all();
        Ok(core::mem::size_of::<OcpLockGetAlgorithmsResp>())
    }
}
