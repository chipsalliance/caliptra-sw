// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{MailboxRespHeader, OcpLockGenerateMekResp, WrappedKey};
use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_error::CaliptraResult;

pub struct GenerateMekCmd;
impl GenerateMekCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        _cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let wrapped_mek = drivers.ocp_lock_context.generate_mek(
            &mut drivers.aes,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.key_vault,
        )?;
        let resp = mutrefbytes::<OcpLockGenerateMekResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.wrapped_mek = WrappedKey::try_from(wrapped_mek)?;

        Ok(core::mem::size_of::<OcpLockGenerateMekResp>())
    }
}
