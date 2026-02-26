// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{MailboxRespHeader, OcpLockEnumerateHpkeHandlesResp};
use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_error::CaliptraResult;

use crate::{mutrefbytes, Drivers};

pub struct EnumerateHpkeHandles;
impl EnumerateHpkeHandles {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        _cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let resp = mutrefbytes::<OcpLockEnumerateHpkeHandlesResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.hpke_handle_count = 0;

        for (returned_handle, (handle, cipher)) in resp
            .hpke_handles
            .iter_mut()
            .zip(drivers.ocp_lock_context.iterate_hpke_handles())
        {
            returned_handle.handle = handle.into();
            returned_handle.hpke_algorithm = cipher.into();
            resp.hpke_handle_count += 1;
        }
        Ok(core::mem::size_of::<OcpLockEnumerateHpkeHandlesResp>())
    }
}
