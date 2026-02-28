// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{MailboxRespHeader, OcpLockRotateHpkeKeyReq, OcpLockRotateHpkeKeyResp};
use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_drivers::hpke::HpkeHandle;

use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

use crate::{mutrefbytes, Drivers};

pub struct RotateHpkeKeyCmd;
impl RotateHpkeKeyCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = OcpLockRotateHpkeKeyReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let hpke_handle = HpkeHandle::from(cmd.hpke_handle);
        let new_handle = drivers
            .ocp_lock_context
            .rotate_hpke_key(&mut drivers.trng, &hpke_handle)?;

        let resp = mutrefbytes::<OcpLockRotateHpkeKeyResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.hpke_handle = u32::from(new_handle);

        Ok(core::mem::size_of::<OcpLockRotateHpkeKeyResp>())
    }
}
