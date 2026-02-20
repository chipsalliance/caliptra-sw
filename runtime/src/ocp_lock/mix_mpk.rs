// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{MailboxRespHeader, OcpLockMixMpkReq, OcpLockMixMpkResp};
use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::FromBytes;

use super::EnabledMpk;

pub struct MixMpkCmd;
impl MixMpkCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = OcpLockMixMpkReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let enabled_mpk = EnabledMpk::try_from(&cmd.enabled_mpk)?;
        let state = &drivers.persistent_data.get().fw.ocp_lock_metadata;

        drivers.ocp_lock_context.mix_mpk(
            &mut drivers.aes,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.key_vault,
            &enabled_mpk,
            state,
        )?;

        let resp = mutrefbytes::<OcpLockMixMpkResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        Ok(core::mem::size_of::<OcpLockMixMpkResp>())
    }
}
