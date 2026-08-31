// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{
    MailboxRespHeader, OcpLockInitializeMekSecretReq, OcpLockInitializeMekSecretResp,
};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_error::CaliptraResult;

use super::{stage_mailbox_request, Dpk, Sek};

pub struct InitializeMekSecretCmd;
impl InitializeMekSecretCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let mut staging_buffer = [0u32; core::mem::size_of::<OcpLockInitializeMekSecretReq>() / 4];
        let cmd =
            stage_mailbox_request::<OcpLockInitializeMekSecretReq>(cmd_args, &mut staging_buffer)?;

        drivers.ocp_lock_context.create_intermediate_mek_secret(
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.key_vault,
            Sek::new(cmd.sek)?,
            Dpk::new(cmd.dpk)?,
        )?;

        let resp = mutrefbytes::<OcpLockInitializeMekSecretResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        Ok(core::mem::size_of::<OcpLockInitializeMekSecretResp>())
    }
}
