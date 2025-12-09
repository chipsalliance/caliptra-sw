// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{
    MailboxRespHeader, OcpLockInitializeMekSecretReq, OcpLockInitializeMekSecretResp,
};
use caliptra_cfi_derive_git::cfi_impl_fn;

use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::FromBytes;

use super::{Dpk, Sek};

pub struct InitializeMekSecretCmd;
impl InitializeMekSecretCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // TODO(clundin): Add a PauserPrivileges check?
        let cmd = OcpLockInitializeMekSecretReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        drivers.ocp_lock_context.create_mek_secret_seed(
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.key_vault,
            Sek(cmd.sek),
            Dpk(cmd.dpk),
        )?;

        let resp = mutrefbytes::<OcpLockInitializeMekSecretResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        Ok(core::mem::size_of::<OcpLockInitializeMekSecretResp>())
    }
}
