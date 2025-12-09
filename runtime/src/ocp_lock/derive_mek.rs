// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{MailboxRespHeader, OcpLockDeriveMekReq, OcpLockDeriveMekResp};
use caliptra_cfi_derive_git::cfi_impl_fn;

use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::FromBytes;

use super::MekChecksum;

pub struct DeriveMekCmd;
impl DeriveMekCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // TODO(clundin): Add a PauserPrivileges check?
        let cmd = OcpLockDeriveMekReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let expected_mek_checksum = MekChecksum(cmd.mek_checksum);
        let checksum = drivers.ocp_lock_context.derive_mek(
            &mut drivers.aes,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.key_vault,
            expected_mek_checksum,
        )?;

        let resp = mutrefbytes::<OcpLockDeriveMekResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.mek_checksum = checksum.0;
        Ok(core::mem::size_of::<OcpLockDeriveMekResp>())
    }
}
