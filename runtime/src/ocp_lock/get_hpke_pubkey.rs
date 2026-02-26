// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{MailboxRespHeader, OcpLockGetHpkePubKeyReq, OcpLockGetHpkePubKeyResp};
use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_drivers::hpke::HpkeHandle;
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::FromBytes;

pub struct GetHpkePubKeyCmd;
impl GetHpkePubKeyCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let ref_from_bytes = OcpLockGetHpkePubKeyReq::ref_from_bytes(cmd_args);
        let cmd = ref_from_bytes.map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let hpke_handle = HpkeHandle::from(cmd.hpke_handle);

        let resp = mutrefbytes::<OcpLockGetHpkePubKeyResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.pub_key_len = drivers.ocp_lock_context.get_hpke_public_key(
            &mut drivers.sha3,
            &mut drivers.ml_kem,
            &mut drivers.ecc384,
            &mut drivers.trng,
            &mut drivers.hmac,
            &hpke_handle,
            &mut resp.pub_key,
        )? as u32;
        Ok(core::mem::size_of::<OcpLockGetHpkePubKeyResp>())
    }
}
