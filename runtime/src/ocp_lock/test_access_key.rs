// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{MailboxRespHeader, OcpLockTestAccessKeyReq, OcpLockTestAccessKeyResp};
use caliptra_cfi_derive_git::cfi_impl_fn;

use caliptra_drivers::hpke::{aead::Aes256GCM, HpkeHandle};
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::FromBytes;

use super::{AccessKey, Current, LockedMpk, Sek};

pub struct TestAccessKeyCmd;
impl TestAccessKeyCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = OcpLockTestAccessKeyReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let hpke_handle = HpkeHandle::from(cmd.sealed_access_key.hpke_handle.handle);
        let enc = &cmd.sealed_access_key.kem_ciphertext;
        let info = cmd
            .sealed_access_key
            .info
            .get(..cmd.sealed_access_key.info_len as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let ct = cmd
            .sealed_access_key
            .ak_ciphertext
            .get(..cmd.sealed_access_key.access_key_len as usize)
            .and_then(|ct| <[u8; AccessKey::<Current>::KEY_LEN]>::ref_from_bytes(ct).ok())
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let tag = cmd
            .sealed_access_key
            .ak_ciphertext
            .get(cmd.sealed_access_key.access_key_len as usize..)
            .and_then(|tag| <[u8; Aes256GCM::NT]>::ref_from_bytes(tag).ok())
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let metadata = cmd
            .locked_mpk
            .metadata
            .get(..cmd.locked_mpk.metadata_len as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let nonce = &cmd.nonce;
        let sek = Sek(cmd.sek);
        let locked_mpk = LockedMpk::try_from(&cmd.locked_mpk)?;

        let access_key = drivers.ocp_lock_context.decapsulate_access_key(
            &mut drivers.sha3,
            &mut drivers.abr,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.aes,
            &hpke_handle,
            enc,
            info,
            metadata,
            tag,
            ct,
        )?;

        let resp = mutrefbytes::<OcpLockTestAccessKeyResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.digest = drivers.ocp_lock_context.test_access_key(
            &mut drivers.aes,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.sha2_512_384,
            &mut drivers.key_vault,
            access_key,
            &locked_mpk,
            sek,
            metadata,
            nonce,
        )?;

        Ok(core::mem::size_of::<OcpLockTestAccessKeyResp>())
    }
}
