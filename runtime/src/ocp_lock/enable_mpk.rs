// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{
    MailboxRespHeader, OcpLockEnableMpkReq, OcpLockEnableMpkResp, WrappedKey,
};
use caliptra_cfi_derive_git::cfi_impl_fn;

use caliptra_drivers::hpke::{aead::Aes256GCM, HpkeHandle};
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::FromBytes;

use super::{AccessKey, Current, LockedMpk, Sek};

pub struct EnableMpkCmd;
impl EnableMpkCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = OcpLockEnableMpkReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let sek = Sek(cmd.sek);
        let hpke_handle = HpkeHandle::from(cmd.sealed_access_key.hpke_handle.handle);
        // Mailbox memory must always have aligned accesses. Copy onto stack to prevent unaligned
        // access.
        let enc = &cmd.sealed_access_key.kem_ciphertext.clone();

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

        let locked_mpk = LockedMpk::try_from(&cmd.locked_mpk)?;

        let access_key = drivers.ocp_lock_context.decapsulate_access_key(
            &mut drivers.sha3,
            &mut drivers.ml_kem,
            &mut drivers.ecc384,
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

        let state = &mut drivers.persistent_data.get_mut().fw.ocp_lock_metadata;

        let enabled_mpk = drivers.ocp_lock_context.enable_mpk(
            &mut drivers.aes,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.key_vault,
            access_key,
            sek,
            &locked_mpk,
            state,
        )?;

        let resp = mutrefbytes::<OcpLockEnableMpkResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.enabled_mpk = WrappedKey::try_from(enabled_mpk)?;
        Ok(core::mem::size_of::<OcpLockEnableMpkResp>())
    }
}
