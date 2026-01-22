// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{
    MailboxRespHeader, OcpLockRewrapMpkReq, OcpLockRewrapMpkResp, WrappedKey,
};
use caliptra_cfi_derive_git::cfi_impl_fn;

use caliptra_drivers::hpke::HpkeHandle;
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::FromBytes;

use super::{AccessKey, Current, EncryptedAccessKey, LockedMpk, New, Sek};

pub struct RewrapMpkCmd;
impl RewrapMpkCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = OcpLockRewrapMpkReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let sek = Sek(cmd.sek);
        let hpke_handle = HpkeHandle::from(cmd.sealed_access_key.hpke_handle.handle);
        let current_locked_mpk = LockedMpk::try_from(&cmd.current_locked_mpk)?;
        let enc = &cmd.sealed_access_key.kem_ciphertext;

        let info = cmd
            .sealed_access_key
            .info
            .get(..cmd.sealed_access_key.info_len as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let metadata = current_locked_mpk
            .metadata
            .get(..current_locked_mpk.metadata_len as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let current_ak_ct = cmd
            .sealed_access_key
            .ak_ciphertext
            .get(..cmd.sealed_access_key.access_key_len as usize)
            .and_then(|ct| <[u8; AccessKey::<Current>::KEY_LEN]>::ref_from_bytes(ct).ok())
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let current_ak_tag = cmd
            .sealed_access_key
            .ak_ciphertext
            .get(cmd.sealed_access_key.access_key_len as usize..)
            .and_then(|tag| <[u8; 16]>::ref_from_bytes(tag).ok())
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let new_ak_ct = cmd
            .new_ak_ciphertext
            .get(..cmd.sealed_access_key.access_key_len as usize)
            .and_then(|ct| <[u8; AccessKey::<New>::KEY_LEN]>::ref_from_bytes(ct).ok())
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let new_ak_tag = cmd
            .new_ak_ciphertext
            .get(cmd.sealed_access_key.access_key_len as usize..)
            .and_then(|tag| <[u8; 16]>::ref_from_bytes(tag).ok())
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let current_enc_ak = EncryptedAccessKey::<Current>::new(*current_ak_tag, *current_ak_ct);
        let new_enc_ak = EncryptedAccessKey::<New>::new(*new_ak_tag, *new_ak_ct);

        let (current_ak, new_ak) = drivers.ocp_lock_context.decapsulate_rotation_access_keys(
            &mut drivers.sha3,
            &mut drivers.ml_kem,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.aes,
            &hpke_handle,
            enc,
            info,
            metadata,
            &current_enc_ak,
            &new_enc_ak,
        )?;

        let new_locked_mpk = drivers.ocp_lock_context.rewrap_mpk(
            &mut drivers.aes,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.key_vault,
            current_ak,
            new_ak,
            sek,
            &current_locked_mpk,
        )?;

        let resp = mutrefbytes::<OcpLockRewrapMpkResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.wrapped_mek = WrappedKey::try_from(new_locked_mpk)?;
        Ok(core::mem::size_of::<OcpLockRewrapMpkResp>())
    }
}
