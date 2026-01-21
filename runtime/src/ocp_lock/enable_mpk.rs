// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{
    MailboxRespHeader, OcpLockEnableMpkReq, OcpLockEnableMpkResp, WrappedKey,
};
use caliptra_cfi_derive_git::cfi_impl_fn;

use caliptra_common::keyids::ocp_lock::{KEY_ID_HEK, KEY_ID_VEK};
use caliptra_drivers::{
    hmac_kdf,
    hpke::{aead::Aes256GCM, HpkeHandle},
    HmacKey, HmacMode, HmacTag, KeyReadArgs, KeyUsage, KeyWriteArgs, OcpLockFlags,
};
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::{FromBytes, IntoBytes};

use super::{AccessKey, Current, LockedMpk, Sek, Vek};

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

        let locked_mpk = LockedMpk::try_from(&cmd.locked_mpk)?;

        let access_key = drivers.ocp_lock_context.decapsulate_access_key(
            &mut drivers.sha3,
            &mut drivers.ml_kem,
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

        if !drivers
            .persistent_data
            .get()
            .fw
            .ocp_lock_metadata
            .flags
            .contains(OcpLockFlags::VEK_AVAILABLE)
        {
            Self::generate_vek(drivers)?;
        } else {
            // Mark the VEK as available to the OCP LOCK context.
            drivers.ocp_lock_context.vek = Some(Vek);
        }

        let enabled_mpk = drivers.ocp_lock_context.enable_mpk(
            &mut drivers.aes,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.key_vault,
            access_key,
            sek,
            &locked_mpk,
        )?;

        let resp = mutrefbytes::<OcpLockEnableMpkResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.enabled_mpk = WrappedKey::try_from(enabled_mpk)?;
        Ok(core::mem::size_of::<OcpLockEnableMpkResp>())
    }

    /// Generate VEK per OCP LOCK v1.0rc2 figure 5.
    ///
    /// If we are successful, make a note in persistent storage that the VEK is available.
    fn generate_vek(drivers: &mut Drivers) -> CaliptraResult<()> {
        let context = &mut drivers.trng.generate()?;
        hmac_kdf(
            &mut drivers.hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_HEK)),
            Vek::KDF_LABEL,
            Some(context.as_bytes()),
            &mut drivers.trng,
            HmacTag::Key(KeyWriteArgs {
                id: KEY_ID_VEK,
                usage: KeyUsage::default().set_hmac_key_en(),
            }),
            HmacMode::Hmac512,
        )?;
        drivers
            .persistent_data
            .get_mut()
            .fw
            .ocp_lock_metadata
            .flags
            .set(OcpLockFlags::VEK_AVAILABLE, true);
        // Mark the VEK as available to the OCP LOCK context.
        drivers.ocp_lock_context.vek = Some(Vek);
        Ok(())
    }
}
