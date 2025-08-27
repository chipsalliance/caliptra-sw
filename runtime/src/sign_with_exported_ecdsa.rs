// Licensed under the Apache-2.0 license

use crate::{dpe_crypto::DpeCrypto, Drivers, PauserPrivileges};

use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_launder};

use caliptra_common::mailbox_api::{
    MailboxResp, MailboxRespHeader, SignWithExportedEcdsaReq, SignWithExportedEcdsaResp,
};
use caliptra_error::{CaliptraError, CaliptraResult};

use crypto::{Crypto, Digest, EcdsaPub, EcdsaSig};
use dpe::{DPE_PROFILE, MAX_EXPORTED_CDI_SIZE};
use zerocopy::{FromBytes, IntoBytes};

pub struct SignWithExportedEcdsaCmd;
impl SignWithExportedEcdsaCmd {
    /// SignWithExported signs a `digest` using an ECDSA keypair derived from a exported_cdi
    /// handle and the CDI stored in DPE.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `digest` - The data to be signed
    /// * `exported_cdi_handle` - A handle from DPE that is exchanged for a CDI.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn ecdsa_sign(
        env: &mut DpeCrypto,
        digest: &Digest,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> CaliptraResult<(EcdsaSig, EcdsaPub)> {
        let algs = DPE_PROFILE.alg_len();
        let key_pair = env.derive_key_pair_exported(
            algs,
            exported_cdi_handle,
            b"Exported ECC",
            b"Exported ECC",
        );

        if cfi_launder(key_pair.is_ok()) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_ok());
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_err());
        }
        let (priv_key, pub_key) = key_pair
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED)?;

        let sig = env
            .ecdsa_sign_with_derived(algs, digest, &priv_key, &pub_key)
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_SIGNATURE_FAILED)?;

        Ok((sig, pub_key))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = SignWithExportedEcdsaReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        match drivers.caller_privilege_level() {
            // SIGN_WITH_EXPORTED_ECDSA MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        let pdata = drivers.persistent_data.get_mut();

        let mut crypto = DpeCrypto::new(
            &mut drivers.sha384,
            &mut drivers.trng,
            &mut drivers.ecc384,
            &mut drivers.hmac384,
            &mut drivers.key_vault,
            &mut pdata.fht.rt_dice_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            &mut pdata.exported_cdi_slots,
        );

        let digest = Digest::new(&cmd.tbs)
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_DIGEST)?;
        let (EcdsaSig { ref r, ref s }, EcdsaPub { ref x, ref y }) =
            Self::ecdsa_sign(&mut crypto, &digest, &cmd.exported_cdi_handle)?;

        let mut resp = SignWithExportedEcdsaResp::default();
        let mut bytes_written = 0;

        if r.len() <= resp.signature_r.len() {
            resp.signature_r[..r.len()].copy_from_slice(r.bytes());
            bytes_written += r.len()
        } else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        }

        if s.len() <= resp.signature_s.len() {
            resp.signature_s[..s.len()].copy_from_slice(s.bytes());
            bytes_written += s.len()
        } else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        }

        if x.len() <= resp.derived_pubkey_x.len() {
            resp.derived_pubkey_x[..x.len()].copy_from_slice(x.bytes());
            bytes_written += x.len()
        } else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        }

        if y.len() <= resp.derived_pubkey_y.len() {
            resp.derived_pubkey_y[..y.len()].copy_from_slice(y.bytes());
            bytes_written += y.len()
        } else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        }
        Ok(MailboxResp::SignWithExportedEcdsa(resp))
    }
}
