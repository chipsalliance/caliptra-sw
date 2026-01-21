// Licensed under the Apache-2.0 license

use crate::{dpe_crypto::DpeCrypto, mutrefbytes, Drivers, PauserPrivileges};

use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_launder};

use caliptra_common::cfi_check;
use caliptra_common::mailbox_api::{
    MailboxRespHeader, SignWithExportedEcdsaReq, SignWithExportedEcdsaResp,
};
use caliptra_error::{CaliptraError, CaliptraResult};

use crypto::ecdsa::curve_384::{EcdsaPub384, EcdsaSignature384};
use crypto::ecdsa::{EcdsaPubKey, EcdsaSignature};
use crypto::{Crypto, Digest, PubKey, SignData, Signature};
use dpe::MAX_EXPORTED_CDI_SIZE;
use zerocopy::FromBytes;

pub struct SignWithExportedEcdsaCmd;
impl SignWithExportedEcdsaCmd {
    /// SignWithExported signs a `digest` using an ECDSA keypair derived from a exported_cdi
    /// handle and the CDI stored in DPE.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `data` - The data to be signed
    /// * `exported_cdi_handle` - A handle from DPE that is exchanged for a CDI.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn ecdsa_sign(
        env: &mut DpeCrypto,
        data: &SignData,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> CaliptraResult<(Signature, PubKey)> {
        let key_pair =
            env.derive_key_pair_exported(exported_cdi_handle, b"Exported ECC", b"Exported ECC");

        cfi_check!(key_pair);
        let (priv_key, pub_key) = key_pair
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED)?;

        let sig = env
            .sign_with_derived(data, &priv_key, &pub_key)
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_SIGNATURE_FAILED)?;

        Ok((sig, pub_key))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
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
        let key_id_rt_priv_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;
        let pdata = drivers.persistent_data.get_mut();

        let mut crypto = DpeCrypto::new(
            &mut drivers.sha2_512_384,
            &mut drivers.trng,
            &mut drivers.ecc384,
            &mut drivers.hmac,
            &mut drivers.key_vault,
            &mut pdata.rom.fht.rt_dice_ecc_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            &mut pdata.fw.dpe.exported_cdi_slots,
        );

        let data = Digest::Sha384(crypto::Sha384(cmd.tbs)).into();
        let (
            Signature::Ecdsa(EcdsaSignature::Ecdsa384(EcdsaSignature384 { r, s })),
            PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384 { x, y })),
        ) = Self::ecdsa_sign(&mut crypto, &data, &cmd.exported_cdi_handle)?
        else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        };

        let resp = mutrefbytes::<SignWithExportedEcdsaResp>(resp)?;
        *resp = SignWithExportedEcdsaResp {
            hdr: MailboxRespHeader::default(),
            derived_pubkey_x: x,
            derived_pubkey_y: y,
            signature_r: r,
            signature_s: s,
        };
        Ok(core::mem::size_of::<SignWithExportedEcdsaResp>())
    }
}
