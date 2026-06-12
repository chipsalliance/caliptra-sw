// Licensed under the Apache-2.0 license

use crate::{dpe_crypto::DpeCrypto, mutrefbytes, Drivers, PauserPrivileges};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};

use caliptra_common::cfi_check;
use caliptra_common::mailbox_api::{
    MailboxRespHeader, MldsaSignType, SignWithExportedMldsaReq, SignWithExportedMldsaResp,
};
use caliptra_drivers::okref;
use caliptra_error::{CaliptraError, CaliptraResult};

use caliptra_dpe::MAX_EXPORTED_CDI_SIZE;
use caliptra_dpe_crypto::ml_dsa::{MldsaPublicKey, MldsaSignature};
use caliptra_dpe_crypto::{Crypto, Mu, PubKey, SignData, Signature};
use zerocopy::FromBytes;

const PROFILE_DESC: &[u8] = b"Exported ML-DSA";

pub struct SignWithExportedMldsaCmd;

impl SignWithExportedMldsaCmd {
    /// SignWithExported signs a `digest` using an MLDSA keypair derived from a exported_cdi
    /// handle and the CDI stored in DPE.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `data` - The data to be signed
    /// * `exported_cdi_handle` - A handle from DPE that is exchanged for a CDI.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn mldsa_sign(
        env: &mut DpeCrypto,
        data: &SignData,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> CaliptraResult<(Signature, PubKey)> {
        let key_pair =
            env.derive_key_pair_exported(exported_cdi_handle, PROFILE_DESC, PROFILE_DESC);

        cfi_check!(key_pair);
        let signer = key_pair
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_KEY_DERIVIATION_FAILED)?;

        let pub_key = signer.public_key();
        let pub_key = okref(&pub_key)
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_KEY_DERIVIATION_FAILED)?;

        let sig = signer.sign(data);
        let sig = okref(&sig)
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_SIGNATURE_FAILED)?;

        Ok((sig.clone(), pub_key.clone()))
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = SignWithExportedMldsaReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        match drivers.caller_privilege_level() {
            // SIGN_WITH_EXPORTED_MLDSA MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_mldsa_keypair_seed(drivers)?;
        let rt_pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers)?;
        let rt_pub_key = PubKey::Mldsa(MldsaPublicKey(rt_pub_key.into()));

        let pdata = drivers.persistent_data.get_mut();

        let mut crypto = DpeCrypto::new_mldsa87(
            &mut drivers.sha2_512_384,
            &mut drivers.trng,
            drivers.abr.abr_reg(),
            &mut drivers.hmac,
            &mut drivers.key_vault,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            &mut pdata.fw.dpe.exported_cdi_slots,
        )?;

        let sign_type = MldsaSignType::try_from(cmd.sign_type)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let data = match sign_type {
            MldsaSignType::Mu => {
                if cmd.tbs_size != 64 {
                    return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
                }
                SignData::Mu(Mu(cmd.tbs[..64].try_into().unwrap()))
            }
            MldsaSignType::Raw => {
                if cmd.tbs_size as usize > cmd.tbs.len() {
                    return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
                }
                SignData::Raw(&cmd.tbs[..cmd.tbs_size as usize])
            }
        };
        let result = Self::mldsa_sign(&mut crypto, &data, &cmd.exported_cdi_handle);
        let (sig, pubkey) = okref(&result)?;
        let (Signature::Mldsa(MldsaSignature(sig)), PubKey::Mldsa(MldsaPublicKey(pubkey))) =
            (sig, pubkey)
        else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_SIGNATURE);
        };

        let resp = mutrefbytes::<SignWithExportedMldsaResp>(resp)?;
        *resp = SignWithExportedMldsaResp {
            hdr: MailboxRespHeader::default(),
            derived_pubkey: *pubkey,
            signature: *sig,
            _padding: Default::default(),
        };
        Ok(core::mem::size_of::<SignWithExportedMldsaResp>())
    }
}
