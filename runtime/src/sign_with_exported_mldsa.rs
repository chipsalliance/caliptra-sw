// Licensed under the Apache-2.0 license

use crate::{dpe_crypto::DpeCrypto, Drivers, PauserPrivileges};

#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_common::mailbox_api::{SignWithExportedMldsaReq, SignWithExportedMldsaResp};
use caliptra_drivers::MLDSA87_MU_BYTES;
use caliptra_error::{CaliptraError, CaliptraResult};

use crypto::{
    ml_dsa::{MldsaPublicKey, MldsaSignature},
    Crypto, CryptoError, Mu, PubKey, SignData, Signature,
};
use dpe::MAX_EXPORTED_CDI_SIZE;
use zerocopy::{FromZeros, IntoBytes};

pub struct SignWithExportedMldsaCmd;
impl SignWithExportedMldsaCmd {
    /// Sign `data` with an ML-DSA-87 key pair derived from an exported CDI
    /// handle, returning the signature and the derived public key.
    ///
    /// This mirrors the ECDSA variant: the exported-CDI lookup and key
    /// derivation live in [`DpeCrypto::derive_key_pair_exported`], which for the
    /// ML-DSA signer reads the raw CDI from `mldsa_exported_cdi_slots`.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn mldsa_sign(
        env: &mut DpeCrypto,
        data: &SignData,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> CaliptraResult<(Signature, PubKey)> {
        let signer = env
            .derive_key_pair_exported(exported_cdi_handle, b"Exported ML-DSA", b"Exported ML-DSA")
            .map_err(|e| match e {
                // No active slot matched the handle.
                CryptoError::InvalidExportedCdiHandle => {
                    CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_FOUND
                }
                _ => CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_KEY_DERIVATION_FAILED,
            })?;

        let pub_key = signer
            .public_key()
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_KEY_DERIVATION_FAILED)?;
        let sig = signer
            .sign(data)
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_SIGNATURE_FAILED)?;

        Ok((sig, pub_key))
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = SignWithExportedMldsaReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        match drivers.caller_privilege_level() {
            // SIGN_WITH_EXPORTED_MLDSA MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        if cmd.message_size as usize > SignWithExportedMldsaReq::MAX_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_PARAMS);
        }

        // Build the data to sign. In data mode `message[..message_size]` is the
        // raw message; in external-mu mode the first MLDSA87_MU_BYTES hold the
        // caller-supplied mu.
        let data = match cmd.sign_mode {
            SignWithExportedMldsaReq::SIGN_MODE_DATA => {
                SignData::Raw(&cmd.message[..cmd.message_size as usize])
            }
            SignWithExportedMldsaReq::SIGN_MODE_EXTERNAL_MU => {
                if cmd.message_size as usize != MLDSA87_MU_BYTES {
                    return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_PARAMS);
                }
                let mut mu = [0u8; MLDSA87_MU_BYTES];
                mu.copy_from_slice(&cmd.message[..MLDSA87_MU_BYTES]);
                SignData::Mu(Mu(mu))
            }
            _ => return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_PARAMS),
        };

        let pdata = drivers.persistent_data.get_mut();
        let mut crypto = DpeCrypto::new_mldsa87(
            &mut drivers.sha384,
            &mut drivers.trng,
            &mut drivers.hmac384,
            &mut drivers.key_vault,
            &pdata.pq_devid_cdi,
            &mut pdata.exported_cdi_slots,
            &pdata.mldsa_exported_cdi_slots,
        )?;

        let (Signature::Mldsa(MldsaSignature(sig)), PubKey::Mldsa(MldsaPublicKey(pub_key))) =
            Self::mldsa_sign(&mut crypto, &data, &cmd.exported_cdi_handle)?
        else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_SIGNATURE_FAILED);
        };

        // Explicitly drop crypto and pdata so the mutable borrow to drivers also ends.
        drop(crypto);
        let _ = pdata;
        Self::send_response(drivers, &pub_key, &sig)
    }

    /// Assemble the response from `pub_key`/`sig` and send it. Kept in its own
    /// (inline-never) frame so the large response buffer does not coexist on the
    /// stack with the ML-DSA keygen/sign frames.
    #[inline(never)]
    fn send_response(drivers: &mut Drivers, pub_key: &[u8], sig: &[u8]) -> CaliptraResult<()> {
        let mut resp = SignWithExportedMldsaResp::new_zeroed();
        resp.derived_pubkey.copy_from_slice(pub_key);
        resp.signature.copy_from_slice(sig);
        crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}
