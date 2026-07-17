// Licensed under the Apache-2.0 license

use crate::sign_with_exported_ecdsa::{sign_exported, ExportedSignError};
use crate::{dpe_crypto::DpeCrypto, Drivers, PauserPrivileges};

#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_common::mailbox_api::{SignWithExportedMldsaReq, SignWithExportedMldsaResp};
use caliptra_drivers::{Array4x12, MLDSA87_MU_BYTES};
use caliptra_error::{CaliptraError, CaliptraResult};

use crypto::{
    ml_dsa::{MldsaPublicKey, MldsaSignature},
    Mu, PubKey, SignData, Signature,
};
use zerocopy::{FromZeros, IntoBytes};

pub struct SignWithExportedMldsaCmd;
impl SignWithExportedMldsaCmd {
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
        let root_cdi = Array4x12::from(&pdata.pq_devid_cdi);
        let mut crypto = DpeCrypto::new_mldsa87(
            &mut drivers.sha384,
            &mut drivers.trng,
            &mut drivers.hmac384,
            &mut drivers.key_vault,
            root_cdi,
            &mut pdata.exported_cdi_slots,
            &mut pdata.mldsa_exported_cdi_slots,
        )?;

        let (Signature::Mldsa(MldsaSignature(sig)), PubKey::Mldsa(MldsaPublicKey(pub_key))) =
            sign_exported(
                &mut crypto,
                &data,
                &cmd.exported_cdi_handle,
                b"Exported ML-DSA",
            )
            .map_err(|e| match e {
                ExportedSignError::NotFound => {
                    CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_FOUND
                }
                ExportedSignError::KeyDerivation => {
                    CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_KEY_DERIVATION_FAILED
                }
                ExportedSignError::Signature => {
                    CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_SIGNATURE_FAILED
                }
            })?
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
