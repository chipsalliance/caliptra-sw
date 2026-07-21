// Licensed under the Apache-2.0 license

use crate::{
    dpe_crypto::{CryptoEngines, DpeCrypto},
    Drivers,
};
use caliptra_drivers::sha384::DpeHasher;

use caliptra_cfi_derive::cfi_impl_fn;
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};

use caliptra_common::mailbox_api::{SignWithExportedEcdsaReq, SignWithExportedEcdsaResp};
use caliptra_error::{CaliptraError, CaliptraResult};

use crypto::{
    ecdsa::{
        curve_384::{EcdsaPub384, EcdsaSignature384},
        EcdsaPubKey, EcdsaSignature,
    },
    Crypto, CryptoError, Digest, PubKey, SignData, Signature,
};
use dpe::MAX_EXPORTED_CDI_SIZE;
use zerocopy::{FromZeros, IntoBytes};

pub struct SignWithExportedEcdsaCmd;
impl SignWithExportedEcdsaCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = SignWithExportedEcdsaReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        // SIGN_WITH_EXPORTED_ECDSA MUST only be called from PL0
        drivers.ensure_pl0()?;

        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        let pdata = drivers.persistent_data.get_mut();
        let rt_pub_key = &mut pdata.fht.rt_dice_pub_key;
        let rt_pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384::from_slice(
            &rt_pub_key.x.into(),
            &rt_pub_key.y.into(),
        )));

        let mut crypto = DpeCrypto::new_ec(
            CryptoEngines {
                hasher: DpeHasher::new(&mut drivers.sha384)?,
                trng: &mut drivers.trng,
                ecc384: &mut drivers.ecc384,
                hmac384: &mut drivers.hmac384,
                key_vault: &mut drivers.key_vault,
            },
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            &mut pdata.exported_cdi_slots,
        )?;

        let data = Digest::Sha384(crypto::Sha384(cmd.tbs)).into();
        let (
            Signature::Ecdsa(EcdsaSignature::Ecdsa384(EcdsaSignature384 { r, s })),
            PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384 { x, y })),
        ) = sign_exported(
            &mut crypto,
            &data,
            &cmd.exported_cdi_handle,
            b"Exported ECC",
        )
        .map_err(|e| match e {
            ExportedSignError::Signature => {
                CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_SIGNATURE_FAILED
            }
            _ => CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED,
        })?
        else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        };

        let mut resp = SignWithExportedEcdsaResp::default();

        if r.len() <= resp.signature_r.len() {
            resp.signature_r[..r.len()].copy_from_slice(r.as_slice());
        } else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        }

        if s.len() <= resp.signature_s.len() {
            resp.signature_s[..s.len()].copy_from_slice(s.as_slice());
        } else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        }

        if x.len() <= resp.derived_pubkey_x.len() {
            resp.derived_pubkey_x[..x.len()].copy_from_slice(x.as_slice());
        } else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        }

        if y.len() <= resp.derived_pubkey_y.len() {
            resp.derived_pubkey_y[..y.len()].copy_from_slice(y.as_slice());
        } else {
            return Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE);
        }

        // Explicitely drop crypto and pdata so the mutable borrow to drivers also ends.
        drop(crypto);
        let _ = pdata;
        crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}

/// Which step of an exported-CDI sign failed, so each command (ECDSA/ML-DSA) can
/// map it to its own algorithm-specific error code.
pub(crate) enum ExportedSignError {
    /// No active exported-CDI slot matched the handle.
    NotFound,
    KeyDerivation,
    Signature,
}

/// Derive the key pair bound to `exported_cdi_handle` (using `label`) and sign
/// `data`, returning the signature and the derived public key. Shared by the
/// SIGN_WITH_EXPORTED_{ECDSA,MLDSA} commands.
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub(crate) fn sign_exported(
    env: &mut DpeCrypto,
    data: &SignData,
    exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    label: &[u8],
) -> Result<(Signature, PubKey), ExportedSignError> {
    let key_pair = env.derive_key_pair_exported(exported_cdi_handle, label, label);
    if cfi_launder(key_pair.is_ok()) {
        #[cfg(feature = "cfi")]
        cfi_assert!(key_pair.is_ok());
    } else {
        #[cfg(feature = "cfi")]
        cfi_assert!(key_pair.is_err());
    }

    let signer = key_pair.map_err(|e| match e {
        CryptoError::InvalidExportedCdiHandle => ExportedSignError::NotFound,
        _ => ExportedSignError::KeyDerivation,
    })?;
    let pub_key = signer
        .public_key()
        .map_err(|_| ExportedSignError::KeyDerivation)?;
    let sig = signer
        .sign(data)
        .map_err(|_| ExportedSignError::Signature)?;
    Ok((sig, pub_key))
}
