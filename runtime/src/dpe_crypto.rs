/*++

Licensed under the Apache-2.0 license.

File Name:

    dpe_crypto.rs

Abstract:

    File contains DpeCrypto implementation.

--*/

use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::keyids::{
    KEY_ID_DPE_CDI, KEY_ID_DPE_PRIV_KEY, KEY_ID_EXPORTED_DPE_CDI, KEY_ID_TMP,
};
use caliptra_drivers::{
    hmac384_kdf, sha384::DpeHasher, Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar,
    Ecc384Seed, ExportedCdiEntry, ExportedCdiHandles, Hmac384, KeyId, KeyReadArgs, KeyUsage,
    KeyVault, KeyWriteArgs, Sha384, Trng,
};
use caliptra_error::CaliptraResult;
use constant_time_eq::constant_time_eq;
use crypto::{
    ecdsa::{
        curve_384::{EcdsaPub384, EcdsaSignature384},
        EcdsaPubKey, EcdsaSignature,
    },
    CdiManager, Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType, Hasher,
    PubKey, SignData, Signature, SignatureAlgorithm, SignatureType,
};
use dpe::{EcdsaAlgorithm, ExportedCdiHandle, U8Bool, MAX_EXPORTED_CDI_SIZE};

pub struct DpeCrypto<'a> {
    trng: &'a mut Trng,
    hmac384: &'a mut Hmac384,
    key_vault: &'a mut KeyVault,
    signer: Signer<'a>,
    hasher: DpeHasher<'a>,
    cdi: Option<KeyId>,
    derived_key: Option<(KeyId, PubKey)>,
    rt_pub_key: PubKey,
    key_id_rt_cdi: KeyId,
    key_id_rt_priv_key: KeyId,
    exported_cdi_slots: &'a mut ExportedCdiHandles,
}

impl<'a> DpeCrypto<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sha384: &'a mut Sha384,
        trng: &'a mut Trng,
        ecc384: &'a mut Ecc384,
        hmac384: &'a mut Hmac384,
        key_vault: &'a mut KeyVault,
        rt_pub_key: PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> CaliptraResult<Self> {
        Ok(Self {
            trng,
            hmac384,
            key_vault,
            signer: Signer::Ec(ecc384),
            hasher: DpeHasher::new(sha384)?,
            cdi: None,
            derived_key: None,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
        })
    }

    fn derive_cdi_inner(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        key_id: KeyId,
    ) -> Result<KeyId, CryptoError> {
        let hasher = self.hasher()?;
        hasher.update(measurement.as_slice())?;
        hasher.update(info)?;
        let context = hasher.finish()?;

        hmac384_kdf(
            self.hmac384,
            KeyReadArgs::new(self.key_id_rt_cdi).into(),
            b"derive_cdi",
            Some(context.as_slice()),
            self.trng,
            KeyWriteArgs::new(
                key_id,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
        Ok(key_id)
    }

    fn derive_key_pair_inner(
        &mut self,
        cdi: &KeyId,
        label: &[u8],
        info: &[u8],
        key_id: KeyId,
    ) -> Result<(KeyId, PubKey), CryptoError> {
        let mut usage: KeyUsage = KeyUsage::default();
        let usage: KeyUsage = match self.signer {
            Signer::Ec(_) => usage.set_ecc_key_gen_seed_en(),
        };

        hmac384_kdf(
            self.hmac384,
            KeyReadArgs::new(*cdi).into(),
            label,
            Some(info),
            self.trng,
            KeyWriteArgs::new(KEY_ID_TMP, usage).into(),
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

        match &mut self.signer {
            Signer::Ec(ecc384) => {
                let pub_key = ecc384
                    .key_pair(
                        &Ecc384Seed::Key(KeyReadArgs::new(KEY_ID_TMP)),
                        &Array4x12::default(),
                        self.trng,
                        KeyWriteArgs::new(key_id, KeyUsage::default().set_ecc_private_key_en())
                            .into(),
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                let pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384::from_slice(
                    &pub_key.x.into(),
                    &pub_key.y.into(),
                )));
                Ok((key_id, pub_key))
            }
        }
    }

    #[inline(never)]
    fn sign_ec(
        ecc384: &mut Ecc384,
        sha384: &mut Sha384,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        let priv_key_args = KeyReadArgs::new(*priv_key);
        let ecc_priv_key = Ecc384PrivKeyIn::Key(priv_key_args);

        let PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384 { x, y })) = pub_key else {
            return Err(CryptoError::MismatchedAlgorithm);
        };
        let ecc_pub_key = Ecc384PubKey {
            x: Ecc384Scalar::from(x),
            y: Ecc384Scalar::from(y),
        };
        let digest = match data {
            SignData::Digest(Digest::Sha384(crypto::Sha384(digest))) => Ecc384Scalar::from(digest),
            SignData::Raw(msg) => sha384.digest(msg).map_err(|_| CryptoError::HashError(0))?,
            _ => return Err(CryptoError::MismatchedAlgorithm),
        };
        let sig = ecc384
            .sign(&ecc_priv_key, &ecc_pub_key, &digest, trng)
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)));
        let sig = match sig.as_ref() {
            Ok(s) => s,
            Err(e) => Err(*e)?,
        };
        Ok(Signature::Ecdsa(EcdsaSignature::Ecdsa384(
            EcdsaSignature384::from_slice(&sig.r.into(), &sig.s.into()),
        )))
    }

    fn sign_helper(
        signer: &mut Signer,
        hasher: &mut DpeHasher,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        match signer {
            Signer::Ec(ecc384) => {
                Self::sign_ec(ecc384, hasher.driver(), trng, data, priv_key, pub_key)
            }
        }
    }
}

impl CryptoSuite for DpeCrypto<'_> {}

impl SignatureType for DpeCrypto<'_> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self.signer {
            Signer::Ec(_) => SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384),
        }
    }
}

impl DigestType for DpeCrypto<'_> {
    fn digest_algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha384
    }
}

impl Drop for DpeCrypto<'_> {
    fn drop(&mut self) {
        let _ = self.key_vault.erase_key(KEY_ID_DPE_CDI);
        let _ = self.key_vault.erase_key(KEY_ID_DPE_PRIV_KEY);
        let _ = self.key_vault.erase_key(KEY_ID_TMP);
    }
}

impl Crypto for DpeCrypto<'_> {
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        for chunk in dst.chunks_mut(48) {
            let trng_bytes = <[u8; 48]>::from(
                self.trng
                    .generate()
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?,
            );
            chunk.copy_from_slice(&trng_bytes[..chunk.len()])
        }
        Ok(())
    }

    fn hasher(&mut self) -> Result<&mut dyn Hasher, CryptoError> {
        Ok(&mut self.hasher)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let mut exported_cdi_handle = [0; MAX_EXPORTED_CDI_SIZE];
        self.rand_bytes(&mut exported_cdi_handle)?;

        // Currently we only use one slot for export CDIs.
        let cdi_slot = KEY_ID_EXPORTED_DPE_CDI;
        // Copy the CDI slots to work around the borrow checker.
        let mut slots_clone = self.exported_cdi_slots.clone();

        for slot in slots_clone.entries.iter_mut() {
            match slot {
                // Matching existing slot
                ExportedCdiEntry {
                    key,
                    handle: _,
                    active,
                } if active.get() && *key == cdi_slot => {
                    Err(CryptoError::ExportedCdiHandleDuplicateCdi)?
                }
                ExportedCdiEntry {
                    key: _,
                    handle: _,
                    active,
                } if !active.get() => {
                    // Empty slot
                    let cdi = self.derive_cdi_inner(measurement, info, cdi_slot)?;
                    *slot = ExportedCdiEntry {
                        key: cdi,
                        handle: exported_cdi_handle,
                        active: U8Bool::new(true),
                    };
                    // We need to update `self.exported_cdi_slots` with our mutation.
                    *self.exported_cdi_slots = slots_clone;
                    return Ok(exported_cdi_handle);
                }
                // Used slot for a different CDI.
                _ => (),
            }
        }
        // Never found an available slot.
        Err(CryptoError::ExportedCdiHandleLimitExceeded)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<&mut dyn CdiManager, CryptoError> {
        self.cdi = Some(self.derive_cdi_inner(measurement, info, KEY_ID_DPE_CDI)?);
        Ok(self)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn crypto::Signer, CryptoError> {
        let cdi = {
            let mut cdi = None;
            for cdi_slot in self.exported_cdi_slots.entries.iter() {
                match cdi_slot {
                    ExportedCdiEntry {
                        key,
                        handle,
                        active,
                    } if active.get() && constant_time_eq(handle, exported_handle) => {
                        cdi = Some(*key);
                        break;
                    }
                    _ => (),
                }
            }
            cdi.ok_or(CryptoError::InvalidExportedCdiHandle)
        }?;
        self.derived_key = Some(self.derive_key_pair_inner(&cdi, label, info, KEY_ID_TMP)?);
        Ok(self)
    }

    fn sign_with_alias(&mut self, data: &SignData) -> Result<Signature, CryptoError> {
        Self::sign_helper(
            &mut self.signer,
            &mut self.hasher,
            self.trng,
            data,
            &self.key_id_rt_priv_key,
            &self.rt_pub_key,
        )
    }
}

impl CdiManager for DpeCrypto<'_> {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_key_pair(
        &mut self,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn crypto::Signer, CryptoError> {
        let cdi: KeyId = self.cdi.ok_or(CryptoError::CryptoLibError(1))?;
        self.derived_key =
            Some(self.derive_key_pair_inner(&cdi, label, info, KEY_ID_DPE_PRIV_KEY)?);
        Ok(self)
    }

    fn as_slice(&self) -> &[u8] {
        // Intentionally unimplemented because this is for test only purposes
        Default::default()
    }
}

impl crypto::Signer for DpeCrypto<'_> {
    fn sign(&mut self, data: &SignData) -> Result<Signature, CryptoError> {
        let Some((priv_key, pub_key)) = &self.derived_key else {
            return Err(CryptoError::CryptoLibError(3));
        };
        Self::sign_helper(
            &mut self.signer,
            &mut self.hasher,
            self.trng,
            data,
            priv_key,
            pub_key,
        )
    }

    fn public_key(&mut self) -> Result<PubKey, CryptoError> {
        let Some((_, pub_key)) = &self.derived_key else {
            return Err(CryptoError::CryptoLibError(4));
        };
        Ok(pub_key.clone())
    }
}

enum Signer<'a> {
    Ec(&'a mut Ecc384),
}
