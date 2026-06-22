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
#[cfg(feature = "mldsa_attestation")]
use {
    caliptra_drivers::{
        Mldsa87, Mldsa87PubKey, Mldsa87Seed, MLDSA87_PRIVATE_SEED_BYTES, MLDSA87_PUBLIC_KEY_BYTES,
        MLDSA87_SIGNATURE_BYTES,
    },
    crypto::ml_dsa::{MldsaAlgorithm, MldsaPublicKey, MldsaSignature},
    zeroize::Zeroizing,
};

pub struct DpeCrypto<'a> {
    trng: &'a mut Trng,
    hmac384: &'a mut Hmac384,
    key_vault: &'a mut KeyVault,
    signer: Signer<'a>,
    hasher: DpeHasher<'a>,
    cdi: Option<KeyId>,
    derived_key: Option<DerivedKey>,
    key_id_rt_cdi: KeyId,
    exported_cdi_slots: &'a mut ExportedCdiHandles,
}

impl<'a> DpeCrypto<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new_ec(
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
            signer: Signer::Ec {
                ecc384,
                rt_pub_key,
                rt_priv_key: key_id_rt_priv_key,
            },
            hasher: DpeHasher::new(sha384)?,
            cdi: None,
            derived_key: None,
            key_id_rt_cdi,
            exported_cdi_slots,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    #[cfg(feature = "mldsa_attestation")]
    pub fn new_mldsa87(
        sha384: &'a mut Sha384,
        trng: &'a mut Trng,
        hmac384: &'a mut Hmac384,
        key_vault: &'a mut KeyVault,
        key_id_rt_cdi: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> CaliptraResult<Self> {
        let mut output = Zeroizing::new(Array4x12::default());
        hmac384_kdf(
            hmac384,
            KeyReadArgs::new(key_id_rt_cdi).into(),
            b"pq_devid_alias",
            None,
            trng,
            (&mut *output).into(),
        )?;

        let bytes: [u8; core::mem::size_of::<Array4x12>()] = (*output).into();
        let mut rt_seed = Zeroizing::new([0u8; MLDSA87_PRIVATE_SEED_BYTES]);
        rt_seed.copy_from_slice(&bytes[..MLDSA87_PRIVATE_SEED_BYTES]);

        Ok(Self {
            trng,
            hmac384,
            key_vault,
            signer: Signer::Mldsa { rt_seed },
            hasher: DpeHasher::new(sha384)?,
            cdi: None,
            derived_key: None,
            key_id_rt_cdi,
            exported_cdi_slots,
        })
    }

    fn derive_cdi_inner(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        key_id: KeyId,
    ) -> Result<KeyId, CryptoError> {
        let context = self.hash_all(&[&measurement.as_slice(), &info])?;

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

    #[cfg(feature = "mldsa_attestation")]
    fn derive_key_pair_mldsa(
        &mut self,
        cdi: &KeyId,
        label: &[u8],
        info: &[u8],
        seed: &mut Mldsa87Seed,
        pub_key: &mut Mldsa87PubKey,
    ) -> Result<(), CryptoError> {
        let mut output = Zeroizing::new(Array4x12::default());
        hmac384_kdf(
            self.hmac384,
            KeyReadArgs::new(*cdi).into(),
            label,
            Some(info),
            self.trng,
            (&mut *output).into(),
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

        let bytes = Zeroizing::new(<[u8; core::mem::size_of::<Array4x12>()]>::from(*output));
        seed.copy_from_slice(&bytes[..MLDSA87_PRIVATE_SEED_BYTES]);

        Mldsa87::pub_from_seed(seed, pub_key, None)
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))
    }

    fn derive_key_pair_ec(
        &mut self,
        cdi: &KeyId,
        label: &[u8],
        info: &[u8],
        key_id: KeyId,
    ) -> Result<(KeyId, PubKey), CryptoError> {
        let mut usage: KeyUsage = KeyUsage::default();
        let usage = usage.set_ecc_key_gen_seed_en();

        match &mut self.signer {
            Signer::Ec { ecc384, .. } => {
                hmac384_kdf(
                    self.hmac384,
                    KeyReadArgs::new(*cdi).into(),
                    label,
                    Some(info),
                    self.trng,
                    KeyWriteArgs::new(KEY_ID_TMP, usage).into(),
                )
                .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

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
            #[cfg(feature = "mldsa_attestation")]
            _ => Err(CryptoError::MismatchedAlgorithm),
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

    fn sign_helper_ec(
        signer: &mut Signer,
        hasher: &mut DpeHasher,
        trng: &mut Trng,
        data: &SignData,
        key_pair: Option<(&PubKey, &KeyId)>,
    ) -> Result<Signature, CryptoError> {
        match (signer, key_pair) {
            (Signer::Ec { ecc384, .. }, Some((pub_key, priv_key))) => {
                Self::sign_ec(ecc384, hasher.driver(), trng, data, priv_key, pub_key)
            }
            (
                Signer::Ec {
                    ecc384,
                    rt_pub_key,
                    rt_priv_key,
                    ..
                },
                None,
            ) => Self::sign_ec(ecc384, hasher.driver(), trng, data, rt_priv_key, rt_pub_key),
            #[cfg(feature = "mldsa_attestation")]
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
    }

    #[cfg(feature = "mldsa_attestation")]
    fn sign_helper_mldsa(
        signer: &mut Signer,
        data: &SignData,
        seed: Option<&Mldsa87Seed>,
    ) -> Result<Signature, CryptoError> {
        let Signer::Mldsa { rt_seed } = signer else {
            return Err(CryptoError::MismatchedAlgorithm);
        };
        let mut sig = [0u8; MLDSA87_SIGNATURE_BYTES];
        let seed = seed.unwrap_or(rt_seed);
        Mldsa87::sign_deterministic(seed, data.as_slice(), &mut sig)
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
        Ok(Signature::Mldsa(MldsaSignature(sig)))
    }
}

impl CryptoSuite for DpeCrypto<'_> {}

impl SignatureType for DpeCrypto<'_> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self.signer {
            Signer::Ec { .. } => SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384),
            #[cfg(feature = "mldsa_attestation")]
            Signer::Mldsa { .. } => SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87),
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

        match self.signer {
            Signer::Ec { .. } => {
                self.derived_key = Some(DerivedKey::Ec(
                    self.derive_key_pair_ec(&cdi, label, info, KEY_ID_TMP)?,
                ));
            }
            #[cfg(feature = "mldsa_attestation")]
            Signer::Mldsa { .. } => {
                let mut seed = Zeroizing::new([0u8; MLDSA87_PRIVATE_SEED_BYTES]);
                let mut pub_key = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
                self.derive_key_pair_mldsa(&cdi, label, info, &mut seed, &mut pub_key)?;
                self.derived_key = Some(DerivedKey::Mldsa((seed, pub_key)));
            }
        }

        Ok(self)
    }

    fn sign_with_alias(&mut self, data: &SignData) -> Result<Signature, CryptoError> {
        match self.signer {
            Signer::Ec { .. } => {
                Self::sign_helper_ec(&mut self.signer, &mut self.hasher, self.trng, data, None)
            }

            #[cfg(feature = "mldsa_attestation")]
            Signer::Mldsa { .. } => Self::sign_helper_mldsa(&mut self.signer, data, None),
        }
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

        match self.signer {
            Signer::Ec { .. } => {
                self.derived_key = Some(DerivedKey::Ec(self.derive_key_pair_ec(
                    &cdi,
                    label,
                    info,
                    KEY_ID_DPE_PRIV_KEY,
                )?));
            }

            #[cfg(feature = "mldsa_attestation")]
            Signer::Mldsa { .. } => {
                let mut seed = Zeroizing::new([0u8; MLDSA87_PRIVATE_SEED_BYTES]);
                let mut pub_key = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
                self.derive_key_pair_mldsa(&cdi, label, info, &mut seed, &mut pub_key)?;
                self.derived_key = Some(DerivedKey::Mldsa((seed, pub_key)));
            }
        }
        Ok(self)
    }

    fn as_slice(&self) -> &[u8] {
        // Intentionally unimplemented because this is for test only purposes
        Default::default()
    }
}

impl crypto::Signer for DpeCrypto<'_> {
    fn sign(&mut self, data: &SignData) -> Result<Signature, CryptoError> {
        match self.signer {
            Signer::Ec { .. } => {
                let Some(DerivedKey::Ec((priv_key, pub_key))) = &self.derived_key else {
                    return Err(CryptoError::CryptoLibError(3));
                };
                Self::sign_helper_ec(
                    &mut self.signer,
                    &mut self.hasher,
                    self.trng,
                    data,
                    Some((pub_key, priv_key)),
                )
            }

            #[cfg(feature = "mldsa_attestation")]
            Signer::Mldsa { .. } => {
                let Some(DerivedKey::Mldsa((seed, _))) = &self.derived_key else {
                    return Err(CryptoError::CryptoLibError(3));
                };
                Self::sign_helper_mldsa(&mut self.signer, data, Some(seed))
            }
        }
    }

    fn public_key(&mut self) -> Result<PubKey, CryptoError> {
        match &self.derived_key {
            Some(DerivedKey::Ec((_, pub_key))) => Ok(pub_key.clone()),
            #[cfg(feature = "mldsa_attestation")]
            Some(DerivedKey::Mldsa((_, pub_key))) => {
                Ok(PubKey::Mldsa(MldsaPublicKey(pub_key.clone())))
            }
            _ => Err(CryptoError::CryptoLibError(4)),
        }
    }
}

enum Signer<'a> {
    Ec {
        ecc384: &'a mut Ecc384,
        rt_pub_key: PubKey,
        rt_priv_key: KeyId,
    },
    #[cfg(feature = "mldsa_attestation")]
    Mldsa { rt_seed: Zeroizing<Mldsa87Seed> },
}

enum DerivedKey {
    Ec((KeyId, PubKey)),
    #[cfg(feature = "mldsa_attestation")]
    Mldsa((Zeroizing<Mldsa87Seed>, Mldsa87PubKey)),
}
