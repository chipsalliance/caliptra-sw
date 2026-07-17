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
use caliptra_dpe_response_buffer::ResponseBufError;
use caliptra_drivers::{
    hmac384_kdf, sha384::DpeHasher, Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar,
    Ecc384Seed, ExportedCdiEntry, ExportedCdiHandles, Hmac384, Hmac384Key, Hmac384Tag, KeyId,
    KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Sha384, Trng,
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
    crate::dice,
    caliptra_drivers::{
        Mldsa87, Mldsa87Mu, Mldsa87PubKey, Mldsa87Seed, Mldsa87Signature, MldsaExportedCdiEntry,
        MLDSA87_PRIVATE_SEED_BYTES, PQ_DEVID_CDI_SIZE,
    },
    crypto::ml_dsa::{MldsaAlgorithm, MldsaPublicKey, MldsaSignature},
    zerocopy::FromBytes,
    zeroize::Zeroizing,
};

// A CDI, held either as a key-vault slot (ECDSA) or in memory (ML-DSA). Used for
// both the root RT CDI and the derived DPE CDI. ML-DSA cannot keep a CDI in a
// key-vault slot: the hardware zeroes any CPU read of an HMAC tag derived from a
// key-vault-sourced key (key_from_kv=true), so it must derive in and from memory.
#[allow(clippy::large_enum_variant)]
enum Cdi {
    Ec(KeyId),
    #[cfg(feature = "mldsa_attestation")]
    Mldsa(Zeroizing<Array4x12>),
}

pub struct DpeCrypto<'a> {
    trng: &'a mut Trng,
    hmac384: &'a mut Hmac384,
    key_vault: &'a mut KeyVault,
    signer: Signer<'a>,
    hasher: DpeHasher<'a>,
    cdi: Option<Cdi>,
    derived_key: Option<DerivedKey>,
    rt_cdi: Cdi,
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
            rt_cdi: Cdi::Ec(key_id_rt_cdi),
            exported_cdi_slots,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "mldsa_attestation")]
    pub fn new_mldsa87(
        sha384: &'a mut Sha384,
        trng: &'a mut Trng,
        hmac384: &'a mut Hmac384,
        key_vault: &'a mut KeyVault,
        root_cdi: Array4x12,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
        exported_cdi_slot: &'a mut MldsaExportedCdiEntry,
    ) -> CaliptraResult<Self> {
        Ok(Self {
            trng,
            hmac384,
            key_vault,
            signer: Signer::Mldsa { exported_cdi_slot },
            hasher: DpeHasher::new(sha384)?,
            cdi: None,
            derived_key: None,
            rt_cdi: Cdi::Mldsa(Zeroizing::new(root_cdi)),
            exported_cdi_slots,
        })
    }

    // Shared CDI-derivation KDF: HMAC(key, "derive_cdi", measurement || info) → output.
    // The `key` (RT CDI) and `output` (derived CDI) enums abstract over key-vault
    // slots (ECDSA) versus in-memory buffers (ML-DSA), which is the only difference
    // between the two algorithms' derivations.
    fn derive_cdi_kdf(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        key: Hmac384Key,
        output: Hmac384Tag,
    ) -> Result<(), CryptoError> {
        let context = self.hash_all(&[&measurement.as_slice(), &info])?;
        hmac384_kdf(
            self.hmac384,
            key,
            b"derive_cdi",
            Some(context.as_slice()),
            self.trng,
            output,
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))
    }

    // EC-only: HMAC from key-vault RT CDI → key-vault output slot.
    fn derive_cdi_inner_ec(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        key_id: KeyId,
    ) -> Result<KeyId, CryptoError> {
        let key_id_rt_cdi = match &self.rt_cdi {
            Cdi::Ec(k) => *k,
            #[cfg(feature = "mldsa_attestation")]
            _ => return Err(CryptoError::CryptoLibError(0x100)),
        };
        self.derive_cdi_kdf(
            measurement,
            info,
            KeyReadArgs::new(key_id_rt_cdi).into(),
            KeyWriteArgs::new(
                key_id,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )?;
        Ok(key_id)
    }

    // ML-DSA: HMAC from in-memory root CDI → in-memory output. key_from_kv stays
    // false so the hardware security model does not zero the HMAC tag on CPU reads.
    #[cfg(feature = "mldsa_attestation")]
    fn derive_cdi_inner_mldsa(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Zeroizing<Array4x12>, CryptoError> {
        // Copy root CDI to the stack before borrowing self.hmac384/trng.
        let root_copy = match &self.rt_cdi {
            Cdi::Mldsa(root) => root.clone(),
            _ => return Err(CryptoError::MismatchedAlgorithm),
        };
        let mut output = Zeroizing::new(Array4x12::default());
        self.derive_cdi_kdf(
            measurement,
            info,
            (&*root_copy).into(),
            (&mut *output).into(),
        )?;
        Ok(output)
    }

    // Derive only the ML-DSA seed from an in-memory CDI.
    #[cfg(feature = "mldsa_attestation")]
    fn derive_key_pair_mldsa(
        &mut self,
        cdi_key: Hmac384Key,
        label: &[u8],
        info: &[u8],
        seed: &mut Mldsa87Seed,
    ) -> Result<(), CryptoError> {
        let mut output = Zeroizing::new(Array4x12::default());
        hmac384_kdf(
            self.hmac384,
            cdi_key,
            label,
            Some(info),
            self.trng,
            (&mut *output).into(),
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

        let bytes = Zeroizing::new(<[u8; core::mem::size_of::<Array4x12>()]>::from(*output));
        seed.copy_from_slice(&bytes[..MLDSA87_PRIVATE_SEED_BYTES]);

        Ok(())
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
            SignData::ResponseBuffer(buf, range) => {
                let mut op = sha384
                    .digest_init()
                    .map_err(|_| CryptoError::HashError(0))?;
                buf.read_range(range.clone(), &mut |d| {
                    op.update(d).map_err(|_| ResponseBufError::Overflow)
                })
                .map_err(|_| CryptoError::HashError(0))?;

                let mut digest = Array4x12::default();
                op.finalize(&mut digest)
                    .map_err(|_| CryptoError::HashError(0))?;
                digest
            }
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
    fn sign_helper_mldsa(data: &SignData, seed: &Mldsa87Seed) -> Result<Signature, CryptoError> {
        let mut sig = Mldsa87Signature::default();
        match data {
            SignData::ResponseBuffer(buf, range) => {
                let mut mu = Mldsa87Mu::default();
                Mldsa87::generate_mu(seed, *buf, range.clone(), &mut mu)
                    .map_err(|_| CryptoError::HashError(0))?;
                Mldsa87::sign_mu_deterministic(seed, &mu, &mut sig)
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))
            }
            SignData::Raw(msg) => Mldsa87::sign_deterministic(seed, msg, &mut sig)
                .map_err(|e| CryptoError::CryptoLibError(u32::from(e))),
            SignData::Mu(mu) => {
                let mu = Mldsa87Mu::ref_from_bytes(&mu.0).map_err(|_| CryptoError::Size)?;
                Mldsa87::sign_mu_deterministic(seed, mu, &mut sig)
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))
            }
            _ => return Err(CryptoError::MismatchedAlgorithm),
        }?;

        Ok(Signature::Mldsa(MldsaSignature(*sig)))
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

        match self.signer {
            Signer::Ec { .. } => {
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
                            return Err(CryptoError::ExportedCdiHandleDuplicateCdi);
                        }
                        ExportedCdiEntry {
                            key: _,
                            handle: _,
                            active,
                        } if !active.get() => {
                            // Empty slot
                            let cdi = self.derive_cdi_inner_ec(measurement, info, cdi_slot)?;
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
            // ML-DSA: CDI cannot live in a key-vault slot, so use the dedicated
            // in-memory persistent-data slot held in the ML-DSA signer variant.
            #[cfg(feature = "mldsa_attestation")]
            Signer::Mldsa { .. } => {
                // Only one ML-DSA exported CDI slot exists; reject if it is in use.
                // Scope the borrow so it ends before derive_cdi_inner_mldsa (&mut self).
                // The borrow will be trivially true since we entered this branch of the match.
                if let Signer::Mldsa { exported_cdi_slot } = &self.signer {
                    if exported_cdi_slot.active.get() {
                        return Err(CryptoError::ExportedCdiHandleLimitExceeded);
                    }
                }

                let mldsa_cdi = self.derive_cdi_inner_mldsa(measurement, info)?;
                let cdi_bytes = <[u8; PQ_DEVID_CDI_SIZE as usize]>::from(*mldsa_cdi);
                // The borrow will be trivially true since we entered this branch of the match.
                if let Signer::Mldsa { exported_cdi_slot } = &mut self.signer {
                    exported_cdi_slot.cdi = cdi_bytes;
                    exported_cdi_slot.handle = exported_cdi_handle;
                    exported_cdi_slot.active = U8Bool::new(true);
                }
                Ok(exported_cdi_handle)
            }
        }
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<&mut dyn CdiManager, CryptoError> {
        self.cdi = match &self.signer {
            Signer::Ec { .. } => Some(Cdi::Ec(self.derive_cdi_inner_ec(
                measurement,
                info,
                KEY_ID_DPE_CDI,
            )?)),
            #[cfg(feature = "mldsa_attestation")]
            Signer::Mldsa { .. } => {
                Some(Cdi::Mldsa(self.derive_cdi_inner_mldsa(measurement, info)?))
            }
        };
        Ok(self)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn crypto::Signer, CryptoError> {
        match self.signer {
            Signer::Ec { .. } => {
                // ECDSA exported CDIs are key-vault slots referenced by KeyId.
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
                    cdi.ok_or(CryptoError::InvalidExportedCdiHandle)?
                };
                self.derived_key = Some(DerivedKey::Ec(
                    self.derive_key_pair_ec(&cdi, label, info, KEY_ID_TMP)?,
                ));
            }
            #[cfg(feature = "mldsa_attestation")]
            Signer::Mldsa { .. } => {
                // The ML-DSA exported CDI is held as raw bytes in a single
                // persistent-data slot; derive directly from those bytes.
                let cdi = {
                    let Signer::Mldsa { exported_cdi_slot } = &self.signer else {
                        return Err(CryptoError::InvalidExportedCdiHandle);
                    };
                    if !(exported_cdi_slot.active.get()
                        && constant_time_eq(&exported_cdi_slot.handle, exported_handle))
                    {
                        return Err(CryptoError::InvalidExportedCdiHandle);
                    }
                    Zeroizing::new(Array4x12::from(&exported_cdi_slot.cdi))
                };
                let mut seed = Mldsa87Seed::default();
                self.derive_key_pair_mldsa((&*cdi).into(), label, info, &mut seed)?;
                self.derived_key = Some(DerivedKey::Mldsa(seed));
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
            Signer::Mldsa { .. } => {
                let cdi = match &self.rt_cdi {
                    Cdi::Mldsa(pq_devid_cdi) => pq_devid_cdi.clone(),
                    _ => return Err(CryptoError::MismatchedAlgorithm),
                };
                let mut seed = Mldsa87Seed::default();
                dice::derive_devid_seed(&((*cdi).into()), &mut seed, self.hmac384, self.trng)
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                Self::sign_helper_mldsa(data, &seed)
            }
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
        match &self.signer {
            Signer::Ec { .. } => {
                let cdi = match &self.cdi {
                    Some(Cdi::Ec(k)) => *k,
                    _ => return Err(CryptoError::CryptoLibError(1)),
                };
                self.derived_key = Some(DerivedKey::Ec(self.derive_key_pair_ec(
                    &cdi,
                    label,
                    info,
                    KEY_ID_DPE_PRIV_KEY,
                )?));
            }
            #[cfg(feature = "mldsa_attestation")]
            Signer::Mldsa { .. } => {
                // Copy CDI bytes to the stack so we can release the borrow on self.cdi
                // before calling derive_key_pair_mldsa which needs &mut self.
                let cdi_bytes = match &self.cdi {
                    Some(Cdi::Mldsa(b)) => **b,
                    _ => return Err(CryptoError::CryptoLibError(1)),
                };
                let mut seed = Mldsa87Seed::default();
                self.derive_key_pair_mldsa((&cdi_bytes).into(), label, info, &mut seed)?;
                self.derived_key = Some(DerivedKey::Mldsa(seed));
            }
        };

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
                let Some(DerivedKey::Mldsa(seed)) = &self.derived_key else {
                    return Err(CryptoError::CryptoLibError(3));
                };
                Self::sign_helper_mldsa(data, seed)
            }
        }
    }

    fn public_key(&mut self) -> Result<PubKey, CryptoError> {
        match &self.derived_key {
            Some(DerivedKey::Ec((_, pub_key))) => Ok(pub_key.clone()),
            #[cfg(feature = "mldsa_attestation")]
            Some(DerivedKey::Mldsa(seed)) => {
                let mut pub_key = Mldsa87PubKey::default();
                Mldsa87::pub_from_seed(seed, &mut pub_key, None)
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                Ok(PubKey::Mldsa(MldsaPublicKey(*pub_key)))
            }
            _ => Err(CryptoError::CryptoLibError(4)),
        }
    }
}

// The mldsa key is significantly larger than ecdsa.  Allow a large enum variant to support it.
#[allow(clippy::large_enum_variant)]
enum Signer<'a> {
    Ec {
        ecc384: &'a mut Ecc384,
        rt_pub_key: PubKey,
        rt_priv_key: KeyId,
    },
    #[cfg(feature = "mldsa_attestation")]
    Mldsa {
        /// Single ML-DSA exported-CDI slot (raw CDI bytes in persistent data).
        /// ECDSA exported CDIs instead live in `exported_cdi_slots`.
        exported_cdi_slot: &'a mut MldsaExportedCdiEntry,
    },
}

// The mldsa key is significantly larger than ecdsa.  Allow a large enum variant to support it.
#[allow(clippy::large_enum_variant)]
enum DerivedKey {
    Ec((KeyId, PubKey)),
    #[cfg(feature = "mldsa_attestation")]
    Mldsa(Mldsa87Seed),
}
