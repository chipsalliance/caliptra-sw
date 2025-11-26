/*++

Licensed under the Apache-2.0 license.

File Name:

    dpe_crypto.rs

Abstract:

    File contains DpeCrypto implementation.

--*/

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::keyids::{
    KEY_ID_DPE_CDI, KEY_ID_DPE_PRIV_KEY, KEY_ID_EXPORTED_DPE_CDI, KEY_ID_TMP,
};
use caliptra_drivers::{
    hmac_kdf, okref,
    sha2_512_384::{Sha2DigestOpTrait, Sha384},
    Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar, Ecc384Seed, ExportedCdiEntry,
    ExportedCdiHandles, Hmac, HmacMode, KeyId, KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs,
    Mldsa87, Mldsa87Mu, Mldsa87PubKey, Mldsa87Seed, Mldsa87SignRnd, Sha2DigestOp, Sha2_512_384,
    Trng,
};
use constant_time_eq::constant_time_eq;
use core::marker::PhantomData;
use crypto::{
    ecdsa::{
        curve_384::{Curve384, EcdsaPub384, EcdsaSignature384},
        EcdsaPubKey, EcdsaSignature,
    },
    ml_dsa::{ExternalMu, MldsaAlgorithm, MldsaPublicKey, MldsaSignature},
    Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType, Hasher, Mu, PubKey,
    SignData, SignDataAlgorithm, SignDataType, Signature, SignatureAlgorithm, SignatureType,
};
use dpe::{EcdsaAlgorithm, ExportedCdiHandle, U8Bool, MAX_EXPORTED_CDI_SIZE};
use zerocopy::IntoBytes;

pub type DpeEcCrypto<'a> = DpeCrypto<'a, Curve384, crypto::Sha384, crypto::Sha384>;
impl CryptoSuite for DpeEcCrypto<'_> {}
impl SignatureType for DpeEcCrypto<'_> {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm = Curve384::SIGNATURE_ALGORITHM;
}
impl DigestType for DpeEcCrypto<'_> {
    const DIGEST_ALGORITHM: DigestAlgorithm = crypto::Sha384::DIGEST_ALGORITHM;
}
impl SignDataType for DpeEcCrypto<'_> {
    const SIGN_DATA_ALGORITHM: SignDataAlgorithm = crypto::Sha384::SIGN_DATA_ALGORITHM;
}

pub type DpeMldsaCrypto<'a> = DpeCrypto<'a, ExternalMu, crypto::Sha384, Mu>;
impl CryptoSuite for DpeMldsaCrypto<'_> {}
impl SignatureType for DpeMldsaCrypto<'_> {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm = ExternalMu::SIGNATURE_ALGORITHM;
}
impl DigestType for DpeMldsaCrypto<'_> {
    const DIGEST_ALGORITHM: DigestAlgorithm = crypto::Sha384::DIGEST_ALGORITHM;
}
impl SignDataType for DpeMldsaCrypto<'_> {
    const SIGN_DATA_ALGORITHM: SignDataAlgorithm = Mu::SIGN_DATA_ALGORITHM;
}

pub struct DpeCrypto<'a, S: SignatureType, D: DigestType, SD: SignDataType> {
    sha2_512_384: &'a mut Sha2_512_384,
    trng: &'a mut Trng,
    hmac: &'a mut Hmac,
    key_vault: &'a mut KeyVault,
    signer: Signer<'a>,
    rt_pub_key: PubKey,
    key_id_rt_cdi: KeyId,
    key_id_rt_priv_key: KeyId,
    exported_cdi_slots: &'a mut ExportedCdiHandles,
    _pd: PhantomData<(S, D, SD)>,
}

impl<'a> DpeEcCrypto<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sha2_512_384: &'a mut Sha2_512_384,
        trng: &'a mut Trng,
        ecc384: &'a mut Ecc384,
        hmac: &'a mut Hmac,
        key_vault: &'a mut KeyVault,
        rt_pub_key: PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> DpeEcCrypto<'a> {
        DpeEcCrypto {
            sha2_512_384,
            trng,
            hmac,
            key_vault,
            signer: Signer::Ec(ecc384),
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
            _pd: PhantomData,
        }
    }
}

impl<'a> DpeMldsaCrypto<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sha2_512_384: &'a mut Sha2_512_384,
        trng: &'a mut Trng,
        mldsa: &'a mut Mldsa87,
        hmac: &'a mut Hmac,
        key_vault: &'a mut KeyVault,
        rt_pub_key: PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> DpeMldsaCrypto<'a> {
        DpeMldsaCrypto {
            sha2_512_384,
            trng,
            hmac,
            key_vault,
            signer: Signer::Mldsa(mldsa),
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
            _pd: PhantomData,
        }
    }
}

impl<S: SignatureType, D: DigestType, SD: SignDataType> DpeCrypto<'_, S, D, SD> {
    fn derive_cdi_inner(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        key_id: KeyId,
    ) -> Result<<Self as crypto::Crypto>::Cdi, CryptoError> {
        let mut usage = KeyUsage::default().set_hmac_key_en();
        let usage = match S::SIGNATURE_ALGORITHM {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => usage.set_ecc_key_gen_seed_en(),
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::Mldsa87) => usage.set_mldsa_key_gen_seed_en(),
            _ => return Err(CryptoError::MismatchedAlgorithm),
        };

        let mut hasher = self.hash_initialize()?;
        hasher.update(measurement.as_slice())?;
        hasher.update(info)?;
        let context = hasher.finish()?;

        hmac_kdf(
            self.hmac,
            KeyReadArgs::new(self.key_id_rt_cdi).into(),
            b"derive_cdi",
            Some(context.as_slice()),
            self.trng,
            KeyWriteArgs::new(key_id, usage).into(),
            HmacMode::Hmac384,
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
        let mut usage = KeyUsage::default();
        let usage = match S::SIGNATURE_ALGORITHM {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => usage.set_ecc_key_gen_seed_en(),
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::Mldsa87) => usage.set_mldsa_key_gen_seed_en(),
            _ => return Err(CryptoError::MismatchedAlgorithm),
        };
        hmac_kdf(
            self.hmac,
            KeyReadArgs::new(*cdi).into(),
            label,
            Some(info),
            self.trng,
            KeyWriteArgs::new(KEY_ID_TMP, usage).into(),
            HmacMode::Hmac384,
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

        match (S::SIGNATURE_ALGORITHM, &mut self.signer) {
            (SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384), Signer::Ec(ecc384)) => {
                let pub_key = ecc384
                    .key_pair(
                        Ecc384Seed::Key(KeyReadArgs::new(KEY_ID_TMP)),
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
            (SignatureAlgorithm::MlDsa(MldsaAlgorithm::Mldsa87), Signer::Mldsa(mldsa)) => {
                let pub_key = mldsa
                    .key_pair(
                        Mldsa87Seed::Key(KeyReadArgs::new(KEY_ID_TMP)),
                        self.trng,
                        None,
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)));
                let pub_key = okref(&pub_key)?;
                Ok((KEY_ID_TMP, PubKey::MlDsa(MldsaPublicKey(pub_key.into()))))
            }
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
    }

    pub fn get_cdi_from_exported_handle(
        &mut self,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> Option<KeyId> {
        for cdi_slot in self.exported_cdi_slots.entries.iter() {
            match cdi_slot {
                ExportedCdiEntry {
                    key,
                    handle,
                    active,
                } if active.get() && constant_time_eq(handle, exported_cdi_handle) => {
                    return Some(*key)
                }
                _ => (),
            }
        }
        None
    }

    #[inline(never)]
    fn sign_ec(
        ecc384: &mut Ecc384,
        sha2_512_384: &mut Sha2_512_384,
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
            SignData::Raw(msg) => sha2_512_384
                .sha384_digest(msg)
                .map_err(|_| CryptoError::HashError(0))?,
            _ => return Err(CryptoError::MismatchedAlgorithm),
        };
        let sig = ecc384
            .sign(ecc_priv_key, &ecc_pub_key, &digest, trng)
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)));
        let sig = okref(&sig)?;
        Ok(Signature::Ecdsa(EcdsaSignature::Ecdsa384(
            EcdsaSignature384::from_slice(&sig.r.into(), &sig.s.into()),
        )))
    }

    #[inline(never)]
    fn sign_mldsa(
        mldsa: &mut Mldsa87,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        let priv_key_args = KeyReadArgs::new(*priv_key);
        let priv_key = Mldsa87Seed::Key(priv_key_args);

        let PubKey::MlDsa(MldsaPublicKey(pub_key)) = pub_key else {
            return Err(CryptoError::MismatchedAlgorithm);
        };
        let pub_key = Mldsa87PubKey::from(pub_key);

        // Deterministic signing
        let sign_rnd = Mldsa87SignRnd::default();

        let sig = match data {
            SignData::Raw(msg) => mldsa.sign_var(priv_key, &pub_key, msg, &sign_rnd, trng),
            SignData::Mu(mu) => {
                let mu = Mldsa87Mu::from(mu.0);
                mldsa.sign_external_mu(priv_key, &pub_key, &mu, &sign_rnd, trng)
            }
            _ => return Err(CryptoError::MismatchedAlgorithm),
        };
        let sig = okref(&sig).map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

        let mut dpe_sig = [0u8; 4627];
        dpe_sig.copy_from_slice(&sig.as_bytes()[..4627]);
        Ok(Signature::MlDsa(MldsaSignature(dpe_sig)))
    }

    fn sign_helper(
        signer: &mut Signer,
        sha2_512_384: &mut Sha2_512_384,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        match (S::SIGNATURE_ALGORITHM, signer) {
            (SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384), Signer::Ec(ecc384)) => {
                Self::sign_ec(ecc384, sha2_512_384, trng, data, priv_key, pub_key)
            }
            (SignatureAlgorithm::MlDsa(MldsaAlgorithm::Mldsa87), Signer::Mldsa(mldsa)) => {
                Self::sign_mldsa(mldsa, trng, data, priv_key, pub_key)
            }
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
    }
}

impl<S: SignatureType, D: DigestType, SD: SignDataType> Drop for DpeCrypto<'_, S, D, SD> {
    fn drop(&mut self) {
        let _ = self.key_vault.erase_key(KEY_ID_DPE_CDI);
        let _ = self.key_vault.erase_key(KEY_ID_DPE_PRIV_KEY);
        let _ = self.key_vault.erase_key(KEY_ID_TMP);
    }
}

pub struct DpeHasher<'a> {
    op: Sha2DigestOp<'a, Sha384>,
}

impl<'a> DpeHasher<'a> {
    pub fn new(op: Sha2DigestOp<'a, Sha384>) -> Self {
        Self { op }
    }
}

impl Hasher for DpeHasher<'_> {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.op
            .update(bytes)
            .map_err(|e| CryptoError::HashError(u32::from(e)))
    }

    fn finish(self) -> Result<Digest, CryptoError> {
        let mut digest = Array4x12::default();
        self.op
            .finalize(&mut digest)
            .map_err(|e| CryptoError::HashError(u32::from(e)))?;
        Ok(Digest::Sha384(crypto::Sha384(digest.into())))
    }
}

impl<S: SignatureType, D: DigestType, SD: SignDataType> Crypto for DpeCrypto<'_, S, D, SD> {
    type Cdi = KeyId;
    type Hasher<'b>
        = DpeHasher<'b>
    where
        Self: 'b;
    type PrivKey = KeyId;

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

    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError> {
        let op = self
            .sha2_512_384
            .sha384_digest_init()
            .map_err(|e| CryptoError::HashError(u32::from(e)))?;
        Ok(DpeHasher::new(op))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
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

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(&mut self, measurement: &Digest, info: &[u8]) -> Result<Self::Cdi, CryptoError> {
        self.derive_cdi_inner(measurement, info, KEY_ID_DPE_CDI)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair(
        &mut self,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, PubKey), CryptoError> {
        self.derive_key_pair_inner(cdi, label, info, KEY_ID_DPE_PRIV_KEY)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, PubKey), CryptoError> {
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
        self.derive_key_pair_inner(&cdi, label, info, KEY_ID_TMP)
    }

    fn sign_with_alias(&mut self, data: &SignData) -> Result<Signature, CryptoError> {
        Self::sign_helper(
            &mut self.signer,
            self.sha2_512_384,
            self.trng,
            data,
            &self.key_id_rt_priv_key,
            &self.rt_pub_key,
        )
    }

    fn sign_with_derived(
        &mut self,
        data: &SignData,
        priv_key: &Self::PrivKey,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        Self::sign_helper(
            &mut self.signer,
            self.sha2_512_384,
            self.trng,
            data,
            priv_key,
            pub_key,
        )
    }
}

enum Signer<'a> {
    Ec(&'a mut Ecc384),
    Mldsa(&'a mut Mldsa87),
}
