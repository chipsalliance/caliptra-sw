/*++

Licensed under the Apache-2.0 license.

File Name:

    dpe_crypto.rs

Abstract:

    File contains DpeCrypto implementation.

--*/

#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::keyids::{
    KEY_ID_DPE_CDI, KEY_ID_DPE_PRIV_KEY, KEY_ID_EXPORTED_DPE_CDI, KEY_ID_TMP,
};
use caliptra_dpe::{EcdsaAlgorithm, ExportedCdiHandle, U8Bool, MAX_EXPORTED_CDI_SIZE};
use caliptra_dpe_crypto::{
    ecdsa::{
        curve_384::{EcdsaPub384, EcdsaSignature384},
        EcdsaPubKey, EcdsaSignature,
    },
    ml_dsa::{MldsaAlgorithm, MldsaPublicKey, MldsaSignature},
    CdiManager, Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType, Hasher,
    PubKey, SignData, SignDataAlgorithm, SignDataType, Signature, SignatureAlgorithm,
    SignatureType,
};
use caliptra_dpe_response_buffer::{ResponseBufError, ResponseBuffer};
use caliptra_drivers::{
    hmac_kdf, okref, sha2_512_384::DpeHasher, Array4x12, CaliptraError, CaliptraResult, Ecc384,
    Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar, Ecc384Seed, ExportedCdiEntry, ExportedCdiHandles,
    Hmac, HmacMode, KeyId, KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Mldsa87, Mldsa87PubKey,
    Mldsa87Seed, Mldsa87SignRnd, Sha2_512_384, Trng,
};
use constant_time_eq::constant_time_eq;
use zerocopy::IntoBytes;

pub struct DpeCrypto<'a> {
    trng: &'a mut Trng,
    hmac: &'a mut Hmac,
    key_vault: &'a mut KeyVault,
    signer: Signer<'a>,
    hasher: DpeHasher<'a>,
    cdi: Option<KeyId>,
    derived_key: Option<DerivedKey>,
    rt_pub_key: PubKey,
    key_id_rt_cdi: KeyId,
    key_id_rt_priv_key: KeyId,
    exported_cdi_slots: &'a mut ExportedCdiHandles,
}

impl<'a> DpeCrypto<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new_ecc384(
        sha2_512_384: &'a mut Sha2_512_384,
        trng: &'a mut Trng,
        ecc384: &'a mut Ecc384,
        hmac: &'a mut Hmac,
        key_vault: &'a mut KeyVault,
        rt_pub_key: PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> CaliptraResult<Self> {
        let hasher = DpeHasher::new(sha2_512_384)?;
        Ok(Self {
            trng,
            hmac,
            key_vault,
            signer: Signer::Ec(ecc384),
            hasher,
            cdi: None,
            derived_key: None,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_mldsa87(
        sha2_512_384: &'a mut Sha2_512_384,
        trng: &'a mut Trng,
        mldsa87: &'a mut Mldsa87,
        hmac: &'a mut Hmac,
        key_vault: &'a mut KeyVault,
        rt_pub_key: PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> CaliptraResult<Self> {
        let hasher = DpeHasher::new(sha2_512_384)?;
        Ok(Self {
            trng,
            hmac,
            key_vault,
            signer: Signer::Mldsa(mldsa87),
            hasher,
            cdi: None,
            derived_key: None,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
        })
    }
}

impl CryptoSuite for DpeCrypto<'_> {}

impl SignatureType for DpeCrypto<'_> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self.signer {
            Signer::Ec(_) => SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384),
            Signer::Mldsa(_) => SignatureAlgorithm::Mldsa(MldsaAlgorithm::Mldsa87),
        }
    }
}

impl DigestType for DpeCrypto<'_> {
    fn digest_algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha384
    }
}

impl SignDataType for DpeCrypto<'_> {
    fn sign_data_algorithm(&self) -> SignDataAlgorithm {
        match self.signer {
            Signer::Ec(_) => SignDataAlgorithm::Sha384,
            Signer::Mldsa(_) => SignDataAlgorithm::Mu,
        }
    }
}

impl DpeCrypto<'_> {
    fn derive_cdi_inner(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        key_id: KeyId,
    ) -> Result<KeyId, CryptoError> {
        let mut usage = KeyUsage::default().set_hmac_key_en();
        let usage = match self.signer {
            Signer::Ec(_) => usage.set_ecc_key_gen_seed_en(),
            Signer::Mldsa(_) => usage.set_mldsa_key_gen_seed_en(),
        };

        let context = self.hash_all(&[&measurement.as_slice(), &info])?;

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
    ) -> Result<DerivedKey, CryptoError> {
        let mut usage = KeyUsage::default();
        let usage = match self.signer {
            Signer::Ec(_) => usage.set_ecc_key_gen_seed_en(),
            Signer::Mldsa(_) => usage.set_mldsa_key_gen_seed_en(),
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

        match &mut self.signer {
            Signer::Ec(ecc384) => {
                let pub_key = ecc384
                    .key_pair(
                        Ecc384Seed::Key(KeyReadArgs::new(KEY_ID_TMP)),
                        &Array4x12::default(),
                        self.trng,
                        KeyWriteArgs::new(key_id, KeyUsage::default().set_ecc_private_key_en())
                            .into(),
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                let pub_key = EcdsaPubKey::Ecdsa384(EcdsaPub384::from_slice(
                    &pub_key.x.into(),
                    &pub_key.y.into(),
                ));
                Ok(DerivedKey::Ecc(key_id, pub_key))
            }
            Signer::Mldsa(_) => {
                // Keep only the seed key id in DpeCrypto. The ML-DSA public key is 2592 bytes and
                // storing it in this stack-resident object overflows Caliptra 2.0's RT stack.
                Ok(DerivedKey::Mldsa(KEY_ID_TMP))
            }
        }
    }

    fn derive_mldsa_pub_key(
        mldsa87: &mut Mldsa87,
        trng: &mut Trng,
        key_id: &KeyId,
    ) -> Result<Mldsa87PubKey, CryptoError> {
        let pub_key = mldsa87
            .dpe_derive_pub_key_from_kv_seed(KeyReadArgs::new(*key_id), trng)
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)));
        let pub_key = okref(&pub_key)?;
        Ok(*pub_key)
    }

    #[inline(never)]
    fn sign_ec(
        ecc384: &mut Ecc384,
        hasher: &mut DpeHasher,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &EcdsaPubKey,
    ) -> Result<Signature, CryptoError> {
        let priv_key_args = KeyReadArgs::new(*priv_key);
        let ecc_priv_key = Ecc384PrivKeyIn::Key(priv_key_args);

        let EcdsaPubKey::Ecdsa384(EcdsaPub384 { x, y }) = pub_key else {
            return Err(CryptoError::MismatchedAlgorithm);
        };
        let ecc_pub_key = Ecc384PubKey {
            x: Ecc384Scalar::from(x),
            y: Ecc384Scalar::from(y),
        };
        let digest = match data {
            SignData::Digest(Digest::Sha384(caliptra_dpe_crypto::Sha384(digest))) => {
                Ecc384Scalar::from(digest)
            }
            SignData::Raw(msg) => hasher
                .driver()
                .sha384_digest(msg)
                .map_err(|_| CryptoError::HashError(0))?,
            SignData::ResponseBuffer(buf, range) => {
                let Digest::Sha384(caliptra_dpe_crypto::Sha384(digest)) =
                    Self::hash_response_buffer(hasher, *buf, range.clone())?
                else {
                    return Err(CryptoError::MismatchedAlgorithm);
                };
                Ecc384Scalar::from(&digest)
            }
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

    fn hash_response_buffer(
        hasher: &mut DpeHasher,
        buf: &dyn ResponseBuffer,
        range: core::ops::Range<usize>,
    ) -> Result<Digest, CryptoError> {
        hasher.initialize()?;
        let mut hash_error = None;
        let read_result = buf.read_range(range, &mut |chunk| {
            if let Err(e) = hasher.update(chunk) {
                hash_error = Some(e);
                return Err(ResponseBufError::Overflow);
            }
            Ok(())
        });
        if let Some(e) = hash_error {
            return Err(e);
        }
        read_result.map_err(|_| CryptoError::Size)?;
        hasher.finish()
    }

    #[inline(never)]
    fn sign_mldsa(
        mldsa87: &mut Mldsa87,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &Mldsa87PubKey,
    ) -> Result<Signature, CryptoError> {
        let priv_key_args = KeyReadArgs::new(*priv_key);
        let priv_key = Mldsa87Seed::Key(priv_key_args);

        let sign_rnd = Mldsa87SignRnd::default();

        let sig = match data {
            SignData::Raw(msg) => mldsa87.sign_var(priv_key, pub_key, msg, &sign_rnd, trng),
            SignData::ResponseBuffer(buf, range) => {
                mldsa87.sign_var_stream(priv_key, pub_key, &sign_rnd, trng, |write_chunk| {
                    let mut write_error = None;
                    let read_result = buf.read_range(range.clone(), &mut |chunk| {
                        if let Err(e) = write_chunk(chunk) {
                            write_error = Some(e);
                            return Err(ResponseBufError::Overflow);
                        }
                        Ok(())
                    });
                    if let Some(e) = write_error {
                        return Err(e);
                    }
                    read_result.map_err(|_| CaliptraError::DRIVER_MLDSA87_HW_ERROR)
                })
            }
            SignData::Mu(_) => return Err(CryptoError::NotImplemented),
            _ => return Err(CryptoError::MismatchedAlgorithm),
        };
        let sig = okref(&sig).map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

        let mut dpe_sig = [0u8; 4627];
        for (dst, src) in dpe_sig.iter_mut().zip(sig.as_bytes().iter()) {
            *dst = *src;
        }
        Ok(Signature::Mldsa(MldsaSignature(dpe_sig)))
    }

    fn sign_helper(
        signer: &mut Signer,
        hasher: &mut DpeHasher,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        match (signer, pub_key) {
            (Signer::Ec(ecc384), PubKey::Ecdsa(pub_key)) => {
                Self::sign_ec(ecc384, hasher, trng, data, priv_key, pub_key)
            }
            (Signer::Mldsa(mldsa87), PubKey::Mldsa(MldsaPublicKey(pub_key))) => {
                let pub_key = Mldsa87PubKey::from(pub_key);
                Self::sign_mldsa(mldsa87, trng, data, priv_key, &pub_key)
            }
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
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

    fn hasher(&mut self) -> Result<&mut dyn caliptra_dpe_crypto::Hasher, CryptoError> {
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

        let cdi_slot = KEY_ID_EXPORTED_DPE_CDI;
        let mut slots_clone = self.exported_cdi_slots.clone();

        for slot in slots_clone.entries.iter_mut() {
            match slot {
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
                    let cdi = self.derive_cdi_inner(measurement, info, cdi_slot)?;
                    *slot = ExportedCdiEntry {
                        key: cdi,
                        handle: exported_cdi_handle,
                        active: U8Bool::new(true),
                    };
                    *self.exported_cdi_slots = slots_clone;
                    return Ok(exported_cdi_handle);
                }
                _ => (),
            }
        }
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
    ) -> Result<&mut dyn caliptra_dpe_crypto::Signer, CryptoError> {
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
    ) -> Result<&mut dyn caliptra_dpe_crypto::Signer, CryptoError> {
        let cdi = self.cdi.ok_or(CryptoError::CryptoLibError(1))?;
        self.derived_key =
            Some(self.derive_key_pair_inner(&cdi, label, info, KEY_ID_DPE_PRIV_KEY)?);
        Ok(self)
    }

    fn as_slice(&self) -> &[u8] {
        Default::default()
    }
}

impl caliptra_dpe_crypto::Signer for DpeCrypto<'_> {
    fn sign(&mut self, data: &SignData) -> Result<Signature, CryptoError> {
        let Some(derived_key) = &self.derived_key else {
            return Err(CryptoError::CryptoLibError(3));
        };
        match (derived_key, &mut self.signer) {
            (DerivedKey::Ecc(key_id, pub_key), Signer::Ec(ecc384)) => {
                Self::sign_ec(ecc384, &mut self.hasher, self.trng, data, key_id, pub_key)
            }
            (DerivedKey::Mldsa(key_id), Signer::Mldsa(mldsa87)) => {
                let pub_key = Self::derive_mldsa_pub_key(mldsa87, self.trng, key_id)?;
                Self::sign_mldsa(mldsa87, self.trng, data, key_id, &pub_key)
            }
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
    }

    fn public_key(&mut self) -> Result<PubKey, CryptoError> {
        let Some(derived_key) = &self.derived_key else {
            return Err(CryptoError::CryptoLibError(4));
        };
        match derived_key {
            DerivedKey::Ecc(_, pub_key) => Ok(PubKey::Ecdsa(pub_key.clone())),
            DerivedKey::Mldsa(key_id) => {
                let Signer::Mldsa(mldsa87) = &mut self.signer else {
                    return Err(CryptoError::MismatchedAlgorithm);
                };
                let pub_key = Self::derive_mldsa_pub_key(mldsa87, self.trng, key_id)?;
                let pub_key = <[u8; MldsaAlgorithm::Mldsa87.public_key_size()]>::from(pub_key);
                Ok(PubKey::Mldsa(MldsaPublicKey(pub_key)))
            }
        }
    }
}

enum Signer<'a> {
    Ec(&'a mut Ecc384),
    Mldsa(&'a mut Mldsa87),
}

enum DerivedKey {
    Ecc(KeyId, EcdsaPubKey),
    Mldsa(KeyId),
}
