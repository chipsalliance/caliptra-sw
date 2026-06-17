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
    CdiManager, Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType, PubKey,
    SignData, SignDataAlgorithm, SignDataType, Signature, SignatureAlgorithm, SignatureType,
};
use caliptra_drivers::{
    hmac_kdf, okref, sha2_512_384::DpeHasher, Array4x12, CaliptraResult, Ecc384, Ecc384PrivKeyIn,
    Ecc384PubKey, Ecc384Scalar, Ecc384Seed, ExportedCdiEntry, ExportedCdiHandles, Hmac, HmacMode,
    KeyId, KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Mldsa87, Mldsa87PubKey, Mldsa87Seed,
    Mldsa87SignRnd, Sha2_512_384, Trng, MLDSA87_SPEC_SIGNATURE_BYTE_SIZE,
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

/// Copy `src` into `dst`, returning `CryptoError::Size` if lengths differ.
/// Uses indexing that the compiler can prove won't panic.
#[inline(always)]
fn checked_copy(dst: &mut [u8], src: &[u8]) -> Result<(), CryptoError> {
    if dst.len() != src.len() {
        return Err(CryptoError::Size);
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    Ok(())
}

/// Split `buf` at `mid`, returning error instead of panicking if out of bounds.
#[inline(always)]
fn checked_split_at_mut(buf: &mut [u8], mid: usize) -> Result<(&mut [u8], &mut [u8]), CryptoError> {
    if mid > buf.len() {
        return Err(CryptoError::Size);
    }
    Ok(buf.split_at_mut(mid))
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
            .key_pair(Mldsa87Seed::Key(KeyReadArgs::new(*key_id)), trng, None)
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)));
        let pub_key = okref(&pub_key)?;
        Ok(*pub_key)
    }

    #[inline(never)]
    fn sign_ec(
        ecc384: &mut Ecc384,
        sha2_512_384: &mut Sha2_512_384,
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
        mldsa87: &mut Mldsa87,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &Mldsa87PubKey,
    ) -> Result<Signature, CryptoError> {
        let mut dpe_sig = [0u8; MLDSA87_SPEC_SIGNATURE_BYTE_SIZE];
        Self::sign_mldsa_into_slice(mldsa87, trng, data, priv_key, pub_key, &mut dpe_sig)?;
        Ok(Signature::Mldsa(MldsaSignature(dpe_sig)))
    }

    fn sign_mldsa_into_slice(
        mldsa87: &mut Mldsa87,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &Mldsa87PubKey,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let priv_key_args = KeyReadArgs::new(*priv_key);
        let priv_key = Mldsa87Seed::Key(priv_key_args);
        let sign_rnd = Mldsa87SignRnd::default();

        match data {
            SignData::Raw(msg) => mldsa87
                .sign_var_into_slice(priv_key, pub_key, msg, &sign_rnd, trng, out)
                .map_err(|e| CryptoError::CryptoLibError(u32::from(e))),
            SignData::Mu(_) => Err(CryptoError::NotImplemented),
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
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
                Self::sign_ec(ecc384, hasher.driver(), trng, data, priv_key, pub_key)
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
            for (d, s) in chunk.iter_mut().zip(trng_bytes.iter()) {
                *d = *s;
            }
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

    fn sign_with_alias_into_slice(
        &mut self,
        data: &SignData,
        signature: &mut [u8],
    ) -> Result<(), CryptoError> {
        match (&mut self.signer, &self.rt_pub_key) {
            (Signer::Ec(ecc384), PubKey::Ecdsa(pub_key)) => {
                let sig = Self::sign_ec(
                    ecc384,
                    self.hasher.driver(),
                    self.trng,
                    data,
                    &self.key_id_rt_priv_key,
                    pub_key,
                )?;
                if let Signature::Ecdsa(ecdsa_sig) = sig {
                    let (r, s) = ecdsa_sig.as_slice();
                    if signature.len() != r.len() + s.len() {
                        return Err(CryptoError::Size);
                    }
                    let (left, right) = checked_split_at_mut(signature, r.len())?;
                    checked_copy(left, r)?;
                    checked_copy(right, s)?;
                    Ok(())
                } else {
                    Err(CryptoError::MismatchedAlgorithm)
                }
            }
            (Signer::Mldsa(mldsa87), PubKey::Mldsa(MldsaPublicKey(pub_key))) => {
                let pub_key = Mldsa87PubKey::from(pub_key);
                Self::sign_mldsa_into_slice(
                    mldsa87,
                    self.trng,
                    data,
                    &self.key_id_rt_priv_key,
                    &pub_key,
                    signature,
                )
            }
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_with_derived_into_slice(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        label: &[u8],
        derived_info: &[u8],
        data: &SignData,
        pub_key: Option<&[u8]>,
        signature: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.derive_cdi(measurement, info)?;
        let cdi = self.cdi.ok_or(CryptoError::CryptoLibError(1))?;
        self.derived_key =
            Some(self.derive_key_pair_inner(&cdi, label, derived_info, KEY_ID_DPE_PRIV_KEY)?);

        let Some(derived_key) = &self.derived_key else {
            return Err(CryptoError::CryptoLibError(3));
        };
        match (derived_key, &mut self.signer) {
            (DerivedKey::Ecc(key_id, ecc_pub_key), Signer::Ec(ecc384)) => {
                let sig = Self::sign_ec(
                    ecc384,
                    self.hasher.driver(),
                    self.trng,
                    data,
                    key_id,
                    ecc_pub_key,
                )?;
                if let Signature::Ecdsa(ecdsa_sig) = sig {
                    let (r, s) = ecdsa_sig.as_slice();
                    if signature.len() != r.len() + s.len() {
                        return Err(CryptoError::Size);
                    }
                    let (left, right) = checked_split_at_mut(signature, r.len())?;
                    checked_copy(left, r)?;
                    checked_copy(right, s)?;
                    Ok(())
                } else {
                    Err(CryptoError::MismatchedAlgorithm)
                }
            }
            (DerivedKey::Mldsa(key_id), Signer::Mldsa(mldsa87)) => {
                // Use the pre-derived public key from the caller to avoid
                // re-deriving (which puts 2592 bytes on the stack).
                if let Some(pk_bytes) = pub_key {
                    let pk_arr =
                        <&[u8; MldsaAlgorithm::Mldsa87.public_key_size()]>::try_from(pk_bytes)
                            .map_err(|_| CryptoError::Size)?;
                    let mldsa_pub_key = Mldsa87PubKey::from(pk_arr);
                    Self::sign_mldsa_into_slice(
                        mldsa87,
                        self.trng,
                        data,
                        key_id,
                        &mldsa_pub_key,
                        signature,
                    )
                } else {
                    let mldsa_pub_key = Self::derive_mldsa_pub_key(mldsa87, self.trng, key_id)?;
                    Self::sign_mldsa_into_slice(
                        mldsa87,
                        self.trng,
                        data,
                        key_id,
                        &mldsa_pub_key,
                        signature,
                    )
                }
            }
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
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
            (DerivedKey::Ecc(key_id, pub_key), Signer::Ec(ecc384)) => Self::sign_ec(
                ecc384,
                self.hasher.driver(),
                self.trng,
                data,
                key_id,
                pub_key,
            ),
            (DerivedKey::Mldsa(key_id), Signer::Mldsa(mldsa87)) => {
                let pub_key = Self::derive_mldsa_pub_key(mldsa87, self.trng, key_id)?;
                Self::sign_mldsa(mldsa87, self.trng, data, key_id, &pub_key)
            }
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
    }

    fn sign_into_slice(
        &mut self,
        data: &SignData,
        _pub_key: Option<&[u8]>,
        signature: &mut [u8],
    ) -> Result<(), CryptoError> {
        let Some(derived_key) = &self.derived_key else {
            return Err(CryptoError::CryptoLibError(3));
        };
        match (derived_key, &mut self.signer) {
            (DerivedKey::Ecc(key_id, pub_key), Signer::Ec(ecc384)) => {
                let sig = Self::sign_ec(
                    ecc384,
                    self.hasher.driver(),
                    self.trng,
                    data,
                    key_id,
                    pub_key,
                )?;
                if let Signature::Ecdsa(ecdsa_sig) = sig {
                    let (r, s) = ecdsa_sig.as_slice();
                    if signature.len() != r.len() + s.len() {
                        return Err(CryptoError::Size);
                    }
                    let (left, right) = checked_split_at_mut(signature, r.len())?;
                    checked_copy(left, r)?;
                    checked_copy(right, s)?;
                    Ok(())
                } else {
                    Err(CryptoError::MismatchedAlgorithm)
                }
            }
            (DerivedKey::Mldsa(key_id), Signer::Mldsa(mldsa87)) => {
                let pub_key = Self::derive_mldsa_pub_key(mldsa87, self.trng, key_id)?;
                Self::sign_mldsa_into_slice(mldsa87, self.trng, data, key_id, &pub_key, signature)
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

    fn public_key_into(&mut self, pub_key_out: &mut [u8]) -> Result<(), CryptoError> {
        let Some(derived_key) = &self.derived_key else {
            return Err(CryptoError::CryptoLibError(4));
        };
        match derived_key {
            DerivedKey::Ecc(_, pub_key) => {
                let (x, y) = pub_key.as_slice();
                let expected_len = x.len() + y.len();
                if pub_key_out.len() != expected_len {
                    return Err(CryptoError::Size);
                }
                let (left, right) = checked_split_at_mut(pub_key_out, x.len())?;
                checked_copy(left, x)?;
                checked_copy(right, y)?;
                Ok(())
            }
            DerivedKey::Mldsa(key_id) => {
                let Signer::Mldsa(mldsa87) = &mut self.signer else {
                    return Err(CryptoError::MismatchedAlgorithm);
                };
                let pub_key = Self::derive_mldsa_pub_key(mldsa87, self.trng, key_id)?;
                let pub_key_bytes = pub_key.as_bytes();
                if pub_key_out.len() != pub_key_bytes.len() {
                    return Err(CryptoError::Size);
                }
                checked_copy(pub_key_out, pub_key_bytes)?;
                Ok(())
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
