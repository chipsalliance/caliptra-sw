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
    hmac_kdf,
    sha2_512_384::{Sha2DigestOpTrait, Sha384},
    Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar, Ecc384Seed, ExportedCdiEntry,
    ExportedCdiHandles, Hmac, HmacMode, KeyId, KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs,
    Mldsa87, Mldsa87PubKey, Mldsa87Seed, Mldsa87SignRnd, Sha2DigestOp, Sha2_512_384, Trng,
};
use constant_time_eq::constant_time_eq;
use crypto::{
    ecdsa::{
        curve_384::{Curve384, EcdsaPub384, EcdsaSignature384},
        EcdsaPubKey, EcdsaSignature,
    },
    ml_dsa::{MldsaAlgorithm, MldsaPublicKey, MldsaSignature},
    Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType, Hasher, PubKey,
    SignData, Signature, SignatureAlgorithm, SignatureType,
};
use dpe::{ExportedCdiHandle, U8Bool, MAX_EXPORTED_CDI_SIZE};

/// Signer abstraction to hold either an ECC or MLDSA signer reference.
pub enum Signer<'a> {
    Ec(&'a mut Ecc384),
    Mldsa(&'a mut Mldsa87),
}

/// Alias public key: either ECC384 or MLDSA87.
#[allow(clippy::large_enum_variant)]
pub enum AliasPubKey {
    Ecc(Ecc384PubKey),
    Mldsa(Mldsa87PubKey),
}

/// Alias private key identifier.
pub enum AliasPrivKey {
    EccKeyId(KeyId),
    MldsaKeyPairSeed(KeyId),
}

pub struct DpeCrypto<'a> {
    sha2_512_384: &'a mut Sha2_512_384,
    trng: &'a mut Trng,
    signer: Signer<'a>,
    hmac: &'a mut Hmac,
    key_vault: &'a mut KeyVault,
    rt_pub_key: AliasPubKey,
    key_id_rt_cdi: KeyId,
    rt_priv_key: AliasPrivKey,
    exported_cdi_slots: &'a mut ExportedCdiHandles,
}

/// Type alias for ECC-based DPE crypto (backward compatible).
pub type DpeEcCrypto<'a> = DpeCrypto<'a>;
/// Type alias for MLDSA-based DPE crypto.
pub type DpeMldsaCrypto<'a> = DpeCrypto<'a>;

impl<'a> DpeCrypto<'a> {
    /// Create a new ECC-based DPE crypto instance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sha2_512_384: &'a mut Sha2_512_384,
        trng: &'a mut Trng,
        ecc384: &'a mut Ecc384,
        hmac: &'a mut Hmac,
        key_vault: &'a mut KeyVault,
        rt_pub_key: &mut Ecc384PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> Self {
        let pub_key_copy = *rt_pub_key;
        Self {
            sha2_512_384,
            trng,
            signer: Signer::Ec(ecc384),
            hmac,
            key_vault,
            rt_pub_key: AliasPubKey::Ecc(pub_key_copy),
            key_id_rt_cdi,
            rt_priv_key: AliasPrivKey::EccKeyId(key_id_rt_priv_key),
            exported_cdi_slots,
        }
    }

    /// Create a new MLDSA-based DPE crypto instance.
    #[allow(clippy::too_many_arguments)]
    pub fn new_mldsa(
        sha2_512_384: &'a mut Sha2_512_384,
        trng: &'a mut Trng,
        mldsa87: &'a mut Mldsa87,
        hmac: &'a mut Hmac,
        key_vault: &'a mut KeyVault,
        rt_pub_key: Mldsa87PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_mldsa_keypair_seed: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> Self {
        Self {
            sha2_512_384,
            trng,
            signer: Signer::Mldsa(mldsa87),
            hmac,
            key_vault,
            rt_pub_key: AliasPubKey::Mldsa(rt_pub_key),
            key_id_rt_cdi,
            rt_priv_key: AliasPrivKey::MldsaKeyPairSeed(key_id_rt_mldsa_keypair_seed),
            exported_cdi_slots,
        }
    }

    fn derive_cdi_inner(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        key_id: KeyId,
    ) -> Result<<DpeCrypto<'a> as crypto::Crypto>::Cdi, CryptoError> {
        let hmac_mode = match &self.signer {
            Signer::Ec(_) => HmacMode::Hmac384,
            Signer::Mldsa(_) => HmacMode::Hmac384,
        };
        let key_usage = match &self.signer {
            Signer::Ec(_) => KeyUsage::default()
                .set_hmac_key_en()
                .set_ecc_key_gen_seed_en(),
            Signer::Mldsa(_) => KeyUsage::default()
                .set_hmac_key_en()
                .set_mldsa_key_gen_seed_en(),
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
            KeyWriteArgs::new(key_id, key_usage).into(),
            hmac_mode,
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
        Ok(key_id)
    }

    fn derive_key_pair_inner(
        &mut self,
        cdi: &<DpeCrypto<'a> as crypto::Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
        key_id: KeyId,
    ) -> Result<(<DpeCrypto<'a> as crypto::Crypto>::PrivKey, PubKey), CryptoError> {
        match &mut self.signer {
            Signer::Ec(ecc384) => {
                hmac_kdf(
                    self.hmac,
                    KeyReadArgs::new(*cdi).into(),
                    label,
                    Some(info),
                    self.trng,
                    KeyWriteArgs::new(KEY_ID_TMP, KeyUsage::default().set_ecc_key_gen_seed_en())
                        .into(),
                    HmacMode::Hmac384,
                )
                .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

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
            Signer::Mldsa(mldsa87) => {
                // For MLDSA, derive a seed then generate a key pair.
                hmac_kdf(
                    self.hmac,
                    KeyReadArgs::new(*cdi).into(),
                    label,
                    Some(info),
                    self.trng,
                    KeyWriteArgs::new(KEY_ID_TMP, KeyUsage::default().set_mldsa_key_gen_seed_en())
                        .into(),
                    HmacMode::Hmac512,
                )
                .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

                let pub_key = mldsa87
                    .key_pair(
                        Mldsa87Seed::Key(KeyReadArgs::new(KEY_ID_TMP)),
                        self.trng,
                        None,
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

                let pub_key_bytes: [u8; MldsaAlgorithm::Mldsa87.public_key_size()] =
                    (&pub_key).into();
                let pub_key = PubKey::MlDsa(MldsaPublicKey::from_slice(&pub_key_bytes));
                // For MLDSA, the "private key" is the seed key ID in the key vault.
                Ok((KEY_ID_TMP, pub_key))
            }
        }
    }

    pub fn get_cdi_from_exported_handle(
        &mut self,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> Option<<DpeCrypto<'a> as crypto::Crypto>::Cdi> {
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

    /// Sign data with the appropriate algorithm based on the signer type.
    fn sign_helper(
        &mut self,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        // For ECC, we may need to hash raw data before signing.
        // Compute the ECC digest up front to avoid borrow conflicts.
        let ecc_digest = if matches!(&self.signer, Signer::Ec(_)) {
            Some(match data {
                SignData::Digest(Digest::Sha384(crypto::Sha384(digest))) => {
                    Ecc384Scalar::from(digest)
                }
                SignData::Raw(msg) => self
                    .sha2_512_384
                    .sha384_digest(msg)
                    .map_err(|_| CryptoError::HashError(0))?,
                _ => return Err(CryptoError::MismatchedAlgorithm),
            })
        } else {
            None
        };

        match &mut self.signer {
            Signer::Ec(ecc384) => {
                let priv_key_args = KeyReadArgs::new(*priv_key);
                let ecc_priv_key = Ecc384PrivKeyIn::Key(priv_key_args);

                let PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384 { x, y })) = pub_key else {
                    return Err(CryptoError::MismatchedAlgorithm);
                };
                let ecc_pub_key = Ecc384PubKey {
                    x: Ecc384Scalar::from(x),
                    y: Ecc384Scalar::from(y),
                };

                // SAFETY: ecc_digest is always Some when signer is Ec.
                let digest = ecc_digest.ok_or(CryptoError::MismatchedAlgorithm)?;

                let sig = ecc384
                    .sign(ecc_priv_key, &ecc_pub_key, &digest, self.trng)
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

                Ok(Signature::Ecdsa(EcdsaSignature::Ecdsa384(
                    EcdsaSignature384::from_slice(&sig.r.into(), &sig.s.into()),
                )))
            }
            Signer::Mldsa(mldsa87) => {
                let PubKey::MlDsa(mldsa_pub_key) = pub_key else {
                    return Err(CryptoError::MismatchedAlgorithm);
                };

                let pub_key_bytes: [u8; MldsaAlgorithm::Mldsa87.public_key_size()] = {
                    let mut buf = [0u8; MldsaAlgorithm::Mldsa87.public_key_size()];
                    buf.copy_from_slice(mldsa_pub_key.as_slice());
                    buf
                };
                let driver_pub_key = Mldsa87PubKey::from(&pub_key_bytes);

                // Get the message bytes to sign.
                let msg = data.as_slice();

                let sig = mldsa87
                    .sign_var(
                        Mldsa87Seed::Key(KeyReadArgs::new(*priv_key)),
                        &driver_pub_key,
                        msg,
                        &Mldsa87SignRnd::default(),
                        self.trng,
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

                // Driver returns LEArray4xN<1157, 4628> (4628 bytes, word-aligned),
                // but crypto crate expects exactly 4627 bytes.
                let sig_full: [u8; 4628] = (&sig).into();
                let mut sig_bytes = [0u8; MldsaAlgorithm::Mldsa87.signature_size()];
                sig_bytes.copy_from_slice(&sig_full[..MldsaAlgorithm::Mldsa87.signature_size()]);
                Ok(Signature::MlDsa(MldsaSignature(sig_bytes)))
            }
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

impl CryptoSuite for DpeCrypto<'_> {}

impl SignatureType for DpeCrypto<'_> {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm = Curve384::SIGNATURE_ALGORITHM;
}

impl DigestType for DpeCrypto<'_> {
    const DIGEST_ALGORITHM: DigestAlgorithm = crypto::Sha384::DIGEST_ALGORITHM;
}

impl Crypto for DpeCrypto<'_> {
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
        match (&self.rt_pub_key, &self.rt_priv_key) {
            (AliasPubKey::Ecc(ecc_pub), AliasPrivKey::EccKeyId(key_id)) => {
                let pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384::from_slice(
                    &ecc_pub.x.into(),
                    &ecc_pub.y.into(),
                )));
                let key_id_copy = *key_id;
                self.sign_helper(data, &key_id_copy, &pub_key)
            }
            (AliasPubKey::Mldsa(mldsa_pub), AliasPrivKey::MldsaKeyPairSeed(seed_key_id)) => {
                let pub_key_bytes: [u8; MldsaAlgorithm::Mldsa87.public_key_size()] =
                    mldsa_pub.into();
                let pub_key = PubKey::MlDsa(MldsaPublicKey::from_slice(&pub_key_bytes));
                let seed_copy = *seed_key_id;
                self.sign_helper(data, &seed_copy, &pub_key)
            }
            _ => Err(CryptoError::MismatchedAlgorithm),
        }
    }

    fn sign_with_derived(
        &mut self,
        data: &SignData,
        priv_key: &Self::PrivKey,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        self.sign_helper(data, priv_key, pub_key)
    }
}
