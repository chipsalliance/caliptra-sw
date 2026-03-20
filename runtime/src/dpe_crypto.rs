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
        curve_384::{Curve384, EcdsaPub384, EcdsaSignature384},
        EcdsaPubKey, EcdsaSignature,
    },
    ml_dsa::{ExternalMu, MldsaAlgorithm, MldsaPublicKey, MldsaSignature},
    Cdi, Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType, Hasher, Mu, PubKey,
    SignData, SignDataAlgorithm, SignDataType, Signature, SignatureAlgorithm, SignatureType,
};
use caliptra_drivers::{
    hmac_kdf, okref,
    sha2_512_384::{Sha2DigestOpTrait, Sha384},
    Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar, Ecc384Seed, ExportedCdiEntry,
    ExportedCdiHandles, Hmac, HmacMode, KeyId, KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs,
    Mldsa87, Mldsa87Mu, Mldsa87PubKey, Mldsa87Seed, Mldsa87SignRnd, Sha2DigestOp, Sha2_512_384,
    Trng,
};
use caliptra_registers::abr::AbrReg;
use constant_time_eq::constant_time_eq;
use core::marker::PhantomData;
use zerocopy::IntoBytes;

pub struct DpeCrypto<'a> {
    sha2_512_384: &'a mut Sha2_512_384,
    trng: &'a mut Trng,
    hmac: &'a mut Hmac,
    key_vault: &'a mut KeyVault,
    signer: Signer<'a>,
    hash_op: Option<Sha2DigestOp<'a, Sha384>>,
    cdi: Option<KeyId>,
    derived_key: Option<(KeyId, PubKey)>,
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
    ) -> DpeCrypto<'a> {
        DpeCrypto {
            sha2_512_384,
            trng,
            hmac,
            key_vault,
            signer: Signer::Ec(ecc384),
            hash_op: None,
            cdi: None,
            derived_key: None,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_mldsa87(
        sha2_512_384: &'a mut Sha2_512_384,
        trng: &'a mut Trng,
        abr_reg: &'a mut AbrReg,
        hmac: &'a mut Hmac,
        key_vault: &'a mut KeyVault,
        rt_pub_key: PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> DpeCrypto<'a> {
        DpeCrypto {
            sha2_512_384,
            trng,
            hmac,
            key_vault,
            signer: Signer::Mldsa(abr_reg),
            hash_op: None,
            cdi: None,
            derived_key: None,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
        }
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
    fn digest_algorithm(&self) -> SignDataAlgorithm {
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

        let mut hasher = self.hasher()?;
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
                let pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384::from_slice(
                    &pub_key.x.into(),
                    &pub_key.y.into(),
                )));
                Ok((key_id, pub_key))
            }
            Signer::Mldsa(abr_reg) => {
                let mut mldsa = Mldsa87::new(abr_reg);
                let pub_key = mldsa
                    .key_pair(
                        Mldsa87Seed::Key(KeyReadArgs::new(KEY_ID_TMP)),
                        self.trng,
                        None,
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)));
                let pub_key = okref(&pub_key)?;
                Ok((KEY_ID_TMP, PubKey::Mldsa(MldsaPublicKey(pub_key.into()))))
            }
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
        mldsa: &mut Mldsa87<'_>,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        let priv_key_args = KeyReadArgs::new(*priv_key);
        let priv_key = Mldsa87Seed::Key(priv_key_args);

        let PubKey::Mldsa(MldsaPublicKey(pub_key)) = pub_key else {
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
        Ok(Signature::Mldsa(MldsaSignature(dpe_sig)))
    }

    fn sign_helper(
        signer: &mut Signer,
        sha2_512_384: &mut Sha2_512_384,
        trng: &mut Trng,
        data: &SignData,
        priv_key: &KeyId,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        match (signer) {
            (Signer::Ec(ecc384)) => {
                Self::sign_ec(ecc384, sha2_512_384, trng, data, priv_key, pub_key)
            }
            (Signer::Mldsa(abr_reg)) => {
                let mut mldsa = Mldsa87::new(abr_reg);
                Self::sign_mldsa(&mut mldsa, trng, data, priv_key, pub_key)
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

impl Hasher for DpeCrypto<'_> {
    fn initialize(&mut self) -> Result<(), CryptoError> {
        let op = self
            .sha2_512_384
            .sha384_digest_init()
            .map_err(|e| CryptoError::HashError(u32::from(e)))?;
        self.hash_op = Some(op);
        Ok(())
    }

    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        let Some(op) = self.hash_op.as_mut() else {
            return Err(CryptoError::HashError(0));
        };
        op.update(bytes)
            .map_err(|e| CryptoError::HashError(u32::from(e)))
    }

    fn finish(&mut self) -> Result<Digest, CryptoError> {
        let op = self.hash_op.take().ok_or(CryptoError::HashError(1))?;
        let mut digest = Array4x12::default();
        op.finalize(&mut digest)
            .map_err(|e| CryptoError::HashError(u32::from(e)))?;
        Ok(Digest::Sha384(caliptra_dpe_crypto::Sha384(digest.into())))
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
        Ok(self)
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
    ) -> Result<&mut dyn Cdi, CryptoError> {
        self.cdi = Some(self.derive_cdi_inner(measurement, info, KEY_ID_DPE_CDI)?);
        Ok(self)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn Signer, CryptoError> {
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
}

impl Cdi for DpeCrypto<'_> {
    fn derive_key_pair(
        &mut self,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn caliptra_dpe_crypto::Signer, CryptoError> {
        let cdi = self.cdi.take().ok_or(CryptoError::CryptoLibError(1))?;
        self.derived_key =
            Some(self.derive_key_pair_inner(&cdi, label, info, KEY_ID_DPE_PRIV_KEY)?);
        Ok(self)
    }

    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<&mut dyn caliptra_dpe_crypto::Signer, CryptoError> {
        let cdi = self.cdi.take().ok_or(CryptoError::CryptoLibError(2))?;
        self.derived_key = Some(self.derive_key_pair_inner(&cdi, label, info, KEY_ID_TMP)?);
        Ok(self)
    }

    fn as_slice(&self) -> &[u8] {
        unimplemented!("Intentionally unimplemented because this is for test only purposes")
    }
}

impl caliptra_dpe_crypto::Signer for DpeCrypto<'_> {
    fn sign(&mut self, data: &SignData) -> Result<Signature, CryptoError> {
        let Some((priv_key, pub_key)) = &self.derived_key else {
            return Err(CryptoError::CryptoLibError(3));
        };
        Self::sign_helper(
            &mut self.signer,
            self.sha2_512_384,
            self.trng,
            data,
            priv_key,
            pub_key,
        )
    }

    fn public_key(&self) -> Result<PubKey, CryptoError> {
        let Some((_, pub_key)) = &self.derived_key else {
            return Err(CryptoError::CryptoLibError(4));
        };
        Ok(pub_key.clone())
    }
}

enum Signer<'a> {
    Ec(&'a mut Ecc384),
    Mldsa(&'a mut AbrReg),
}
