/*++

Licensed under the Apache-2.0 license.

File Name:

    dpe_crypto.rs

Abstract:

    File contains DpeCrypto implementation.

--*/

use core::cmp::min;

use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_launder};
use caliptra_common::keyids::{
    KEY_ID_DPE_CDI, KEY_ID_DPE_PRIV_KEY, KEY_ID_EXPORTED_DPE_CDI, KEY_ID_TMP,
};
use caliptra_drivers::{
    hmac384_kdf, Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar, Ecc384Seed,
    ExportedCdiEntry, ExportedCdiHandles, Hmac384, Hmac384Data, Hmac384Key, Hmac384Tag, KeyId,
    KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Sha384, Sha384DigestOp, Trng,
};
use crypto::{
    ecdsa::{
        curve_384::{Curve384, EcdsaPub384, EcdsaSignature384},
        EcdsaPubKey, EcdsaSignature,
    },
    Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm, DigestType, Hasher, PubKey,
    Signature, SignatureAlgorithm, SignatureType,
};
use dpe::{
    response::DpeErrorCode, x509::MeasurementData, EcdsaAlgorithm, ExportedCdiHandle, U8Bool,
    MAX_EXPORTED_CDI_SIZE,
};
use zerocopy::IntoBytes;
use zeroize::Zeroize;

pub struct DpeCrypto<'a> {
    sha384: &'a mut Sha384,
    trng: &'a mut Trng,
    ecc384: &'a mut Ecc384,
    hmac384: &'a mut Hmac384,
    key_vault: &'a mut KeyVault,
    rt_pub_key: &'a mut Ecc384PubKey,
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
        rt_pub_key: &'a mut Ecc384PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> Self {
        Self {
            sha384,
            trng,
            ecc384,
            hmac384,
            key_vault,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
        }
    }

    fn derive_cdi_inner(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        key_id: KeyId,
    ) -> Result<<DpeCrypto<'a> as crypto::Crypto>::Cdi, CryptoError> {
        let mut hasher = self.hash_initialize()?;
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
        cdi: &<DpeCrypto<'a> as crypto::Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
        key_id: KeyId,
    ) -> Result<(<DpeCrypto<'a> as crypto::Crypto>::PrivKey, PubKey), CryptoError> {
        hmac384_kdf(
            self.hmac384,
            KeyReadArgs::new(*cdi).into(),
            label,
            Some(info),
            self.trng,
            KeyWriteArgs::new(KEY_ID_TMP, KeyUsage::default().set_ecc_key_gen_seed_en()).into(),
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

        let pub_key = self
            .ecc384
            .key_pair(
                &Ecc384Seed::Key(KeyReadArgs::new(KEY_ID_TMP)),
                &Array4x12::default(),
                self.trng,
                KeyWriteArgs::new(key_id, KeyUsage::default().set_ecc_private_key_en()).into(),
            )
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
        let pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(
            EcdsaPub384::from_slice(&pub_key.x.into(), &pub_key.y.into())
                .map_err(|_| CryptoError::Size)?,
        ));
        Ok((key_id, pub_key))
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
                } if active.get() && handle == exported_cdi_handle => return Some(*key),
                _ => (),
            }
        }
        None
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
    op: Sha384DigestOp<'a>,
}

impl<'a> DpeHasher<'a> {
    pub fn new(op: Sha384DigestOp<'a>) -> Self {
        Self { op }
    }
}

impl<'a> Hasher for DpeHasher<'a> {
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

impl<'a> Crypto for DpeCrypto<'a> {
    type Cdi = KeyId;
    type Hasher<'b> = DpeHasher<'b> where Self: 'b;
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
            .sha384
            .digest_init()
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
                    handle,
                    active,
                } if active.get() && *key == cdi_slot => {
                    Err(CryptoError::ExportedCdiHandleDuplicateCdi)?
                }
                ExportedCdiEntry {
                    key,
                    handle,
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
                    } if active.get() && handle == exported_handle => {
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

    fn sign_with_alias(&mut self, digest: &Digest) -> Result<Signature, CryptoError> {
        let pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(
            EcdsaPub384::from_slice(&self.rt_pub_key.x.into(), &self.rt_pub_key.y.into())
                .map_err(|_| CryptoError::Size)?,
        ));
        self.sign_with_derived(digest, &self.key_id_rt_priv_key.clone(), &pub_key)
    }

    fn sign_with_derived(
        &mut self,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        let priv_key_args = KeyReadArgs::new(*priv_key);
        let ecc_priv_key = Ecc384PrivKeyIn::Key(priv_key_args);

        let PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384 {r:  x, s: y })) = pub_key else {
            return Err(CryptoError::MismatchedAlgorithm);
        };
        let ecc_pub_key = Ecc384PubKey {
            x: Ecc384Scalar::from(x),
            y: Ecc384Scalar::from(y),
        };

        let Digest::Sha384(crypto::Sha384(digest)) = digest else {
            return Err(CryptoError::MismatchedAlgorithm);
        };

        let sig = self
            .ecc384
            .sign(
                &ecc_priv_key,
                &ecc_pub_key,
                &Ecc384Scalar::from(digest),
                self.trng,
            )
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

        Ok(Signature::Ecdsa(EcdsaSignature::Ecdsa384(
            EcdsaSignature384::from_slice(&sig.r.into(), &sig.s.into())
                .map_err(|_| CryptoError::Size)?,
        )))
    }
}
