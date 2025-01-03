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
    cprintln, hmac_kdf,
    sha2_512_384::{Sha2DigestOpTrait, Sha384},
    Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar, Ecc384Seed, Hmac, HmacData,
    HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Sha2DigestOp,
    Sha2_512_384, Trng,
};
use crypto::{AlgLen, Crypto, CryptoBuf, CryptoError, Digest, EcdsaPub, EcdsaSig, Hasher};
use dpe::{
    response::DpeErrorCode, x509::MeasurementData, ExportedCdiHandle, MAX_EXPORTED_CDI_SIZE,
};
use zerocopy::IntoBytes;
use zeroize::Zeroize;

// Currently only can export CDI once, but in the future we may want to support multiple exported
// CDI handles at the cost of using more KeyVault slots.
pub const EXPORTED_HANDLES_NUM: usize = 1;
pub type ExportedCdiHandles = [Option<(KeyId, ExportedCdiHandle)>; EXPORTED_HANDLES_NUM];

pub struct DpeCrypto<'a> {
    sha2_512_384: &'a mut Sha2_512_384,
    trng: &'a mut Trng,
    ecc384: &'a mut Ecc384,
    hmac: &'a mut Hmac,
    key_vault: &'a mut KeyVault,
    rt_pub_key: &'a mut Ecc384PubKey,
    key_id_rt_cdi: KeyId,
    key_id_rt_priv_key: KeyId,
    exported_cdi_slots: &'a mut ExportedCdiHandles,
}

impl<'a> DpeCrypto<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sha2_512_384: &'a mut Sha2_512_384,
        trng: &'a mut Trng,
        ecc384: &'a mut Ecc384,
        hmac: &'a mut Hmac,
        key_vault: &'a mut KeyVault,
        rt_pub_key: &'a mut Ecc384PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> Self {
        Self {
            sha2_512_384,
            trng,
            ecc384,
            hmac,
            key_vault,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
        }
    }

    fn derive_cdi_inner(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
        key_id: KeyId,
    ) -> Result<<DpeCrypto<'a> as crypto::Crypto>::Cdi, CryptoError> {
        match algs {
            AlgLen::Bit256 => Err(CryptoError::Size),
            AlgLen::Bit384 => {
                let mut hasher = self.hash_initialize(algs)?;
                hasher.update(measurement.bytes())?;
                hasher.update(info)?;
                let context = hasher.finish()?;

                hmac_kdf(
                    self.hmac,
                    KeyReadArgs::new(self.key_id_rt_cdi).into(),
                    b"derive_cdi",
                    Some(context.bytes()),
                    self.trng,
                    KeyWriteArgs::new(
                        key_id,
                        KeyUsage::default()
                            .set_hmac_key_en()
                            .set_ecc_key_gen_seed_en(),
                    )
                    .into(),
                    HmacMode::Hmac384,
                )
                .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                Ok(key_id)
            }
        }
    }

    fn derive_key_pair_inner(
        &mut self,
        algs: AlgLen,
        cdi: &<DpeCrypto<'a> as crypto::Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
        key_id: KeyId,
    ) -> Result<(<DpeCrypto<'a> as crypto::Crypto>::PrivKey, EcdsaPub), CryptoError> {
        match algs {
            AlgLen::Bit256 => Err(CryptoError::Size),
            AlgLen::Bit384 => {
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

                let pub_key = self
                    .ecc384
                    .key_pair(
                        &Ecc384Seed::Key(KeyReadArgs::new(KEY_ID_TMP)),
                        &Array4x12::default(),
                        self.trng,
                        KeyWriteArgs::new(key_id, KeyUsage::default().set_ecc_private_key_en())
                            .into(),
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                let pub_key = EcdsaPub {
                    x: CryptoBuf::new(&<[u8; AlgLen::Bit384.size()]>::from(pub_key.x))
                        .map_err(|_| CryptoError::Size)?,
                    y: CryptoBuf::new(&<[u8; AlgLen::Bit384.size()]>::from(pub_key.y))
                        .map_err(|_| CryptoError::Size)?,
                };
                Ok((key_id, pub_key))
            }
        }
    }

    pub fn get_cdi_from_exported_handle(
        &mut self,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> Option<<DpeCrypto<'a> as crypto::Crypto>::Cdi> {
        for cdi_slot in self.exported_cdi_slots.iter() {
            match cdi_slot {
                Some((cdi, handle)) if handle == exported_cdi_handle => return Some(*cdi),
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
    op: Sha2DigestOp<'a, Sha384>,
}

impl<'a> DpeHasher<'a> {
    pub fn new(op: Sha2DigestOp<'a, Sha384>) -> Self {
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
        Digest::new(<[u8; AlgLen::Bit384.size()]>::from(digest).as_ref())
    }
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

    fn hash_initialize(&mut self, algs: AlgLen) -> Result<Self::Hasher<'_>, CryptoError> {
        match algs {
            AlgLen::Bit256 => Err(CryptoError::Size),
            AlgLen::Bit384 => {
                let op = self
                    .sha2_512_384
                    .sha384_digest_init()
                    .map_err(|e| CryptoError::HashError(u32::from(e)))?;
                Ok(DpeHasher::new(op))
            }
        }
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let mut exported_cdi_handle = [0; MAX_EXPORTED_CDI_SIZE];
        self.rand_bytes(&mut exported_cdi_handle)?;
        let cdi = self.derive_cdi_inner(algs, measurement, info, KEY_ID_EXPORTED_DPE_CDI)?;

        for slot in self.exported_cdi_slots.iter_mut() {
            match slot {
                // Matching existing slot
                Some((cached_cdi, handle)) if *cached_cdi == cdi => {
                    Err(CryptoError::ExportedCdiHandleDuplicateCdi)?
                }
                // Empty slot
                None => {
                    *slot = Some((cdi, exported_cdi_handle));
                    return Ok(exported_cdi_handle);
                }
                // Used slot for a different CDI.
                _ => (),
            }
        }
        Err(CryptoError::ExportedCdiHandleLimitExceeded)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        self.derive_cdi_inner(algs, measurement, info, KEY_ID_DPE_CDI)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair(
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, EcdsaPub), CryptoError> {
        self.derive_key_pair_inner(algs, cdi, label, info, KEY_ID_DPE_PRIV_KEY)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        algs: AlgLen,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, EcdsaPub), CryptoError> {
        let cdi = {
            let mut cdi = None;
            for cdi_slot in self.exported_cdi_slots.iter() {
                match cdi_slot {
                    Some((stored_cdi, stored_handle)) if stored_handle == exported_handle => {
                        cdi = Some(*stored_cdi);
                        break;
                    }
                    _ => (),
                }
            }
            cdi.ok_or(CryptoError::InvalidExportedCdiHandle)
        }?;
        self.derive_key_pair_inner(algs, &cdi, label, info, KEY_ID_TMP)
    }

    fn ecdsa_sign_with_alias(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
    ) -> Result<EcdsaSig, CryptoError> {
        let pub_key = EcdsaPub {
            x: CryptoBuf::new(&<[u8; AlgLen::Bit384.size()]>::from(self.rt_pub_key.x))
                .map_err(|_| CryptoError::Size)?,
            y: CryptoBuf::new(&<[u8; AlgLen::Bit384.size()]>::from(self.rt_pub_key.y))
                .map_err(|_| CryptoError::Size)?,
        };
        self.ecdsa_sign_with_derived(algs, digest, &self.key_id_rt_priv_key.clone(), &pub_key)
    }

    fn ecdsa_sign_with_derived(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        pub_key: &EcdsaPub,
    ) -> Result<EcdsaSig, CryptoError> {
        match algs {
            AlgLen::Bit256 => Err(CryptoError::Size),
            AlgLen::Bit384 => {
                let priv_key_args = KeyReadArgs::new(*priv_key);
                let ecc_priv_key = Ecc384PrivKeyIn::Key(priv_key_args);

                const SIZE: usize = AlgLen::Bit384.size();
                let mut x = [0u8; SIZE];
                let mut y = [0u8; SIZE];
                x.get_mut(..SIZE)
                    .ok_or(CryptoError::CryptoLibError(0))?
                    .copy_from_slice(
                        pub_key
                            .x
                            .bytes()
                            .get(..SIZE)
                            .ok_or(CryptoError::CryptoLibError(0))?,
                    );
                y.get_mut(..SIZE)
                    .ok_or(CryptoError::CryptoLibError(0))?
                    .copy_from_slice(
                        pub_key
                            .y
                            .bytes()
                            .get(..SIZE)
                            .ok_or(CryptoError::CryptoLibError(0))?,
                    );
                let ecc_pub_key = Ecc384PubKey {
                    x: Ecc384Scalar::from(x),
                    y: Ecc384Scalar::from(y),
                };

                let mut digest_arr = [0u8; SIZE];
                digest_arr
                    .get_mut(..SIZE)
                    .ok_or(CryptoError::CryptoLibError(0))?
                    .copy_from_slice(
                        digest
                            .bytes()
                            .get(..SIZE)
                            .ok_or(CryptoError::CryptoLibError(0))?,
                    );

                let sig = self
                    .ecc384
                    .sign(
                        &ecc_priv_key,
                        &ecc_pub_key,
                        &Ecc384Scalar::from(digest_arr),
                        self.trng,
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

                let r = CryptoBuf::new(&<[u8; SIZE]>::from(sig.r))?;
                let s = CryptoBuf::new(&<[u8; SIZE]>::from(sig.s))?;

                Ok(EcdsaSig { r, s })
            }
        }
    }
}
