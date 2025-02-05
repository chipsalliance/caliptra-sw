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
use caliptra_common::keyids::{KEY_ID_DPE_CDI, KEY_ID_DPE_PRIV_KEY, KEY_ID_TMP};
use caliptra_drivers::{
    cprintln, hmac_kdf, Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar, Ecc384Seed,
    Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage, KeyVault,
    KeyWriteArgs, Sha2DigestOp, Sha2_512_384, Trng,
};
use crypto::{AlgLen, Crypto, CryptoBuf, CryptoError, Digest, EcdsaPub, EcdsaSig, Hasher, HmacSig};
use zerocopy::AsBytes;
use zeroize::Zeroize;

pub struct DpeCrypto<'a> {
    sha2_512_384: &'a mut Sha2_512_384,
    trng: &'a mut Trng,
    ecc384: &'a mut Ecc384,
    hmac: &'a mut Hmac,
    key_vault: &'a mut KeyVault,
    rt_pub_key: &'a mut Ecc384PubKey,
    key_id_rt_cdi: KeyId,
    key_id_rt_priv_key: KeyId,
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
    op: Sha2DigestOp<'a, 384>,
}

impl<'a> DpeHasher<'a> {
    pub fn new(op: Sha2DigestOp<'a, 384>) -> Self {
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
        let mut curr_idx = 0;
        while curr_idx < dst.len() {
            let trng_bytes = <[u8; 48]>::from(
                self.trng
                    .generate()
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?,
            );
            let bytes_to_write = min(dst.len() - curr_idx, trng_bytes.len());
            dst[curr_idx..curr_idx + bytes_to_write].copy_from_slice(&trng_bytes[..bytes_to_write]);
            curr_idx += bytes_to_write;
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
    fn derive_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
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
                        KEY_ID_DPE_CDI,
                        KeyUsage::default()
                            .set_hmac_key_en()
                            .set_ecc_key_gen_seed_en()
                            .set_mldsa_key_gen_seed_en(),
                    )
                    .into(),
                    HmacMode::Hmac384,
                )
                .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                Ok(KEY_ID_DPE_CDI)
            }
        }
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair(
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, EcdsaPub), CryptoError> {
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
                        KeyWriteArgs::new(
                            KEY_ID_DPE_PRIV_KEY,
                            KeyUsage::default().set_ecc_private_key_en(),
                        )
                        .into(),
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                let pub_key = EcdsaPub {
                    x: CryptoBuf::new(&<[u8; AlgLen::Bit384.size()]>::from(pub_key.x))
                        .map_err(|_| CryptoError::Size)?,
                    y: CryptoBuf::new(&<[u8; AlgLen::Bit384.size()]>::from(pub_key.y))
                        .map_err(|_| CryptoError::Size)?,
                };
                Ok((KEY_ID_DPE_PRIV_KEY, pub_key))
            }
        }
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

    fn hmac_sign_with_derived(
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
        digest: &Digest,
    ) -> Result<HmacSig, CryptoError> {
        match algs {
            AlgLen::Bit256 => Err(CryptoError::Size),
            AlgLen::Bit384 => {
                // derive an EC key pair from the CDI
                // note: the output point must be kept secret since it is derived from the private key,
                // so as long as that output is kept secret and not released outside of Caliptra,
                // it is safe to use it as key material.
                let key_pair = Self::derive_key_pair(self, algs, cdi, label, info);
                if cfi_launder(key_pair.is_ok()) {
                    cfi_assert!(key_pair.is_ok());
                } else {
                    cfi_assert!(key_pair.is_err());
                }
                let (_, hmac_seed) = key_pair?;

                // create ikm to the hmac kdf by hashing the seed entropy from the pub key
                // this is more secure than directly using the pub key components in the hmac
                // kdf since the distribution of the pub key is taken from a set of discrete points
                let mut hasher = Self::hash_initialize(self, algs)?;
                hasher.update(hmac_seed.x.bytes())?;
                hasher.update(hmac_seed.y.bytes())?;
                let mut hmac_ikm: [u8; 48] = hasher
                    .finish()?
                    .bytes()
                    .try_into()
                    .map_err(|_| CryptoError::Size)?;

                // derive an hmac key
                let mut hmac_key = Array4x12::default();
                hmac_kdf(
                    self.hmac,
                    HmacKey::Array4x12(&Array4x12::from(hmac_ikm)),
                    &[],
                    None,
                    self.trng,
                    HmacTag::Array4x12(&mut hmac_key),
                    HmacMode::Hmac384,
                )
                .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                hmac_ikm.zeroize();

                // sign digest with HMAC key
                let mut tag = Array4x12::default();
                self.hmac
                    .hmac(
                        &HmacKey::Array4x12(&hmac_key),
                        &HmacData::Slice(digest.bytes()),
                        self.trng,
                        HmacTag::Array4x12(&mut tag),
                        HmacMode::Hmac384,
                    )
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
                hmac_key.zeroize();
                HmacSig::new(tag.as_bytes())
            }
        }
    }
}
