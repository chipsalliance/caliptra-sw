// Licensed under the Apache-2.0 license

use core::cmp::min;

use caliptra_common::keyids::{
    KEY_ID_DPE_CDI, KEY_ID_DPE_PRIV_KEY, KEY_ID_RT_CDI, KEY_ID_RT_PRIV_KEY, KEY_ID_TMP,
};
use caliptra_drivers::{
    hmac384_kdf, Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar, Ecc384Seed,
    Hmac384, Hmac384Data, Hmac384Tag, KeyId, KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Sha384,
    Sha384DigestOp, Trng,
};
use crypto::{AlgLen, Crypto, CryptoBuf, CryptoError, Digest, EcdsaPub, EcdsaSig, Hasher, HmacSig};
use zerocopy::AsBytes;

pub struct DpeCrypto<'a> {
    sha384: &'a mut Sha384,
    trng: &'a mut Trng,
    ecc384: &'a mut Ecc384,
    hmac384: &'a mut Hmac384,
    key_vault: &'a mut KeyVault,
    rt_pub_key: Ecc384PubKey,
}

impl<'a> DpeCrypto<'a> {
    pub fn new(
        sha384: &'a mut Sha384,
        trng: &'a mut Trng,
        ecc384: &'a mut Ecc384,
        hmac384: &'a mut Hmac384,
        key_vault: &'a mut KeyVault,
        rt_pub_key: Ecc384PubKey,
    ) -> Self {
        Self {
            sha384,
            trng,
            ecc384,
            hmac384,
            key_vault,
            rt_pub_key,
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
    op: Sha384DigestOp<'a>,
}

impl<'a> DpeHasher<'a> {
    pub fn new(op: Sha384DigestOp<'a>) -> Self {
        Self { op }
    }
}

impl<'a> Hasher for DpeHasher<'a> {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.op.update(bytes).map_err(|_| CryptoError::HashError)
    }

    fn finish(self) -> Result<Digest, CryptoError> {
        let mut digest = Array4x12::default();
        self.op
            .finalize(&mut digest)
            .map_err(|_| CryptoError::HashError)?;
        Digest::new(
            <[u8; AlgLen::Bit384.size()]>::from(digest).as_ref(),
            AlgLen::Bit384,
        )
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
                    .map_err(|_| CryptoError::CryptoLibError)?,
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
                    .sha384
                    .digest_init()
                    .map_err(|_| CryptoError::HashError)?;
                Ok(DpeHasher::new(op))
            }
        }
    }

    fn derive_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        match algs {
            AlgLen::Bit256 => Err(CryptoError::Size),
            AlgLen::Bit384 => {
                let mut hasher = self
                    .hash_initialize(algs)
                    .map_err(|_| CryptoError::HashError)?;
                hasher
                    .update(measurement.bytes())
                    .map_err(|_| CryptoError::HashError)?;
                hasher.update(info).map_err(|_| CryptoError::HashError)?;
                let context = hasher.finish().map_err(|_| CryptoError::HashError)?;

                hmac384_kdf(
                    self.hmac384,
                    KeyReadArgs::new(KEY_ID_RT_CDI).into(),
                    b"derive_cdi",
                    Some(context.bytes()),
                    self.trng,
                    KeyWriteArgs::new(
                        KEY_ID_DPE_CDI,
                        KeyUsage::default()
                            .set_hmac_key_en()
                            .set_ecc_key_gen_seed_en(),
                    )
                    .into(),
                )
                .map_err(|_| CryptoError::CryptoLibError)?;
                Ok(KEY_ID_DPE_CDI)
            }
        }
    }

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
                hmac384_kdf(
                    self.hmac384,
                    KeyReadArgs::new(*cdi).into(),
                    label,
                    Some(info),
                    self.trng,
                    KeyWriteArgs::new(KEY_ID_TMP, KeyUsage::default().set_ecc_key_gen_seed_en())
                        .into(),
                )
                .map_err(|_| CryptoError::CryptoLibError)?;

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
                    .map_err(|_| CryptoError::CryptoLibError)?;
                let pub_key = EcdsaPub {
                    x: CryptoBuf::new(&<[u8; AlgLen::Bit384.size()]>::from(pub_key.x), algs)
                        .map_err(|_| CryptoError::Size)?,
                    y: CryptoBuf::new(&<[u8; AlgLen::Bit384.size()]>::from(pub_key.y), algs)
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
            x: CryptoBuf::new(
                &<[u8; AlgLen::Bit384.size()]>::from(self.rt_pub_key.x),
                algs,
            )
            .map_err(|_| CryptoError::Size)?,
            y: CryptoBuf::new(
                &<[u8; AlgLen::Bit384.size()]>::from(self.rt_pub_key.y),
                algs,
            )
            .map_err(|_| CryptoError::Size)?,
        };
        self.ecdsa_sign_with_derived(algs, digest, &KEY_ID_RT_PRIV_KEY, pub_key)
    }

    fn ecdsa_sign_with_derived(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        pub_key: EcdsaPub,
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
                    .ok_or(CryptoError::CryptoLibError)?
                    .copy_from_slice(
                        pub_key
                            .x
                            .bytes()
                            .get(..SIZE)
                            .ok_or(CryptoError::CryptoLibError)?,
                    );
                y.get_mut(..SIZE)
                    .ok_or(CryptoError::CryptoLibError)?
                    .copy_from_slice(
                        pub_key
                            .y
                            .bytes()
                            .get(..SIZE)
                            .ok_or(CryptoError::CryptoLibError)?,
                    );
                let ecc_pub_key = Ecc384PubKey {
                    x: Ecc384Scalar::from(x),
                    y: Ecc384Scalar::from(y),
                };

                let mut digest_arr = [0u8; SIZE];
                digest_arr
                    .get_mut(..SIZE)
                    .ok_or(CryptoError::CryptoLibError)?
                    .copy_from_slice(
                        digest
                            .bytes()
                            .get(..SIZE)
                            .ok_or(CryptoError::CryptoLibError)?,
                    );

                let sig = self
                    .ecc384
                    .sign(
                        &ecc_priv_key,
                        &ecc_pub_key,
                        &Ecc384Scalar::from(digest_arr),
                        self.trng,
                    )
                    .map_err(|_| CryptoError::CryptoLibError)?;

                let r = CryptoBuf::new(&<[u8; SIZE]>::from(sig.r), algs)?;
                let s = CryptoBuf::new(&<[u8; SIZE]>::from(sig.s), algs)?;

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
                hmac384_kdf(
                    self.hmac384,
                    KeyReadArgs::new(*cdi).into(),
                    label,
                    Some(info),
                    self.trng,
                    KeyWriteArgs::new(KEY_ID_DPE_PRIV_KEY, KeyUsage::default().set_hmac_key_en())
                        .into(),
                )
                .map_err(|_| CryptoError::CryptoLibError)?;

                let mut tag = Array4x12::default();
                self.hmac384
                    .hmac(
                        &KeyReadArgs::new(KEY_ID_DPE_PRIV_KEY).into(),
                        &Hmac384Data::Slice(digest.bytes()),
                        self.trng,
                        Hmac384Tag::Array4x12(&mut tag),
                    )
                    .map_err(|_| CryptoError::CryptoLibError)?;
                HmacSig::new(tag.as_bytes(), algs)
            }
        }
    }
}
