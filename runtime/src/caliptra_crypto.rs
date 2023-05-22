// Licensed under the Apache-2.0 license

use crypto::{AlgLen, Crypto, CryptoError, Digest, EcdsaPub, Hasher, HmacSig};
use caliptra_drivers::KeyId;

pub struct CaliptraHasher;

impl Hasher for CaliptraHasher {
    fn update(&mut self, _bytes: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn finish(self) -> Result<Digest, CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}

pub struct CaliptraCrypto;

impl Crypto for CaliptraCrypto {
    type Cdi = KeyId;
    type Hasher = CaliptraHasher;
    type PrivKey = KeyId;

    #[cfg(not(feature = "deterministic_rand"))]
    fn rand_bytes(_dst: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn hash_initialize(_algs: AlgLen) -> Result<Self::Hasher, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_cdi(
        _algs: AlgLen,
        _measurement: &Digest,
        _info: &[u8],
        _rand_seed: Option<&[u8]>,
    ) -> Result<Self::Cdi, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_private_key(
        _algs: AlgLen,
        _cdi: &Self::Cdi,
        _label: &[u8],
        _info: &[u8],
    ) -> Result<Self::PrivKey, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_ecdsa_pub(_algs: AlgLen, _priv_key: &Self::PrivKey) -> Result<EcdsaPub, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn ecdsa_sign_with_alias(
        _algs: AlgLen,
        _digest: &Digest,
    ) -> Result<super::EcdsaSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn ecdsa_sign_with_derived(
        _algs: AlgLen,
        _digest: &Digest,
        _priv_key: &Self::PrivKey,
    ) -> Result<super::EcdsaSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn get_ecdsa_alias_serial(_algs: AlgLen, _serial: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn hmac_sign_with_derived(
        _algs: AlgLen,
        _cdi: &Self::Cdi,
        _label: &[u8],
        _info: &[u8],
        _digest: &Digest,
    ) -> Result<HmacSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}
