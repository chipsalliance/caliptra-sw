// Licensed under the Apache-2.0 license

use caliptra_drivers::{Array4x12, KeyId, Sha384, Sha384DigestOp};
use crypto::{AlgLen, Crypto, CryptoError, Digest, EcdsaPub, EcdsaSig, Hasher, HmacSig};

pub struct DpeCrypto<'a> {
    sha384: &'a mut Sha384,
}

impl<'a> DpeCrypto<'a> {
    pub fn new(sha384: &'a mut Sha384) -> Self {
        Self { sha384 }
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

    fn rand_bytes(&mut self, _dst: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
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
        _algs: AlgLen,
        _measurement: &Digest,
        _info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_private_key(
        &mut self,
        _algs: AlgLen,
        _cdi: &Self::Cdi,
        _label: &[u8],
        _info: &[u8],
    ) -> Result<Self::PrivKey, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_ecdsa_pub(
        &mut self,
        _algs: AlgLen,
        _priv_key: &Self::PrivKey,
    ) -> Result<EcdsaPub, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn ecdsa_sign_with_alias(
        &mut self,
        _algs: AlgLen,
        _digest: &Digest,
    ) -> Result<EcdsaSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn ecdsa_sign_with_derived(
        &mut self,
        _algs: AlgLen,
        _digest: &Digest,
        _priv_key: &Self::PrivKey,
    ) -> Result<EcdsaSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn get_ecdsa_alias_serial(
        &mut self,
        _algs: AlgLen,
        _serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn hmac_sign_with_derived(
        &mut self,
        _algs: AlgLen,
        _cdi: &Self::Cdi,
        _label: &[u8],
        _info: &[u8],
        _digest: &Digest,
    ) -> Result<HmacSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}
