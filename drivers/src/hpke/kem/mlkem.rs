// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};

use crate::{
    hpke::{kdf, suites::KemIdExt},
    MlKem1024, MlKem1024Ciphertext, MlKem1024DecapsKey, MlKem1024EncapsKey, MlKem1024Message,
    MlKem1024MessageSource, MlKem1024Seed, MlKem1024Seeds, MlKem1024SharedKey,
    MlKem1024SharedKeyOut, Sha3, Trng,
};

use super::{DecapsulationKey, EncapsulatedSecret, EncapsulationKey, Kem, SharedSecret};

use zerocopy::FromBytes;

pub type MlKemEncapsulatedSecret = EncapsulatedSecret<{ MlKem::NENC }>;
pub type MlKemEncapsulationKey = EncapsulationKey<{ MlKem::NPK }>;
pub type MlKemDecapsulationKey = DecapsulationKey<{ MlKem::NSK }>;
pub type MlKemSharedSecret = SharedSecret<{ MlKem::NSECRET }>;

impl Default for MlKemEncapsulationKey {
    fn default() -> Self {
        Self {
            buf: [0; MlKem::NPK],
        }
    }
}

impl From<MlKem1024SharedKey> for MlKemSharedSecret {
    fn from(value: MlKem1024SharedKey) -> Self {
        let buf = <[u8; MlKem::NSECRET]>::from(value);
        Self { buf }
    }
}

impl From<&MlKemEncapsulatedSecret> for MlKem1024Ciphertext {
    fn from(value: &EncapsulatedSecret<{ MlKem::NENC }>) -> Self {
        value.buf.into()
    }
}

impl From<MlKem1024Ciphertext> for MlKemEncapsulatedSecret {
    fn from(value: MlKem1024Ciphertext) -> Self {
        let buf = <[u8; MlKem::NENC]>::from(value);
        Self { buf }
    }
}

impl From<[u8; MlKem::NENC]> for MlKemEncapsulatedSecret {
    fn from(value: [u8; MlKem::NENC]) -> Self {
        Self { buf: value }
    }
}

impl From<&[u8; MlKem::NENC]> for MlKemEncapsulatedSecret {
    fn from(value: &[u8; MlKem::NENC]) -> Self {
        Self { buf: *value }
    }
}

impl From<MlKem1024EncapsKey> for MlKemEncapsulationKey {
    fn from(value: MlKem1024EncapsKey) -> Self {
        let buf = <[u8; MlKem::NPK]>::from(value);
        Self { buf }
    }
}

impl From<&MlKemEncapsulationKey> for MlKem1024EncapsKey {
    fn from(value: &MlKemEncapsulationKey) -> Self {
        value.buf.into()
    }
}

impl From<[u8; 64]> for MlKemDecapsulationKey {
    fn from(value: [u8; 64]) -> Self {
        Self { buf: value }
    }
}

pub struct MlKem<'a> {
    sha: &'a mut Sha3,
    ml_kem: &'a mut MlKem1024,
}

impl MlKem<'_> {
    pub const NSK: usize = 64;
    pub const NENC: usize = 1568;
    pub const NPK: usize = 1568;
    pub const NSECRET: usize = 32;
}

impl<'a> MlKem<'a> {
    /// Create a new instance of `MlKem`
    pub fn new(sha: &'a mut Sha3, ml_kem: &'a mut MlKem1024) -> Self {
        Self { sha, ml_kem }
    }

    /// https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/03/ Section 3.
    ///
    /// Derive an ML-KEM decapsulation key in the 64-byte seed format,
    /// then uses the function ML-KEM.KeyGen_internal from [FIPS203] to
    /// compute the corresponding encapsulation key
    fn expand_decaps_key(
        &mut self,
        dk: &[u8; MlKem::NSK],
    ) -> CaliptraResult<(MlKem1024EncapsKey, MlKem1024DecapsKey)> {
        let (a, b) = {
            let mut a = [0; 32];
            a.clone_from_slice(&dk[..32]);

            let mut b = [0; 32];
            b.clone_from_slice(&dk[32..]);

            let a_seed = MlKem1024Seed::from(&a);
            let b_seed = MlKem1024Seed::from(&b);

            (a_seed, b_seed)
        };

        let derived_ikm = MlKem1024Seeds::Arrays(&a, &b);
        self.ml_kem.key_pair(derived_ikm)
    }
}

impl Kem<{ MlKem::NSK }, { MlKem::NENC }, { MlKem::NPK }, { MlKem::NSECRET }> for MlKem<'_> {
    const KEM_ID_EXT: KemIdExt = KemIdExt::ML_KEM_1024;
    type EK = MlKem1024EncapsKey;

    fn derive_key_pair(
        &mut self,
        ikm: &[u8; MlKem::NSK],
    ) -> CaliptraResult<(Self::EK, MlKemDecapsulationKey)> {
        let ikm =
            kdf::Shake256::labeled_derive(self.sha, Self::KEM_ID_EXT, ikm, b"DeriveKeyPair", b"")?;
        let (ek, _dk) = self.expand_decaps_key(&ikm)?;
        Ok((ek, ikm.into()))
    }

    fn encap(
        &mut self,
        trng: &mut Trng,
        encaps_key: &Self::EK,
    ) -> CaliptraResult<(MlKemEncapsulatedSecret, MlKemSharedSecret)> {
        let message = {
            let mut message = MlKem1024Message::default();
            let rnd = trng.generate16()?;
            let rnd = rnd
                .0
                .get(..8)
                .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_ENCAP_TRNG_FAIL)?;
            message.0[..].clone_from_slice(rnd);
            message
        };
        let mut enc = MlKem1024SharedKey::default();
        let shared_secret = self.ml_kem.encapsulate(
            encaps_key,
            MlKem1024MessageSource::Array(&message),
            MlKem1024SharedKeyOut::Array(&mut enc),
        )?;
        Ok((shared_secret.into(), enc.into()))
    }

    /// Derive expanded decapsulation key from 64 byte seed.
    /// See https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/03/ section 3.
    fn decap(
        &mut self,
        enc: &MlKemEncapsulatedSecret,
        dk: &MlKemDecapsulationKey,
    ) -> CaliptraResult<MlKemSharedSecret> {
        let (_ek, dk) = self.expand_decaps_key(dk.as_ref())?;
        let mut shared_key = MlKem1024SharedKey::default();
        let enc = MlKem1024Ciphertext::ref_from_bytes(enc.buf.as_slice())
            .map_err(|_| CaliptraError::RUNTIME_DRIVER_HPKE_ML_KEM_PKR_DESERIALIZATION_FAIL)?;
        self.ml_kem
            .decapsulate(&dk, enc, MlKem1024SharedKeyOut::Array(&mut shared_key))?;
        Ok(SharedSecret::from(shared_key))
    }
}
