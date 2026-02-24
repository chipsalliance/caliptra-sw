// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};

use crate::{
    hpke::{
        kdf,
        suites::{CipherSuite, KemId},
    },
    Array4x16, LEArray4x392, MlKem1024, MlKem1024Ciphertext, MlKem1024DecapsKey,
    MlKem1024EncapsKey, MlKem1024Message, MlKem1024MessageSource, MlKem1024Seed, MlKem1024Seeds,
    MlKem1024SharedKey, MlKem1024SharedKeyOut, Sha3, Trng,
};

use super::{DecapsulationKey, EncapsulatedSecret, EncapsulationKey, Kem, SharedSecret};

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

impl From<[u8; MlKem::NPK]> for MlKemEncapsulationKey {
    fn from(value: [u8; MlKem::NPK]) -> Self {
        Self { buf: value }
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

pub struct MlKemContext<'a> {
    sha: &'a mut Sha3,
    ml_kem: &'a mut MlKem1024,
    trng: &'a mut Trng,
}

impl<'a> MlKemContext<'a> {
    /// Create a new instance of `MlKemContext`
    pub fn new(trng: &'a mut Trng, sha: &'a mut Sha3, ml_kem: &'a mut MlKem1024) -> Self {
        Self { trng, sha, ml_kem }
    }
}

/// MlKem KEM operations type
pub struct MlKem {
    ikm: [u8; Self::NSK],
}

impl MlKem {
    pub const NSK: usize = 64;
    pub const NENC: usize = 1568;
    pub const NPK: usize = 1568;
    pub const NSECRET: usize = 32;

    /// Creates an ML-KEM object without first conditioning it with a KDF
    /// This should only be used for hybrid KEMs.
    pub fn derive_key_pair_raw(ikm: [u8; Self::NSK]) -> Self {
        Self { ikm }
    }
}

impl MlKem {
    /// https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/03/ Section 3.
    ///
    /// Derive an ML-KEM decapsulation key in the 64-byte seed format,
    /// then uses the function ML-KEM.KeyGen_internal from [FIPS203] to
    /// compute the corresponding encapsulation key
    fn expand_decaps_key(
        &mut self,
        ctx: &mut MlKemContext<'_>,
    ) -> CaliptraResult<(MlKem1024EncapsKey, MlKem1024DecapsKey)> {
        let (a, b) = {
            let mut a = [0; 32];
            a.clone_from_slice(&self.ikm[..32]);

            let mut b = [0; 32];
            b.clone_from_slice(&self.ikm[32..]);

            let a_seed = MlKem1024Seed::from(&a);
            let b_seed = MlKem1024Seed::from(&b);

            (a_seed, b_seed)
        };

        let derived_ikm = MlKem1024Seeds::Arrays(&a, &b);
        ctx.ml_kem.key_pair(derived_ikm)
    }
}

impl Kem<{ MlKem::NSK }, { MlKem::NENC }, { MlKem::NPK }, { MlKem::NSECRET }> for MlKem {
    const KEM_ID: KemId = KemId::ML_KEM_1024;
    type CONTEXT<'a> = MlKemContext<'a>;
    type EK = MlKem1024EncapsKey;

    fn derive_key_pair(
        ctx: &mut Self::CONTEXT<'_>,
        ikm: &[u8; MlKem::NSK],
    ) -> CaliptraResult<Self> {
        let ikm: Array4x16 = kdf::Shake256::<{ MlKem::NSK as u16 }>::labeled_derive(
            ctx.sha,
            CipherSuite::Kem(Self::KEM_ID),
            ikm,
            b"DeriveKeyPair",
            b"",
        )?;
        Ok(Self { ikm: ikm.into() })
    }

    fn encap(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
        encaps_key: &Self::EK,
    ) -> CaliptraResult<(MlKemEncapsulatedSecret, MlKemSharedSecret)> {
        let message = {
            let mut message = MlKem1024Message::default();
            let rnd = ctx.trng.generate16()?;
            let rnd = rnd
                .0
                .get(..8)
                .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_ENCAP_TRNG_FAIL)?;
            message.0[..].clone_from_slice(rnd);
            message
        };
        let mut enc = MlKem1024SharedKey::default();
        let shared_secret = ctx.ml_kem.encapsulate(
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
        ctx: &mut Self::CONTEXT<'_>,
        enc: &MlKemEncapsulatedSecret,
    ) -> CaliptraResult<MlKemSharedSecret> {
        let (_ek, dk) = self.expand_decaps_key(ctx)?;
        let mut shared_key = MlKem1024SharedKey::default();
        // Can't use zerocopy here because the slice is not guaranteed to be aligned.
        let enc = LEArray4x392::from(enc.buf);
        ctx.ml_kem
            .decapsulate(&dk, &enc, MlKem1024SharedKeyOut::Array(&mut shared_key))?;
        Ok(SharedSecret::from(shared_key))
    }

    fn serialize_public_key(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
    ) -> CaliptraResult<EncapsulationKey<{ MlKem::NPK }>> {
        let (ek, _dk) = self.expand_decaps_key(ctx)?;
        Ok(MlKemEncapsulationKey::from(ek))
    }
}
