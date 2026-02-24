// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};
use zeroize::ZeroizeOnDrop;

use crate::{
    hpke::{
        kdf::Shake256,
        kem::{
            EncapsulatedSecret, EncapsulationKey, Kem, MlKem, MlKemContext,
            MlKemEncapsulatedSecret, P384KemContext, SharedSecret, P384,
        },
        suites::{CipherSuite, KemId},
    },
    Array4x28, Array4x8, Ecc384, Hmac, LEArray4x8, MlKem1024, MlKem1024EncapsKey, Sha3, Trng,
};

use zerocopy::{FromBytes, IntoBytes};

use super::{
    MlKemEncapsulationKey, MlKemSharedSecret, P384EncapsulatedSecret, P384EncapsulationKey,
    P384SharedSecret,
};

pub type HybridEncapsulatedSecret = EncapsulatedSecret<{ MlKem1024P384::NENC }>;
pub type HybridEncapsulationKey = EncapsulationKey<{ MlKem1024P384::NPK }>;
pub type HybridSharedSecret = SharedSecret<{ MlKem1024P384::NSECRET }>;

impl TryFrom<(MlKemEncapsulationKey, P384EncapsulationKey)> for HybridEncapsulationKey {
    type Error = CaliptraError;
    fn try_from(value: (MlKemEncapsulationKey, P384EncapsulationKey)) -> Result<Self, Self::Error> {
        let mut buf = [0; MlKem1024P384::NPK];
        buf.get_mut(..MlKem::NPK)
            .map(|buf| {
                buf.clone_from_slice(value.0.as_ref());
            })
            .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_HYBRID_ENC_SERIALIZATION_FAIL)?;
        buf.get_mut(MlKem::NPK..MlKem::NPK + P384::NPK)
            .map(|buf| {
                buf.clone_from_slice(value.1.as_ref());
            })
            .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_HYBRID_ENC_SERIALIZATION_FAIL)?;
        Ok(Self { buf })
    }
}

impl TryFrom<(MlKemEncapsulatedSecret, P384EncapsulatedSecret)> for HybridEncapsulatedSecret {
    type Error = CaliptraError;
    fn try_from(
        value: (MlKemEncapsulatedSecret, P384EncapsulatedSecret),
    ) -> Result<Self, Self::Error> {
        let mut buf = [0; MlKem1024P384::NENC];
        buf.get_mut(..MlKem::NENC)
            .map(|buf| {
                buf.clone_from_slice(value.0.as_ref());
            })
            .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_HYBRID_ENC_SERIALIZATION_FAIL)?;
        buf.get_mut(MlKem::NENC..MlKem::NENC + P384::NENC)
            .map(|buf| {
                buf.clone_from_slice(value.1.as_ref());
            })
            .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_HYBRID_ENC_SERIALIZATION_FAIL)?;
        Ok(Self { buf })
    }
}

#[derive(ZeroizeOnDrop)]
pub struct MlKem1024P384 {
    seed: [u8; Self::NSK],
    // Can't store just the seed because the hardware mixes a nonce into the key generation.
    trad: P384,
}

impl MlKem1024P384 {
    pub const NSK: usize = 32;
    pub const NENC: usize = MlKem::NENC + P384::NENC;
    pub const NPK: usize = MlKem::NPK + P384::NPK;
    pub const NSECRET: usize = 32;
    pub const FULL_SEED: usize = MlKem::NSK + P384::NSK;
    pub const COMBINER_SIZE: usize = MlKem::NSECRET
        + P384::NSECRET
        + MlKem::NSK
        + P384::NSK
        + P384::NPK
        + Self::COMBINER_LABEL.len();
    pub const COMBINER_LABEL: &[u8] = b"MLKEM1024-P384";

    pub fn new(seed: [u8; Self::NSK], trad: P384) -> Self {
        Self { seed, trad }
    }

    /// Section 4 from https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/03/.
    fn expand_seed(
        sha: &mut Sha3,
        ikm: &[u8; Self::NSK],
    ) -> CaliptraResult<([u8; MlKem::NSK], [u8; P384::NSK])> {
        let seed = {
            let seed: Array4x8 = Shake256::<{ Self::NSK as u16 }>::labeled_derive(
                sha,
                CipherSuite::Kem(Self::KEM_ID),
                ikm,
                b"DeriveKeyPair",
                b"",
            )?;
            LEArray4x8::from(seed)
        };

        let expanded_seed: [u8; Self::FULL_SEED] = {
            let mut op = sha.shake256_digest_init()?;
            op.update(seed.as_bytes())?;
            let expanded_seed: Array4x28 = op.finalize()?;
            expanded_seed.into()
        };

        let mut mlkem_seed = [0u8; MlKem::NSK];
        mlkem_seed.copy_from_slice(&expanded_seed[..MlKem::NSK]);

        let mut p384_seed = [0u8; P384::NSK];
        p384_seed.copy_from_slice(&expanded_seed[MlKem::NSK..]);

        Ok((mlkem_seed, p384_seed))
    }

    /// C2PRICombiner from section 5.1.3 of
    /// https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-08.txt.
    fn combiner(
        sha: &mut Sha3,
        shared_secret_pq: &MlKemSharedSecret,
        shared_secret_trad: &P384SharedSecret,
        trad_enc: &P384EncapsulatedSecret,
        trad_ek: &P384EncapsulationKey,
    ) -> CaliptraResult<HybridSharedSecret> {
        let combiner_input = [
            shared_secret_pq.as_ref(),
            shared_secret_trad.as_ref(),
            trad_enc.as_ref(),
            trad_ek.as_ref(),
            Self::COMBINER_LABEL,
        ];
        let res = sha.sha3_256_digest_ext(combiner_input.iter())?;
        Ok(HybridSharedSecret::from(res))
    }
}

pub struct MlKem1024P384KemContext<'a> {
    trng: &'a mut Trng,
    sha: &'a mut Sha3,
    ml_kem: &'a mut MlKem1024,
    ecc: &'a mut Ecc384,
    hmac: &'a mut Hmac,
}

impl<'a> MlKem1024P384KemContext<'a> {
    pub fn new(
        trng: &'a mut Trng,
        sha: &'a mut Sha3,
        ml_kem: &'a mut MlKem1024,
        ecc: &'a mut Ecc384,
        hmac: &'a mut Hmac,
    ) -> Self {
        Self {
            trng,
            sha,
            ml_kem,
            ecc,
            hmac,
        }
    }
}

impl
    Kem<
        { MlKem1024P384::NSK },
        { MlKem1024P384::NENC },
        { MlKem1024P384::NPK },
        { MlKem1024P384::NSECRET },
    > for MlKem1024P384
{
    const KEM_ID: KemId = KemId::ML_KEM_1024_P384;
    type CONTEXT<'a> = MlKem1024P384KemContext<'a>;
    type EK = HybridEncapsulationKey;

    fn derive_key_pair(ctx: &mut Self::CONTEXT<'_>, ikm: &[u8; 32]) -> CaliptraResult<Self> {
        let (_, trad_seed) = Self::expand_seed(ctx.sha, ikm)?;
        let mut ctx = P384KemContext::new(ctx.trng, ctx.ecc, ctx.hmac);
        let trad = P384::derive_key_pair_raw(&mut ctx, &trad_seed)?;
        Ok(Self::new(*ikm, trad))
    }

    fn encap(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
        encaps_key: &Self::EK,
    ) -> CaliptraResult<(HybridEncapsulatedSecret, HybridSharedSecret)> {
        let encaps_key: &[u8; Self::NPK] = encaps_key.as_ref();
        let pq_ek = encaps_key
            .get(..MlKem::NPK)
            .and_then(|pq_encaps_key| MlKem1024EncapsKey::ref_from_bytes(pq_encaps_key).ok())
            .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_HYBRID_ENCAP_KEY_DESERIALIZATION_FAIL)?;

        let trad_ek = encaps_key
            .get(MlKem::NPK..MlKem::NPK + P384::NPK)
            .and_then(|pq_encaps_key| P384EncapsulationKey::ref_from_bytes(pq_encaps_key).ok())
            .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_HYBRID_ENCAP_KEY_DESERIALIZATION_FAIL)?;

        let (pq_enc, pq_shared_secret) = {
            let (pq_seed, _) = Self::expand_seed(ctx.sha, &self.seed)?;
            let mut ctx = MlKemContext::new(ctx.trng, ctx.sha, ctx.ml_kem);
            let mut mlkem = MlKem::derive_key_pair_raw(pq_seed);
            mlkem.encap(&mut ctx, pq_ek)?
        };

        let (trad_enc, trad_shared_secret) = {
            let mut ctx = P384KemContext::new(ctx.trng, ctx.ecc, ctx.hmac);
            self.trad.raw_encap(&mut ctx, trad_ek)?
        };

        let shared_secret = Self::combiner(
            ctx.sha,
            &pq_shared_secret,
            &trad_shared_secret,
            &trad_enc,
            trad_ek,
        )?;
        let enc = HybridEncapsulatedSecret::try_from((pq_enc, trad_enc))?;

        Ok((enc, shared_secret))
    }

    fn decap(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
        enc: &HybridEncapsulatedSecret,
    ) -> CaliptraResult<HybridSharedSecret> {
        let enc = enc.as_ref();
        let (pq_enc, rem) = MlKemEncapsulatedSecret::ref_from_prefix(enc)
            .map_err(|_| CaliptraError::RUNTIME_DRIVER_HPKE_HYBRID_ENC_DESERIALIZATION_FAIL)?;
        let trad_enc = P384EncapsulatedSecret::ref_from_bytes(rem)
            .map_err(|_| CaliptraError::RUNTIME_DRIVER_HPKE_HYBRID_ENC_DESERIALIZATION_FAIL)?;

        let pq_shared_secret = {
            let (pq_seed, _) = Self::expand_seed(ctx.sha, &self.seed)?;
            let mut ctx = MlKemContext::new(ctx.trng, ctx.sha, ctx.ml_kem);
            let mut mlkem = MlKem::derive_key_pair_raw(pq_seed);
            mlkem.decap(&mut ctx, pq_enc)?
        };

        let (trad_shared_secret, trad_ek) = {
            let mut ctx = P384KemContext::new(ctx.trng, ctx.ecc, ctx.hmac);
            let shared_secret = self.trad.raw_decap(&mut ctx, trad_enc)?;
            let ek = self.trad.serialize_public_key(&mut ctx)?;
            (shared_secret, ek)
        };

        Self::combiner(
            ctx.sha,
            &pq_shared_secret,
            &trad_shared_secret,
            trad_enc,
            &trad_ek,
        )
    }

    fn serialize_public_key(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
    ) -> CaliptraResult<HybridEncapsulationKey> {
        let pq_ek = {
            let (pq_seed, _) = Self::expand_seed(ctx.sha, &self.seed)?;
            let mut ctx = MlKemContext::new(ctx.trng, ctx.sha, ctx.ml_kem);
            let mut mlkem = MlKem::derive_key_pair_raw(pq_seed);
            mlkem.serialize_public_key(&mut ctx)?
        };
        let trad_ek = {
            let mut ctx = P384KemContext::new(ctx.trng, ctx.ecc, ctx.hmac);
            self.trad.serialize_public_key(&mut ctx)?
        };
        HybridEncapsulationKey::try_from((pq_ek, trad_ek))
    }
}
