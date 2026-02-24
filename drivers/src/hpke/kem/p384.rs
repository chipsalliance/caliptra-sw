// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};
use zeroize::ZeroizeOnDrop;

use crate::{
    hpke::{
        kdf::{Hmac384, L},
        suites::{CipherSuite, KemId},
    },
    Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Scalar, Ecc384Seed,
    Hmac, HmacKey, HmacTag, Trng,
};

use super::{DecapsulationKey, EncapsulatedSecret, EncapsulationKey, Kem, SharedSecret};

use zerocopy::FromBytes;

pub type P384EncapsulatedSecret = EncapsulatedSecret<{ P384::NENC }>;
pub type P384EncapsulationKey = EncapsulationKey<{ P384::NPK }>;
pub type P384DecapsulationKey = DecapsulationKey<{ P384::NSK }>;
pub type P384SharedSecret = SharedSecret<{ P384::NSECRET }>;

impl From<[u8; P384::NENC]> for P384EncapsulatedSecret {
    fn from(value: [u8; P384::NENC]) -> Self {
        Self { buf: value }
    }
}

impl From<[u8; P384::NPK]> for P384EncapsulationKey {
    fn from(value: [u8; P384::NPK]) -> Self {
        Self { buf: value }
    }
}

impl TryFrom<&P384EncapsulatedSecret> for Ecc384PubKey {
    type Error = CaliptraError;
    fn try_from(value: &P384EncapsulatedSecret) -> Result<Self, Self::Error> {
        let encaps_key: &[u8; P384::NENC] = value.as_ref();
        encaps_key.try_into()
    }
}

impl TryFrom<&P384EncapsulationKey> for Ecc384PubKey {
    type Error = CaliptraError;
    fn try_from(value: &P384EncapsulationKey) -> Result<Self, Self::Error> {
        let encaps_key: &[u8; P384::NPK] = value.as_ref();
        encaps_key.try_into()
    }
}

impl TryFrom<&[u8; P384::NPK]> for Ecc384PubKey {
    type Error = CaliptraError;
    fn try_from(value: &[u8; P384::NPK]) -> Result<Self, Self::Error> {
        // Skip compression encoding.
        let value = value
            .get(1..)
            .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_P384_ENCAP_KEY_DESERIALIZATION_FAIL)?;

        let (x, rem) = <[u8; Ecc384Scalar::bytes_size()]>::ref_from_prefix(value)
            .map_err(|_| CaliptraError::RUNTIME_DRIVER_HPKE_P384_ENCAP_KEY_DESERIALIZATION_FAIL)?;

        let y = <[u8; Ecc384Scalar::bytes_size()]>::ref_from_bytes(rem)
            .map_err(|_| CaliptraError::RUNTIME_DRIVER_HPKE_P384_ENCAP_KEY_DESERIALIZATION_FAIL)?;

        Ok(Ecc384PubKey {
            x: Array4x12::from(x),
            y: Array4x12::from(y),
        })
    }
}

impl From<Ecc384PubKey> for P384EncapsulationKey {
    fn from(value: Ecc384PubKey) -> Self {
        Self {
            buf: value.to_der(),
        }
    }
}

impl From<Ecc384Scalar> for P384DecapsulationKey {
    fn from(value: Ecc384Scalar) -> Self {
        Self { buf: value.into() }
    }
}

impl From<&P384DecapsulationKey> for Ecc384Scalar {
    fn from(value: &P384DecapsulationKey) -> Self {
        value.buf.into()
    }
}

#[derive(ZeroizeOnDrop)]
pub struct P384 {
    pub_key: Ecc384PubKey,
    priv_key: Ecc384Scalar,
}

impl P384 {
    pub const NSK: usize = 48;
    pub const NENC: usize = 97;
    pub const NPK: usize = 97;
    pub const NSECRET: usize = 48;
    pub const NDH: usize = 48;

    // Derive a key pair without first running through a KDF.
    // For use in Hybrid KEMs
    pub(super) fn derive_key_pair_raw(
        ctx: &mut P384KemContext<'_>,
        seed: &[u8; Self::NSK],
    ) -> CaliptraResult<Self> {
        let seed = Ecc384Scalar::from(seed);
        let mut priv_key = Ecc384Scalar::default();
        let pub_key = ctx.ecc.key_pair(
            Ecc384Seed::Array4x12(&seed),
            &Array4x12::default(),
            ctx.trng,
            Ecc384PrivKeyOut::Array4x12(&mut priv_key),
        )?;
        Ok(Self { pub_key, priv_key })
    }

    /// # SAFETY
    /// This function SHALL NOT be used in firmware
    ///
    /// This function is for side-loading a public & private key for validating against
    /// a test vector. This is because the hardware key generation mixes a nonce into the
    /// derivation, causing a different key pair to get generated from a known seed.
    pub unsafe fn load_raw_keys(pub_key: Ecc384PubKey, priv_key: Ecc384Scalar) -> Self {
        Self { pub_key, priv_key }
    }

    /// The `encap` operation with no KDF applied to the shared secret.
    /// Hybrid KEMs need the raw shared secret of the KEM algorithm.
    pub(super) fn raw_encap(
        &mut self,
        ctx: &mut P384KemContext<'_>,
        encaps_key: &P384EncapsulationKey,
    ) -> CaliptraResult<(P384EncapsulatedSecret, P384SharedSecret)> {
        // NOTE: The HPKE specification states that:
        // > For P-256, P-384 and P-521, senders and recipients MUST perform
        //   partial public key validation on all public key inputs, as defined
        //   in Section 5.6.2.3.4 of [keyagreement].
        //
        //  This check is performed by Caliptra's hardware. The `DH` operation
        //  will validate public keys as outlined in https://secg.org/sec1-v2.pdf.
        //
        //  Therefore this firmware DOES NOT do any public key validation.

        let enc = self.pub_key.to_der();
        let pk_r = Ecc384PubKey::try_from(encaps_key)?;

        let mut dh = Ecc384Scalar::default();
        ctx.ecc.ecdh(
            Ecc384PrivKeyIn::Array4x12(&self.priv_key),
            &pk_r,
            ctx.trng,
            Ecc384PrivKeyOut::Array4x12(&mut dh),
        )?;

        Ok((enc.into(), SharedSecret::<{ Hmac384::NH }>::from(dh)))
    }

    /// The `decap` operation with no KDF applied to the shared secret.
    /// Hybrid KEMs need the raw shared secret of the KEM algorithm.
    pub(super) fn raw_decap(
        &mut self,
        ctx: &mut P384KemContext<'_>,
        enc: &P384EncapsulatedSecret,
    ) -> CaliptraResult<P384SharedSecret> {
        // NOTE: The HPKE specification states that:
        // > For P-256, P-384 and P-521, senders and recipients MUST perform
        //   partial public key validation on all public key inputs, as defined
        //   in Section 5.6.2.3.4 of [keyagreement].
        //
        //  This check is performed by Caliptra's hardware. The `DH` operation
        //  will validate public keys as outlined in https://secg.org/sec1-v2.pdf.
        //
        //  Therefore this firmware DOES NOT do any public key validation.
        let pk_e = Ecc384PubKey::try_from(enc)?;
        let mut dh = Ecc384Scalar::default();
        ctx.ecc.ecdh(
            Ecc384PrivKeyIn::Array4x12(&self.priv_key),
            &pk_e,
            ctx.trng,
            Ecc384PrivKeyOut::Array4x12(&mut dh),
        )?;
        Ok(SharedSecret::<{ Hmac384::NH }>::from(dh))
    }
}

pub struct P384KemContext<'a> {
    trng: &'a mut Trng,
    ecc: &'a mut Ecc384,
    hmac: &'a mut Hmac,
}

impl<'a> P384KemContext<'a> {
    pub fn new(trng: &'a mut Trng, ecc: &'a mut Ecc384, hmac: &'a mut Hmac) -> Self {
        Self { trng, ecc, hmac }
    }
}

impl Kem<{ P384::NSK }, { P384::NENC }, { P384::NPK }, { P384::NSECRET }> for P384 {
    const KEM_ID: KemId = KemId::P_384;
    type EK = P384EncapsulationKey;
    type CONTEXT<'a> = P384KemContext<'a>;
    fn derive_key_pair(ctx: &mut Self::CONTEXT<'_>, ikm: &[u8; P384::NSK]) -> CaliptraResult<Self> {
        let suite_id = &CipherSuite::Kem(Self::KEM_ID);

        let mut kdf = Hmac384::new(ctx.hmac);
        let dkp_prk = {
            let dkp_prk =
                kdf.labeled_extract(ctx.trng, suite_id, &[], &b"dkp_prk"[..], &ikm[..])?;
            Array4x12::from(dkp_prk)
        };

        let mut okm = Array4x12::default();
        kdf.labeled_expand(
            ctx.trng,
            suite_id,
            HmacKey::Array4x12(&dkp_prk),
            &b"candidate"[..],
            // The spec uses a counter but the hardware does rejection sampling so we just set
            // `0` as the counter.
            &0u8.to_be_bytes(),
            L::new::<{ P384::NSK }>(),
            HmacTag::Array4x12(&mut okm),
        )?;

        let seed = Ecc384Scalar::from(okm);
        let mut priv_key = Ecc384Scalar::default();
        let pub_key = ctx.ecc.key_pair(
            Ecc384Seed::Array4x12(&seed),
            &Array4x12::default(),
            ctx.trng,
            Ecc384PrivKeyOut::Array4x12(&mut priv_key),
        )?;

        Ok(Self { pub_key, priv_key })
    }

    fn encap(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
        encaps_key: &Self::EK,
    ) -> CaliptraResult<(P384EncapsulatedSecret, P384SharedSecret)> {
        let (enc, shared_secret) = self.raw_encap(ctx, encaps_key)?;
        let mut kdf = Hmac384::new(ctx.hmac);
        let shared_secret = kdf.extract_and_expand(
            ctx.trng,
            CipherSuite::Kem(KemId::P_384),
            shared_secret.as_ref(),
            enc.as_ref(),
            encaps_key.as_ref(),
            L::new::<{ P384::NSECRET }>(),
        )?;
        Ok((enc, shared_secret))
    }

    fn decap(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
        enc: &P384EncapsulatedSecret,
    ) -> CaliptraResult<P384SharedSecret> {
        let shared_secret = self.raw_decap(ctx, enc)?;
        let mut kdf = Hmac384::new(ctx.hmac);
        let pk_rm = self.pub_key.to_der();
        kdf.extract_and_expand(
            ctx.trng,
            CipherSuite::Kem(KemId::P_384),
            shared_secret.as_ref(),
            enc.as_ref(),
            &pk_rm,
            L::new::<{ P384::NSECRET }>(),
        )
    }

    fn serialize_public_key(
        &mut self,
        _ctx: &mut Self::CONTEXT<'_>,
    ) -> CaliptraResult<P384EncapsulationKey> {
        Ok(self.pub_key.to_der().into())
    }
}
