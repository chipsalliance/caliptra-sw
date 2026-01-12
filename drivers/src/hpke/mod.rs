// Licensed under the Apache-2.0 license

use caliptra_error::CaliptraResult;

use encryption_context::{EncryptionContext, MlKemEncryptionContext, Receiver, Sender};
use kdf::Hmac384;
use kem::{
    EncapsulatedSecret, EncapsulationKey, Kem, MlKem, MlKemEncapsulatedSecret,
    MlKemEncapsulationKey,
};
use suites::CipherSuite;
use zerocopy::IntoBytes;
use zeroize::ZeroizeOnDrop;

use crate::Trng;

mod aead;
mod encryption_context;
pub mod kdf;
pub mod kem;
mod suites;

/// HPKE trait - A high level interface to
/// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02.
///
/// NOTE:
/// * Does not support `PSKs`.
/// * Only supports HMAC-SHA384-KDF as the KDF
/// * Only supports AES-256-GCM as the AEAD algorithm
pub trait Hpke<
    // Length of bytes of an encoded private key for the KEM.
    const NSK: usize,
    // Length of bytes of an encapsulated secret produced by the KEM.
    const NENC: usize,
    // Length of bytes of an encoded public key for the KEM.
    const NPK: usize,
    // Length in bytes of a KEM shared secret produced by the KEM.
    const NSECRET: usize,
>
{
    /// The `KEM` type.
    type K<'k>: Kem<NSK, NENC, NPK, NSECRET>;
    /// CipherSuite identifier for the HPKE implementation.
    const SUITE_ID: CipherSuite;

    /// Establish a `Sender` `EncryptionContext`.
    /// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-5.1.1
    fn setup_base_s(
        &self,
        kem: &mut Self::K<'_>,
        kdf: &mut Hmac384,
        trng: &mut Trng,
        pkr: &EncapsulationKey<NPK>,
        info: &[u8],
    ) -> CaliptraResult<(
        EncapsulatedSecret<NENC>,
        EncryptionContext<Sender, NSK, NENC, NPK, NSECRET>,
    )>;

    /// Establish a `Receiver` `EncryptionContext`.
    /// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-5.1.1
    fn setup_base_r(
        &self,
        kem: &mut Self::K<'_>,
        kdf: &mut Hmac384,
        trng: &mut Trng,
        enc: &EncapsulatedSecret<{ MlKem::NENC }>,
        info: &[u8],
    ) -> CaliptraResult<EncryptionContext<Receiver, NSK, NENC, NPK, NSECRET>>;

    /// Serialize the encapsulation key
    fn serialize_public_key(&self, kem: &mut Self::K<'_>) -> CaliptraResult<EncapsulationKey<NPK>>;
}

/// ML-KEM 1024 HPKE Context
#[derive(ZeroizeOnDrop)]
pub struct HpkeMlKemContext {
    /// Secret string used to derive the ML-KEM key pair.
    ikm: [u8; MlKem::NSK],
}

impl HpkeMlKemContext {
    /// Create a new `HpkeMlKemContext` context. Seeds the `ikm` secret using `trng`.
    pub fn generate(trng: &mut Trng) -> CaliptraResult<Self> {
        let rnd = trng.generate16()?;
        let mut ikm = [0; MlKem::NSK];
        ikm.clone_from_slice(rnd.as_bytes());
        Ok(Self { ikm })
    }

    /// # SAFETY
    /// This function is meant for testing against the HPKE ML-KEM-1024 test vectors.
    /// You should use `generate` instead.
    pub unsafe fn from_seed(ikm: [u8; MlKem::NSK]) -> Self {
        Self { ikm }
    }
}

impl Hpke<{ MlKem::NSK }, { MlKem::NENC }, { MlKem::NPK }, { MlKem::NSECRET }>
    for HpkeMlKemContext
{
    type K<'k> = MlKem<'k>;
    const SUITE_ID: CipherSuite = CipherSuite::ML_KEM_1024;

    fn setup_base_s(
        &self,
        kem: &mut MlKem,
        kdf: &mut Hmac384,
        trng: &mut Trng,
        pkr: &MlKemEncapsulationKey,
        info: &[u8],
    ) -> CaliptraResult<(MlKemEncapsulatedSecret, MlKemEncryptionContext<Sender>)> {
        let (enc, shared_secret) = kem.encap(trng, pkr)?;
        let (key, base_nonce, _exporter_secret) =
            kdf.combine_secrets::<{ MlKem::NSECRET }>(trng, &Self::SUITE_ID, shared_secret, info)?;
        let ctx = MlKemEncryptionContext::<Sender>::new_sender(key, base_nonce);
        Ok((enc, ctx))
    }

    fn setup_base_r(
        &self,
        kem: &mut Self::K<'_>,
        kdf: &mut Hmac384,
        trng: &mut Trng,
        enc: &MlKemEncapsulatedSecret,
        info: &[u8],
    ) -> CaliptraResult<MlKemEncryptionContext<Receiver>> {
        let (_ek, dk) = kem.derive_key_pair(&self.ikm)?;
        let shared_secret = kem.decap(enc, &kem::MlKemDecapsulationKey::from(dk))?;
        let (key, base_nonce, _exporter_secret) =
            kdf.combine_secrets::<{ MlKem::NSECRET }>(trng, &Self::SUITE_ID, shared_secret, info)?;
        let ctx = MlKemEncryptionContext::<Receiver>::new_receiver(key, base_nonce);
        Ok(ctx)
    }

    fn serialize_public_key(&self, kem: &mut Self::K<'_>) -> CaliptraResult<MlKemEncapsulationKey> {
        let (ek, _dk) = kem.derive_key_pair(&self.ikm)?;
        Ok(MlKemEncapsulationKey::from(ek))
    }
}

// High level struct for https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02.
// TODO(clundin): This will be generated on boot and used for rotating HPKE keys.
pub struct HpkeContext {
    // TODO(clundin): This will be used in a future PR as the HPKE driver is tied into the OCP LOCK
    // runtime implementation.
    #[allow(dead_code)]
    ml_kem: HpkeMlKemContext,
}
