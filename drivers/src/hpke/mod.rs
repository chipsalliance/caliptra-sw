// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};

pub use encryption_context::{EncryptionContext, Receiver, Sender};
use kdf::Hmac384;
use kem::{
    EncapsulatedSecret, EncapsulationKey, Kem, MlKem, MlKemContext, MlKemEncapsulatedSecret,
    MlKemEncapsulationKey, P384KemContext, P384,
};
use suites::HpkeCipherSuite;
use zerocopy::{transmute, FromBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Ecc384, Hmac, LEArray4x392, MlKem1024, Sha3, Trng};

pub mod aead;
mod encryption_context;
pub mod kdf;
pub mod kem;
pub mod suites;

#[derive(Clone, Zeroize, PartialEq)]
pub struct HpkeHandle(u32);

impl From<u32> for HpkeHandle {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<HpkeHandle> for u32 {
    fn from(value: HpkeHandle) -> Self {
        value.0
    }
}

/// Tracks the next HPKE handle id
#[derive(Default)]
pub struct HpkeCursor(u32);

impl HpkeCursor {
    /// Creates the next available HPKE handle.
    fn generate_handle(&mut self) -> HpkeHandle {
        // There are only a small number of active handles (certainly less than `u32::MAX` so it's
        // okay to wrap the handle count.
        self.0 = self.0.wrapping_add(1);
        HpkeHandle(self.0)
    }
}

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
    /// CipherSuite identifier for the HPKE implementation.
    const SUITE_ID: HpkeCipherSuite;

    /// The `KEM` type.
    type K: Kem<NSK, NENC, NPK, NSECRET>;

    /// The HPKE Driver Context.
    /// Useful for tracking types that cannot be borrowed for the lifetime of `Self`.
    type DriverContext<'a>;

    /// Establish a `Sender` `EncryptionContext`.
    /// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-5.1.1
    fn setup_base_s(
        &self,
        kem: &mut Self::K,
        ctx: &mut Self::DriverContext<'_>,
        pkr: &EncapsulationKey<NPK>,
        info: &[u8],
    ) -> CaliptraResult<(EncapsulatedSecret<NENC>, EncryptionContext<Sender>)>;

    /// Establish a `Receiver` `EncryptionContext`.
    /// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-5.1.1
    fn setup_base_r(
        &self,
        kem: &mut Self::K,
        ctx: &mut Self::DriverContext<'_>,
        enc: &EncapsulatedSecret<{ NENC }>,
        info: &[u8],
    ) -> CaliptraResult<EncryptionContext<Receiver>>;

    /// Serialize the encapsulation key
    fn serialize_public_key(
        &self,
        kem: &mut Self::K,
        ctx: &mut Self::DriverContext<'_>,
        out_key: &mut [u8; NPK],
    ) -> CaliptraResult<usize>;
}

#[derive(ZeroizeOnDrop)]
enum HpkePrivateKey {
    MlKem {
        handle: HpkeHandle,
        context: HpkeMlKemContext,
    },
    P384 {
        handle: HpkeHandle,
        context: HpkeP384Context,
    },
}

// High level struct for https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02.
pub struct HpkeContext {
    /// HPKE Private Keys
    priv_keys: [HpkePrivateKey; 2],
    /// Tracks the next unique HPKE handle
    /// Used by the rotate command to create new HPKE handles on rotation.
    handle_cursor: HpkeCursor,
}

impl HpkeContext {
    pub fn new(trng: &mut Trng) -> CaliptraResult<Self> {
        let mut handle_cursor = HpkeCursor::default();
        let ml_kem_key = HpkePrivateKey::MlKem {
            handle: handle_cursor.generate_handle(),
            context: HpkeMlKemContext::generate(trng)?,
        };
        let p384_key = HpkePrivateKey::P384 {
            handle: handle_cursor.generate_handle(),
            context: HpkeP384Context::generate(trng)?,
        };

        let priv_keys = [ml_kem_key, p384_key];
        Ok(Self {
            priv_keys,
            handle_cursor,
        })
    }

    pub fn iter(&self) -> HpkeContextIter<'_> {
        HpkeContextIter {
            ctx: self,
            index: 0,
        }
    }

    /// Searches for a matching `HpkeHandle`. If it is found a new HPKE seed is generated and a new
    /// handle is returned
    ///
    /// If `hpke_handle` does not match any existing `HpkeHandle`, `CaliptraError` is returned
    pub fn rotate(
        &mut self,
        trng: &mut Trng,
        hpke_handle: &HpkeHandle,
    ) -> CaliptraResult<HpkeHandle> {
        for handle in self.priv_keys.iter_mut() {
            match handle {
                HpkePrivateKey::MlKem {
                    ref mut handle,
                    ref mut context,
                } if handle == hpke_handle => {
                    *context = HpkeMlKemContext::generate(trng)?;
                    *handle = self.handle_cursor.generate_handle();
                    return Ok(handle.clone());
                }
                HpkePrivateKey::P384 {
                    ref mut handle,
                    ref mut context,
                } if handle == hpke_handle => {
                    *context = HpkeP384Context::generate(trng)?;
                    *handle = self.handle_cursor.generate_handle();
                    return Ok(handle.clone());
                }
                _ => (),
            }
        }
        Err(CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_HPKE_HANDLE)
    }

    /// Get HPKE public key
    #[allow(clippy::too_many_arguments)]
    pub fn get_pub_key(
        &mut self,
        sha: &mut Sha3,
        ml_kem: &mut MlKem1024,
        ecc: &mut crate::Ecc384,
        trng: &mut Trng,
        hmac: &mut Hmac,
        hpke_handle: &HpkeHandle,
        pub_out: &mut [u8],
    ) -> CaliptraResult<usize> {
        for key in self.priv_keys.iter() {
            match key {
                HpkePrivateKey::MlKem { handle, context } if handle == hpke_handle => {
                    let mut ctx = MlKemContext::new(trng, sha, ml_kem);
                    let mut kem = MlKem::derive_key_pair(&mut ctx, context.as_ref())?;
                    let pub_out = pub_out
                        .get_mut(..MlKem::NPK)
                        .and_then(|pub_out| <[u8; MlKem::NPK]>::mut_from_bytes(pub_out).ok())
                        .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_INVALID_PUB_KEY_BUFFER_SIZE)?;
                    let mut ctx = HpkeMlKemDrivers::new(trng, sha, hmac, ml_kem);
                    return context.serialize_public_key(&mut kem, &mut ctx, pub_out);
                }
                HpkePrivateKey::P384 { handle, context } if handle == hpke_handle => {
                    let mut ctx = P384KemContext::new(trng, ecc, hmac);
                    let mut kem = P384::derive_key_pair(&mut ctx, context.as_ref())?;
                    let pub_out = pub_out
                        .get_mut(..kem::P384::NPK)
                        .and_then(|pub_out| <[u8; kem::P384::NPK]>::mut_from_bytes(pub_out).ok())
                        .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_INVALID_PUB_KEY_BUFFER_SIZE)?;
                    let mut ctx = HpkeP384DriverContext::new(trng, ecc, hmac);
                    return context.serialize_public_key(&mut kem, &mut ctx, pub_out);
                }
                _ => (),
            }
        }
        Err(CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_HPKE_HANDLE)
    }

    /// Get HPKE Cipher Suite
    pub fn get_cipher_suite(
        &mut self,
        hpke_handle: &HpkeHandle,
    ) -> CaliptraResult<HpkeCipherSuite> {
        for key in self.priv_keys.iter() {
            match key {
                HpkePrivateKey::MlKem { handle, .. } if handle == hpke_handle => {
                    return Ok(HpkeCipherSuite::ML_KEM_1024);
                }
                HpkePrivateKey::P384 { handle, .. } if handle == hpke_handle => {
                    return Ok(HpkeCipherSuite::P_384);
                }
                _ => (),
            }
        }
        Err(CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_HPKE_HANDLE)
    }

    /// Decap encapsulated data
    ///
    /// Performs a `decap` operation and returns a context that can open encrypted messages
    #[allow(clippy::too_many_arguments)]
    pub fn decap(
        &mut self,
        sha: &mut Sha3,
        ml_kem: &mut MlKem1024,
        ecc: &mut Ecc384,
        hmac: &mut Hmac,
        trng: &mut Trng,
        hpke_handle: &HpkeHandle,
        enc: &[u8],
        info: &[u8],
    ) -> CaliptraResult<EncryptionContext<Receiver>> {
        for key in self.priv_keys.iter() {
            match key {
                HpkePrivateKey::MlKem { handle, context } if handle == hpke_handle => {
                    let enc = enc
                        .get(..MlKem::NENC)
                        .and_then(|enc| MlKemEncapsulatedSecret::ref_from_bytes(enc).ok())
                        .ok_or(CaliptraError::RUNTIME_OCP_LOCK_DESERIALIZE_ENC_FAILURE)?;

                    let mut ctx = MlKemContext::new(trng, sha, ml_kem);
                    let mut kem = MlKem::derive_key_pair(&mut ctx, context.as_ref())?;

                    let mut ctx = HpkeMlKemDrivers::new(trng, sha, hmac, ml_kem);
                    return context.setup_base_r(&mut kem, &mut ctx, enc, info);
                }
                HpkePrivateKey::P384 { handle, context } if handle == hpke_handle => {
                    let enc = enc
                        .get(..kem::P384::NENC)
                        .and_then(|enc| kem::P384EncapsulatedSecret::ref_from_bytes(enc).ok())
                        .ok_or(CaliptraError::RUNTIME_OCP_LOCK_DESERIALIZE_ENC_FAILURE)?;
                    let mut ctx = P384KemContext::new(trng, ecc, hmac);
                    let mut kem = P384::derive_key_pair(&mut ctx, context.as_ref())?;

                    let mut ctx = HpkeP384DriverContext::new(trng, ecc, hmac);
                    return context.setup_base_r(&mut kem, &mut ctx, enc, info);
                }
                _ => (),
            }
        }
        Err(CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_HPKE_HANDLE)
    }
}

pub struct HpkeContextIter<'a> {
    ctx: &'a HpkeContext,
    index: usize,
}

impl Iterator for HpkeContextIter<'_> {
    type Item = (HpkeHandle, HpkeCipherSuite);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.ctx.priv_keys.get(self.index);
        let item = match key {
            Some(HpkePrivateKey::MlKem { handle, .. }) => {
                Some((handle.clone(), HpkeCipherSuite::ML_KEM_1024))
            }
            Some(HpkePrivateKey::P384 { handle, .. }) => {
                Some((handle.clone(), HpkeCipherSuite::P_384))
            }
            _ => None,
        };
        self.index += 1;
        item
    }
}

pub struct HpkeMlKemDrivers<'a> {
    sha: &'a mut Sha3,
    ml_kem: &'a mut MlKem1024,
    trng: &'a mut Trng,
    hmac: &'a mut Hmac,
}

impl<'a> HpkeMlKemDrivers<'a> {
    pub fn new(
        trng: &'a mut Trng,
        sha: &'a mut Sha3,
        hmac: &'a mut Hmac,
        ml_kem: &'a mut MlKem1024,
    ) -> Self {
        Self {
            sha,
            ml_kem,
            trng,
            hmac,
        }
    }
}

/// ML-KEM 1024 HPKE Context
#[derive(ZeroizeOnDrop)]
pub struct HpkeMlKemContext {
    /// Secret string used to derive the ML-KEM key pair.
    ikm: [u8; MlKem::NSK],
}

impl AsRef<[u8; MlKem::NSK]> for HpkeMlKemContext {
    fn as_ref(&self) -> &[u8; MlKem::NSK] {
        &self.ikm
    }
}

impl HpkeMlKemContext {
    /// Create a new `HpkeMlKemContext` context. Seeds the `ikm` secret using `trng`.
    pub fn generate(trng: &mut Trng) -> CaliptraResult<Self> {
        let rnd = trng.generate16()?;
        Ok(Self {
            ikm: transmute!(rnd),
        })
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
    type K = MlKem;
    type DriverContext<'a> = HpkeMlKemDrivers<'a>;
    const SUITE_ID: HpkeCipherSuite = HpkeCipherSuite::ML_KEM_1024;

    fn setup_base_s(
        &self,
        kem: &mut Self::K,
        ctx: &mut Self::DriverContext<'_>,
        pkr: &MlKemEncapsulationKey,
        info: &[u8],
    ) -> CaliptraResult<(MlKemEncapsulatedSecret, EncryptionContext<Sender>)> {
        let pkr = LEArray4x392::ref_from_bytes(pkr.as_ref())
            .map_err(|_| CaliptraError::RUNTIME_DRIVER_HPKE_ML_KEM_PKR_DESERIALIZATION_FAIL)?;

        let mut kem_ctx = MlKemContext::new(ctx.trng, ctx.sha, ctx.ml_kem);
        let (enc, shared_secret) = kem.encap(&mut kem_ctx, pkr)?;

        let mut kdf = Hmac384::new(ctx.hmac);
        let (key, base_nonce, _exporter_secret) = kdf.combine_secrets::<{ MlKem::NSECRET }>(
            ctx.trng,
            Self::SUITE_ID,
            shared_secret,
            info,
        )?;
        let ctx = EncryptionContext::<Sender>::new_sender(key, base_nonce);
        Ok((enc, ctx))
    }

    fn setup_base_r(
        &self,
        kem: &mut Self::K,
        ctx: &mut Self::DriverContext<'_>,
        enc: &MlKemEncapsulatedSecret,
        info: &[u8],
    ) -> CaliptraResult<EncryptionContext<Receiver>> {
        let mut kem_ctx = MlKemContext::new(ctx.trng, ctx.sha, ctx.ml_kem);
        let shared_secret = kem.decap(&mut kem_ctx, enc)?;

        let mut kdf = Hmac384::new(ctx.hmac);
        let (key, base_nonce, _exporter_secret) = kdf.combine_secrets::<{ MlKem::NSECRET }>(
            ctx.trng,
            Self::SUITE_ID,
            shared_secret,
            info,
        )?;
        let ctx = EncryptionContext::<Receiver>::new_receiver(key, base_nonce);
        Ok(ctx)
    }

    fn serialize_public_key(
        &self,
        kem: &mut Self::K,
        ctx: &mut Self::DriverContext<'_>,
        out_key: &mut [u8; MlKem::NPK],
    ) -> CaliptraResult<usize> {
        let mut ctx = MlKemContext::new(ctx.trng, ctx.sha, ctx.ml_kem);
        let ek = kem.serialize_public_key(&mut ctx)?;
        out_key.clone_from_slice(ek.as_ref());
        Ok(MlKem::NPK)
    }
}

/// P-384 HPKE Context
#[derive(ZeroizeOnDrop)]
pub struct HpkeP384Context {
    /// Secret string used to derive the P-384 key pair.
    ikm: [u8; P384::NSK],
}

impl AsRef<[u8; P384::NSK]> for HpkeP384Context {
    fn as_ref(&self) -> &[u8; P384::NSK] {
        &self.ikm
    }
}

impl HpkeP384Context {
    /// Create a new `HpkeP384Context` context. Seeds the `ikm` secret using `trng`.
    pub fn generate(trng: &mut Trng) -> CaliptraResult<Self> {
        let rnd = trng.generate()?;
        Ok(Self {
            ikm: transmute!(rnd),
        })
    }
}

pub struct HpkeP384DriverContext<'a> {
    trng: &'a mut Trng,
    ecc: &'a mut Ecc384,
    hmac: &'a mut Hmac,
}

impl<'a> HpkeP384DriverContext<'a> {
    /// Create a new instance of `HpkeP384DriverContext`
    pub fn new(trng: &'a mut Trng, ecc: &'a mut Ecc384, hmac: &'a mut Hmac) -> Self {
        Self { trng, ecc, hmac }
    }
}

impl Hpke<{ kem::P384::NSK }, { kem::P384::NENC }, { kem::P384::NPK }, { kem::P384::NSECRET }>
    for HpkeP384Context
{
    type K = kem::P384;
    type DriverContext<'a> = HpkeP384DriverContext<'a>;
    const SUITE_ID: HpkeCipherSuite = HpkeCipherSuite::P_384;

    fn setup_base_s(
        &self,
        kem: &mut Self::K,
        ctx: &mut Self::DriverContext<'_>,
        pkr: &kem::P384EncapsulationKey,
        info: &[u8],
    ) -> CaliptraResult<(kem::P384EncapsulatedSecret, EncryptionContext<Sender>)> {
        let mut kem_ctx = P384KemContext::new(ctx.trng, ctx.ecc, ctx.hmac);
        let (enc, shared_secret) = kem.encap(&mut kem_ctx, pkr)?;

        let mut kdf = Hmac384::new(ctx.hmac);
        let (key, base_nonce, _exporter_secret) = kdf.combine_secrets::<{ kem::P384::NSECRET }>(
            ctx.trng,
            Self::SUITE_ID,
            shared_secret,
            info,
        )?;
        let ctx = EncryptionContext::<Sender>::new_sender(key, base_nonce);
        Ok((enc, ctx))
    }

    fn setup_base_r(
        &self,
        kem: &mut Self::K,
        ctx: &mut Self::DriverContext<'_>,
        enc: &kem::P384EncapsulatedSecret,
        info: &[u8],
    ) -> CaliptraResult<EncryptionContext<Receiver>> {
        let mut kem_ctx = P384KemContext::new(ctx.trng, ctx.ecc, ctx.hmac);
        let shared_secret = kem.decap(&mut kem_ctx, enc)?;

        let mut kdf = Hmac384::new(ctx.hmac);
        let (key, base_nonce, _exporter_secret) = kdf.combine_secrets::<{ kem::P384::NSECRET }>(
            ctx.trng,
            Self::SUITE_ID,
            shared_secret,
            info,
        )?;
        let ctx = EncryptionContext::<Receiver>::new_receiver(key, base_nonce);
        Ok(ctx)
    }

    fn serialize_public_key(
        &self,
        kem: &mut Self::K,
        ctx: &mut Self::DriverContext<'_>,
        out_key: &mut [u8; kem::P384::NPK],
    ) -> CaliptraResult<usize> {
        let mut kem_ctx = P384KemContext::new(ctx.trng, ctx.ecc, ctx.hmac);
        let ek = kem.serialize_public_key(&mut kem_ctx)?;
        out_key.clone_from_slice(ek.as_ref());
        Ok(kem::P384::NPK)
    }
}
