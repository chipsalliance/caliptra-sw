// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};

use encryption_context::{EncryptionContext, Receiver, Sender};
use kdf::Hmac384;
use kem::{
    EncapsulatedSecret, EncapsulationKey, Kem, MlKem, MlKemEncapsulatedSecret,
    MlKemEncapsulationKey,
};
use suites::CipherSuite;
use zerocopy::{transmute, FromBytes, IntoBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{LEArray4x392, MlKem1024, Sha3, Trng};

mod aead;
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
    ) -> CaliptraResult<(EncapsulatedSecret<NENC>, EncryptionContext<Sender>)>;

    /// Establish a `Receiver` `EncryptionContext`.
    /// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-5.1.1
    fn setup_base_r(
        &self,
        kem: &mut Self::K<'_>,
        kdf: &mut Hmac384,
        trng: &mut Trng,
        enc: &EncapsulatedSecret<{ NENC }>,
        info: &[u8],
    ) -> CaliptraResult<EncryptionContext<Receiver>>;

    /// Serialize the encapsulation key
    fn serialize_public_key(
        &self,
        kem: &mut Self::K<'_>,
        out_key: &mut [u8; NPK],
    ) -> CaliptraResult<usize>;
}

#[derive(ZeroizeOnDrop)]
enum HpkePrivateKey {
    MlKem {
        handle: HpkeHandle,
        context: HpkeMlKemContext,
    },
}

// High level struct for https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02.
pub struct HpkeContext {
    /// HPKE Private Keys
    priv_keys: [HpkePrivateKey; 1],
    /// Tracks the next unique HPKE handle
    /// Used by the rotate command to create new HPKE handles on rotation.
    #[allow(unused)]
    handle_cursor: HpkeCursor,
}

impl HpkeContext {
    pub fn new(trng: &mut Trng) -> CaliptraResult<Self> {
        let mut handle_cursor = HpkeCursor::default();
        let hpke_key = HpkePrivateKey::MlKem {
            handle: handle_cursor.generate_handle(),
            context: HpkeMlKemContext::generate(trng)?,
        };

        let priv_keys = [hpke_key];
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
                _ => (),
            }
        }
        Err(CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_HPKE_HANDLE)
    }

    /// Get HPKE public key
    pub fn get_pub_key(
        &mut self,
        sha: &mut Sha3,
        ml_kem: &mut MlKem1024,
        hpke_handle: &HpkeHandle,
        pub_out: &mut [u8],
    ) -> CaliptraResult<usize> {
        for key in self.priv_keys.iter() {
            match key {
                HpkePrivateKey::MlKem { handle, context } if handle == hpke_handle => {
                    let mut ml_kem = MlKem::new(sha, ml_kem);
                    let pub_out = pub_out
                        .get_mut(..MlKem::NPK)
                        .and_then(|pub_out| <[u8; MlKem::NPK]>::mut_from_bytes(pub_out).ok())
                        .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_INVALID_PUB_KEY_BUFFER_SIZE)?;
                    return context.serialize_public_key(&mut ml_kem, pub_out);
                }
                _ => (),
            }
        }
        Err(CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_HPKE_HANDLE)
    }

    /// Get HPKE Cipher Suite
    pub fn get_cipher_suite(&mut self, hpke_handle: &HpkeHandle) -> CaliptraResult<CipherSuite> {
        for key in self.priv_keys.iter() {
            match key {
                HpkePrivateKey::MlKem { handle, .. } if handle == hpke_handle => {
                    return Ok(CipherSuite::ML_KEM_1024);
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
    type Item = (HpkeHandle, CipherSuite);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.ctx.priv_keys.get(self.index);
        let item = match key {
            Some(HpkePrivateKey::MlKem { handle, .. }) => {
                Some((handle.clone(), CipherSuite::ML_KEM_1024))
            }
            _ => None,
        };
        self.index += 1;
        item
    }
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
    type K<'k> = MlKem<'k>;
    const SUITE_ID: CipherSuite = CipherSuite::ML_KEM_1024;

    fn setup_base_s(
        &self,
        kem: &mut MlKem,
        kdf: &mut Hmac384,
        trng: &mut Trng,
        pkr: &MlKemEncapsulationKey,
        info: &[u8],
    ) -> CaliptraResult<(MlKemEncapsulatedSecret, EncryptionContext<Sender>)> {
        let pkr = LEArray4x392::ref_from_bytes(pkr.as_ref())
            .map_err(|_| CaliptraError::RUNTIME_DRIVER_HPKE_ML_KEM_PKR_DESERIALIZATION_FAIL)?;
        let (enc, shared_secret) = kem.encap(trng, pkr)?;
        let (key, base_nonce, _exporter_secret) =
            kdf.combine_secrets::<{ MlKem::NSECRET }>(trng, &Self::SUITE_ID, shared_secret, info)?;
        let ctx = EncryptionContext::<Sender>::new_sender(key, base_nonce);
        Ok((enc, ctx))
    }

    fn setup_base_r(
        &self,
        kem: &mut Self::K<'_>,
        kdf: &mut Hmac384,
        trng: &mut Trng,
        enc: &MlKemEncapsulatedSecret,
        info: &[u8],
    ) -> CaliptraResult<EncryptionContext<Receiver>> {
        let (_ek, dk) = kem.derive_key_pair(&self.ikm)?;
        let shared_secret = kem.decap(enc, &kem::MlKemDecapsulationKey::from(dk))?;
        let (key, base_nonce, _exporter_secret) =
            kdf.combine_secrets::<{ MlKem::NSECRET }>(trng, &Self::SUITE_ID, shared_secret, info)?;
        let ctx = EncryptionContext::<Receiver>::new_receiver(key, base_nonce);
        Ok(ctx)
    }

    fn serialize_public_key(
        &self,
        kem: &mut Self::K<'_>,
        out_key: &mut [u8; MlKem::NPK],
    ) -> CaliptraResult<usize> {
        let (ek, _dk) = kem.derive_key_pair(&self.ikm)?;
        let ek = <[u8; MlKem::NPK]>::ref_from_bytes(ek.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_DRIVER_HPKE_ML_KEM_ENCAP_KEY_SERIALIZATION_FAIL)?;
        out_key.clone_from_slice(ek);
        Ok(MlKem::NPK)
    }
}
