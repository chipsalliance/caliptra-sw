// Licensed under the Apache-2.0 license

use core::marker::PhantomData;

use caliptra_error::{CaliptraError, CaliptraResult};
use zeroize::ZeroizeOnDrop;

use crate::{Aes, AesGcmIv, AesKey, Array4x12, LEArray4x4, Trng};

use super::{
    aead::{Aes256GCM, EncryptionKey, Nonce},
    kdf::Hmac384,
};

/// The Encryption Context role
///
/// This trait is used to statically prevent mixing roles.
pub trait Role {}

/// An Encryption Context that can `seal` messages.
pub struct Sender;

/// An Encryption Context that can `open` messages.
pub struct Receiver;

impl Role for Sender {}
impl Role for Receiver {}

#[derive(ZeroizeOnDrop)]
pub struct ExporterSecret {
    buf: [u8; Hmac384::NH],
}

impl From<Array4x12> for ExporterSecret {
    fn from(value: Array4x12) -> Self {
        Self { buf: value.into() }
    }
}

impl From<[u8; Hmac384::NH]> for ExporterSecret {
    fn from(value: [u8; Hmac384::NH]) -> Self {
        Self { buf: value }
    }
}

/// Implements Encryption Context from https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-5
#[derive(ZeroizeOnDrop)]
pub struct EncryptionContext<R>
where
    R: Role,
{
    key: EncryptionKey,
    base_nonce: Nonce,
    sequence_number: u64,
    _role: PhantomData<R>,
}

impl<R> core::fmt::Debug for EncryptionContext<R>
where
    R: Role,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "EncryptionContext<R>")
    }
}

impl<R> EncryptionContext<R>
where
    R: Role,
{
    /// Increments the message sequence number.
    ///
    /// If the number of messages reaches 2 ^ 64 -1 this will overflow and cause an error.
    /// This is lower then the (1 << (8 * Aes256GCM::NN)) - 1 limit from the spec, but it is is
    /// simpler to store this information in a `u64` and it is unlikely that we reach
    /// this limit.
    ///
    /// Should this error occur, integrators should rotate the HPKE key pair by calling
    /// the `OCP_LOCK_ROTATE_HPKE_KEY` mailbox command.
    pub fn increment_sequence(&mut self) -> CaliptraResult<()> {
        let sequence = self
            .sequence_number
            .checked_add(1)
            .ok_or(CaliptraError::RUNTIME_DRIVER_HPKE_SEQ_EXHAUSTED)?;
        self.sequence_number = sequence;
        Ok(())
    }

    /// Compute HPKE Nonce.
    /// Ref: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-5.2
    pub fn compute_nonce(&self) -> Nonce {
        self.base_nonce
            .xor_with_sequence_count(self.sequence_number)
    }
}

impl EncryptionContext<Sender> {
    /// Create a new `Sender` `EncryptionContext`
    pub fn new_sender(key: EncryptionKey, base_nonce: Nonce) -> Self {
        Self {
            key,
            base_nonce,
            sequence_number: 0,
            _role: PhantomData,
        }
    }

    /// Encrypt a plaintext message
    pub fn seal(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> CaliptraResult<[u8; Aes256GCM::NT]> {
        let nonce = self.compute_nonce().into();
        let iv = AesGcmIv::Array(&nonce);
        let (_iv, tag) = aes.aes_256_gcm_encrypt(
            trng,
            iv,
            AesKey::Array(self.key.as_ref()),
            aad,
            pt,
            ct,
            Aes256GCM::NT,
        )?;
        self.increment_sequence()?;
        Ok(<[u8; Aes256GCM::NT]>::from(tag))
    }
}

impl EncryptionContext<Receiver> {
    /// Create a new `Receiver` `EncryptionContext`
    pub fn new_receiver(key: EncryptionKey, base_nonce: Nonce) -> Self {
        Self {
            key,
            base_nonce,
            sequence_number: 0,
            _role: PhantomData,
        }
    }

    /// Decrypt an encrypted message
    pub fn open(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        aad: &[u8],
        tag: &[u8; Aes256GCM::NT],
        ct: &[u8],
        pt: &mut [u8],
    ) -> CaliptraResult<()> {
        let tag = LEArray4x4::from(tag);
        let nonce = self.compute_nonce().into();
        aes.aes_256_gcm_decrypt(
            trng,
            &nonce,
            AesKey::Array(self.key.as_ref()),
            aad,
            ct,
            pt,
            &tag,
        )?;
        self.increment_sequence()?;
        Ok(())
    }
}
