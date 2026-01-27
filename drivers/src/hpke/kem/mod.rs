// Licensed under the Apache-2.0 license

use caliptra_error::CaliptraResult;
use zeroize::ZeroizeOnDrop;

mod mlkem;

pub use mlkem::*;

use zerocopy::{FromBytes, Immutable, KnownLayout};

use super::suites::KemId;
use crate::Array4x12;

use super::kdf::Hmac384;

// TODO(clundin): Leaving the trait in for now but I am not sure we really need it.
// TODO(clundin): Clean up copies & serialization + deserialize by making EK & DK internal or
// associated types.

/// Implements KEM functionality for HPKE
pub trait Kem<const NSK: usize, const NENC: usize, const NPK: usize, const NSECRET: usize> {
    /// The extended Kem id, fed into the labeled derive function to expand `ikm`.
    const KEM_ID: KemId;

    /// Holds a KEM specific GAT for objects whose lifetime must be shorter than the KEM
    /// implementer.
    type CONTEXT<'a>;

    /// The encapsulation key.
    type EK;

    /// Derives a KEM keypair from the `ikm` seed.
    fn derive_key_pair(ctx: &mut Self::CONTEXT<'_>, ikm: &[u8; NSK]) -> CaliptraResult<Self>
    where
        Self: Sized;

    /// Generates a shared secret key and associated ciphertext
    fn encap(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
        encaps_key: &Self::EK,
    ) -> CaliptraResult<(EncapsulatedSecret<NENC>, SharedSecret<NSECRET>)>;

    /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
    fn decap(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
        enc: &EncapsulatedSecret<NENC>,
    ) -> CaliptraResult<SharedSecret<NSECRET>>;

    /// Serializes the public key
    fn serialize_public_key(
        &mut self,
        ctx: &mut Self::CONTEXT<'_>,
    ) -> CaliptraResult<EncapsulationKey<NPK>>;
}

/// Shared Secret produced by `encap`.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret<const NSECRET: usize> {
    buf: [u8; NSECRET],
}

impl<const NSECRET: usize> AsRef<[u8]> for SharedSecret<NSECRET> {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl From<Array4x12> for SharedSecret<{ Hmac384::NH }> {
    fn from(value: Array4x12) -> Self {
        Self { buf: value.into() }
    }
}

/// Ciphertext produced by `encap`.
#[derive(Debug, PartialEq, KnownLayout, Immutable, FromBytes)]
pub struct EncapsulatedSecret<const NENC: usize> {
    buf: [u8; NENC],
}

/// Serialized ML-KEM Encap key
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub struct EncapsulationKey<const NPK: usize> {
    buf: [u8; NPK],
}

impl<const NPK: usize> From<&[u8; NPK]> for EncapsulationKey<NPK> {
    fn from(value: &[u8; NPK]) -> Self {
        Self { buf: *value }
    }
}

impl<const NPK: usize> AsRef<[u8]> for EncapsulationKey<NPK> {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl<const NPK: usize> AsRef<[u8; NPK]> for EncapsulationKey<NPK> {
    fn as_ref(&self) -> &[u8; NPK] {
        &self.buf
    }
}

/// Serialized Decap key
#[derive(Debug, ZeroizeOnDrop)]
pub struct DecapsulationKey<const NSK: usize> {
    buf: [u8; NSK],
}

impl<const NSK: usize> From<&[u8; NSK]> for DecapsulationKey<NSK> {
    fn from(value: &[u8; NSK]) -> Self {
        Self { buf: *value }
    }
}

impl<const NSK: usize> AsRef<[u8; NSK]> for DecapsulationKey<NSK> {
    fn as_ref(&self) -> &[u8; NSK] {
        &self.buf
    }
}
