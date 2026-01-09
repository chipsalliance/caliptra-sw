// Licensed under the Apache-2.0 license

use caliptra_error::CaliptraResult;
use zeroize::ZeroizeOnDrop;

mod mlkem;

pub use mlkem::*;

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::Trng;

use super::suites::KemIdExt;

// TODO(clundin): Leaving the trait in for now but I am not sure we really need it.

/// Implements KEM functionality for HPKE
pub trait Kem<const NSK: usize, const NENC: usize, const NPK: usize, const NSECRET: usize> {
    /// The extended Kem id, fed into the labeled derive function to expand `ikm`.
    const KEM_ID_EXT: KemIdExt;

    /// Derives a KEM keypair from the `ikm` seed.
    fn derive_key_pair(
        &mut self,
        ikm: &[u8; NSK],
    ) -> CaliptraResult<(EncapsulationKey<NPK>, DecapsulationKey<NSK>)>;

    /// Generates a shared secret key and associated ciphertext
    fn encap(
        &mut self,
        trng: &mut Trng,
        encaps_key: &EncapsulationKey<NPK>,
    ) -> CaliptraResult<(EncapsulatedSecret<NENC>, SharedSecret<NSECRET>)>;

    /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
    fn decap(
        &mut self,
        enc: &EncapsulatedSecret<NENC>,
        dk: &DecapsulationKey<NSK>,
    ) -> CaliptraResult<SharedSecret<NSECRET>>;
}

/// Shared Secret produced by `encap`.
pub struct SharedSecret<const NSECRET: usize> {
    buf: [u8; NSECRET],
}

impl<const NSECRET: usize> AsRef<[u8]> for SharedSecret<NSECRET> {
    fn as_ref(&self) -> &[u8] {
        &self.buf
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

/// Serialized ML-KEM Decap key
#[derive(ZeroizeOnDrop)]
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
