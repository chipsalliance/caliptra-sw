// Licensed under the Apache-2.0 license

use zerocopy::IntoBytes;
use zeroize::ZeroizeOnDrop;

use crate::{Array4x12, LEArray4x3, LEArray4x8};

#[derive(ZeroizeOnDrop)]
pub struct EncryptionKey {
    buf: LEArray4x8,
}

impl From<Array4x12> for EncryptionKey {
    fn from(value: Array4x12) -> Self {
        let mut buf = [0; Aes256GCM::NK];
        let value = <[u8; 48]>::from(value);
        buf.clone_from_slice(&value.as_bytes()[..Aes256GCM::NK]);
        Self { buf: buf.into() }
    }
}

impl AsRef<LEArray4x8> for EncryptionKey {
    fn as_ref(&self) -> &LEArray4x8 {
        &self.buf
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Nonce {
    buf: [u8; Aes256GCM::NN],
}

impl From<u64> for Nonce {
    fn from(value: u64) -> Self {
        // NOTE: `AES-256-GCM` has an NN of 12, so the Nonce is 12 bytes.
        // A u64 is 8 bytes. This implies that we need to left pad the created Nonce with 4
        // bytes.
        let value = value.to_be_bytes();
        let padding = Aes256GCM::NN.saturating_sub(value.len());

        let mut nonce = Self {
            buf: [0; Aes256GCM::NN],
        };
        nonce.buf[padding..].clone_from_slice(&value);
        nonce
    }
}

impl From<[u8; Aes256GCM::NN]> for Nonce {
    fn from(value: [u8; Aes256GCM::NN]) -> Self {
        Self { buf: value }
    }
}

impl From<Array4x12> for Nonce {
    fn from(value: Array4x12) -> Self {
        let mut buf = [0; Aes256GCM::NN];
        let value = <[u8; 48]>::from(value);
        buf.clone_from_slice(&value.as_bytes()[..Aes256GCM::NN]);
        Self { buf }
    }
}

impl From<Nonce> for LEArray4x3 {
    fn from(value: Nonce) -> Self {
        LEArray4x3::from(value.buf)
    }
}

impl From<Nonce> for [u8; Aes256GCM::NN] {
    fn from(value: Nonce) -> Self {
        value.buf
    }
}

impl Nonce {
    /// xor `self` with sequence and return a new `Nonce`.
    pub fn xor_with_sequence_count(&self, sequence: u64) -> Self {
        let mut nonce = Self::from(sequence);
        for (base, seq) in self.buf.iter().zip(nonce.buf.iter_mut()) {
            *seq ^= base;
        }
        nonce
    }
}

pub struct Aes256GCM;
impl Aes256GCM {
    /// NK: The length in bytes of a key for this algorithm.
    pub const NK: usize = 32;
    /// NN: The length in bytes of a nonce for this algorithm.
    pub const NN: usize = 12;
    /// NT: The length in bytes of the authentication tag for this algorithm.
    pub const NT: usize = 16;
}
