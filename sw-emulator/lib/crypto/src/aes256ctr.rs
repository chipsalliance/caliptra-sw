/*++

Licensed under the Apache-2.0 license.

File Name:

    aes256ctr.rs

Abstract:

    File contains implementation of AES-256 CTR algorithm

--*/

use crate::{AES_256_BLOCK_SIZE, AES_256_KEY_SIZE};
use aes::Aes256;
use cipher::{KeyIvInit, StreamCipherCore};

pub struct Aes256Ctr {
    cryptor: Ctr,
}

impl Default for Aes256Ctr {
    fn default() -> Self {
        Self::new(&[0u8; AES_256_IV_SIZE], &[0u8; AES_256_KEY_SIZE])
    }
}

const AES_256_IV_SIZE: usize = AES_256_BLOCK_SIZE;

type Ctr = ctr::CtrCore<Aes256, ctr::flavors::Ctr128BE>;

impl Aes256Ctr {
    pub fn new(iv: &[u8; AES_256_IV_SIZE], key: &[u8; AES_256_KEY_SIZE]) -> Self {
        Self {
            cryptor: Ctr::new(key.into(), iv.into()),
        }
    }

    /// Streaming mode: encrypt or decrypt a single block and return the output.
    pub fn crypt_block(&mut self, block: &[u8; AES_256_BLOCK_SIZE]) -> [u8; AES_256_BLOCK_SIZE] {
        let mut out_block = [(*block).into()];
        self.cryptor.apply_keystream_blocks(&mut out_block);
        out_block[0].into()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Aes256Ctr, AES_256_BLOCK_SIZE};

    #[test]
    fn test_encrypt_decrypt() {
        let mut ctr = Aes256Ctr::new(&[0u8; 16], &[0u8; 32]);

        let plaintext: [u8; 48] = [
            0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84,
            0x20, 0x87, 0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1,
            0xc4, 0xcb, 0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e,
            0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
        ];

        for pblock in plaintext.chunks_exact(AES_256_BLOCK_SIZE) {
            assert_eq!(pblock, ctr.crypt_block(&[0u8; AES_256_BLOCK_SIZE]));
        }
    }
}
