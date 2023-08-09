// Licensed under the Apache-2.0 license

use caliptra_drivers::{Array4x8, CaliptraResult, Sha256};

use sha2::digest::block_buffer::Block;
use sha2::digest::consts::U64;

const SHA256_BLOCK_BYTE_SIZE: usize = 64;

#[derive(Default)]
pub struct Sha256SoftwareDriver {
    /// Hash
    hash: [u32; 8],
}

impl Sha256 for Sha256SoftwareDriver {
    unsafe fn zeroize() {
        // No hardware registers to zero
    }

    fn zeroize_internal(&mut self) {
        self.hash = Self::HASH_IV_256;
    }

    fn copy_digest_to_buf(&mut self, buf: &mut Array4x8) -> CaliptraResult<()> {
        *buf = Array4x8::from(self.hash);
        Ok(())
    }

    fn digest_block(
        &mut self,
        block: &[u8; SHA256_BLOCK_BYTE_SIZE],
        _first: bool,
    ) -> CaliptraResult<()> {
        let this_block = *Block::<U64>::from_slice(block);
        // Assumes little-endian
        sha2::compress256(&mut self.hash, &[this_block]);

        Ok(())
    }

    unsafe fn digest_blocks_raw(
        &mut self,
        mut ptr: *const [u32; 16],
        n_blocks: usize,
    ) -> CaliptraResult<Array4x8> {
        for _i in 0..n_blocks {
            let block = &*(ptr as *const [u8; SHA256_BLOCK_BYTE_SIZE]);
            let this_block = *Block::<U64>::from_slice(block);
            // Assumes little-endian
            sha2::compress256(&mut self.hash, &[this_block]);
            ptr = ptr.wrapping_add(1);
        }
        self.digest_partial_block(&[], n_blocks == 0, n_blocks * 64)?;
        Ok(Array4x8::from(self.hash))
    }
}

impl Sha256SoftwareDriver {
    /// SHA-256-256 Initial Hash Vectors
    #[rustfmt::skip]
    const HASH_IV_256 : [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    pub fn new() -> Self {
        Self {
            hash: Self::HASH_IV_256,
        }
    }
}
