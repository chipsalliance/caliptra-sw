/*++

Licensed under the Apache-2.0 license.

File Name:

    sha512.rs

Abstract:

    File contains implementation of Secure Hash 512 Algorithm (SHA-512)

--*/

use crate::helpers::EndianessTransform;
use sha2::digest::block_buffer::Block;
use sha2::digest::consts::U128;

/// SHA-512 Mode
#[derive(Debug, Copy, Clone)]
pub enum Sha512Mode {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl From<Sha512Mode> for u32 {
    /// Converts to this type from the input type.
    fn from(sha_mode: Sha512Mode) -> Self {
        sha_mode as Self
    }
}

/// SHA-512
pub struct Sha512 {
    /// Hash
    hash: [u64; 8],

    /// SHA 512 Mode
    mode: Sha512Mode,

    /// Partial block to be processed
    partial_block: Vec<u8>,

    /// Number of full blocks processed to create hash
    blocks_processed: usize,
}

impl Sha512 {
    /// SHA-512 Block Size
    pub const BLOCK_SIZE: usize = 128;

    /// SHA-512 Hash Size
    pub const HASH_SIZE: usize = 64;

    /// SHA-512-224 Initial Hash Vectors
    const HASH_IV_224: [u64; 8] = [
        0x8c3d37c819544da2,
        0x73e1996689dcd4d6,
        0x1dfab7ae32ff9c82,
        0x679dd514582f9fcf,
        0x0f6d2b697bd44da8,
        0x77e36f7304c48942,
        0x3f9d85a86a1d36c8,
        0x1112e6ad91d692a1,
    ];

    /// SHA-512-256 Initial Hash Vectors
    const HASH_IV_256: [u64; 8] = [
        0x22312194fc2bf72c,
        0x9f555fa3c84c64c2,
        0x2393b86b6f53b151,
        0x963877195940eabd,
        0x96283ee2a88effe3,
        0xbe5e1e2553863992,
        0x2b0199fc2c85b8aa,
        0x0eb72ddc81c52ca2,
    ];

    /// SHA-384 Initial Hash Vectors
    const HASH_IV_384: [u64; 8] = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];

    /// SHA-512 Initial Hash Vectors
    const HASH_IV_512: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    /// Create a new instance of Secure Hash Algorithm object
    ///
    /// # Arguments
    ///
    /// * `mode` - Mode of the SHA Operation
    pub fn new(mode: Sha512Mode) -> Self {
        Self {
            hash: Self::hash_iv(mode),
            mode,
            partial_block: vec![],
            blocks_processed: 0,
        }
    }

    /// Reset the state
    pub fn reset(&mut self, mode: Sha512Mode) {
        self.mode = mode;
        self.hash = Self::hash_iv(self.mode);
        self.blocks_processed = 0;
    }

    /// Update the hash
    ///
    /// # Arguments
    ///
    /// * `block` - Block to compress. Each word in `block` is expected to
    ///   be little-endian
    pub fn update(&mut self, block: &[u8; Self::BLOCK_SIZE]) {
        let mut block = *Block::<U128>::from_slice(block);
        block.to_big_endian();

        sha2::compress512(&mut self.hash, &[block]);
        self.blocks_processed += 1;
    }

    /// Update the hash with an arbitrary number of bytes
    ///
    /// `bytes` is expected to be big-endian data.
    /// `dlen` may be specified when `bytes` can have undesired padding.
    /// `dlen` is expected to be the total number of bytes to hash.
    pub fn update_bytes(&mut self, bytes: &[u8], dlen: Option<u32>) {
        self.partial_block.extend_from_slice(bytes);

        let total_received_bytes =
            self.blocks_processed * Self::BLOCK_SIZE + self.partial_block.len();
        if let Some(dlen) = dlen {
            if total_received_bytes > dlen as usize {
                // TODO: can panic if `update_bytes` is used wrong
                //       (e.g. calling `update_bytes` with a dlen that would remove more bytes than BLOCK_SIZE)
                let to_remove =
                    (self.partial_block.len() - (total_received_bytes - dlen as usize))..;
                self.partial_block.drain(to_remove);
            }
        }

        while self.partial_block.len() >= Self::BLOCK_SIZE {
            // Safe to unwrap becasue slice is guaranteed to be correct size
            self.partial_block[..Self::BLOCK_SIZE].to_little_endian();
            self.update(&self.partial_block[..Self::BLOCK_SIZE].try_into().unwrap());
            self.partial_block.drain(..Self::BLOCK_SIZE);
        }
    }

    /// Finalize the hash by adding padding
    pub fn finalize(&mut self, dlen: u32) {
        // Check if dlen is less than the amount of data streamed
        // TODO: What to do if dlen is less than the blocks we've already processed?
        let bytes_of_blocks = self.blocks_processed * Self::BLOCK_SIZE;
        let partial = if (dlen as usize) < bytes_of_blocks + self.partial_block.len() {
            (dlen as usize) - bytes_of_blocks
        } else {
            self.partial_block.len()
        };

        let msg_len = (self.blocks_processed * Self::BLOCK_SIZE) + partial;
        self.partial_block.resize(partial, 0);

        self.partial_block.push(0b1000_0000);
        let zeros: usize = Self::BLOCK_SIZE - ((msg_len + 1 + 16) % 128);
        self.partial_block.extend_from_slice(&vec![0u8; zeros]);

        // Add bit length of hashed data
        self.partial_block
            .extend_from_slice(&((msg_len * 8) as u128).to_be_bytes());

        // update function expects little endian words
        self.partial_block.to_little_endian();

        while self.partial_block.len() >= Self::BLOCK_SIZE {
            // Safe to unwrap becasue slice is guaranteed to be correct size
            self.update(&self.partial_block[..Self::BLOCK_SIZE].try_into().unwrap());
            self.partial_block.drain(..Self::BLOCK_SIZE);
        }
    }

    /// Retrieve the hash
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash to copy
    pub fn copy_hash(&self, hash: &mut [u8]) {
        // Return the hash as a list of big-endian DWORDs.
        let mut hash_be: [u64; 8] = self.hash;
        hash_be.to_big_endian();

        hash_be
            .iter()
            .flat_map(|i| i.to_be_bytes())
            .take(std::cmp::min(hash.len(), Self::HASH_SIZE))
            .zip(hash)
            .for_each(|(src, dest)| *dest = src);
    }

    /// Get the length of the hash
    pub fn hash_len(&self) -> usize {
        match self.mode {
            Sha512Mode::Sha224 => 28,
            Sha512Mode::Sha256 => 32,
            Sha512Mode::Sha384 => 48,
            Sha512Mode::Sha512 => 64,
        }
    }

    /// Retrieve the hash initialization vector for specified SHA mode
    ///
    /// # Arguments
    ///
    /// * `mode` - Mode of the SHA Operation
    ///
    /// # Returns
    ///
    /// * `[u64; 8]` - The initialization vector
    fn hash_iv(mode: Sha512Mode) -> [u64; 8] {
        match mode {
            Sha512Mode::Sha224 => Self::HASH_IV_224,
            Sha512Mode::Sha256 => Self::HASH_IV_256,
            Sha512Mode::Sha384 => Self::HASH_IV_384,
            Sha512Mode::Sha512 => Self::HASH_IV_512,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_512_TEST_BLOCK: [u8; 128] = [
        0x61, 0x62, 0x63, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
    ];

    #[test]
    fn test_sha512_224() {
        let mut sha_512_test_block_var = SHA_512_TEST_BLOCK;
        sha_512_test_block_var.to_big_endian();

        let mut sha = Sha512::new(Sha512Mode::Sha224);
        sha.update(&sha_512_test_block_var);

        let expected: [u8; 28] = [
            0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54, 0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08,
            0x42, 0xE2, 0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4, 0x3E, 0x89, 0x24, 0xAA,
        ];

        let mut hash = [0u8; 28];
        sha.copy_hash(&mut hash);
        hash.to_little_endian();
        assert_eq!(&hash, &expected);
    }

    #[test]
    fn test_sha512_256() {
        let mut sha_512_test_block_var = SHA_512_TEST_BLOCK;
        sha_512_test_block_var.to_big_endian();

        let mut sha = Sha512::new(Sha512Mode::Sha256);
        sha.update(&sha_512_test_block_var);

        let expected: [u8; 32] = [
            0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9, 0x9B, 0x2E, 0x29, 0xB7, 0x6B, 0x4C,
            0x7D, 0xAB, 0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC, 0x6D, 0x46, 0xE0, 0xE2, 0xF1, 0x31,
            0x07, 0xE7, 0xAF, 0x23,
        ];

        let mut hash = [0u8; 32];
        sha.copy_hash(&mut hash);
        hash.to_little_endian();

        assert_eq!(&hash, &expected);
    }

    #[test]
    fn test_sha384() {
        let mut sha_512_test_block_var = SHA_512_TEST_BLOCK;
        sha_512_test_block_var.to_big_endian();

        let mut sha = Sha512::new(Sha512Mode::Sha384);
        sha.update(&sha_512_test_block_var);

        let expected: [u8; 48] = [
            0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6,
            0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A,
            0x43, 0xFF, 0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA,
            0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
        ];

        let mut hash = [0u8; 48];
        sha.copy_hash(&mut hash);
        hash.to_little_endian();

        assert_eq!(&hash, &expected);
    }

    #[test]
    fn test_finalize_sha384() {
        let mut sha = Sha512::new(Sha512Mode::Sha384);
        sha.update_bytes(&SHA_512_TEST_BLOCK, None);
        sha.finalize(128);

        let expected: [u8; 48] = [
            0x3e, 0x16, 0x50, 0xca, 0x72, 0x6e, 0x44, 0x7e, 0xca, 0xdf, 0x8f, 0xa9, 0xe5, 0xd2,
            0xb9, 0x81, 0x02, 0x9d, 0x5a, 0x76, 0xfc, 0x2c, 0x68, 0xa9, 0xdb, 0x34, 0x1e, 0xa1,
            0x3d, 0x01, 0xc7, 0xff, 0x7e, 0x82, 0x7f, 0x0f, 0x6a, 0x62, 0xde, 0x5a, 0x6f, 0xa3,
            0x2f, 0xcd, 0xa2, 0x3e, 0xb8, 0x3b,
        ];

        let mut hash = [0u8; 48];
        sha.copy_hash(&mut hash);
        hash.to_little_endian();

        assert_eq!(&hash, &expected);
    }

    #[test]
    fn test_finalize_127byte_sha384() {
        let mut sha = Sha512::new(Sha512Mode::Sha384);
        sha.update_bytes(&SHA_512_TEST_BLOCK, Some(127));
        sha.finalize(127);

        let expected: [u8; 48] = [
            0x4e, 0x12, 0xac, 0x25, 0xbf, 0xad, 0xf7, 0x25, 0x5c, 0xb7, 0x9a, 0x06, 0x3d, 0x83,
            0x45, 0x4f, 0x87, 0x9b, 0x89, 0x70, 0x13, 0x0f, 0xa4, 0xf1, 0xed, 0xcc, 0xbd, 0xee,
            0xd2, 0x22, 0x6e, 0x6d, 0xcd, 0x36, 0xcb, 0x11, 0x6c, 0x9b, 0x1a, 0x41, 0x6b, 0x4b,
            0xbb, 0x62, 0x45, 0xe1, 0x79, 0xfd,
        ];

        let mut hash = [0u8; 48];
        sha.copy_hash(&mut hash);
        hash.to_little_endian();

        assert_eq!(&hash, &expected);
    }

    #[test]
    fn test_sha512() {
        let mut sha_512_test_block_var = SHA_512_TEST_BLOCK;
        sha_512_test_block_var.to_big_endian();

        let mut sha = Sha512::new(Sha512Mode::Sha512);
        sha.update(&sha_512_test_block_var);

        let expected: [u8; 64] = [
            0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20,
            0x41, 0x31, 0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2, 0x0A, 0x9E, 0xEE, 0xE6,
            0x4B, 0x55, 0xD3, 0x9A, 0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA,
            0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD, 0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
            0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
        ];

        let mut hash = [0u8; 64];
        sha.copy_hash(&mut hash);
        hash.to_little_endian();

        assert_eq!(&hash, &expected);
    }
}
