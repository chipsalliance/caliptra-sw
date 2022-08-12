/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256.rs

Abstract:

    File contains implementation of Secure Hash 256 Algorithm (SHA-256 )

--*/

use sha2::digest::block_buffer::Block;
use sha2::digest::consts::U64;

/// SHA-256 Mode
#[derive(Debug, Copy, Clone)]
pub enum Sha256Mode {
    Sha224,
    Sha256,
}

/// SHA-256
pub struct Sha256 {
    /// Hash
    hash: [u32; 8],

    /// SHA 256 Mode
    mode: Sha256Mode,
}

impl Sha256 {
    /// SHA-256 Block Size
    pub const BLOCK_SIZE: usize = 64;

    /// SHA-256 Hash Size
    pub const HASH_SIZE: usize = 32;

    /// SHA-256-224 Initial Hash Vectors
    #[cfg_attr(rustfmt, rustfmt_skip)]
    const HASH_IV_224: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
    ];

    /// SHA-256-256 Initial Hash Vectors
    #[cfg_attr(rustfmt, rustfmt_skip)]
    const HASH_IV_256 : [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    /// Create a new instance of Secure Hash Algorithm object
    ///
    /// # Arguments
    ///
    /// * `mode` - Mode of the SHA Operation
    pub fn new(mode: Sha256Mode) -> Self {
        Self {
            hash: Self::hash_iv(mode),
            mode,
        }
    }

    /// Reset the state
    pub fn reset(&mut self, mode: Sha256Mode) {
        self.mode = mode;
        self.hash = Self::hash_iv(self.mode)
    }

    /// Update the hash
    ///
    /// # Arguments
    ///
    /// * `block` - Block to compress
    pub fn update(&mut self, block: &[u8; Self::BLOCK_SIZE]) {
        let block = *Block::<U64>::from_slice(block);
        sha2::compress256(&mut self.hash, &[block]);
    }

    /// Retrieve the hash
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash to copy
    pub fn hash(&mut self, hash: &mut [u8]) {
        self.hash
            .iter()
            .flat_map(|i| i.to_be_bytes())
            .take(self.hash_len())
            .zip(hash)
            .for_each(|(src, dest)| *dest = src);
    }

    /// Get the length of the hash
    pub fn hash_len(&self) -> usize {
        match self.mode {
            Sha256Mode::Sha224 => 28,
            Sha256Mode::Sha256 => 32,
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
    fn hash_iv(mode: Sha256Mode) -> [u32; 8] {
        match mode {
            Sha256Mode::Sha224 => Self::HASH_IV_224,
            Sha256Mode::Sha256 => Self::HASH_IV_256,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const SHA_256_TEST_BLOCK: [u8; 64] = [
        0x61, 0x62, 0x63, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
    ];

    #[test]
    fn test_sha256_224() {
        let mut sha = Sha256::new(Sha256Mode::Sha224);
        sha.update(&SHA_256_TEST_BLOCK);

        #[cfg_attr(rustfmt, rustfmt_skip)]
            let expected: [u8; 28] = [
            0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
            0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
        ];

        let mut hash = [0u8; 28];
        sha.hash(&mut hash);

        assert_eq!(&hash, &expected);
    }

    #[test]
    fn test_sha256_256() {
        let mut sha = Sha256::new(Sha256Mode::Sha256);
        sha.update(&SHA_256_TEST_BLOCK);

        #[cfg_attr(rustfmt, rustfmt_skip)]
            let expected: [u8; 32] = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x1, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
            0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x0, 0x15, 0xAD,
        ];

        let mut hash = [0u8; 32];
        sha.hash(&mut hash);

        assert_eq!(&hash, &expected);
    }
}
