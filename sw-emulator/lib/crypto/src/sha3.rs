/*++

Licensed under the Apache-2.0 license.

File Name:

    sha3.rs

Abstract:

    File contains implementation of Secure Hash 3 Algorithm (SHA-3)

--*/

// use crate::helpers::EndianessTransform;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Sha3Mode {
    SHA3 = 0x0,
    SHAKE = 0x1,
}

impl From<Sha3Mode> for u32 {
    /// Converts to this type from the input type.
    fn from(mode: Sha3Mode) -> Self {
        mode as Self
    }
}

impl From<u32> for Sha3Mode {
    /// Converts to this type from the input type.
    fn from(value: u32) -> Self {
        match value {
            0x0 => Sha3Mode::SHA3,
            0x1 => Sha3Mode::SHAKE,
            _ => panic!("Invalid mode"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Sha3Strength {
    L128 = 0x0,
    L224 = 0x1,
    L256 = 0x2,
    L384 = 0x3,
    L512 = 0x4,
}

impl From<Sha3Strength> for u32 {
    /// Converts to this type from the input type.
    fn from(strength: Sha3Strength) -> Self {
        strength as Self
    }
}

impl From<u32> for Sha3Strength {
    /// Converts to this type from the input type.
    fn from(value: u32) -> Self {
        match value {
            0x0 => Sha3Strength::L128,
            0x1 => Sha3Strength::L224,
            0x2 => Sha3Strength::L256,
            0x3 => Sha3Strength::L384,
            0x4 => Sha3Strength::L512,
            _ => panic!("Invalid strength"),
        }
    }
}

const DIGEST_SIZE: usize = 200;

/// SHA-3
pub struct Sha3 {
    /// Hasher
    hasher: Option<Shake256>,

    /// Output digest
    digest: [u8; DIGEST_SIZE],
}

impl Default for Sha3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3 {
    /// Create a new instance of Secure Hash Algorithm object
    ///
    /// # Arguments
    ///
    /// * `mode` - Mode of the SHA Operation
    /// * `strength` - Strength of SHA Operation
    pub fn new() -> Self {
        Self {
            hasher: None,
            digest: [0u8; DIGEST_SIZE],
        }
    }

    /// Set hashing algorithm.
    pub fn set_hasher(&mut self, mode: Sha3Mode, strength: Sha3Strength) {
        if mode != Sha3Mode::SHAKE || strength != Sha3Strength::L256 {
            todo!("Only SHAKE256 implemented currently");
        }

        self.hasher = Some(Shake256::default());
    }

    /// Write data to hasher.
    pub fn update(&mut self, data: &[u8]) -> bool {
        if let Some(ref mut hasher) = &mut self.hasher {
            hasher.update(data);
            return true;
        }

        false
    }

    /// Write hash to digest.
    pub fn finalize(&mut self) -> bool {
        if let Some(hasher) = &self.hasher {
            let mut reader = hasher.clone().finalize_xof();
            reader.read(&mut self.digest);
            return true;
        }

        false
    }

    pub fn digest(&self) -> [u8; DIGEST_SIZE] {
        self.digest
    }

    pub fn has_hasher(&self) -> bool {
        self.hasher.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_invalid_mode() {
        let mut sha3 = Sha3::new();
        sha3.set_hasher(Sha3Mode::SHA3, Sha3Strength::L256);
    }

    #[test]
    fn test_shake256() {
        let mut shake = Sha3::new();
        shake.set_hasher(Sha3Mode::SHAKE, Sha3Strength::L256);
        shake.update(b"abc");
        shake.finalize();

        assert!(shake.digest.iter().any(|n| *n != 0));
    }

    #[test]
    fn test_shake256_kat() {
        let mut shake = Sha3::new();
        shake.set_hasher(Sha3Mode::SHAKE, Sha3Strength::L256);
        shake.update(&[0xEF, 0xBE, 0xAD, 0xDE]);
        shake.finalize();

        let expected = [
            0x5e, 0xf7, 0xcc, 0xa6, 0x1e, 0xd4, 0x44, 0x74, 0xcc, 0x56, 0x82, 0x73, 0x7e, 0x25,
            0x75, 0xf8, 0xc5, 0x9a, 0x56, 0x5d, 0xa8, 0xab, 0x5b, 0x29, 0x44, 0x75, 0xb2, 0x6e,
            0x76, 0x79, 0x79, 0xe5, 0x4d, 0x0c, 0x37, 0x51, 0x0b, 0xb4, 0x3b, 0x6d, 0x5e, 0x48,
            0xba, 0xae, 0x48, 0x56, 0x75, 0xc1, 0x40, 0x6d, 0x6d, 0x8b, 0x57, 0x45, 0x6f, 0x6c,
            0x87, 0x08, 0xfb, 0x6e, 0x36, 0x3d, 0x8a, 0x56, 0xa4, 0xae, 0x90, 0xff, 0x72, 0x30,
            0x06, 0x14, 0x2a, 0x72, 0x87, 0x4f, 0xc6, 0x31, 0x21, 0xbf, 0xe5, 0x26, 0xda, 0x23,
            0xe7, 0x64, 0xe0, 0xf8, 0xa5, 0x4a, 0x49, 0xe3, 0x6f, 0x05, 0xe6, 0x22, 0x9f, 0x21,
            0x67, 0xdf, 0xb8, 0xef, 0xa9, 0x69, 0x2f, 0x8a, 0xc6, 0xa6, 0x87, 0x84, 0x68, 0x39,
            0x04, 0x7b, 0x82, 0xcb, 0x55, 0x00, 0x95, 0x41, 0x28, 0x19, 0x51, 0x57, 0xf3, 0xc8,
            0x71, 0xaa, 0x97, 0x0e, 0x7c, 0xc6, 0x43, 0x66, 0x7e, 0xe2, 0xab, 0xe9, 0xc1, 0x3e,
            0x05, 0xc3, 0xaf, 0x69, 0xb1, 0x0d, 0x3e, 0x35, 0xb0, 0x1d, 0x1b, 0x8d, 0x02, 0x32,
            0xcd, 0x05, 0xb8, 0x7b, 0x7c, 0x38, 0x9c, 0xe5, 0x58, 0xdb, 0x66, 0x1c, 0xe4, 0x79,
            0xc5, 0x51, 0x44, 0x2d, 0x0f, 0xeb, 0x7e, 0x8d, 0x9b, 0x7a, 0x2b, 0x5e, 0xf8, 0x78,
            0xe5, 0xad, 0xc1, 0xfd, 0x31, 0x70, 0xcf, 0xf0, 0x3e, 0x04, 0x15, 0x6b, 0x3e, 0x27,
            0xe3, 0xb8, 0x6d, 0x4f,
        ];

        assert_eq!(shake.digest, expected);
    }

    #[test]
    fn test_unset_hasher() {
        let mut shake = Sha3::new();
        let res = shake.update(b"abc");
        assert!(!res);
        shake.finalize();

        assert!(shake.digest.iter().all(|n| *n == 0));
    }
}
