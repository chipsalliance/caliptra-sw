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
            0x0 => Sha3Mode::SHAKE,
            0x1 => Sha3Mode::SHA3,
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
    fn test_unset_hasher() {
        let mut shake = Sha3::new();
        let res = shake.update(b"abc");
        assert!(!res);
        shake.finalize();

        assert!(shake.digest.iter().all(|n| *n == 0));
    }
}
