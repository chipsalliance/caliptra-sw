/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384.rs

Abstract:

    File contains API for ECC-384 Cryptography operations

--*/

use crate::reg::ecc384_regs::*;
use crate::slice::{
    CopyFromByteSlice, CopyFromReadOnlyRegisterArray, CopyFromReadWriteRegisterArray,
};
use crate::CptrResult;
use tock_registers::interfaces::{Readable, Writeable};

/// ECC-384 coordinate size in bytes
pub const ECC_384_COORD_SIZE: usize = 48;

/// ECC-384 Coordinate
pub type Ecc384Scalar = [u8; ECC_384_COORD_SIZE];

/// ECC-384 Private Key
pub type Ecc384PrivKey = Ecc384Scalar;

/// ECC-384 Public Key
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Ecc384PubKey {
    /// X coordinate
    pub x: Ecc384Scalar,

    /// Y coordinate
    pub y: Ecc384Scalar,
}

impl Default for Ecc384PubKey {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self {
            x: [0u8; ECC_384_COORD_SIZE],
            y: [0u8; ECC_384_COORD_SIZE],
        }
    }
}

/// ECC-384 Signature
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Ecc384Signature {
    /// Random point
    pub r: Ecc384Scalar,

    /// Proof
    pub s: Ecc384Scalar,
}

impl Default for Ecc384Signature {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self {
            r: [0u8; ECC_384_COORD_SIZE],
            s: [0u8; ECC_384_COORD_SIZE],
        }
    }
}

/// Elliptic Curve P-384 API
pub enum Ecc384 {}

impl Ecc384 {
    /// Generate ECC-384 Key Pair
    ///
    /// # Arguments
    ///
    /// * `seed` - seed for deterministic ECC Key Pair generation
    /// 
    /// # Returns
    /// A tuple of private key and public key (private_key, public_key)
    /// 
    pub fn gen_key_pair(seed: &Ecc384Scalar) -> CptrResult<(Ecc384PrivKey, Ecc384PubKey)> {
        // Wait for hardware ready
        Self::_wait_for_hw_ready();

        // Copy the seed to register
        ECC384_REGS.seed.copy_from_byte_slice(seed);

        // Program the command register
        ECC384_REGS.control.write(CONTROL::CMD::GEN_KEY);

        // Wait for command to complete
        Self::_wait_for_cmd();

        // Copy private key
        let mut priv_key: Ecc384PrivKey = [0u8; ECC_384_COORD_SIZE];
        priv_key.copy_from_rw_reg(&ECC384_REGS.priv_key);

        // Copy public key
        let mut pub_key = Ecc384PubKey::default();
        pub_key.x.copy_from_rw_reg(&ECC384_REGS.pub_key_x);
        pub_key.y.copy_from_rw_reg(&ECC384_REGS.pub_key_y);

        Ok((priv_key, pub_key))
    }

    /// Sign the digest with specified private key
    ///
    /// # Arguments
    ///
    /// * `priv_key` - Private key
    /// * `digest` - Digest to sign
    ///
    /// # Result
    ///
    /// *  Ecc384Signature - Signature
    pub fn sign(
        priv_key: &Ecc384PrivKey,
        digest: &Ecc384Scalar,
        signature: &mut Ecc384Signature,
    ) -> CptrResult<()> {
        // Wait for hardware ready
        Self::_wait_for_hw_ready();

        // Copy private key
        ECC384_REGS.priv_key.copy_from_byte_slice(priv_key);

        // Copy digest
        ECC384_REGS.digest.copy_from_byte_slice(digest);

        // Program the command register
        ECC384_REGS.control.write(CONTROL::CMD::SIGN);

        // Wait for command to complete
        Self::_wait_for_cmd();

        // Copy signature
        signature.r.copy_from_rw_reg(&ECC384_REGS.sig_r);
        signature.s.copy_from_rw_reg(&ECC384_REGS.sig_s);

        Ok(())
    }

    /// Verify signature with specified public key and digest
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key
    /// * `digest` - digest to verify
    /// * `signature` - Signature to verify
    ///
    /// # Result
    ///
    /// *  `bool` - True if the signature verification passed else false
    pub fn verify(
        pub_key: &Ecc384PubKey,
        digest: &Ecc384Scalar,
        signature: &Ecc384Signature,
    ) -> CptrResult<bool> {
        // Wait for hardware ready
        Self::_wait_for_hw_ready();

        // Copy public key to registers
        ECC384_REGS.pub_key_x.copy_from_byte_slice(&pub_key.x);
        ECC384_REGS.pub_key_y.copy_from_byte_slice(&pub_key.y);

        // Copy digest to registers
        ECC384_REGS.digest.copy_from_byte_slice(digest);

        // Copy signature to registers
        ECC384_REGS.sig_r.copy_from_byte_slice(&signature.r);
        ECC384_REGS.sig_s.copy_from_byte_slice(&signature.s);

        // Program the command register
        ECC384_REGS.control.write(CONTROL::CMD::VERIFY);

        // Wait for command to complete
        Self::_wait_for_cmd();

        // Copy the random value
        let mut verify_r = [0u8; ECC_384_COORD_SIZE];
        verify_r.copy_from_ro_reg(&ECC384_REGS.verify_r);

        // compare the hardware generate `r` with one in signature
        if verify_r == signature.r {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[inline]
    fn _wait_for_hw_ready() {
        while !ECC384_REGS.status.is_set(STATUS::READY) {}
    }

    #[inline]
    fn _wait_for_cmd() {
        while !ECC384_REGS.status.is_set(STATUS::VALID) {}
    }
}
