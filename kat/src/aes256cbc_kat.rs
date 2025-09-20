/*++

Licensed under the Apache-2.0 license.

File Name:

    aes256gcm_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for AES-256-CBC cryptography operations.

--*/

use caliptra_drivers::{Aes, AesOperation, CaliptraError, CaliptraResult};

// Generated from Python code:
// >>> import os
// >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
// >>> key = b'\x00' * 32
// >>> iv = b'\x00' * 16
// >>> cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
// >>> encryptor = cipher.encryptor()
// >>> ct = encryptor.update(iv * 3) + encryptor.finalize()
// >>> print(ct.hex())
// dc95c078a2408989ad48a2149284208708c374848c228233c2b34f332bd2e9d38b70c515a6663d38cdb8e6532b266491

const KEY: [u8; 32] = [0u8; 32];
const IV: [u8; 16] = [0u8; 16];
const PT: [u8; 48] = [0u8; 48];
const CT: [u8; 48] = [
    0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87,
    0x08, 0xc3, 0x74, 0x84, 0x8c, 0x22, 0x82, 0x33, 0xc2, 0xb3, 0x4f, 0x33, 0x2b, 0xd2, 0xe9, 0xd3,
    0x8b, 0x70, 0xc5, 0x15, 0xa6, 0x66, 0x3d, 0x38, 0xcd, 0xb8, 0xe6, 0x53, 0x2b, 0x26, 0x64, 0x91,
];

#[derive(Default, Debug)]
pub struct Aes256CbcKat {}

impl Aes256CbcKat {
    /// This function executes the Known Answer Tests (aka KAT) for AES-256-CBC.
    ///
    /// Test vector source:
    /// NIST test vectors
    ///
    /// # Arguments
    ///
    /// * `aes` - AES driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, aes: &mut Aes) -> CaliptraResult<()> {
        self.encrypt_decrypt(aes)
    }

    fn encrypt_decrypt(&self, aes: &mut Aes) -> CaliptraResult<()> {
        let mut ciphertext: [u8; 48] = [0u8; 48];
        aes.aes_256_cbc(
            &KEY,
            &IV,
            AesOperation::Encrypt,
            &PT[..],
            &mut ciphertext,
            true,
        )?;

        if ciphertext != CT {
            Err(CaliptraError::KAT_AES_CIPHERTEXT_MISMATCH)?;
        }

        let mut plaintext: [u8; 48] = [0u8; 48];
        aes.aes_256_cbc(
            &KEY,
            &IV,
            AesOperation::Decrypt,
            &CT[..],
            &mut plaintext,
            true,
        )?;
        if plaintext != PT {
            Err(CaliptraError::KAT_AES_PLAINTEXT_MISMATCH)?;
        }

        Ok(())
    }
}
