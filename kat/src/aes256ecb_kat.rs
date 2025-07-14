/*++

Licensed under the Apache-2.0 license.

File Name:

    aes256ecb_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for AES-256-ECB cryptography operations.

--*/

use caliptra_drivers::{Aes, AesKey, AesOperation, CaliptraError, CaliptraResult};

// Generated from Python code:
// >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
// >>> key = b'\x00' * 32
// >>> pt = b'\x00' * 48
// >>> cipher = Cipher(algorithms.AES(key), modes.ECB)
// >>> encryptor = cipher.encryptor()
// >>> ct = encryptor.update(pt) + encryptor.finalize()
// >>> print(ct.hex())
// dc95c078a2408989ad48a21492842087dc95c078a2408989ad48a21492842087dc95c078a2408989ad48a21492842087dc95c078a2408989ad48a21492842087

const KEY: AesKey<'_> = AesKey::Array(&[0u8; 32]);
const PT: [u8; 48] = [0u8; 48];
const CT: [u8; 48] = [
    0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87,
    0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87,
    0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87,
];

#[derive(Default, Debug)]
pub struct Aes256EcbKat {}

impl Aes256EcbKat {
    /// This function executes the Known Answer Tests (aka KAT) for AES-256-ECB.
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
        aes.aes_256_ecb(KEY, AesOperation::Encrypt, &PT[..], &mut ciphertext)?;

        if ciphertext != CT {
            Err(CaliptraError::KAT_AES_CIPHERTEXT_MISMATCH)?;
        }

        let mut plaintext: [u8; 48] = [0u8; 48];
        aes.aes_256_ecb(KEY, AesOperation::Decrypt, &CT[..], &mut plaintext)?;
        if plaintext != PT {
            Err(CaliptraError::KAT_AES_PLAINTEXT_MISMATCH)?;
        }

        Ok(())
    }
}
