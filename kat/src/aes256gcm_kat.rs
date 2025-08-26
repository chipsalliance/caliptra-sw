/*++

Licensed under the Apache-2.0 license.

File Name:

    aes256gcm_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for AES-256-GCM cryptography operations.

--*/

use caliptra_drivers::{Aes, AesKey, CaliptraError, CaliptraResult, LEArray4x8, Trng};

// Taken from NIST test vectors: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#GCMVS

// KEY = f0eaf7b41b42f4500635bc05d9cede11a5363d59a6288870f527bcffeb4d6e04
// IV = 18f316781077a595c72d4c07
// CT = 7a1b61009dce6b7cd4d1ea0203b179f1219dd5ce7407e12ea0a4c56c71bb791b
// AAD = 42cade3a19204b7d4843628c425c2375
// Tag = 4419180b0b963b7289a4fa3f45c535a3
// PT = 400fb5ef32083b3abea957c4f068abad50c8d86bbf9351fa72e7da5171df38f9

const KEY: LEArray4x8 = LEArray4x8::new([
    0xb4f7eaf0, 0x50f4421b, 0x05bc3506, 0x11deced9, 0x593d36a5, 0x708828a6, 0xffbc27f5, 0x046e4deb,
]);
const IV: [u8; 12] = [
    0x18, 0xf3, 0x16, 0x78, 0x10, 0x77, 0xa5, 0x95, 0xc7, 0x2d, 0x4c, 0x07,
];
const CT: [u8; 32] = [
    0x7a, 0x1b, 0x61, 0x0, 0x9d, 0xce, 0x6b, 0x7c, 0xd4, 0xd1, 0xea, 0x2, 0x3, 0xb1, 0x79, 0xf1,
    0x21, 0x9d, 0xd5, 0xce, 0x74, 0x7, 0xe1, 0x2e, 0xa0, 0xa4, 0xc5, 0x6c, 0x71, 0xbb, 0x79, 0x1b,
];
const AAD: [u8; 16] = [
    0x42, 0xca, 0xde, 0x3a, 0x19, 0x20, 0x4b, 0x7d, 0x48, 0x43, 0x62, 0x8c, 0x42, 0x5c, 0x23, 0x75,
];
const TAG: [u8; 16] = [
    0x44, 0x19, 0x18, 0xb, 0xb, 0x96, 0x3b, 0x72, 0x89, 0xa4, 0xfa, 0x3f, 0x45, 0xc5, 0x35, 0xa3,
];
const PT: [u8; 32] = [
    0x40, 0xf, 0xb5, 0xef, 0x32, 0x8, 0x3b, 0x3a, 0xbe, 0xa9, 0x57, 0xc4, 0xf0, 0x68, 0xab, 0xad,
    0x50, 0xc8, 0xd8, 0x6b, 0xbf, 0x93, 0x51, 0xfa, 0x72, 0xe7, 0xda, 0x51, 0x71, 0xdf, 0x38, 0xf9,
];

#[derive(Default, Debug)]
pub struct Aes256GcmKat {}

impl Aes256GcmKat {
    /// This function executes the Known Answer Tests (aka KAT) for AES-256-GCM.
    ///
    /// Test vector source:
    /// NIST test vectors
    ///
    /// # Arguments
    ///
    /// * `aes` - AES driver
    /// * `trng` - TRNG driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, aes: &mut Aes, trng: &mut Trng) -> CaliptraResult<()> {
        self.encrypt_decrypt(aes, trng)
    }

    fn encrypt_decrypt(&self, aes: &mut Aes, trng: &mut Trng) -> CaliptraResult<()> {
        let iv = (&IV).into();
        let key = AesKey::Array(&KEY);
        let mut ciphertext = [0u8; 32];
        let (_, tag) =
            aes.aes_256_gcm_encrypt(trng, iv, key, &AAD[..], &PT[..], &mut ciphertext, 16)?;

        if ciphertext != CT {
            Err(CaliptraError::KAT_AES_CIPHERTEXT_MISMATCH)?;
        }
        if tag != TAG {
            Err(CaliptraError::KAT_AES_TAG_MISMATCH)?;
        }

        let mut plaintext = [0u8; 32];
        aes.aes_256_gcm_decrypt(trng, &IV, key, &AAD[..], &CT[..], &mut plaintext, &TAG[..])?;
        if plaintext != PT {
            Err(CaliptraError::KAT_AES_PLAINTEXT_MISMATCH)?;
        }

        Ok(())
    }
}
