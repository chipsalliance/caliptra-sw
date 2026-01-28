/*++

Licensed under the Apache-2.0 license.

File Name:

    aes256gcm_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for AES-256-CTR cryptography operations.

--*/

use crate::{Aes, CaliptraError, CaliptraResult, LEArray4x4, LEArray4x8};

// From NIST SP800-38A, F.5.5
// CTR-AES256.Encrypt
// Key
// 603deb1015ca71be2b73aef0857d7781
// 1f352c073b6108d72d9810a30914dff4
// Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
// Block #1
// Input Block
// f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
// Output Block
// 0bdf7df1591716335e9a8b15c860c502
// Plaintext
// 6bc1bee22e409f96e93d7e117393172a
// Ciphertext
// 601ec313775789a5b7a7f504bbf3d228
// Block #2
// Input Block
// f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
// Output Block
// 5a6e699d536119065433863c8f657b94
// Plaintext
// ae2d8a571e03ac9c9eb76fac45af8e51
// Ciphertext
// f443e3ca4d62b59aca84e990cacaf5c5
// Block #3
// Input Block
// f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
// Output Block
// 1bc12c9c01610d5d0d8bd6a3378eca62
// Plaintext
// 30c81c46a35ce411e5fbc1191a0a52ef
// Ciphertext
// 2b0930daa23de94ce87017ba2d84988d
// Block #4
// Input Block
// f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
// Output Block
// 2956e1c8693536b1bee99c73a31576b6
// Plaintext
// f69f2445df4f9b17ad2b417be66c3710
// Ciphertext
// dfc9c58db67aada613c2dd08457941a6

const KEY: LEArray4x8 = LEArray4x8::new([
    0x10eb3d60, 0xbe71ca15, 0xf0ae732b, 0x81777d85, 0x072c351f, 0xd708613b, 0xa310982d, 0xf4df1409,
]);
const IV: LEArray4x4 = LEArray4x4::new([0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc]);
const PT: [u8; 64] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
];
const CT: [u8; 64] = [
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
    0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
    0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
    0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6,
];

#[derive(Default, Debug)]
pub struct Aes256CtrKat {}

impl Aes256CtrKat {
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
        let mut ciphertext: [u8; 64] = [0u8; 64];
        aes.aes_256_ctr_impl(&KEY, &IV, 0, &PT[..], &mut ciphertext)?;

        if ciphertext != CT {
            Err(CaliptraError::KAT_AES_CIPHERTEXT_MISMATCH)?;
        }

        let mut plaintext: [u8; 64] = [0u8; 64];
        aes.aes_256_ctr_impl(&KEY, &IV, 0, &CT[..], &mut plaintext)?;
        if plaintext != PT {
            Err(CaliptraError::KAT_AES_PLAINTEXT_MISMATCH)?;
        }

        Ok(())
    }
}
