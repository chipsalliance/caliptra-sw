/*++

Licensed under the Apache-2.0 license.

File Name:

    aes256gcm_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for AES-256-CMAC cryptography operations.

--*/

use caliptra_drivers::{Aes, AesKey, CaliptraError, CaliptraResult, LEArray4x4};

// FROM ACVP test vector:
// {
//   "tgId": 21,
//   "testType": "AFT",
//   "direction": "gen",
//   "keyLen": 256,
//   "msgLen": 0,
//   "macLen": 128,
//   "tests": [
//     {
//       "tcId": 161,
//       "key": "699A4FCEF53E9FA9236EBCAA0A142270722F0D1045F6C3812D82A9E2564CFAD8",
//       "message": ""
//     },
// ...
// {
//   "tgId": 21,
//   "tests": [
//     {
//       "tcId": 161,
//       "mac": "43108180C8C4FD4D94C511FE0B084629"
//     },

const KEY: [u8; 32] = [
    0x69, 0x9a, 0x4f, 0xce, 0xf5, 0x3e, 0x9f, 0xa9, 0x23, 0x6e, 0xbc, 0xaa, 0x0a, 0x14, 0x22, 0x70,
    0x72, 0x2f, 0x0d, 0x10, 0x45, 0xf6, 0xc3, 0x81, 0x2d, 0x82, 0xa9, 0xe2, 0x56, 0x4c, 0xfa, 0xd8,
];

const EXPECTED_MAC: LEArray4x4 = LEArray4x4::new([0x43108180, 0xc8c4fd4d, 0x94c511fe, 0x0b084629]);

#[derive(Default, Debug)]
pub struct Aes256CmacKat {}

impl Aes256CmacKat {
    /// This function executes the Known Answer Tests (aka KAT) for AES-256-CMAC.
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
        let mac = aes.cmac(AesKey::Array(&KEY), &[])?;
        if mac != EXPECTED_MAC {
            Err(CaliptraError::KAT_AES_CIPHERTEXT_MISMATCH)?;
        }

        Ok(())
    }
}
