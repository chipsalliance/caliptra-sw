/*++

Licensed under the Apache-2.0 license.

File Name:

    aes256gcm_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for AES-256-CMAC cryptography operations.

--*/

use caliptra_drivers::{Aes, AesKey, CaliptraError, CaliptraResult, LEArray4x4, LEArray4x8};

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

const KEY: LEArray4x8 = LEArray4x8::new([
    0xce4f9a69, 0xa99f3ef5, 0xaabc6e23, 0x7022140a, 0x100d2f72, 0x81c3f645, 0xe2a9822d, 0xd8fa4c56,
]);

const EXPECTED_MAC: LEArray4x4 =
    LEArray4x4::new([0x80811043u32, 0x4dfdc4c8u32, 0xfe11c594u32, 0x2946080bu32]);

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
