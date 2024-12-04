/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for HMAC-384 cryptography operations.

--*/

use caliptra_drivers::{hmac_kdf, Array4x12, CaliptraError, CaliptraResult, Hmac, HmacMode, Trng};

const KEY: Array4x12 = Array4x12::new([
    0xb57dc523, 0x54afee11, 0xedb4c905, 0x2a528344, 0x348b2c6b, 0x6c39f321, 0x33ed3bb7, 0x2035a4ab,
    0x55d6648c, 0x1529ef7a, 0x9170fec9, 0xef26a81e,
]);

const LABEL: [u8; 60] = [
    0x17, 0xe6, 0x41, 0x90, 0x9d, 0xed, 0xfe, 0xe4, 0x96, 0x8b, 0xb9, 0x5d, 0x7f, 0x77, 0x0e, 0x45,
    0x57, 0xca, 0x34, 0x7a, 0x46, 0x61, 0x4c, 0xb3, 0x71, 0x42, 0x3f, 0x0d, 0x91, 0xdf, 0x3b, 0x58,
    0xb5, 0x36, 0xed, 0x54, 0x53, 0x1f, 0xd2, 0xa2, 0xeb, 0x0b, 0x8b, 0x2a, 0x16, 0x34, 0xc2, 0x3c,
    0x88, 0xfa, 0xd9, 0x70, 0x6c, 0x45, 0xdb, 0x44, 0x11, 0xa2, 0x3b, 0x89,
];

const EXPECTED_OUT: [u8; 40] = [
    0x59, 0x49, 0xac, 0xf9, 0x63, 0x5a, 0x77, 0x29, 0x79, 0x28, 0xc1, 0xe1, 0x55, 0xd4, 0x3a, 0x4e,
    0x4b, 0xca, 0x61, 0xb1, 0x36, 0x9a, 0x5e, 0xf5, 0x05, 0x30, 0x88, 0x85, 0x50, 0xba, 0x27, 0x0e,
    0x26, 0xbe, 0x4a, 0x42, 0x1c, 0xdf, 0x80, 0xb7,
];

#[derive(Default, Debug)]
pub struct Hmac384KdfKat {}

impl Hmac384KdfKat {
    /// This function executes the Known Answer Tests (aka KAT) for HMAC384Kdf.
    ///
    /// Test vector source:
    /// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Key-Derivation
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC-384 Driver
    /// * `trng` - TRNG Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        self.kat_nist_vector(hmac, trng)?;
        Ok(())
    }

    /// Performs KDF generation with a single fixed input data buffer.
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC-384 Driver
    /// * `trng` - TRNG Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    fn kat_nist_vector(&self, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        let mut out = Array4x12::default();

        hmac_kdf(
            hmac,
            (&KEY).into(),
            &LABEL,
            None,
            trng,
            (&mut out).into(),
            HmacMode::Hmac384,
        )
        .map_err(|_| CaliptraError::KAT_HMAC384_FAILURE)?;

        if EXPECTED_OUT != <[u8; 48]>::from(out)[..EXPECTED_OUT.len()] {
            Err(CaliptraError::KAT_HMAC384_TAG_MISMATCH)?;
        }

        Ok(())
    }
}
