/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_kdf_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for HMAC-384 and HMAC-512 cryptography operations.

--*/

use caliptra_drivers::{
    hmac_kdf, Array4x12, Array4x16, CaliptraError, CaliptraResult, Hmac, HmacMode, Trng,
};

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

#[derive(Default, Debug)]
pub struct Hmac512KdfKat {}

impl Hmac512KdfKat {
    /// This function executes the Known Answer Tests (aka KAT) for HMAC512Kdf.
    ///
    /// Test vector source:
    /// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Key-Derivation
    /// NOTE: Test vectors do not include separate label and context. Instead, split the input of
    ///       one vector that included a 0x00 byte into those fields.
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC-512 Driver
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
    /// * `hmac` - HMAC-512 Driver
    /// * `trng` - TRNG Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    fn kat_nist_vector(&self, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        let key: [u8; 64] = [
            0x24, 0x43, 0x56, 0xbe, 0x9b, 0x32, 0x79, 0x64, 0x73, 0x2e, 0xb4, 0xa7, 0xc0, 0x9b,
            0x04, 0xb4, 0x20, 0x71, 0x23, 0x96, 0xeb, 0x57, 0xf7, 0x2b, 0xc9, 0x49, 0x24, 0x06,
            0x6c, 0x68, 0x7e, 0x87, 0x8e, 0x79, 0x8e, 0x0a, 0x03, 0x3a, 0x1e, 0xe1, 0xa4, 0xd8,
            0xcd, 0xc2, 0xda, 0x04, 0x43, 0xec, 0xd7, 0x74, 0x01, 0xd0, 0x46, 0x0c, 0xd9, 0x06,
            0xea, 0xab, 0x02, 0x65, 0x6c, 0x1e, 0xdc, 0x98,
        ];

        let label: [u8; 44] = [
            0xd8, 0x06, 0xe2, 0xdf, 0x8c, 0x85, 0xd3, 0xba, 0xf5, 0xd6, 0x7e, 0x9c, 0x97, 0xb7,
            0x46, 0xee, 0x6b, 0xbb, 0x1b, 0xc1, 0x0d, 0xcd, 0xf6, 0xc7, 0xa6, 0x07, 0x5c, 0x31,
            0x1c, 0xf3, 0x47, 0x52, 0xac, 0xbe, 0x60, 0xe6, 0x8f, 0x23, 0xc7, 0xf8, 0x90, 0xb5,
            0xea, 0x73,
        ];

        let context: [u8; 15] = [
            0xa1, 0xad, 0x32, 0x17, 0x82, 0x54, 0x88, 0x52, 0x46, 0xf0, 0x49, 0x39, 0x87, 0xa6,
            0xe8,
        ];

        let expected_out: [u8; 40] = [
            0xf0, 0xb5, 0xbc, 0x74, 0x9e, 0xb3, 0x00, 0xca, 0x21, 0x7c, 0xa8, 0x2f, 0xdf, 0xfe,
            0xd8, 0x9b, 0x1b, 0xf2, 0xc8, 0xaf, 0xc2, 0xb3, 0x6e, 0xe2, 0xb4, 0x86, 0x95, 0xe5,
            0x08, 0x5b, 0x89, 0x3a, 0x6d, 0xaa, 0xd5, 0x47, 0x4f, 0x74, 0xef, 0x0f,
        ];

        let mut out = Array4x12::default();

        hmac_kdf(
            hmac,
            (&Array4x16::from(key)).into(),
            &label,
            Some(&context),
            trng,
            (&mut out).into(),
            HmacMode::Hmac512,
        )
        .map_err(|_| CaliptraError::KAT_HMAC384_FAILURE)?;

        if expected_out != <[u8; 48]>::from(out)[..expected_out.len()] {
            Err(CaliptraError::KAT_HMAC384_TAG_MISMATCH)?;
        }

        Ok(())
    }
}
