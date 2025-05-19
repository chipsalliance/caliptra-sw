/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_kdf_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for HKDF Extract and Expand using HMAC-384 and HMAC-512.

--*/

use caliptra_drivers::{
    hkdf_expand, hkdf_extract, Array4x12, Array4x16, CaliptraError, CaliptraResult, Hmac, HmacMode,
    Trng,
};

const KI_384: [u8; 48] = [
    0x2f, 0x0f, 0x2e, 0x94, 0x19, 0x44, 0x7b, 0x12, 0x2c, 0x2d, 0x62, 0xe9, 0xcc, 0x51, 0x16, 0x86,
    0xed, 0x6d, 0x04, 0x4f, 0x67, 0xaa, 0x49, 0x95, 0x6a, 0x79, 0x54, 0xe5, 0xbb, 0x7e, 0xe7, 0xa6,
    0x8d, 0x19, 0x93, 0xcc, 0xa0, 0xcc, 0xb3, 0xaf, 0x29, 0x78, 0xc3, 0xb9, 0x5d, 0x04, 0xc9, 0x09,
];

const KI_512: [u8; 64] = [
    0xd5, 0x58, 0x05, 0x7f, 0x2b, 0xdd, 0x1d, 0x69, 0xbb, 0xbc, 0x10, 0x9f, 0xfd, 0x0d, 0xdf, 0x8f,
    0xa5, 0xdf, 0x35, 0xc0, 0xd5, 0xe7, 0xad, 0xb5, 0x70, 0x5d, 0xda, 0xa5, 0x07, 0x40, 0x30, 0x8c,
    0x98, 0xbf, 0x99, 0x3c, 0x6d, 0xa6, 0x2e, 0x0c, 0x56, 0xd8, 0x2c, 0x30, 0x74, 0x04, 0xfd, 0x14,
    0xbd, 0xc6, 0x36, 0x2f, 0x97, 0x16, 0xe6, 0x15, 0x00, 0x1f, 0x9f, 0xcf, 0x85, 0x23, 0x05, 0x0a,
];

#[derive(Default, Debug)]
pub struct Hkdf384Kat {}

impl Hkdf384Kat {
    /// This function executes the Known Answer Tests (aka KAT) for HKDF with HMAC-SHA384.
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC Driver
    /// * `trng` - TRNG Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        self.hkdf_extract_kat_nist_vector(hmac, trng)?;
        self.hkdf_expand_kat_nist_vector(hmac, trng)?;
        Ok(())
    }

    /// This function executes the Known Answer Tests (aka KAT) for HKDF-Extract with HMAC-SHA384.
    ///
    /// Test vector source:
    /// Python script: (No NIST test vectors available.)
    /// >>> import hashlib
    /// >>> import hmac
    /// >>> key = bytes.fromhex("2f0f2e9419447b122c2d62e9cc511686ed6d044f67aa49956a7954e5bb7ee7a68d1993cca0ccb3af2978c3b95d04c909")
    /// >>> print(hmac.new(b"", key, hashlib.sha384).hexdigest())
    ///
    /// 5a93140871c1301c2f55cb4e720e02d29f12bc8f7738a0d86a1cfb96fe014efd126f226adeb887f5982be71d998973fd
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC-384 Driver
    /// * `trng` - TRNG Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    fn hkdf_extract_kat_nist_vector(&self, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        const EXPECTED: [u8; 48] = [
            0x24, 0x14, 0xda, 0x94, 0x53, 0xbf, 0x5e, 0x6e, 0xea, 0xe9, 0xf8, 0xb5, 0xb6, 0x3c,
            0xa0, 0xff, 0x15, 0x0c, 0x47, 0xd2, 0x5f, 0x04, 0x28, 0x5b, 0x5c, 0xd4, 0xac, 0x75,
            0x11, 0x06, 0x9a, 0xd8, 0x86, 0x03, 0xd1, 0xbe, 0x6e, 0xd7, 0xe0, 0x37, 0x41, 0x55,
            0x44, 0x7f, 0xab, 0x69, 0xc5, 0x59,
        ];

        let mut out = Array4x12::default();

        hkdf_extract(
            hmac,
            &KI_384,
            &[],
            trng,
            (&mut out).into(),
            HmacMode::Hmac384,
        )
        .map_err(|_| CaliptraError::KAT_HMAC384_FAILURE)?;

        if EXPECTED != <[u8; 48]>::from(out)[..EXPECTED.len()] {
            Err(CaliptraError::KAT_HMAC384_TAG_MISMATCH)?;
        }

        Ok(())
    }

    /// This function executes the Known Answer Tests (aka KAT) for HKDF-Expand with HMAC-SHA384.
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
    fn hkdf_expand_kat_nist_vector(&self, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        // COUNT=39
        // L = 320
        // KI = 2f0f2e9419447b122c2d62e9cc511686ed6d044f67aa49956a7954e5bb7ee7a68d1993cca0ccb3af2978c3b95d04c909
        // FixedInputDataByteLen = 60
        // FixedInputData = 9a31c5deeb0304aabdb2d8cd0ebb82583b2b30db519c9413e2f7281a9ca4f8d919e8cdf1a518ed16788ec7a74d02724e0241e4f6b369297b1525f97a
        //         Binary rep of i = 01
        //         instring = 9a31c5deeb0304aabdb2d8cd0ebb82583b2b30db519c9413e2f7281a9ca4f8d919e8cdf1a518ed16788ec7a74d02724e0241e4f6b369297b1525f97a01
        // KO = d201f90262f79f11109047763ffaea2f5f3baf7fc5345c587fd2cde0d93a90ea43f5f321d52650c1
        const KI_384: [u8; 48] = [
            0x2f, 0x0f, 0x2e, 0x94, 0x19, 0x44, 0x7b, 0x12, 0x2c, 0x2d, 0x62, 0xe9, 0xcc, 0x51,
            0x16, 0x86, 0xed, 0x6d, 0x04, 0x4f, 0x67, 0xaa, 0x49, 0x95, 0x6a, 0x79, 0x54, 0xe5,
            0xbb, 0x7e, 0xe7, 0xa6, 0x8d, 0x19, 0x93, 0xcc, 0xa0, 0xcc, 0xb3, 0xaf, 0x29, 0x78,
            0xc3, 0xb9, 0x5d, 0x04, 0xc9, 0x09,
        ];

        const FIXED_INFO: [u8; 60] = [
            0x9a, 0x31, 0xc5, 0xde, 0xeb, 0x03, 0x04, 0xaa, 0xbd, 0xb2, 0xd8, 0xcd, 0x0e, 0xbb,
            0x82, 0x58, 0x3b, 0x2b, 0x30, 0xdb, 0x51, 0x9c, 0x94, 0x13, 0xe2, 0xf7, 0x28, 0x1a,
            0x9c, 0xa4, 0xf8, 0xd9, 0x19, 0xe8, 0xcd, 0xf1, 0xa5, 0x18, 0xed, 0x16, 0x78, 0x8e,
            0xc7, 0xa7, 0x4d, 0x02, 0x72, 0x4e, 0x02, 0x41, 0xe4, 0xf6, 0xb3, 0x69, 0x29, 0x7b,
            0x15, 0x25, 0xf9, 0x7a,
        ];

        const KO: [u8; 40] = [
            0xd2, 0x01, 0xf9, 0x02, 0x62, 0xf7, 0x9f, 0x11, 0x10, 0x90, 0x47, 0x76, 0x3f, 0xfa,
            0xea, 0x2f, 0x5f, 0x3b, 0xaf, 0x7f, 0xc5, 0x34, 0x5c, 0x58, 0x7f, 0xd2, 0xcd, 0xe0,
            0xd9, 0x3a, 0x90, 0xea, 0x43, 0xf5, 0xf3, 0x21, 0xd5, 0x26, 0x50, 0xc1,
        ];

        let mut out = Array4x12::default();
        let ki: Array4x12 = Array4x12::from(&KI_384);

        hkdf_expand(
            hmac,
            (&ki).into(),
            &FIXED_INFO,
            trng,
            (&mut out).into(),
            HmacMode::Hmac384,
        )
        .map_err(|_| CaliptraError::KAT_HMAC384_FAILURE)?;

        if KO != <[u8; 48]>::from(out)[..KO.len()] {
            Err(CaliptraError::KAT_HMAC384_TAG_MISMATCH)?;
        }

        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct Hkdf512Kat {}

impl Hkdf512Kat {
    /// This function executes the Known Answer Tests (aka KAT) for HKDF with HMAC-SHA512.
    ///
    /// Test vector source:
    /// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Key-Derivation
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC Driver
    /// * `trng` - TRNG Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        self.hkdf_extract_kat_nist_vector(hmac, trng)?;
        self.hkdf_expand_kat_nist_vector(hmac, trng)?;
        Ok(())
    }

    /// This function executes the Known Answer Tests (aka KAT) for HKDF-Extract with HMAC-SHA512.
    ///
    /// Test vector source:
    /// Python script: (No NIST test vectors available.)
    /// >>> import hashlib
    /// >>> import hmac
    /// >>> key = bytes.fromhex("d558057f2bdd1d69bbbc109ffd0ddf8fa5df35c0d5e7adb5705ddaa50740308c98bf993c6da62e0c56d82c307404fd14bdc6362f9716e615001f9fcf8523050a")
    /// >>> print(hmac.new(b"", key, hashlib.sha512).hexdigest())
    ///
    /// 8ed0c3c9a36e122ed29fab9ec3963fabd084d86b689a159c3f0927f71f26070696718a738cc97fb954ea12e64cd5bc4b40ab4b55b8c0dde35db63c8612e377cf
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC Driver
    /// * `trng` - TRNG Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    fn hkdf_extract_kat_nist_vector(&self, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        const EXPECTED: [u8; 64] = [
            0x8e, 0xd0, 0xc3, 0xc9, 0xa3, 0x6e, 0x12, 0x2e, 0xd2, 0x9f, 0xab, 0x9e, 0xc3, 0x96,
            0x3f, 0xab, 0xd0, 0x84, 0xd8, 0x6b, 0x68, 0x9a, 0x15, 0x9c, 0x3f, 0x09, 0x27, 0xf7,
            0x1f, 0x26, 0x07, 0x06, 0x96, 0x71, 0x8a, 0x73, 0x8c, 0xc9, 0x7f, 0xb9, 0x54, 0xea,
            0x12, 0xe6, 0x4c, 0xd5, 0xbc, 0x4b, 0x40, 0xab, 0x4b, 0x55, 0xb8, 0xc0, 0xdd, 0xe3,
            0x5d, 0xb6, 0x3c, 0x86, 0x12, 0xe3, 0x77, 0xcf,
        ];

        let mut out = Array4x16::default();

        hkdf_extract(
            hmac,
            &KI_512,
            &[],
            trng,
            (&mut out).into(),
            HmacMode::Hmac512,
        )
        .map_err(|_| CaliptraError::KAT_HMAC384_FAILURE)?;

        if EXPECTED != <[u8; 64]>::from(out)[..EXPECTED.len()] {
            Err(CaliptraError::KAT_HMAC384_TAG_MISMATCH)?;
        }

        Ok(())
    }

    /// Performs KDF generation with a single fixed input data buffer.
    ///
    /// Test vector source:
    /// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Key-Derivation
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC Driver
    /// * `trng` - TRNG Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    fn hkdf_expand_kat_nist_vector(&self, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        // COUNT=39
        // L = 320
        // KI = d558057f2bdd1d69bbbc109ffd0ddf8fa5df35c0d5e7adb5705ddaa50740308c98bf993c6da62e0c56d82c307404fd14bdc6362f9716e615001f9fcf8523050a
        // FixedInputDataByteLen = 60
        // FixedInputData = 7a4cad59057380a1f8979c960e8e2d07ce5260e6f94b0a77eb1fc59b4d87a6c6a94155f3c3c9d5565d0c7214a24b78dfcad23c69d7c064f46378c5fb
        //         Binary rep of i = 01
        //         instring = 7a4cad59057380a1f8979c960e8e2d07ce5260e6f94b0a77eb1fc59b4d87a6c6a94155f3c3c9d5565d0c7214a24b78dfcad23c69d7c064f46378c5fb01
        // KO = e0d67286cc618d06db2a67b4e8c4455cf802efc4d93edbe63aeffa777601821c42405ae6eec3a874

        const FIXED_INPUT: [u8; 60] = [
            0x7a, 0x4c, 0xad, 0x59, 0x05, 0x73, 0x80, 0xa1, 0xf8, 0x97, 0x9c, 0x96, 0x0e, 0x8e,
            0x2d, 0x07, 0xce, 0x52, 0x60, 0xe6, 0xf9, 0x4b, 0x0a, 0x77, 0xeb, 0x1f, 0xc5, 0x9b,
            0x4d, 0x87, 0xa6, 0xc6, 0xa9, 0x41, 0x55, 0xf3, 0xc3, 0xc9, 0xd5, 0x56, 0x5d, 0x0c,
            0x72, 0x14, 0xa2, 0x4b, 0x78, 0xdf, 0xca, 0xd2, 0x3c, 0x69, 0xd7, 0xc0, 0x64, 0xf4,
            0x63, 0x78, 0xc5, 0xfb,
        ];
        const KO: [u8; 40] = [
            0xe0, 0xd6, 0x72, 0x86, 0xcc, 0x61, 0x8d, 0x06, 0xdb, 0x2a, 0x67, 0xb4, 0xe8, 0xc4,
            0x45, 0x5c, 0xf8, 0x02, 0xef, 0xc4, 0xd9, 0x3e, 0xdb, 0xe6, 0x3a, 0xef, 0xfa, 0x77,
            0x76, 0x01, 0x82, 0x1c, 0x42, 0x40, 0x5a, 0xe6, 0xee, 0xc3, 0xa8, 0x74,
        ];

        let mut out = Array4x16::default();
        let ki: Array4x16 = Array4x16::from(&KI_512);

        hkdf_expand(
            hmac,
            (&ki).into(),
            &FIXED_INPUT,
            trng,
            (&mut out).into(),
            HmacMode::Hmac512,
        )
        .map_err(|_| CaliptraError::KAT_HMAC384_FAILURE)?;

        if KO != <[u8; 64]>::from(out)[..KO.len()] {
            Err(CaliptraError::KAT_HMAC384_TAG_MISMATCH)?;
        }

        Ok(())
    }
}
