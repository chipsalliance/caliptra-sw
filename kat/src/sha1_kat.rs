/*++

Licensed under the Apache-2.0 license.

File Name:

    sha1_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA-1 cryptography operations.

--*/

use caliptra_drivers::{Array4x5, CaliptraError, CaliptraResult, Sha1};

const EXPECTED_DIGEST: Array4x5 =
    Array4x5::new([0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709]);

#[derive(Default, Debug)]
pub struct Sha1Kat {}

impl Sha1Kat {
    /// This function executes the Known Answer Tests (aka KAT) for SHA1.
    ///
    /// Test vector source:
    /// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
    ///
    /// # Arguments
    ///
    /// * `sha` - SHA1 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, sha: &mut Sha1) -> CaliptraResult<()> {
        self.kat_no_data(sha)
    }

    fn kat_no_data(&self, sha: &mut Sha1) -> CaliptraResult<()> {
        let data = [];
        let digest = sha
            .digest(&data)
            .map_err(|_| CaliptraError::ROM_KAT_SHA1_DIGEST_FAILURE)?;

        if digest != EXPECTED_DIGEST {
            Err(CaliptraError::ROM_KAT_SHA1_DIGEST_MISMATCH)?;
        }

        Ok(())
    }
}
