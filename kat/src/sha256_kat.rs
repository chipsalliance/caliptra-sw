/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA-256 cryptography operations.

--*/

use caliptra_drivers::{Array4x8, CaliptraError, CaliptraResult, Sha256};

const EXPECTED_DIGEST: Array4x8 = Array4x8::new([
    0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855,
]);

#[derive(Default, Debug)]
pub struct Sha256Kat {}

impl Sha256Kat {
    /// This function executes the Known Answer Tests (aka KAT) for SHA256.
    ///
    /// Test vector source:
    /// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
    ///
    /// # Arguments
    ///
    /// * `sha` - SHA2-256 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, sha: &mut Sha256) -> CaliptraResult<()> {
        self.kat_no_data(sha)
    }

    fn kat_no_data(&self, sha: &mut Sha256) -> CaliptraResult<()> {
        let data = [];

        let digest = sha
            .digest(&data)
            .map_err(|_| CaliptraError::ROM_KAT_SHA256_DIGEST_FAILURE)?;

        if digest != EXPECTED_DIGEST {
            return Err(CaliptraError::ROM_KAT_SHA256_DIGEST_MISMATCH);
        }

        Ok(())
    }
}
