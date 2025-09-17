/*++

Licensed under the Apache-2.0 license.

File Name:

    sha3_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA3 cryptography operations.

--*/

use caliptra_drivers::{Array4x8, CaliptraError, CaliptraResult, Sha3};

pub const EXPECTED_SHAKE256_DIGEST: Array4x8 = Array4x8::new([
    0x46b9dd2b, 0x0ba88d13, 0x233b3feb, 0x743eeb24, 0x3fcd52ea, 0x62b81b82, 0xb50c2764, 0x6ed5762f,
]);

#[derive(Default, Debug)]
pub struct Shake256Kat {}

impl Shake256Kat {
    /// This function executes the Known Answer Tests (aka KAT) for SHAKE256.
    ///
    /// # Arguments
    ///
    /// * `sha` - SHA3 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, sha: &mut Sha3) -> CaliptraResult<()> {
        self.kat_no_data(sha)
    }

    fn kat_no_data(&self, sha3: &mut Sha3) -> CaliptraResult<()> {
        let data = &[];
        let digest = sha3
            .shake256_digest(data)
            .map_err(|_| CaliptraError::KAT_SHA3_SHAKE256_DIGEST_FAILURE)?;

        if digest != EXPECTED_SHAKE256_DIGEST {
            Err(CaliptraError::KAT_SHA3_SHAKE256_DIGEST_MISMATCH)?;
        }

        Ok(())
    }
}
