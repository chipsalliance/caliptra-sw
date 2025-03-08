/*++

Licensed under the Apache-2.0 license.

File Name:

    sha512_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA-512 cryptography operations.

--*/

use caliptra_drivers::{Array4x16, CaliptraError, CaliptraResult, Sha2_512_384};

pub const EXPECTED_DIGEST: Array4x16 = Array4x16::new([
    0xcf83e135, 0x7eefb8bd, 0xf1542850, 0xd66d8007, 0xd620e405, 0xb5715dc, 0x83f4a921, 0xd36ce9ce,
    0x47d0d13c, 0x5d85f2b0, 0xff8318d2, 0x877eec2f, 0x63b931bd, 0x47417a81, 0xa538327a, 0xf927da3e,
]);

#[derive(Default, Debug)]
pub struct Sha512Kat {}

impl Sha512Kat {
    /// This function executes the Known Answer Tests (aka KAT) for SHA512.
    ///
    /// # Arguments
    ///
    /// * `sha` - SHA2-512 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, sha: &mut Sha2_512_384) -> CaliptraResult<()> {
        self.kat_no_data(sha)
    }

    fn kat_no_data(&self, sha2: &mut Sha2_512_384) -> CaliptraResult<()> {
        let data = &[];
        let digest = sha2
            .sha512_digest(data)
            .map_err(|_| CaliptraError::KAT_SHA512_DIGEST_FAILURE)?;

        if digest != EXPECTED_DIGEST {
            Err(CaliptraError::KAT_SHA512_DIGEST_MISMATCH)?;
        }

        Ok(())
    }
}
