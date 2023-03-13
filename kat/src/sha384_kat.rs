/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA-384 cryptography operations.

--*/

use crate::caliptra_err_def;
use caliptra_lib::{Array4x12, Array4xN, CaliptraResult, Sha384};

caliptra_err_def! {
    Sha384Kat,
    Sha384KatErr
    {
        DigestFailure = 0x01,
        DigestMismatch = 0x2,
    }
}

pub const SHA384_EXPECTED_DIGEST: Array4xN<12, 48> = Array4xN([
    0x38b060a7, 0x51ac9638, 0x4cd9327e, 0xb1b1e36a, 0x21fdb711, 0x14be0743, 0x4c0cc7bf, 0x63f6e1da,
    0x274edebf, 0xe76f65fb, 0xd51ad2f1, 0x4898b95b,
]);

#[derive(Default, Debug)]
pub struct Sha384Kat {}

impl Sha384Kat {
    /// This function executes the Known Answer Tests (aka KAT) for SHA384.
    ///
    /// Test vector source:
    /// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
    ///
    /// # Arguments
    ///
    /// * `sha` - SHA2-384 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, sha: &Sha384) -> CaliptraResult<()> {
        self.kat_no_data(sha)
    }

    fn kat_no_data(&self, sha: &Sha384) -> CaliptraResult<()> {
        let data = &[];
        let mut digest = Array4x12::default();

        sha.digest(data, &mut digest)
            .map_err(|_| err_u32!(DigestFailure))?;

        if digest != SHA384_EXPECTED_DIGEST {
            raise_err!(DigestMismatch);
        }

        Ok(())
    }
}
