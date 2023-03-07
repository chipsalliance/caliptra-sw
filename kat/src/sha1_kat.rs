/*++

Licensed under the Apache-2.0 license.

File Name:

    sha1_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA-1 cryptography operations.

--*/

use caliptra_lib::caliptra_err_def;
use caliptra_lib::Array4x5;
use caliptra_lib::Array4xN;
use caliptra_lib::CaliptraResult;
use caliptra_lib::Sha1;

caliptra_err_def! {
    Sha1,
    Sha1KatErr
    {
        // "No Data Test" failure
        NoDataTestFailure = 0x01,
    }
}

#[derive(Default, Debug)]
pub struct Sha1Kat {}

impl Sha1Kat {
    // This function executes the Known Answer Tests (aka KAT) for SHA1.
    //
    // Test vector source:
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
    //
    // # Arguments
    //
    /// * None
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self) -> CaliptraResult<()> {
        self.kat_no_data()?;
        Ok(())
    }

    fn kat_no_data(&self) -> CaliptraResult<()> {
        let expected_digest =
            Array4xN([0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709]);
        let data = [];
        let mut digest = Array4x5::default();
        let result = Sha1::default().digest(&data, &mut digest);
        if result.is_err() || digest != expected_digest {
            raise_err!(NoDataTestFailure);
        }
        Ok(())
    }
}
