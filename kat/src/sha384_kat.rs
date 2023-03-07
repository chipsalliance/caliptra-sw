/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA-384 cryptography operations.

--*/

use caliptra_lib::caliptra_err_def;
use caliptra_lib::Array4x12;
use caliptra_lib::Array4xN;
use caliptra_lib::CaliptraResult;
use caliptra_lib::Sha384;

caliptra_err_def! {
    Sha384,
    Sha384KatErr
    {
        // "No Data Test" failure
        NoDataTestFailure = 0x01,
    }
}

#[derive(Default, Debug)]
pub struct Sha384Kat {}

impl Sha384Kat {
    // This function executes the Known Answer Tests (aka KAT) for SHA384.
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

    // Performs the digest operation on a zero size buffer.
    //
    // # Arguments
    //
    /// * None
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    fn kat_no_data(&self) -> CaliptraResult<()> {
        let expected_digest = Array4xN([
            0x38b060a7, 0x51ac9638, 0x4cd9327e, 0xb1b1e36a, 0x21fdb711, 0x14be0743, 0x4c0cc7bf,
            0x63f6e1da, 0x274edebf, 0xe76f65fb, 0xd51ad2f1, 0x4898b95b,
        ]);
        let data = &[];
        let mut digest = Array4x12::default();
        let result = Sha384::default().digest(data.into(), (&mut digest).into());
        if result.is_err() || digest != expected_digest {
            raise_err!(NoDataTestFailure);
        }
        Ok(())
    }
}
