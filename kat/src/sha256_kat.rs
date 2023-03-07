/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA-256 cryptography operations.

--*/

use caliptra_lib::Array4xN;
use caliptra_lib::CaliptraResult;
use caliptra_lib::Sha256;
use caliptra_lib::{caliptra_err_def, Array4x8};

caliptra_err_def! {
    Sha256,
    Sha256KatErr
    {
        // "No Data Test" failure
        NoDataTestFailure = 0x01,
    }
}

#[derive(Default, Debug)]
pub struct Sha256Kat {}

impl Sha256Kat {
    // This function executes the Known Answer Tests (aka KAT) for SHA256.
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
        let expected_digest = Array4xN([
            0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
            0x7852b855,
        ]);
        let data = [];
        let mut digest = Array4x8::default();
        let result = Sha256::default().digest(&data, &mut digest);
        if result.is_err() || digest != expected_digest {
            raise_err!(NoDataTestFailure);
        }
        Ok(())
    }
}
