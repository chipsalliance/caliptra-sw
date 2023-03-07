/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384acc_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA384 accelerator cryptography operations.

--*/

use caliptra_lib::{caliptra_err_def, Array4x12, Array4xN, CaliptraResult, Sha384Acc};

caliptra_err_def! {
    Sha384Acc,
    Sha384AccKatErr
    {
        // "No Data Test" failure
        NoDataTestFailure = 0x01,
    }
}

#[derive(Default)]
pub struct Sha384AccKat {}

impl Sha384AccKat {
    // This function executes the Known Answer Tests (aka KAT) for SHA384ACC.
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
        let mut digest = Array4x12::default();
        let sha_acc = Sha384Acc::default();
        if let Some(mut sha_acc_op) = sha_acc.try_start_operation() {
            let result = sha_acc_op.digest(0, 0, false, &mut digest);
            if result.is_err() || digest != expected_digest {
                raise_err!(NoDataTestFailure);
            }
            drop(sha_acc_op);
        } else {
            raise_err!(NoDataTestFailure);
        }

        Ok(())
    }
}
