/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384acc_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA384 accelerator cryptography operations.

--*/
use crate::sha384_kat::SHA384_EXPECTED_DIGEST;
use caliptra_drivers::{Array4x12, CaliptraError, CaliptraResult, Sha384Acc, ShaAccLockState};

#[derive(Default)]
pub struct Sha384AccKat {}

impl Sha384AccKat {
    /// This function executes the Known Answer Tests (aka KAT) for SHA384ACC.
    ///
    /// Test vector source:
    /// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
    ///
    /// # Arguments
    ///
    /// * `sha_acc` - SHA2-384 Accelerator Driver
    /// * `lock_state` - SHA Acc Lock State
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(
        &self,
        sha_acc: &mut Sha384Acc,
        lock_state: ShaAccLockState,
    ) -> CaliptraResult<()> {
        self.kat_no_data(sha_acc, lock_state)?;
        Ok(())
    }

    fn kat_no_data(
        &self,
        sha_acc: &mut Sha384Acc,
        lock_state: ShaAccLockState,
    ) -> CaliptraResult<()> {
        let mut digest = Array4x12::default();

        if let Some(mut sha_acc_op) = sha_acc.try_start_operation(lock_state)? {
            sha_acc_op
                .digest(0, 0, false, &mut digest)
                .map_err(|_| CaliptraError::KAT_SHA384_ACC_DIGEST_FAILURE)?;
            if digest != SHA384_EXPECTED_DIGEST {
                // Don't drop the operation, since that will unlock the
                // peripheral for SoC use, which we're not allowed to do if the
                // KAT doesn't pass.
                core::mem::forget(sha_acc_op);
                Err(CaliptraError::KAT_SHA384_ACC_DIGEST_MISMATCH)?;
            }
        } else {
            Err(CaliptraError::KAT_SHA384_ACC_DIGEST_START_OP_FAILURE)?;
        }

        Ok(())
    }
}
