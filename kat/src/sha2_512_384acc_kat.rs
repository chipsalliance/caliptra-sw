/*++

Licensed under the Apache-2.0 license.

File Name:

    sha2_512_384acc_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for SHA512 accelerator cryptography operations.

--*/
use caliptra_drivers::{
    Array4x16, CaliptraError, CaliptraResult, Sha2_512_384Acc, ShaAccLockState,
};

const SHA512_EXPECTED_DIGEST: Array4x16 = Array4x16::new([
    0xcf83e135, 0x7eefb8bd, 0xf1542850, 0xd66d8007, 0xd620e405, 0x0b5715dc, 0x83f4a921, 0xd36ce9ce,
    0x47d0d13c, 0x5d85f2b0, 0xff8318d2, 0x877eec2f, 0x63b931bd, 0x47417a81, 0xa538327a, 0xf927da3e,
]);

#[derive(Default)]
pub struct Sha2_512_384AccKat {}

impl Sha2_512_384AccKat {
    /// This function executes the Known Answer Tests (aka KAT) for SHA512ACC.
    /// Performing this test for SHA512 mode also covers SHA384
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
        sha_acc: &mut Sha2_512_384Acc,
        lock_state: ShaAccLockState,
    ) -> CaliptraResult<()> {
        self.kat_no_data(sha_acc, lock_state)?;
        Ok(())
    }

    fn kat_no_data(
        &self,
        sha_acc: &mut Sha2_512_384Acc,
        lock_state: ShaAccLockState,
    ) -> CaliptraResult<()> {
        let mut digest = Array4x16::default();

        if let Some(mut sha_acc_op) = sha_acc.try_start_operation(lock_state)? {
            let result = || -> CaliptraResult<()> {
                // SHA 512
                sha_acc_op
                    .digest_512(0, 0, false, &mut digest)
                    .map_err(|_| CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_FAILURE)?;
                if digest.ne(&SHA512_EXPECTED_DIGEST) {
                    Err(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_MISMATCH)?;
                }

                Ok(())
            }();

            // If error, don't drop the operation since that will unlock the
            // peripheral for SoC use, which we're not allowed to do if the
            // KAT doesn't pass.
            if result.is_err() {
                caliptra_drivers::cprintln!("Droping operation");
                core::mem::forget(sha_acc_op);
            }
            result?;
        } else {
            Err(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE)?;
        };

        Ok(())
    }
}
