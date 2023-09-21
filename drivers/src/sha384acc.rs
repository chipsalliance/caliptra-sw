/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384acc.rs

Abstract:

    File contains API for SHA384 accelerator operations

--*/
use crate::wait;
use crate::Array4x12;
use crate::CaliptraResult;

use caliptra_error::CaliptraError;
use caliptra_registers::sha512_acc::regs::ExecuteWriteVal;
use caliptra_registers::sha512_acc::Sha512AccCsr;

/// Maximum mailbox capacity in Bytes.
const MAX_MAILBOX_CAPACITY_BYTES: u32 = 128 << 10;

pub type Sha384Digest<'a> = &'a mut Array4x12;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaAccLockState {
    AssumedLockState = 0xAAAA_AAA5,
    NotAcquired = 0x5555_555A,
}

pub struct Sha384Acc {
    sha512_acc: Sha512AccCsr,
}

impl Sha384Acc {
    pub fn new(sha512_acc: Sha512AccCsr) -> Self {
        Self { sha512_acc }
    }
    /// Acquire the SHA384 Accelerator lock.
    ///
    /// # Arguments
    ///
    /// * assumed_lock_state - The assumed lock state of the SHA384 Accelerator.
    /// Note: Callers should pass assumed_lock_state=ShaAccLockState::NotAcquired
    ///  unless they are the first caller to the peripheral after a cold/warm boot.
    ///
    /// # Returns
    ///
    /// * On success, either an object representing the SHA384 accelerator operation or
    /// 'None' if unable to acquire the SHA384 Accelerator lock.
    /// On failure, an error code.
    ///
    pub fn try_start_operation(
        &mut self,
        assumed_lock_state: ShaAccLockState,
    ) -> CaliptraResult<Option<Sha384AccOp>> {
        let sha_acc = self.sha512_acc.regs();

        match assumed_lock_state {
            ShaAccLockState::NotAcquired => {
                if sha_acc.lock().read().lock() {
                    // Either SOC has the lock (correct state),
                    // or the uC has the lock but the caller doesn't realize it (bug).
                    Ok(None)
                } else {
                    // The uC acquired the lock just now.
                    Ok(Some(Sha384AccOp {
                        sha512_acc: &mut self.sha512_acc,
                    }))
                }
            }
            ShaAccLockState::AssumedLockState => {
                if sha_acc.lock().read().lock() {
                    // SHA Acc is locked and the caller is assuming that the uC has it.
                    Ok(Some(Sha384AccOp {
                        sha512_acc: &mut self.sha512_acc,
                    }))
                } else {
                    // Caller expected uC to already have the lock, but uC actually didn't (bug)
                    Err(CaliptraError::DRIVER_SHA384ACC_UNEXPECTED_ACQUIRED_LOCK_STATE)
                }
            }
        }
    }

    /// Zeroize the hardware registers.
    ///
    /// This is useful to call from a fatal-error-handling routine.
    ///
    /// # Safety
    ///
    /// The caller must be certain that the results of any pending cryptographic
    /// operations will not be used after this function is called.
    ///
    /// This function is safe to call from a trap handler.
    pub unsafe fn zeroize() {
        let mut sha512_acc = Sha512AccCsr::new();
        sha512_acc.regs_mut().control().write(|w| w.zeroize(true));
    }

    /// Lock the accelerator.
    ///
    /// This is useful to call from a fatal-error-handling routine.
    ///
    /// # Safety
    ///
    /// The caller must be certain that the results of any pending cryptographic
    /// operations will not be used after this function is called.
    ///
    /// This function is safe to call from a trap handler.
    pub unsafe fn lock() {
        let sha512_acc = Sha512AccCsr::new();
        while sha512_acc.regs().lock().read().lock()
            && sha512_acc.regs().status().read().soc_has_lock()
        {}
    }

    /// Try to acquire the accelerator lock.
    ///
    /// This is useful to call from a fatal-error-handling routine.
    ///
    /// # Safety
    ///
    /// The caller must be certain that the results of any pending cryptographic
    /// operations will not be used after this function is called.
    ///
    /// This function is safe to call from a trap handler.
    pub unsafe fn try_lock() {
        let sha512_acc = Sha512AccCsr::new();
        sha512_acc.regs().lock().read().lock();
    }
}

pub struct Sha384AccOp<'a> {
    sha512_acc: &'a mut Sha512AccCsr,
}

impl Drop for Sha384AccOp<'_> {
    /// Release the SHA384 Accelerator lock.
    ///
    /// # Arguments
    ///
    /// * None
    fn drop(&mut self) {
        let sha_acc = self.sha512_acc.regs_mut();
        sha_acc.lock().write(|w| w.lock(true));
    }
}

impl Sha384AccOp<'_> {
    pub fn digest(
        &mut self,
        dlen: u32,
        start_address: u32,
        maintain_data_endianess: bool,
        digest: Sha384Digest,
    ) -> CaliptraResult<()> {
        let sha_acc = self.sha512_acc.regs_mut();

        if start_address >= MAX_MAILBOX_CAPACITY_BYTES
            || (start_address + dlen) > MAX_MAILBOX_CAPACITY_BYTES
        {
            return Err(CaliptraError::DRIVER_SHA384ACC_INDEX_OUT_OF_BOUNDS);
        }

        // Set the data length to read from the mailbox.
        sha_acc.dlen().write(|_| dlen);

        // Set the start offset of the data in the mailbox.
        sha_acc.start_address().write(|_| start_address);

        // Set the SHA accelerator mode (only SHA384 supported) and
        // set the option to maintain the DWORD endianess of the data in the
        // mailbox provided to the SHA384 engine.
        sha_acc.mode().write(|w| {
            w.mode(|w| w.sha_mbox_384())
                .endian_toggle(maintain_data_endianess)
        });

        // Trigger the SHA384 operation.
        sha_acc.execute().write(|_| ExecuteWriteVal::from(1));

        // Wait for the digest operation to finish
        wait::until(|| sha_acc.status().read().valid());

        self.copy_digest_to_buf(digest)?;

        // Zeroize the hardware registers.
        self.sha512_acc
            .regs_mut()
            .control()
            .write(|w| w.zeroize(true));

        Ok(())
    }

    /// Copy digest to buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Digest buffer
    fn copy_digest_to_buf(&mut self, buf: &mut Array4x12) -> CaliptraResult<()> {
        let sha_acc = self.sha512_acc.regs();
        *buf = Array4x12::read_from_reg(sha_acc.digest().truncate::<12>());
        Ok(())
    }
}
