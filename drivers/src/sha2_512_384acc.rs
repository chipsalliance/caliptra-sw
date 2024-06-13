/*++

Licensed under the Apache-2.0 license.

File Name:

    sha2_512_384acc.rs

Abstract:

    File contains API for SHA2 512/384 accelerator operations

--*/
use crate::wait;
use crate::CaliptraResult;
use crate::{Array4x12, Array4x16};

use caliptra_error::CaliptraError;
use caliptra_registers::sha512_acc::enums::ShaCmdE;
use caliptra_registers::sha512_acc::regs::ExecuteWriteVal;
use caliptra_registers::sha512_acc::Sha512AccCsr;

/// Maximum mailbox capacity in Bytes.
const MAX_MAILBOX_CAPACITY_BYTES: u32 = 128 << 10;

pub type Sha384Digest<'a> = &'a mut Array4x12;
pub type Sha512Digest<'a> = &'a mut Array4x16;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaAccLockState {
    AssumedLocked = 0xAAAA_AAA5,
    NotAcquired = 0x5555_555A,
}

pub struct Sha2_512_384Acc {
    sha512_acc: Sha512AccCsr,
}

impl Sha2_512_384Acc {
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
    ) -> CaliptraResult<Option<Sha2_512_384AccOp>> {
        let sha_acc = self.sha512_acc.regs();

        match assumed_lock_state {
            ShaAccLockState::NotAcquired => {
                if sha_acc.lock().read().lock() {
                    // Either SOC has the lock (correct state),
                    // or the uC has the lock but the caller doesn't realize it (bug).
                    Ok(None)
                } else {
                    // The uC acquired the lock just now.
                    Ok(Some(Sha2_512_384AccOp {
                        sha512_acc: &mut self.sha512_acc,
                    }))
                }
            }
            ShaAccLockState::AssumedLocked => {
                if sha_acc.lock().read().lock() {
                    // SHA Acc is locked and the caller is assuming that the uC has it.
                    Ok(Some(Sha2_512_384AccOp {
                        sha512_acc: &mut self.sha512_acc,
                    }))
                } else {
                    // Caller expected uC to already have the lock, but uC actually didn't (bug)
                    Err(CaliptraError::DRIVER_SHA2_512_384ACC_UNEXPECTED_ACQUIRED_LOCK_STATE)
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

pub struct Sha2_512_384AccOp<'a> {
    sha512_acc: &'a mut Sha512AccCsr,
}

impl Drop for Sha2_512_384AccOp<'_> {
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

impl Sha2_512_384AccOp<'_> {
    /// Perform SHA digest with a configurable mode
    ///
    /// # Arguments
    ///
    /// * `dlen` - length of data to read from the mailbox
    /// * `start_address` - start offset for the data in the mailbox
    /// * `maintain_data_endianess` - reorder byte endianess if false, leave as-is if true
    /// * `cmd` - SHA mode/command to use from ShaCmdE
    fn digest_generic(
        &mut self,
        dlen: u32,
        start_address: u32,
        maintain_data_endianess: bool,
        cmd: ShaCmdE,
    ) -> CaliptraResult<()> {
        let sha_acc = self.sha512_acc.regs_mut();

        if start_address >= MAX_MAILBOX_CAPACITY_BYTES
            || (start_address + dlen) > MAX_MAILBOX_CAPACITY_BYTES
        {
            return Err(CaliptraError::DRIVER_SHA2_512_384ACC_INDEX_OUT_OF_BOUNDS);
        }

        // Set the data length to read from the mailbox.
        sha_acc.dlen().write(|_| dlen);

        // Set the start offset of the data in the mailbox.
        sha_acc.start_address().write(|_| start_address);

        // Set the SHA accelerator mode and set the option to maintain the DWORD
        // endianess of the data in the mailbox provided to the SHA384 engine.
        sha_acc
            .mode()
            .write(|w| w.mode(|_| cmd).endian_toggle(maintain_data_endianess));

        // Trigger the SHA operation.
        sha_acc.execute().write(|_| ExecuteWriteVal::from(1));

        // Wait for the digest operation to finish
        wait::until(|| sha_acc.status().read().valid());

        Ok(())
    }

    /// Perform SHA 384 digest
    ///
    /// # Arguments
    ///
    /// * `dlen` - length of data to read from the mailbox
    /// * `start_address` - start offset for the data in the mailbox
    /// * `maintain_data_endianess` - reorder byte endianess if false, leave as-is if true
    /// * `digest` - buffer to populate with resulting digest
    pub fn digest_384(
        &mut self,
        dlen: u32,
        start_address: u32,
        maintain_data_endianess: bool,
        digest: Sha384Digest,
    ) -> CaliptraResult<()> {
        self.digest_generic(
            dlen,
            start_address,
            maintain_data_endianess,
            ShaCmdE::ShaMbox384,
        )?;

        // Copy digest to buffer
        let sha_acc = self.sha512_acc.regs();
        *digest = Array4x12::read_from_reg(sha_acc.digest().truncate::<12>());

        // Zeroize the hardware registers.
        self.sha512_acc
            .regs_mut()
            .control()
            .write(|w| w.zeroize(true));

        Ok(())
    }

    /// Perform SHA 512 digest
    ///
    /// # Arguments
    ///
    /// * `dlen` - length of data to read from the mailbox
    /// * `start_address` - start offset for the data in the mailbox
    /// * `maintain_data_endianess` - reorder byte endianess if false, leave as-is if true
    /// * `digest` - buffer to populate with resulting digest
    pub fn digest_512(
        &mut self,
        dlen: u32,
        start_address: u32,
        maintain_data_endianess: bool,
        digest: Sha512Digest,
    ) -> CaliptraResult<()> {
        self.digest_generic(
            dlen,
            start_address,
            maintain_data_endianess,
            ShaCmdE::ShaMbox512,
        )?;

        // Copy digest to buffer
        let sha_acc = self.sha512_acc.regs();
        *digest = Array4x16::read_from_reg(sha_acc.digest());

        // Zeroize the hardware registers.
        self.sha512_acc
            .regs_mut()
            .control()
            .write(|w| w.zeroize(true));

        Ok(())
    }
}
