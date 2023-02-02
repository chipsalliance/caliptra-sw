use crate::Array4x12;
/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384acc.rs

Abstract:

    File contains API for SHA384 accelerator operations

--*/
use crate::caliptra_err_def;
use crate::wait;
use crate::CaliptraResult;
use caliptra_registers::sha512_acc;
use caliptra_registers::sha512_acc::regs::ExecuteWriteVal;

/// Maximum mailbox capacity in Bytes.
const MAX_MAILBOX_CAPACITY_BYTES: u32 = 128 << 10;

caliptra_err_def! {
    Sha384Acc,
    Sha384AccErr
    {
        // Invalid Operation
        InvalidOp = 0x01,

        // Max data limit reached
        MaxDataErr = 0x02,

        // Array Index out of bounds
        IndexOutOfBounds = 0x03,
    }
}

pub type Sha384Digest<'a> = &'a mut Array4x12;

#[derive(Default)]
pub struct Sha384Acc {}

impl Sha384Acc {
    /// Acquire the SHA384 Accelerator lock.
    ///
    /// # Arguments
    ///
    /// * None
    ///
    /// # Returns
    ///
    /// * `Sha384AccOp` - On, success, an object representing the SHA384 accelerator operation.
    /// * 'None' - On failure to acquire the SHA384 Accelerator lock.
    pub fn try_start_operation(&self) -> Option<Sha384AccOp> {
        let sha_acc = sha512_acc::RegisterBlock::sha512_acc_csr();

        if sha_acc.lock().read().lock() {
            None
        } else {
            Some(Sha384AccOp::default())
        }
    }
}

#[derive(Default)]
pub struct Sha384AccOp {}

impl Drop for Sha384AccOp {
    /// Release the SHA384 Accelerator lock.
    ///
    /// # Arguments
    ///
    /// * None
    fn drop(&mut self) {
        let sha_acc = sha512_acc::RegisterBlock::sha512_acc_csr();
        sha_acc.lock().write(|w| w.lock(true));
    }
}

impl Sha384AccOp {
    pub fn digest(
        &mut self,
        dlen: u32,
        start_address: u32,
        maintain_data_endianess: bool,
        digest: Sha384Digest,
    ) -> CaliptraResult<()> {
        let sha_acc = sha512_acc::RegisterBlock::sha512_acc_csr();

        if start_address >= MAX_MAILBOX_CAPACITY_BYTES
            || (start_address + dlen) > MAX_MAILBOX_CAPACITY_BYTES
        {
            raise_err!(IndexOutOfBounds)
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

        Ok(())
    }

    /// Copy digest to buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Digest buffer
    fn copy_digest_to_buf(&self, buf: &mut Array4x12) -> CaliptraResult<()> {
        *buf = Array4x12::read_from_reg(sha512_acc::RegisterBlock::sha512_acc_csr().digest());
        Ok(())
    }
}
