/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384.rs

Abstract:

    File contains API for SHA-384 Cryptography operations

--*/

use core::marker::PhantomData;
use core::usize;

use crate::{pcr_bank::PcrBank, Array4x12, Array4x8, FortimacRegSteal, PcrId};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::pv::PvReg;
use fortimac_hal::{Fortimac384, FortimacErr};
pub use fortimac_hal::{FortimacPeriph as Sha384Periph, FortimacReg as Sha384Reg};

// TODO: Fortimac requires seed, consider replacing with prng
const SEED: u32 = 0;
const SHA384_BLOCK_BYTE_SIZE: usize = 128;
const SHA384_MAX_DATA_SIZE: usize = 1024 * 1024;
pub const SHA384_HASH_SIZE: usize = 48;

/// SHA-384 Digest
pub type Sha384Digest<'a> = &'a mut Array4x12;

pub struct Sha384 {
    sha384: Sha384Reg,
}

impl Sha384 {
    pub fn new(sha384: Sha384Reg) -> Self {
        Self { sha384 }
    }
    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha384Digest` - Object representing the digest operation
    pub fn digest_init<'a>(&'a mut self) -> CaliptraResult<Sha384DigestOp<'a>> {
        let engine = Fortimac384::new_sha(unsafe { Sha384Reg::steal() }, SEED);
        let op = Sha384DigestOp {
            _marker: PhantomData,
            sha: engine,
            data_size: 0,
        };

        Ok(op)
    }

    /// Calculate the digest for specified data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x12> {
        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::SHA384_DIGEST_FAILURE)?
        }

        // Check if the buffer is not large
        if buf.len() > SHA384_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        let sha = Fortimac384::new_sha(unsafe { Sha384Reg::steal() }, SEED);

        let mut digest = [0; 48];
        sha.digest(buf, &mut digest)
            .map_err(|err| err.into_caliptra_err())?;

        #[cfg(feature = "fips-test-hooks")]
        let digest = unsafe {
            crate::FipsTestHook::corrupt_data_if_hook_set(
                crate::FipsTestHook::SHA384_CORRUPT_DIGEST,
                &digest,
            )
        };

        self.zeroize_internal();

        Ok(Array4x12::from(digest))
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        unsafe { self.sha384.cfg().write_with_zero(|w| w.srst().set_bit()) };
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
        let sha384 = Sha384Reg::steal();
        sha384.cfg().write_with_zero(|w| w.srst().set_bit());
    }

    /// Generate digest over PCRs + nonce
    ///
    /// # Arguments
    ///
    /// * `nonce`- Nonce buffer
    ///
    /// # Returns
    ///
    /// * `buf` - Digest buffer
    pub fn gen_pcr_hash(&mut self, nonce: Array4x8) -> CaliptraResult<Array4x12> {
        let pv = unsafe { PvReg::new() };

        // Read pcr vault as array of bytes
        let mut pcr_data = PcrBank::ALL_PCR_IDS
            .into_iter()
            .map(|pcr_id| {
                let entry = pv.regs().pcr_entry().at(pcr_id.into()).read();
                Self::words_to_bytes_48(entry)
            })
            .enumerate()
            .fold(
                [0; PcrBank::ALL_PCR_IDS.len() * 48 + 32], // bytes for all pcr entries + nonce
                |mut acc, (index, next)| {
                    acc[index * 48..(index + 1) * 48].copy_from_slice(&next);

                    acc
                },
            );

        // Fill nonce bytes
        let len = pcr_data.len();
        let nonce = Self::words_to_bytes_32(nonce.0);
        pcr_data[len - 32..].copy_from_slice(&nonce);

        self.digest(&pcr_data)
    }

    pub fn pcr_extend(&mut self, id: PcrId, data: &[u8]) -> CaliptraResult<()> {
        let total_bytes = data.len() + SHA384_HASH_SIZE;
        if total_bytes > (SHA384_BLOCK_BYTE_SIZE - 1) {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        // Wait on the PCR to be retrieved from the PCR vault.
        let pcr = self.retrieve_pcr(id)?;
        let pcr = Self::words_to_bytes_48(pcr);

        // Prepare the data block; first SHA384_HASH_SIZE bytes are not filled
        // to account for the PCR retrieved. The retrieved PCR is unaffected as
        // writing to the first SHA384_HASH_SIZE bytes is skipped by the hardware.
        let mut block = [0u8; SHA384_BLOCK_BYTE_SIZE];

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if SHA384_HASH_SIZE > total_bytes || total_bytes > block.len() {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }
        block[..SHA384_HASH_SIZE].copy_from_slice(&pcr);
        block[SHA384_HASH_SIZE..total_bytes].copy_from_slice(data);

        if let Some(slice) = block.get(..total_bytes) {
            let sha = Fortimac384::new_sha(unsafe { Sha384Reg::steal() }, SEED);
            let mut digest = [0; 48];
            sha.digest(slice, &mut digest)
                .map_err(|err| err.into_caliptra_err())?;
            // write back to `id`-th slot in pcr vault
            let mut pv = unsafe { PvReg::new() };
            let digest = Array4x12::from(digest);
            pv.regs_mut().pcr_entry().at(id.into()).write(&digest.0);
        } else {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        Ok(())
    }

    /// Waits for the PCR to be retrieved from the PCR vault
    /// and copied to the block registers.
    ///
    /// # Arguments
    ///
    /// * `pcr_id` - PCR to hash extend
    fn retrieve_pcr(&mut self, pcr_id: PcrId) -> CaliptraResult<[u32; 12]> {
        let pv = unsafe { PvReg::new() }; // or use bank like in tests
        let pcr = pv.regs().pcr_entry().at(pcr_id.into()).read();

        Ok(pcr)
    }

    /// Converts word array to byte array
    fn words_to_bytes_32(words: [u32; 8]) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (chunk, word) in bytes.chunks_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }

        bytes
    }

    /// Converts word array to byte array
    fn words_to_bytes_48(words: [u32; 12]) -> [u8; 48] {
        let mut bytes = [0; 48];
        for (chunk, word) in bytes.chunks_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }

        bytes
    }
}

/// Multi step SHA-384 digest operation
pub struct Sha384DigestOp<'a> {
    /// Keep the original behaviour
    _marker: PhantomData<&'a ()>,

    /// SHA-384 Engine
    sha: Fortimac384,

    /// Data size
    data_size: usize,
}

impl Sha384DigestOp<'_> {
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    pub fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.data_size + data.len() > SHA384_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        self.sha
            .update(data)
            .map_err(|err| err.into_caliptra_err())?;

        Ok(())
    }

    /// Finalize the digest operations
    pub fn finalize(self, digest: &mut Array4x12) -> CaliptraResult<()> {
        let mut digest_bytes = [0; 48];
        self.sha
            .finalize(&mut digest_bytes)
            .map_err(|err| err.into_caliptra_err())?;
        *digest = Array4x12::from(digest_bytes);

        Ok(())
    }
}

/// SHA-384 Fortimac error trait
trait Sha384FortimacErr {
    fn into_caliptra_err(self) -> CaliptraError;
}

impl Sha384FortimacErr for FortimacErr {
    /// Convert Fortimac errors to Caliptra during processing
    fn into_caliptra_err(self) -> CaliptraError {
        match self {
            FortimacErr::InvalidState => CaliptraError::DRIVER_SHA384_INVALID_STATE_ERR,
            FortimacErr::DataProc => CaliptraError::DRIVER_SHA384_DATA_PROC,
            FortimacErr::FaultInj => CaliptraError::DRIVER_SHA384_FAULT_INJ,
        }
    }
}
