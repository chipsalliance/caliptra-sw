/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384.rs

Abstract:

    File contains API for HMAC-384 Cryptography operations

--*/

use crate::kv_access::{self, KvAccess, KvAccessErr};
use crate::{
    wait, Array4x12, Array4x5, CaliptraError, CaliptraResult, FortimacRegSteal, KeyReadArgs,
    KeyWriteArgs, Trng,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_registers::kv::KvReg;
use core::usize;
use fortimac_hal::{Fortimac384, FortimacErr};
pub use fortimac_hal::{FortimacPeriph as HmacPeriph, FortimacReg as HmacReg};

const HMAC384_MAX_DATA_SIZE: usize = 1024 * 1024;

/// HMAC-384 Data
#[derive(Debug, Copy, Clone)]
pub enum Hmac384Data<'a> {
    /// Slice
    Slice(&'a [u8]),

    /// Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a [u8]> for Hmac384Data<'a> {
    /// Converts to this type from the input type.
    ///
    fn from(value: &'a [u8]) -> Self {
        Self::Slice(value)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Hmac384Data<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a [u8; N]) -> Self {
        Self::Slice(value)
    }
}

impl From<KeyReadArgs> for Hmac384Data<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

/// Hmac-384 Tag
#[derive(Debug)]
pub enum Hmac384Tag<'a> {
    /// Array
    Array4x12(&'a mut Array4x12),

    /// Key output
    Key(KeyWriteArgs),
}

impl<'a> From<&'a mut Array4x12> for Hmac384Tag<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a mut Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl<'a> From<KeyWriteArgs> for Hmac384Tag<'a> {
    /// Converts to this type from the input type.
    fn from(value: KeyWriteArgs) -> Self {
        Self::Key(value)
    }
}

///
/// Hmac-384 Key
///
#[derive(Debug, Copy, Clone)]
pub enum Hmac384Key<'a> {
    /// Array
    Array4x12(&'a Array4x12),

    // Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a Array4x12> for Hmac384Key<'a> {
    ///
    /// Converts to this type from the input type.
    ///
    fn from(value: &'a Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl From<KeyReadArgs> for Hmac384Key<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

pub struct Hmac384 {
    hmac: HmacReg,
}

impl Hmac384 {
    pub fn new(hmac: HmacReg) -> Self {
        Self { hmac }
    }
    /// Initialize multi step HMAC operation
    ///
    /// # Arguments
    ///
    /// * `key`  - HMAC Key
    /// * `trng` - TRNG driver instance
    ///
    /// * `tag`  -  The calculated tag
    pub fn hmac_init<'a>(
        &'a mut self,
        key: &Hmac384Key,
        trng: &mut Trng,
        tag: Hmac384Tag<'a>,
    ) -> CaliptraResult<Hmac384Op> {
        let mut key_vault_used = false;

        let key = match key {
            Hmac384Key::Array4x12(arr) => arr.0,
            Hmac384Key::Key(key) => {
                key_vault_used = true;
                let kv = unsafe { KvReg::new() };
                kv.regs().key_entry().at(key.id.into()).read()
            }
        };
        let key = Self::words_to_bytes_48(key);

        // Generate an LFSR seed and copy to key vault.
        // self.gen_lfsr_seed(trng)?;

        // Generate an LFSR seed.
        let rand_data = trng.generate()?;
        let hw_seed = rand_data.0[0];
        let hmac = Fortimac384::new_hmac(unsafe { HmacReg::steal() }, &key, hw_seed)
            .map_err(|err| err.into_caliptra_err())?;

        let op = Hmac384Op {
            hmac_engine: hmac,
            data_size: 0,
            tag,
            key_vault_used,
        };

        Ok(op)
    }

    /// Generate an LFSR seed and copy to keyvault.
    ///
    /// # Arguments
    ///
    /// * `trng` - TRNG driver instance
    /*fn gen_lfsr_seed(&mut self, trng: &mut Trng) -> CaliptraResult<()> {
        let hmac = self.hmac.regs_mut();

        let rand_data = trng.generate()?;

        // Support HW 1.0 RTL (except for ROM)
        #[cfg(not(feature = "rom"))]
        if crate::soc_ifc::is_hw_gen_1_0() {
            use crate::Array4x5;
            let iv: [u32; 5] = rand_data.0[..5].try_into().unwrap();
            KvAccess::copy_from_arr(&Array4x5::from(iv), hmac.lfsr_seed().truncate::<5>())?;
            return Ok(());
        }

        let iv: [u32; 12] = rand_data.0[..12].try_into().unwrap();
        KvAccess::copy_from_arr(&Array4x12::from(iv), hmac.lfsr_seed())?;
        Ok(())
    }*/

    /// Calculate the hmac for specified data
    ///
    /// # Arguments
    ///
    /// * `key`  - HMAC Key
    /// * `data` - Data to calculate the HMAC over
    /// * `trng` - TRNG driver instance
    ///
    /// * `tag`  -  The calculated tag
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn hmac(
        &mut self,
        key: &Hmac384Key,
        data: &Hmac384Data,
        trng: &mut Trng,
        tag: Hmac384Tag,
    ) -> CaliptraResult<()> {
        let mut tag = tag;
        let mut key_vault_used = false;

        let key = match key {
            Hmac384Key::Array4x12(arr) => arr.0,
            Hmac384Key::Key(key) => {
                key_vault_used = true;
                let kv = unsafe { KvReg::new() };
                kv.regs().key_entry().at(key.id.into()).read()
            }
        };
        let key = Self::words_to_bytes_48(key);

        // Generate an LFSR seed and copy to key vault.
        // self.gen_lfsr_seed(trng)?;

        // Generate an LFSR seed.
        let rand_data = trng.generate()?;
        let hw_seed = rand_data.0[0];
        let hmac = Fortimac384::new_hmac(unsafe { HmacReg::steal() }, &key, hw_seed)
            .map_err(|err| err.into_caliptra_err())?;

        // Calculate the hmac
        let mut digest_bytes = [0; 48];
        match data {
            Hmac384Data::Slice(buf) => {
                hmac.digest(buf, &mut digest_bytes)
                    .map_err(|err| err.into_caliptra_err())?;
            }
            Hmac384Data::Key(key) => {
                key_vault_used = true;
                let kv = unsafe { KvReg::new() };
                let buf = kv.regs().key_entry().at(key.id.into()).read();
                let len = kv.regs().key_ctrl().at(key.id.into()).read().last_dword();
                let buf = Self::words_to_bytes_48(buf);
                let len = ((len + 1) * 4) as usize;
                hmac.digest(&buf[..len], &mut digest_bytes)
                    .map_err(|err| err.into_caliptra_err())?;
            }
        }

        let digest = Array4x12::from(digest_bytes);

        // Copy the tag to the specified location
        match &mut tag {
            Hmac384Tag::Array4x12(arr) => {
                **arr = if key_vault_used {
                    Array4x12::default() // zeros according to comment in `test_hmac5`
                } else {
                    digest
                }
            }
            Hmac384Tag::Key(key) => {
                let mut kv = unsafe { KvReg::new() };
                let valid = u32::from(key.usage.hmac_key())
                    + (u32::from(key.usage.hmac_data()) << 1)
                    + (u32::from(key.usage.sha_data()) << 2)
                    + (u32::from(key.usage.ecc_private_key()) << 3);
                kv.regs_mut()
                    .key_ctrl()
                    .at(key.id.into())
                    .write(|w| w.dest_valid(valid));
                kv.regs_mut().key_entry().at(key.id.into()).write(&digest.0);
            }
        };

        self.zeroize_internal();

        Ok(())
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        unsafe { self.hmac.cfg().write_with_zero(|w| w.srst().set_bit()) };
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
        let hmac = HmacReg::steal();
        hmac.cfg().write_with_zero(|w| w.srst().set_bit());
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

/// HMAC multi step operation
pub struct Hmac384Op<'a> {
    /// Hmac-384 Engine
    hmac_engine: Fortimac384,

    /// Data size
    data_size: usize,

    /// Tag
    tag: Hmac384Tag<'a>,

    key_vault_used: bool,
}

impl<'a> Hmac384Op<'a> {
    ///
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    pub fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.data_size + data.len() > HMAC384_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_HMAC384_MAX_DATA);
        }

        self.hmac_engine
            .update(data)
            .map_err(|err| err.into_caliptra_err())?;

        Ok(())
    }

    /// Finalize the digest operations
    pub fn finalize(mut self) -> CaliptraResult<()> {
        let mut digest_bytes = [0; 48];
        self.hmac_engine
            .finalize(&mut digest_bytes)
            .map_err(|err| err.into_caliptra_err())?;
        let digest = Array4x12::from(digest_bytes);

        // Copy the tag to the specified location
        match &mut self.tag {
            Hmac384Tag::Array4x12(arr) => {
                **arr = if self.key_vault_used {
                    Array4x12::default() // zeros according to comment in `test_hmac5`
                } else {
                    digest
                }
            }
            Hmac384Tag::Key(key) => {
                let mut kv = unsafe { KvReg::new() };
                let valid = u32::from(key.usage.hmac_key())
                    + (u32::from(key.usage.hmac_data()) << 1)
                    + (u32::from(key.usage.sha_data()) << 2)
                    + (u32::from(key.usage.ecc_private_key()) << 3);
                kv.regs_mut()
                    .key_ctrl()
                    .at(key.id.into())
                    .write(|w| w.dest_valid(valid));
                kv.regs_mut().key_entry().at(key.id.into()).write(&digest.0)
            }
        }

        Ok(())
    }
}

/// HMAC-384 Fortimac error trait
trait HmacFortimacErr {
    fn into_caliptra_err(self) -> CaliptraError;
}

impl HmacFortimacErr for FortimacErr {
    /// Convert Fortimac errors to Caliptra during processing
    fn into_caliptra_err(self) -> CaliptraError {
        match self {
            FortimacErr::InvalidState => CaliptraError::DRIVER_HMAC384_INVALID_STATE,
            FortimacErr::DataProc => CaliptraError::DRIVER_HMAC384_DATA_PROC,
            FortimacErr::FaultInj => CaliptraError::DRIVER_HMAC384_FAULT_INJ,
        }
    }
}
