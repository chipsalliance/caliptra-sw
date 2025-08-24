/*++

Licensed under the Apache-2.0 license.

File Name:

    ml_kem.rs

Abstract:

    File contains API for ML-KEM-1024 Cryptography operations

--*/
#![allow(dead_code)]

use crate::{
    array::{LEArray4x392, LEArray4x792, LEArray4x8},
    kv_access::{KvAccess, KvAccessErr},
    wait, CaliptraError, CaliptraResult, KeyReadArgs, KeyWriteArgs,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_derive::Launder;
use caliptra_registers::abr::{AbrReg, RegisterBlock};

#[must_use]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Launder)]
pub enum MlKemResult {
    Success = 0xAAAAAAAA,
    OperationFailed = 0x55555555,
}

/// ML-KEM-1024 Encapsulation Key (1568 bytes)
pub type MlKem1024EncapsKey = LEArray4x392;

/// ML-KEM-1024 Decapsulation Key (3168 bytes)
pub type MlKem1024DecapsKey = LEArray4x792;

/// ML-KEM-1024 Ciphertext (1568 bytes)
pub type MlKem1024Ciphertext = LEArray4x392;

/// ML-KEM-1024 Shared Key (32 bytes)
pub type MlKem1024SharedKey = LEArray4x8;

/// ML-KEM-1024 Message (32 bytes)
pub type MlKem1024Message = LEArray4x8;

/// ML-KEM-1024 Seed (32 bytes)
pub type MlKem1024Seed = LEArray4x8;

// Control register constants.
const KEYGEN: u32 = 1;
const ENCAPS: u32 = 2;
const DECAPS: u32 = 3;
const KEYGEN_DECAPS: u32 = 4;

/// ML-KEM-1024 Seeds
#[derive(Debug, Copy, Clone)]
pub enum MlKem1024Seeds<'a> {
    /// Array pair (seed_d, seed_z)
    Arrays(&'a MlKem1024Seed, &'a MlKem1024Seed),

    /// Key Vault Key (contains both seeds)
    Key(KeyReadArgs),
}

impl<'a> From<(&'a MlKem1024Seed, &'a MlKem1024Seed)> for MlKem1024Seeds<'a> {
    /// Converts to this type from the input type.
    fn from(value: (&'a MlKem1024Seed, &'a MlKem1024Seed)) -> Self {
        Self::Arrays(value.0, value.1)
    }
}

impl From<KeyReadArgs> for MlKem1024Seeds<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

/// ML-KEM-1024 Message source
#[derive(Debug, Copy, Clone)]
pub enum MlKem1024MessageSource<'a> {
    /// Array
    Array(&'a MlKem1024Message),

    /// Key Vault Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a MlKem1024Message> for MlKem1024MessageSource<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a MlKem1024Message) -> Self {
        Self::Array(value)
    }
}

impl From<KeyReadArgs> for MlKem1024MessageSource<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

/// ML-KEM-1024 Shared Key output
#[derive(Debug)]
pub enum MlKem1024SharedKeyOut<'a> {
    /// Array
    Array(&'a mut MlKem1024SharedKey),

    /// Key Vault Key
    Key(KeyWriteArgs),
}

impl<'a> From<&'a mut MlKem1024SharedKey> for MlKem1024SharedKeyOut<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a mut MlKem1024SharedKey) -> Self {
        Self::Array(value)
    }
}

impl From<KeyWriteArgs> for MlKem1024SharedKeyOut<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyWriteArgs) -> Self {
        Self::Key(value)
    }
}

/// ML-KEM-1024 API
pub struct MlKem1024 {
    mlkem: AbrReg,
}

impl MlKem1024 {
    pub fn new(mlkem: AbrReg) -> Self {
        Self { mlkem }
    }

    // Wait on the provided condition OR the error condition defined in this function
    // In the event of the error condition being set, clear the error bits and return an error
    fn wait<F>(regs: RegisterBlock<ureg::RealMmioMut>, condition: F) -> CaliptraResult<()>
    where
        F: Fn() -> bool,
    {
        let err_condition = || {
            (u32::from(regs.intr_block_rf().error_global_intr_r().read()) != 0)
                || (u32::from(regs.intr_block_rf().error_internal_intr_r().read()) != 0)
                || regs.mlkem_status().read().error()
        };

        // Wait for either the given condition or the error condition
        wait::until(|| (condition() || err_condition()));

        if err_condition() {
            // Clear the errors
            // error_global_intr_r is RO
            regs.intr_block_rf()
                .error_internal_intr_r()
                .write(|_| u32::from(regs.intr_block_rf().error_internal_intr_r().read()).into());
            return Err(CaliptraError::DRIVER_MLKEM_HW_ERROR);
        }

        Ok(())
    }

    /// Generate ML-KEM-1024 Key Pair
    ///
    /// # Arguments
    ///
    /// * `seeds` - Either arrays of seed_d and seed_z or a key vault key containing both seeds.
    ///
    /// # Returns
    ///
    /// * `(MlKem1024EncapsKey, MlKem1024DecapsKey)` - Generated ML-KEM-1024 key pair
    pub fn key_pair(
        &mut self,
        seeds: MlKem1024Seeds,
    ) -> CaliptraResult<(MlKem1024EncapsKey, MlKem1024DecapsKey)> {
        let mlkem = self.mlkem.regs_mut();

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().ready())?;

        // Clear the hardware before start
        mlkem.mlkem_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().ready())?;

        // Copy seeds to the hardware
        match seeds {
            MlKem1024Seeds::Arrays(seed_d, seed_z) => {
                seed_d.write_to_reg(mlkem.mlkem_seed_d());
                seed_z.write_to_reg(mlkem.mlkem_seed_z());
            }
            MlKem1024Seeds::Key(key) => KvAccess::copy_from_kv(
                key,
                mlkem.kv_mlkem_seed_rd_status(),
                mlkem.kv_mlkem_seed_rd_ctrl(),
            )
            .map_err(|err| err.into_read_seed_err())?,
        }

        // Program the command register for key generation
        mlkem.mlkem_ctrl().write(|w| w.ctrl(KEYGEN));

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().valid())?;

        // Copy keys
        let encaps_key = MlKem1024EncapsKey::read_from_reg(mlkem.mlkem_encaps_key());
        let decaps_key = MlKem1024DecapsKey::read_from_reg(mlkem.mlkem_decaps_key());

        // Clear the hardware when done
        mlkem.mlkem_ctrl().write(|w| w.zeroize(true));

        Ok((encaps_key, decaps_key))
    }

    /// Encapsulate a shared secret
    ///
    /// # Arguments
    ///
    /// * `encaps_key` - Encapsulation key.
    /// * `message` - Message source (array or key vault).
    /// * `shared_key_out` - Shared key output destination.
    ///
    /// # Returns
    ///
    /// * `MlKem1024Ciphertext` - Generated ciphertext
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn encapsulate(
        &mut self,
        encaps_key: &MlKem1024EncapsKey,
        message: MlKem1024MessageSource,
        shared_key_out: MlKem1024SharedKeyOut,
    ) -> CaliptraResult<MlKem1024Ciphertext> {
        let mlkem = self.mlkem.regs_mut();

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().ready())?;

        // Clear the hardware before start
        mlkem.mlkem_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().ready())?;

        // Copy encapsulation key
        encaps_key.write_to_reg(mlkem.mlkem_encaps_key());

        // Copy message
        match message {
            MlKem1024MessageSource::Array(msg) => msg.write_to_reg(mlkem.mlkem_msg()),
            MlKem1024MessageSource::Key(key) => KvAccess::copy_from_kv(
                key,
                mlkem.kv_mlkem_msg_rd_status(),
                mlkem.kv_mlkem_msg_rd_ctrl(),
            )
            .map_err(|err| err.into_read_msg_err())?,
        }

        // Set up shared key output destination
        let mut shared_key_out = shared_key_out;
        match &mut shared_key_out {
            MlKem1024SharedKeyOut::Array(_) => {
                // No key vault setup needed for array output
            }
            MlKem1024SharedKeyOut::Key(key) => {
                mlkem.kv_mlkem_sharedkey_wr_ctrl().write(|w| {
                    w.write_en(true)
                        .write_entry(key.id.into())
                        .hmac_key_dest_valid(key.usage.hmac_key())
                        .hmac_block_dest_valid(key.usage.hmac_data())
                        .mldsa_seed_dest_valid(key.usage.mldsa_seed())
                        .ecc_pkey_dest_valid(key.usage.ecc_key_gen_seed())
                        .ecc_seed_dest_valid(key.usage.ecc_private_key())
                        .aes_key_dest_valid(key.usage.aes_key())
                        .mlkem_seed_dest_valid(key.usage.mlkem_seed())
                        .mlkem_msg_dest_valid(key.usage.mlkem_msg())
                });
            }
        }

        // Program the command register for encapsulation
        mlkem.mlkem_ctrl().write(|w| w.ctrl(ENCAPS));

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().valid())?;

        // Copy results
        match &mut shared_key_out {
            MlKem1024SharedKeyOut::Array(shared_key) => {
                **shared_key = MlKem1024SharedKey::read_from_reg(mlkem.mlkem_shared_key());
            }
            MlKem1024SharedKeyOut::Key(_) => {
                // Wait for key vault write to complete
                MlKem1024::wait(mlkem, || {
                    mlkem.kv_mlkem_sharedkey_wr_status().read().valid()
                })?;
            }
        }

        let ciphertext = MlKem1024Ciphertext::read_from_reg(mlkem.mlkem_ciphertext());

        // Clear the hardware when done
        mlkem.mlkem_ctrl().write(|w| w.zeroize(true));

        Ok(ciphertext)
    }

    /// Decapsulate a shared secret
    ///
    /// # Arguments
    ///
    /// * `decaps_key` - Decapsulation key.
    /// * `ciphertext` - Ciphertext to decapsulate.
    /// * `shared_key_out` - Shared key output destination.
    ///
    /// # Returns
    ///
    /// * `()` - Success
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn decapsulate(
        &mut self,
        decaps_key: &MlKem1024DecapsKey,
        ciphertext: &MlKem1024Ciphertext,
        shared_key_out: MlKem1024SharedKeyOut,
    ) -> CaliptraResult<()> {
        let mlkem = self.mlkem.regs_mut();

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().ready())?;

        // Clear the hardware before start
        mlkem.mlkem_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().ready())?;

        // Copy decapsulation key and ciphertext
        decaps_key.write_to_reg(mlkem.mlkem_decaps_key());
        ciphertext.write_to_reg(mlkem.mlkem_ciphertext());

        // Set up shared key output destination
        let mut shared_key_out = shared_key_out;
        match &mut shared_key_out {
            MlKem1024SharedKeyOut::Array(_) => {
                // No key vault setup needed for array output
            }
            MlKem1024SharedKeyOut::Key(key) => {
                mlkem.kv_mlkem_sharedkey_wr_ctrl().write(|w| {
                    w.write_en(true)
                        .write_entry(key.id.into())
                        .hmac_key_dest_valid(key.usage.hmac_key())
                        .hmac_block_dest_valid(key.usage.hmac_data())
                        .mldsa_seed_dest_valid(key.usage.mldsa_seed())
                        .ecc_pkey_dest_valid(key.usage.ecc_private_key())
                        .ecc_seed_dest_valid(key.usage.ecc_key_gen_seed())
                        .aes_key_dest_valid(key.usage.aes_key())
                        .mlkem_seed_dest_valid(key.usage.mlkem_seed())
                        .mlkem_msg_dest_valid(key.usage.mlkem_msg())
                });
            }
        }

        // Program the command register for decapsulation
        mlkem.mlkem_ctrl().write(|w| w.ctrl(DECAPS));

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().valid())?;

        // Copy results
        match &mut shared_key_out {
            MlKem1024SharedKeyOut::Array(shared_key) => {
                **shared_key = MlKem1024SharedKey::read_from_reg(mlkem.mlkem_shared_key());
            }
            MlKem1024SharedKeyOut::Key(_) => {
                // Wait for key vault write to complete
                MlKem1024::wait(mlkem, || {
                    mlkem.kv_mlkem_sharedkey_wr_status().read().valid()
                })?;
            }
        }

        // Clear the hardware when done
        mlkem.mlkem_ctrl().write(|w| w.zeroize(true));

        Ok(())
    }

    /// Generate key pair and immediately decapsulate (saves memory for decaps key)
    ///
    /// # Arguments
    ///
    /// * `seeds` - Either arrays of seed_d and seed_z or a key vault key containing both seeds.
    /// * `ciphertext` - Ciphertext to decapsulate.
    /// * `shared_key_out` - Shared key output destination.
    ///
    /// # Returns
    ///
    /// * `()` - Success
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn keygen_decapsulate(
        &mut self,
        seeds: MlKem1024Seeds,
        ciphertext: &MlKem1024Ciphertext,
        shared_key_out: MlKem1024SharedKeyOut,
    ) -> CaliptraResult<()> {
        let mlkem = self.mlkem.regs_mut();

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().ready())?;

        // Clear the hardware before start
        mlkem.mlkem_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().ready())?;

        // Copy seeds to the hardware
        match seeds {
            MlKem1024Seeds::Arrays(seed_d, seed_z) => {
                seed_d.write_to_reg(mlkem.mlkem_seed_d());
                seed_z.write_to_reg(mlkem.mlkem_seed_z());
            }
            MlKem1024Seeds::Key(key) => KvAccess::copy_from_kv(
                key,
                mlkem.kv_mlkem_seed_rd_status(),
                mlkem.kv_mlkem_seed_rd_ctrl(),
            )
            .map_err(|err| err.into_read_seed_err())?,
        }

        // Copy ciphertext
        ciphertext.write_to_reg(mlkem.mlkem_ciphertext());

        // Set up shared key output destination
        let mut shared_key_out = shared_key_out;
        match &mut shared_key_out {
            MlKem1024SharedKeyOut::Array(_) => {
                // No key vault setup needed for array output
            }
            MlKem1024SharedKeyOut::Key(key) => {
                mlkem.kv_mlkem_sharedkey_wr_ctrl().write(|w| {
                    w.write_en(true)
                        .write_entry(key.id.into())
                        .hmac_key_dest_valid(key.usage.hmac_key())
                        .hmac_block_dest_valid(key.usage.hmac_data())
                        .mldsa_seed_dest_valid(key.usage.mldsa_seed())
                        .ecc_pkey_dest_valid(key.usage.ecc_key_gen_seed())
                        .ecc_seed_dest_valid(key.usage.ecc_private_key())
                        .aes_key_dest_valid(key.usage.aes_key())
                        .mlkem_seed_dest_valid(key.usage.mlkem_seed())
                        .mlkem_msg_dest_valid(key.usage.mlkem_msg())
                });
            }
        }

        // Program the command register for keygen + decapsulation
        mlkem.mlkem_ctrl().write(|w| w.ctrl(KEYGEN_DECAPS));

        // Wait for hardware ready
        MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().valid())?;

        // Copy results
        match &mut shared_key_out {
            MlKem1024SharedKeyOut::Array(shared_key) => {
                **shared_key = MlKem1024SharedKey::read_from_reg(mlkem.mlkem_shared_key());
            }
            MlKem1024SharedKeyOut::Key(_) => {
                // Wait for key vault write to complete
                MlKem1024::wait(mlkem, || {
                    mlkem.kv_mlkem_sharedkey_wr_status().read().valid()
                })?;
            }
        }

        // Clear the hardware when done
        mlkem.mlkem_ctrl().write(|w| w.zeroize(true));

        Ok(())
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
        let mut mlkem_reg = AbrReg::new();
        let mlkem = mlkem_reg.regs_mut();
        mlkem.mlkem_ctrl().write(|f| f.zeroize(true));

        // Wait for hardware ready. Ignore errors
        let _ = MlKem1024::wait(mlkem, || mlkem.mlkem_status().read().ready());
    }
}

/// ML-KEM key access error trait
trait MlKemKeyAccessErr {
    /// Convert to read seed operation error
    fn into_read_seed_err(self) -> CaliptraError;
    /// Convert to read message operation error
    fn into_read_msg_err(self) -> CaliptraError;
}

impl MlKemKeyAccessErr for KvAccessErr {
    /// Convert to read seed operation error
    fn into_read_seed_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_MLKEM_READ_SEED_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_MLKEM_READ_SEED_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_MLKEM_READ_SEED_KV_UNKNOWN,
        }
    }

    /// Convert to read message operation error
    fn into_read_msg_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_MLKEM_READ_MSG_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_MLKEM_READ_MSG_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_MLKEM_READ_MSG_KV_UNKNOWN,
        }
    }
}
