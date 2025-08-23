/*++

Licensed under the Apache-2.0 license.

File Name:

    Mldsa87.rs

Abstract:

    File contains API for MLDSA-87 Cryptography operations

--*/
#![allow(dead_code)]

use crate::{
    array::{LEArray4x1157, LEArray4x1224, LEArray4x16, LEArray4x648, LEArray4x8},
    kv_access::{KvAccess, KvAccessErr},
    wait, CaliptraError, CaliptraResult, KeyReadArgs, Trng,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_derive::Launder;
use caliptra_cfi_lib::{
    cfi_assert_eq, cfi_assert_eq_16_words, cfi_assert_ne_16_words, cfi_launder,
};
use caliptra_registers::abr::{AbrReg, RegisterBlock};
use zerocopy::FromBytes;
use zerocopy::{IntoBytes, Unalign};

#[must_use]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Launder)]
pub enum Mldsa87Result {
    Success = 0xAAAAAAAA,
    SigVerifyFailed = 0x55555555,
}

/// MLDSA-87 Public Key
pub type Mldsa87PubKey = LEArray4x648;

/// MLDSA-87 Private Key
pub type Mldsa87PrivKey = LEArray4x1224;

/// MLDSA-87 Signature
pub type Mldsa87Signature = LEArray4x1157;

/// MLDSA-87 Message (64 Bytes)
pub type Mldsa87Msg = LEArray4x16;

/// MLDSA-87 Signature RND
pub type Mldsa87SignRnd = LEArray4x8;

type Mldsa87VerifyRes = LEArray4x16;

pub const MLDSA87_VERIFY_RES_WORD_LEN: usize = 16;

/// MLDSA-87 Seed
#[derive(Debug, Copy, Clone)]
pub enum Mldsa87Seed<'a> {
    /// Array
    Array4x8(&'a LEArray4x8),

    /// Key Vault Key
    Key(KeyReadArgs),

    /// Private Key
    PrivKey(&'a Mldsa87PrivKey),
}

impl<'a> From<&'a LEArray4x8> for Mldsa87Seed<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a LEArray4x8) -> Self {
        Self::Array4x8(value)
    }
}

impl From<KeyReadArgs> for Mldsa87Seed<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

impl<'a> From<&'a Mldsa87PrivKey> for Mldsa87Seed<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a Mldsa87PrivKey) -> Self {
        Self::PrivKey(value)
    }
}

/// MLDSA-87  API
pub struct Mldsa87 {
    mldsa87: AbrReg,
}

impl Mldsa87 {
    pub fn new(mldsa87: AbrReg) -> Self {
        Self { mldsa87 }
    }

    fn generate_iv(trng: &mut Trng) -> CaliptraResult<LEArray4x16> {
        let iv = trng.generate16()?;
        Ok(LEArray4x16::from(iv))
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
        };

        // Wait for either the given condition or the error condition
        wait::until(|| (condition() || err_condition()));

        if err_condition() {
            // Clear the errors
            // error_global_intr_r is RO
            regs.intr_block_rf()
                .error_internal_intr_r()
                .write(|_| u32::from(regs.intr_block_rf().error_internal_intr_r().read()).into());
            return Err(CaliptraError::DRIVER_MLDSA87_HW_ERROR);
        }

        Ok(())
    }

    /// Generate MLDSA-87 Key Pair
    ///
    /// # Arguments
    ///
    /// * `seed` - Either an array of 4x8 bytes or a key vault key to use as seed.
    /// * `trng` - TRNG driver instance.
    /// * `priv_key_out` - Optional output parameter to store the private key.
    ///
    /// # Returns
    ///
    /// * `Mldsa87PubKey` - Generated MLDSA-87 Public Key
    pub fn key_pair(
        &mut self,
        seed: Mldsa87Seed,
        trng: &mut Trng,
        priv_key_out: Option<&mut Mldsa87PrivKey>,
    ) -> CaliptraResult<Mldsa87PubKey> {
        let mldsa = self.mldsa87.regs_mut();

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Clear the hardware before start
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Copy seed to the hardware
        match seed {
            Mldsa87Seed::Array4x8(arr) => arr.write_to_reg(mldsa.mldsa_seed()),
            Mldsa87Seed::Key(key) => KvAccess::copy_from_kv(
                key,
                mldsa.kv_mldsa_seed_rd_status(),
                mldsa.kv_mldsa_seed_rd_ctrl(),
            )
            .map_err(|err| err.into_read_seed_err())?,
            Mldsa87Seed::PrivKey(_) => Err(CaliptraError::DRIVER_MLDSA87_KEY_GEN_SEED_BAD_USAGE)?,
        }

        // Generate an IV.
        let iv = Self::generate_iv(trng)?;
        iv.write_to_reg(mldsa.entropy());

        // Program the command register for key generation
        mldsa.mldsa_ctrl().write(|w| w.ctrl(|s| s.keygen()));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().valid())?;

        // Copy pubkey
        let pubkey = Mldsa87PubKey::read_from_reg(mldsa.mldsa_pubkey());

        // Copy private key if requested.
        if let Some(priv_key) = priv_key_out {
            *priv_key = Mldsa87PrivKey::read_from_reg(mldsa.mldsa_privkey_out());
        }

        // Clear the hardware when done
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        Ok(pubkey)
        // TODO check that pubkey is valid?
    }

    /// Sign the digest with specified private key. To defend against glitching
    /// attacks that could expose the private key, this function also verifies
    /// the generated signature.
    ///
    /// # Arguments
    ///
    /// * `seed` - Key Vault slot containing the seed for deterministic MLDSA Key Pair generation.
    /// * `pub_key` - Public key to verify the signature with.
    /// * `msg` - Message to sign.
    /// * `sign_rnd` - Signature RND input
    /// * `trng` - TRNG driver instance.
    ///
    /// # Returns
    ///
    /// * `Mldsa87Signature` - Generated signature
    pub fn sign(
        &mut self,
        seed: Mldsa87Seed,
        pub_key: &Mldsa87PubKey,
        msg: &Mldsa87Msg,
        sign_rnd: &Mldsa87SignRnd,
        trng: &mut Trng,
    ) -> CaliptraResult<Mldsa87Signature> {
        let mut gen_keypair = true;
        let mldsa = self.mldsa87.regs_mut();

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Clear the hardware before start
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Copy seed or the private key to the hardware
        match seed {
            Mldsa87Seed::Array4x8(arr) => arr.write_to_reg(mldsa.mldsa_seed()),
            Mldsa87Seed::Key(key) => KvAccess::copy_from_kv(
                key,
                mldsa.kv_mldsa_seed_rd_status(),
                mldsa.kv_mldsa_seed_rd_ctrl(),
            )
            .map_err(|err| err.into_read_seed_err())?,
            Mldsa87Seed::PrivKey(priv_key) => {
                gen_keypair = false;
                priv_key.write_to_reg(mldsa.mldsa_privkey_in())
            }
        }

        // Copy digest
        msg.write_to_reg(mldsa.mldsa_msg());

        // Sign RND, TODO do we want deterministic?
        sign_rnd.write_to_reg(mldsa.mldsa_sign_rnd());

        // Generate an IV.
        let iv = Self::generate_iv(trng)?;
        iv.write_to_reg(mldsa.entropy());

        // Program the command register for key generation
        mldsa.mldsa_ctrl().write(|w| {
            w.ctrl(|w| {
                if gen_keypair {
                    w.keygen_sign()
                } else {
                    w.signing()
                }
            })
        });

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().valid())?;

        // Copy signature
        let signature = Mldsa87Signature::read_from_reg(mldsa.mldsa_signature());

        // No need to zeroize here, as the hardware will be zeroized by verify.
        let result = self.verify(pub_key, msg, &signature)?;
        if result == Mldsa87Result::Success {
            cfi_assert_eq(cfi_launder(result), Mldsa87Result::Success);
            Ok(signature)
        } else {
            Err(CaliptraError::DRIVER_MLDSA87_SIGN_VALIDATION_FAILED)
        }
    }

    fn program_var_msg(mldsa: RegisterBlock<ureg::RealMmioMut>, msg: &[u8]) -> CaliptraResult<()> {
        // Wait for stream ready or valid status.
        Mldsa87::wait(mldsa, || {
            mldsa.mldsa_status().read().msg_stream_ready() || mldsa.mldsa_status().read().valid()
        })?;

        // Check if the operation completed prematurely.
        // This can happen in case of verification where the signature is invalid.
        // In this case, we should not proceed with streaming the message.
        if mldsa.mldsa_status().read().valid() {
            return Ok(());
        }

        // Reset the message strobe register.
        mldsa.mldsa_msg_strobe().write(|s| s.strobe(0xF));

        // Stream the message to the hardware.
        let dwords = msg.chunks_exact(size_of::<u32>());
        let remainder = dwords.remainder();
        for dword in dwords {
            let dw = <Unalign<u32>>::read_from_bytes(dword).unwrap();
            mldsa.mldsa_msg().at(0).write(|_| dw.get());
        }

        let last_strobe = match remainder.len() {
            0 => 0b0000,
            1 => 0b0001,
            2 => 0b0011,
            3 => 0b0111,
            _ => 0b0000, // should never happen
        };
        mldsa.mldsa_msg_strobe().write(|s| s.strobe(last_strobe));

        // Write last dword; 0 for no remainder.
        let mut last_word = 0_u32;
        last_word.as_mut_bytes()[..remainder.len()].copy_from_slice(remainder);
        mldsa.mldsa_msg().at(0).write(|_| last_word);

        // Wait for status to be valid
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().valid())?;

        Ok(())
    }

    pub fn sign_var(
        &mut self,
        seed: Mldsa87Seed,
        pub_key: &Mldsa87PubKey,
        msg: &[u8],
        sign_rnd: &Mldsa87SignRnd,
        trng: &mut Trng,
    ) -> CaliptraResult<Mldsa87Signature> {
        let mut gen_keypair = true;
        let mldsa = self.mldsa87.regs_mut();

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Clear the hardware before start
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Sign RND.
        sign_rnd.write_to_reg(mldsa.mldsa_sign_rnd());

        // Generate an IV.
        let iv = Self::generate_iv(trng)?;
        iv.write_to_reg(mldsa.entropy());

        // Copy seed or the private key to the hardware
        match seed {
            Mldsa87Seed::Array4x8(arr) => arr.write_to_reg(mldsa.mldsa_seed()),
            Mldsa87Seed::Key(key) => KvAccess::copy_from_kv(
                key,
                mldsa.kv_mldsa_seed_rd_status(),
                mldsa.kv_mldsa_seed_rd_ctrl(),
            )
            .map_err(|err| err.into_read_seed_err())?,
            Mldsa87Seed::PrivKey(priv_key) => {
                gen_keypair = false;
                priv_key.write_to_reg(mldsa.mldsa_privkey_in())
            }
        }

        // Program the command register for key generation
        mldsa.mldsa_ctrl().write(|w| {
            w.ctrl(|w| {
                if gen_keypair {
                    w.keygen_sign()
                } else {
                    w.signing()
                }
            })
            .stream_msg(true)
        });

        // Program the message to the hardware
        Mldsa87::program_var_msg(mldsa, msg)?;

        // Copy signature
        let signature = Mldsa87Signature::read_from_reg(mldsa.mldsa_signature());

        // No need to zeroize here, as the hardware will be zeroized by verify.
        let result = self.verify_var(pub_key, msg, &signature)?;
        if result == Mldsa87Result::Success {
            cfi_assert_eq(cfi_launder(result), Mldsa87Result::Success);
            Ok(signature)
        } else {
            Err(CaliptraError::DRIVER_MLDSA87_SIGN_VALIDATION_FAILED)
        }
    }

    /// Verify the signature with specified public key and message.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key.
    /// * `msg` - Message to verify.
    /// * `signature` - Signature to verify.
    ///
    /// # Result
    ///
    /// *  `Mldsa87Result` - Mldsa87Result::Success if the signature verification passed else an error code.
    fn verify_res(
        &mut self,
        pub_key: &Mldsa87PubKey,
        msg: &Mldsa87Msg,
        signature: &Mldsa87Signature,
    ) -> CaliptraResult<Mldsa87VerifyRes> {
        let mldsa = self.mldsa87.regs_mut();

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Clear the hardware before start
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Copy digest
        msg.write_to_reg(mldsa.mldsa_msg());

        // Copy pubkey
        pub_key.write_to_reg(mldsa.mldsa_pubkey());

        // Copy signature
        signature.write_to_reg(mldsa.mldsa_signature());

        // Program the command register for signature verification
        mldsa.mldsa_ctrl().write(|w| w.ctrl(|s| s.verifying()));

        // Wait for status to be valid
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().valid())?;

        // Copy the random value
        let verify_res = LEArray4x16::read_from_reg(mldsa.mldsa_verify_res());

        // Clear the hardware when done
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        Ok(verify_res)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn verify(
        &mut self,
        pub_key: &Mldsa87PubKey,
        msg: &Mldsa87Msg,
        signature: &Mldsa87Signature,
    ) -> CaliptraResult<Mldsa87Result> {
        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::MLDSA_VERIFY_FAILURE)?
        }

        let truncated_signature = &signature.0[..MLDSA87_VERIFY_RES_WORD_LEN];
        let empty_verify_res = [0; MLDSA87_VERIFY_RES_WORD_LEN];
        if truncated_signature == empty_verify_res {
            Err(CaliptraError::DRIVER_MLDSA87_UNSUPPORTED_SIGNATURE)?;
        }
        cfi_assert_ne_16_words(truncated_signature.try_into().unwrap(), &empty_verify_res);

        let verify_res = self.verify_res(pub_key, msg, signature)?;

        let result = if verify_res.0 == truncated_signature {
            cfi_assert_eq_16_words(&verify_res.0, &truncated_signature.try_into().unwrap());
            Mldsa87Result::Success
        } else {
            Mldsa87Result::SigVerifyFailed
        };

        Ok(result)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn verify_var(
        &mut self,
        pub_key: &Mldsa87PubKey,
        msg: &[u8],
        signature: &Mldsa87Signature,
    ) -> CaliptraResult<Mldsa87Result> {
        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::MLDSA_VERIFY_FAILURE)?
        }

        let truncated_signature = &signature.0[..MLDSA87_VERIFY_RES_WORD_LEN];
        let empty_verify_res = [0; MLDSA87_VERIFY_RES_WORD_LEN];
        if truncated_signature == empty_verify_res {
            Err(CaliptraError::DRIVER_MLDSA87_UNSUPPORTED_SIGNATURE)?;
        }
        cfi_assert_ne_16_words(truncated_signature.try_into().unwrap(), &empty_verify_res);

        let mldsa = self.mldsa87.regs_mut();

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Clear the hardware before start
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Copy pubkey
        pub_key.write_to_reg(mldsa.mldsa_pubkey());

        // Copy signature
        signature.write_to_reg(mldsa.mldsa_signature());

        // Program the command register for signature verification with streaming
        mldsa
            .mldsa_ctrl()
            .write(|w| w.ctrl(|s| s.verifying()).stream_msg(true));

        // Program the message to the hardware
        Mldsa87::program_var_msg(mldsa, msg)?;

        // Copy the result
        let verify_res = LEArray4x16::read_from_reg(mldsa.mldsa_verify_res());

        // Clear the hardware when done
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        let result = if verify_res.0 == truncated_signature {
            cfi_assert_eq_16_words(&verify_res.0, &truncated_signature.try_into().unwrap());
            Mldsa87Result::Success
        } else {
            Mldsa87Result::SigVerifyFailed
        };

        Ok(result)
    }

    /// Sign the PCR digest with PCR signing private key (seed) in keyvault slot 8 (KV8).
    /// KV8 contains the Alias FMC MLDSA keypair seed.
    ///
    /// # Arguments
    ///
    /// * `trng` - TRNG driver instance
    ///
    /// # Returns
    ///
    /// * `Mldsa87Signature` - Generated signature
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn pcr_sign_flow(&mut self, trng: &mut Trng) -> CaliptraResult<Mldsa87Signature> {
        let mldsa = self.mldsa87.regs_mut();

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Clear the hardware before start
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready())?;

        // Generate an IV.
        let iv = Self::generate_iv(trng)?;
        iv.write_to_reg(mldsa.entropy());

        mldsa
            .mldsa_ctrl()
            .write(|w| w.pcr_sign(true).ctrl(|s| s.keygen_sign()));

        // Wait for command to complete
        Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().valid())?;

        // Copy signature
        let signature = Mldsa87Signature::read_from_reg(mldsa.mldsa_signature());

        // Clear the hardware.
        mldsa.mldsa_ctrl().write(|w| w.zeroize(true));

        Ok(signature)
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
        let mut mldsa_reg = AbrReg::new();
        let mldsa = mldsa_reg.regs_mut();
        mldsa.mldsa_ctrl().write(|f| f.zeroize(true));

        // Wait for hardware ready. Ignore errors
        let _ = Mldsa87::wait(mldsa, || mldsa.mldsa_status().read().ready());
    }
}

/// Mldsa87 key access error trait
trait MlDsaKeyAccessErr {
    /// Convert to read seed operation error
    fn into_read_seed_err(self) -> CaliptraError;
}

impl MlDsaKeyAccessErr for KvAccessErr {
    /// Convert to read seed operation error
    fn into_read_seed_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_MLDSA87_READ_SEED_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_MLDSA87_READ_SEED_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_MLDSA87_READ_SEED_KV_UNKNOWN,
        }
    }
}
