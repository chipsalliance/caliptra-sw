/*++

Licensed under the Apache-2.0 license.

File Name:

    Mldsa87.rs

Abstract:

    File contains API for MLDSA-87 Cryptography operations

--*/
#![allow(dead_code)]

use crate::{
    array::{Array4x1157, Array4x1224, Array4x16, Array4x648, Array4x8},
    kv_access::{KvAccess, KvAccessErr},
    wait, CaliptraError, CaliptraResult, KeyReadArgs, Trng,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_derive::Launder;
use caliptra_cfi_lib::{cfi_assert_eq, cfi_assert_eq_12_words, cfi_assert_eq_8_words, cfi_launder};
use caliptra_registers::mldsa::{MldsaReg, RegisterBlock};

#[must_use]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Launder)]
pub enum Mldsa87Result {
    Success = 0xAAAAAAAA,
    SigVerifyFailed = 0x55555555,
}

/// MLDSA-87 Public Key
pub type Mldsa87PubKey = Array4x648;

/// MLDSA-87 Private Key
pub type Mldsa87PrivKey = Array4x1224;

/// MLDSA-87 Signature
pub type Mldsa87Signature = Array4x1157;

/// MLDSA-87 Message (64 Bytes)
pub type Mldsa87Msg = Array4x16;

/// MLDSA-87 Signature RND
pub type Mldsa87SignRnd = Array4x8;

type Mldsa87VerifyRes = Array4x16;

/// MLDSA-87 Seed
#[derive(Debug, Copy, Clone)]
pub enum Mldsa87Seed<'a> {
    /// Array
    Array4x8(&'a Array4x8),

    /// Key Vault Key
    Key(KeyReadArgs),

    /// Private Key
    PrivKey(&'a Mldsa87PrivKey),
}

impl<'a> From<&'a Array4x8> for Mldsa87Seed<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a Array4x8) -> Self {
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
    mldsa87: MldsaReg,
}

impl Mldsa87 {
    pub fn new(mldsa87: MldsaReg) -> Self {
        Self { mldsa87 }
    }

    // The trng only generates 12 dwords
    fn generate_iv(trng: &mut Trng) -> CaliptraResult<Array4x16> {
        let iv = {
            let mut iv = [0; 16];
            let iv1 = trng.generate()?;
            let iv2 = trng.generate()?;
            iv[..12].copy_from_slice(&iv1.0);
            iv[12..16].copy_from_slice(&iv2.0[0..4]);
            Array4x16::from(iv)
        };
        Ok(iv)
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
        seed: &Mldsa87Seed,
        trng: &mut Trng,
        priv_key_out: Option<&mut Mldsa87PrivKey>,
    ) -> CaliptraResult<Mldsa87PubKey> {
        let mldsa = self.mldsa87.regs_mut();

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.status().read().ready())?;

        // Clear the hardware before start
        mldsa.ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.status().read().ready())?;

        // Copy seed to the hardware
        match seed {
            Mldsa87Seed::Array4x8(arr) => KvAccess::copy_from_arr(arr, mldsa.seed())?,
            Mldsa87Seed::Key(key) => {
                KvAccess::copy_from_kv(*key, mldsa.kv_rd_seed_status(), mldsa.kv_rd_seed_ctrl())
                    .map_err(|err| err.into_read_seed_err())?
            }
            Mldsa87Seed::PrivKey(_) => Err(CaliptraError::DRIVER_MLDSA87_KEY_GEN_SEED_BAD_USAGE)?,
        }

        // Generate an IV.
        let iv = Self::generate_iv(trng)?;
        KvAccess::copy_from_arr(&iv, mldsa.entropy())?;

        // Program the command register for key generation
        mldsa.ctrl().write(|w| w.ctrl(|w| w.keygen()));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.status().read().valid())?;

        // Copy pubkey
        let pubkey = Mldsa87PubKey::read_from_reg(mldsa.pubkey());

        // Copy private key if requested.
        if let Some(priv_key) = priv_key_out {
            *priv_key = Mldsa87PrivKey::read_from_reg(mldsa.privkey_out());
        }

        // Clear the hardware when done
        mldsa.ctrl().write(|w| w.zeroize(true));

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
        seed: &Mldsa87Seed,
        pub_key: &Mldsa87PubKey,
        msg: &Mldsa87Msg,
        sign_rnd: &Mldsa87SignRnd,
        trng: &mut Trng,
    ) -> CaliptraResult<Mldsa87Signature> {
        let mut gen_keypair = true;
        let mldsa = self.mldsa87.regs_mut();

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.status().read().ready())?;

        // Clear the hardware before start
        mldsa.ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.status().read().ready())?;

        // Copy seed or the private key to the hardware
        match seed {
            Mldsa87Seed::Array4x8(arr) => KvAccess::copy_from_arr(arr, mldsa.seed())?,
            Mldsa87Seed::Key(key) => {
                KvAccess::copy_from_kv(*key, mldsa.kv_rd_seed_status(), mldsa.kv_rd_seed_ctrl())
                    .map_err(|err| err.into_read_seed_err())?
            }
            Mldsa87Seed::PrivKey(priv_key) => {
                gen_keypair = false;
                KvAccess::copy_from_arr(priv_key, mldsa.privkey_in())?
            }
        }

        // Copy digest
        KvAccess::copy_from_arr(msg, mldsa.msg())?;

        // Sign RND, TODO do we want deterministic?
        KvAccess::copy_from_arr(sign_rnd, mldsa.sign_rnd())?;

        // Generate an IV.
        let iv = Self::generate_iv(trng)?;
        KvAccess::copy_from_arr(&iv, mldsa.entropy())?;

        // Program the command register for key generation
        mldsa.ctrl().write(|w| {
            w.ctrl(|w| {
                if gen_keypair {
                    w.keygen_sign()
                } else {
                    w.signing()
                }
            })
        });

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.status().read().valid())?;

        // Copy signature
        let signature = Mldsa87Signature::read_from_reg(mldsa.signature());

        // No need to zeroize here, as the hardware will be zeroized by verify.
        let result = self.verify(pub_key, msg, &signature)?;
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
        Mldsa87::wait(mldsa, || mldsa.status().read().ready())?;

        // Clear the hardware before start
        mldsa.ctrl().write(|w| w.zeroize(true));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.status().read().ready())?;

        // Copy digest
        msg.write_to_reg(mldsa.msg());

        // Copy pubkey
        pub_key.write_to_reg(mldsa.pubkey());

        // Copy signature
        signature.write_to_reg(mldsa.signature());

        // Program the command register for signature verification
        mldsa.ctrl().write(|w| w.ctrl(|w| w.verifying()));

        // Wait for hardware ready
        Mldsa87::wait(mldsa, || mldsa.status().read().valid())?;

        // Copy the random value
        let verify_res = Array4x16::read_from_reg(mldsa.verify_res());

        // Clear the hardware when done
        mldsa.ctrl().write(|w| w.zeroize(true));

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

        let verify_res = self.verify_res(pub_key, msg, signature)?;

        let truncated_signature = &signature.0[signature.0.len() - verify_res.0.len()..];

        let result = if verify_res.0 == truncated_signature {
            // We only have a 6, 8 and 12 dword cfi assert
            cfi_assert_eq_12_words(
                &verify_res.0[..12].try_into().unwrap(),
                &truncated_signature[..12].try_into().unwrap(),
            );
            cfi_assert_eq_8_words(
                &verify_res.0[8..].try_into().unwrap(),
                &truncated_signature[8..].try_into().unwrap(),
            );
            Mldsa87Result::Success
        } else {
            Mldsa87Result::SigVerifyFailed
        };

        Ok(result)
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
