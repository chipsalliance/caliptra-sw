/*++

Licensed under the Apache-2.0 license.

File Name:

    ml_dsa87.rs

Abstract:

    File contains API for Ml_Dsa87 5 Cryptography operations

--*/

use crate::kv_access::{KvAccess, KvAccessErr};
use crate::{
    okmutref, wait, Array4x1157, Array4x1224, Array4x16, Array4x648, Array4x8, CaliptraError,
    CaliptraResult, KeyReadArgs, Trng,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_registers::ml_dsa87::MlDsa87Reg;

#[must_use]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsa87Result {
    Success = 0xAAAAAAAA,
    SigVerifyFailed = 0x55555555,
}

/// MlDsa87 msg 512bit
pub type MlDsa87MsgScalar = Array4x16;

/// MlDsa87 Secret Key
pub type MlDsa87SecretKeyScalar = Array4x1224;

/// MlDsa87 Public Key
pub type MlDsa87PublicKeyScalar = Array4x648;

/// MlDsa87 Signature
pub type MlDsa87SignatureScalar = Array4x1157;

/// Dilitium Key Vault Seed
pub type MlDsa87KvSeed = KeyReadArgs;

/// MlDsa87 Key Vault Secret Key
pub type MlDsa87SecretKey = KeyReadArgs;

/// Dilitium Seed
pub type MlDsa87Seed = Array4x8;

/// MlDsa87 Public Key
#[derive(Debug, Copy, Clone)]
pub enum MlDsa87PublicKey<'a> {
    /// Array
    Array4x648(&'a MlDsa87PublicKeyScalar),
    // Key Vault Key
    // TODO    Key(KeyReadArgs),
}

impl<'a> From<&'a Array4x648> for MlDsa87PublicKey<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a Array4x648) -> Self {
        Self::Array4x648(value)
    }
}

/// MlDsa87  API
pub struct MlDsa87 {
    ml_dsa87: MlDsa87Reg,
}

impl MlDsa87 {
    pub fn new(ml_dsa87: MlDsa87Reg) -> Self {
        Self { ml_dsa87 }
    }

    // The trng onlyu generates 12 dwords
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

    /// Generate MlDsa87 Key Pair
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed for deterministic MlDsa87 Key Pair generation
    /// * `trng` - TRNG driver instance
    ///
    /// # Returns
    ///
    /// * `(MlDsa87SecretKey, MlDsa87PubKey)` - Generated MlDsa87 Key pair
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn key_pair(
        &mut self,
        seed: &MlDsa87KvSeed,
        trng: &mut Trng,
    ) -> CaliptraResult<MlDsa87PublicKeyScalar> {
        let ml_dsa87 = self.ml_dsa87.regs_mut();

        // Wait for hardware ready
        wait::until(|| ml_dsa87.status().read().ready());

        // Write seed
        KvAccess::copy_from_kv(
            *seed,
            ml_dsa87.kv_rd_seed_status(),
            ml_dsa87.kv_rd_seed_ctrl(),
        )
        .map_err(|err| match err {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_READ_SEED_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_READ_SEED_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_READ_SEED_KV_UNKNOWN,
        })?;

        // Write IV
        KvAccess::copy_from_arr(&Self::generate_iv(trng)?, ml_dsa87.iv())?;

        ml_dsa87.ctrl().write(|w| w.ctrl(|w| w.keygen()));

        // Wait for command to complete
        wait::until(|| ml_dsa87.status().read().valid());

        let public_key = Array4x648::read_from_reg(ml_dsa87.public_key());

        self.zeroize_internal();

        Ok(public_key)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn sign_internal(
        &mut self,
        secret_key: &MlDsa87SecretKey,
        data: &MlDsa87MsgScalar,
        trng: &mut Trng,
    ) -> CaliptraResult<MlDsa87SignatureScalar> {
        let ml_dsa87 = self.ml_dsa87.regs_mut();

        // Wait for hardware ready
        wait::until(|| ml_dsa87.status().read().ready());

        // Key vault contains seeds, not secret keys. The hardware will create
        KvAccess::copy_from_kv(
            *secret_key,
            ml_dsa87.kv_rd_seed_status(),
            ml_dsa87.kv_rd_seed_ctrl(),
        )
        .map_err(|err| match err {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_READ_SEED_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_READ_SEED_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_READ_SEED_KV_UNKNOWN,
        })?;

        // Copy msg
        KvAccess::copy_from_arr(data, ml_dsa87.msg())?;

        // Copy IV
        KvAccess::copy_from_arr(&Self::generate_iv(trng)?, ml_dsa87.iv())?;

        // Copy Seed
        // KvAccess::copy_from_arr(seed, ml_dsa87.seed())?;

        // TODO SIGN_RND needs to be inputted here??

        // Program the command register
        ml_dsa87.ctrl().write(|w| w.ctrl(|w| w.signing()));

        // Wait for hardware ready
        wait::until(|| ml_dsa87.status().read().ready());

        let signature = Array4x1157::read_from_reg(ml_dsa87.signature());

        self.zeroize_internal();

        Ok(signature)
    }

    /// Sign the digest with specified private key. To defend against glitching
    /// attacks that could expose the private key, this function also verifies
    /// the generated signature.
    ///
    /// # Arguments
    ///
    /// * `priv_key` - Private key
    /// * `pub_key` - Public key to verify with
    /// * `data` - Digest to sign
    /// * `trng` - TRNG driver instance
    ///
    /// # Returns
    ///
    /// * `MlDsa87Signature` - Generate signature
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn sign(
        &mut self,
        secret_key: &MlDsa87SecretKey,
        pub_key: &MlDsa87PublicKey,
        data: &MlDsa87MsgScalar,
        trng: &mut Trng,
    ) -> CaliptraResult<MlDsa87SignatureScalar> {
        let mut signature_result = self.sign_internal(secret_key, data, trng);
        let sig = okmutref(&mut signature_result)?;

        // Verify the signature just created
        let result = self.verify(pub_key, data, sig)?;
        if result == MlDsa87Result::Success {
            signature_result
        } else {
            Err(CaliptraError::DRIVER_ML_DSA87_SIGN_VALIDATION_FAILED)
        }
    }

    /// Verify signature with specified public key and digest
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key
    /// * `msg` - digest to verify
    /// * `signature` - Signature to verify
    ///
    /// # Result
    ///
    /// *  `MlDsa87Result` - MlDsa87Result::Success if the signature verification passed else an error code.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn verify(
        &mut self,
        pub_key: &MlDsa87PublicKey,
        msg: &MlDsa87MsgScalar,
        signature: &MlDsa87SignatureScalar,
    ) -> CaliptraResult<MlDsa87Result> {
        // TODO?? Check range??

        let ml_dsa87 = self.ml_dsa87.regs_mut();

        // Wait for hardware ready
        wait::until(|| ml_dsa87.status().read().ready());

        // Copy public key to register
        match pub_key {
            MlDsa87PublicKey::Array4x648(arr) => arr.write_to_reg(ml_dsa87.public_key()),
        }

        // Copy digest to register
        msg.write_to_reg(ml_dsa87.msg());

        // Copy signature
        signature.write_to_reg(ml_dsa87.signature());

        // Program the command register
        ml_dsa87.ctrl().write(|w| w.ctrl(|w| w.verifying()));

        // Wait for hardware ready
        wait::until(|| ml_dsa87.status().read().ready());

        let result = Array4x16::read_from_reg(ml_dsa87.verification_result());
        // TODO currently emulator returns 1 on each word for success. Update when behavior is fleshed out
        let success = result.0.iter().fold(Ok(true), |mut acc, x| {
            match *x {
                // TODO update when hw is better specified
                0 => acc = Ok(false),
                1 => (), // Do nothing
                _ => return Err(CaliptraError::DRIVER_ML_DSA87_SIGN_VALIDATION_FAILED),
            }
            acc
        })?;
        if success {
            Ok(MlDsa87Result::Success)
        } else {
            Ok(MlDsa87Result::SigVerifyFailed)
        }
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        self.ml_dsa87.regs_mut().ctrl().write(|w| w.zeroize(true));
    }
}
