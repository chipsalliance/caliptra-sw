/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384.rs

Abstract:

    File contains API for ECC-384 Cryptography operations

--*/

use crate::kv_access::{KvAccess, KvAccessErr};
use crate::{
    array_concat3, okmutref, wait, Array4x12, Array4xN, CaliptraError, CaliptraResult, KeyReadArgs,
    KeyWriteArgs, Trng,
};
use caliptra_registers::ecc::EccReg;
use core::cmp::Ordering;
use zerocopy::{AsBytes, FromBytes};

/// ECC-384 Coordinate
pub type Ecc384Scalar = Array4x12;

#[must_use]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecc384Result {
    Success = 0xAAAAAAAA,
    SigVerifyFailed = 0x55555555,
}

/// ECC-384 Seed
#[derive(Debug, Copy, Clone)]
pub enum Ecc384Seed<'a> {
    /// Array
    Array4x12(&'a Ecc384Scalar),

    /// Key Vault Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a Array4x12> for Ecc384Seed<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl From<KeyReadArgs> for Ecc384Seed<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

/// ECC-384 Public Key output
#[derive(Debug)]
pub enum Ecc384PrivKeyOut<'a> {
    /// Array
    Array4x12(&'a mut Ecc384Scalar),

    /// Key Vault Key
    Key(KeyWriteArgs),
}

impl<'a> From<&'a mut Array4x12> for Ecc384PrivKeyOut<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a mut Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl<'a> From<KeyWriteArgs> for Ecc384PrivKeyOut<'a> {
    /// Converts to this type from the input type.
    fn from(value: KeyWriteArgs) -> Self {
        Self::Key(value)
    }
}

/// ECC-384 Public Key input
#[derive(Debug, Copy, Clone)]
pub enum Ecc384PrivKeyIn<'a> {
    /// Array
    Array4x12(&'a Ecc384Scalar),

    /// Key Vault Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a Array4x12> for Ecc384PrivKeyIn<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a Array4x12) -> Self {
        Self::Array4x12(value)
    }
}
impl From<KeyReadArgs> for Ecc384PrivKeyIn<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}
impl<'a> From<Ecc384PrivKeyOut<'a>> for Ecc384PrivKeyIn<'a> {
    fn from(value: Ecc384PrivKeyOut<'a>) -> Self {
        match value {
            Ecc384PrivKeyOut::Array4x12(arr) => Ecc384PrivKeyIn::Array4x12(arr),
            Ecc384PrivKeyOut::Key(key) => Ecc384PrivKeyIn::Key(KeyReadArgs { id: key.id }),
        }
    }
}

/// ECC-384 Public Key
#[repr(C)]
#[derive(AsBytes, FromBytes, Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct Ecc384PubKey {
    /// X coordinate
    pub x: Ecc384Scalar,

    /// Y coordinate
    pub y: Ecc384Scalar,
}

impl Ecc384PubKey {
    /// Return DER formatted public key in uncompressed form
    #[inline(never)]
    pub fn to_der(&self) -> [u8; 97] {
        array_concat3([0x04], (&self.x).into(), (&self.y).into())
    }

    pub fn zeroize(&mut self) {
        self.x.0.fill(0);
        self.y.0.fill(0);
    }
}

/// ECC-384 Signature
#[repr(C)]
#[derive(Debug, Default, AsBytes, FromBytes, Copy, Clone, Eq, PartialEq)]
pub struct Ecc384Signature {
    /// Random point
    pub r: Ecc384Scalar,

    /// Proof
    pub s: Ecc384Scalar,
}

impl Ecc384Signature {
    pub fn zeroize(&mut self) {
        self.r.0.fill(0);
        self.s.0.fill(0);
    }
}

/// Elliptic Curve P-384 API
pub struct Ecc384 {
    ecc: EccReg,
}

impl Ecc384 {
    pub fn new(ecc: EccReg) -> Self {
        Self { ecc }
    }

    // Check that `scalar` is in the range [1, n-1] for the P-384 curve
    fn scalar_range_check(scalar: &Ecc384Scalar) -> bool {
        // n-1 for The NIST P-384 curve
        const SECP384_ORDER_MIN1: &[u32] = &[
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xc7634d81,
            0xf4372ddf, 0x581a0db2, 0x48b0a77a, 0xecec196a, 0xccc52972,
        ];

        // Check scalar <= n-1
        for (i, word) in SECP384_ORDER_MIN1.iter().enumerate() {
            match scalar.0[i].cmp(word) {
                Ordering::Greater => return false,
                Ordering::Less => break,
                Ordering::Equal => continue,
            }
        }

        // If scalar is non-zero, return true
        for word in scalar.0 {
            if word != 0 {
                return true;
            }
        }

        // scalar is zero
        false
    }

    /// Generate ECC-384 Key Pair
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed for deterministic ECC Key Pair generation
    /// * `nonce` - Nonce for deterministic ECC Key Pair generation
    /// * `trng` - TRNG driver instance
    /// * `priv_key` - Generate ECC-384 Private key
    ///
    /// # Returns
    ///
    /// * `Ecc384PubKey` - Generated ECC-384 Public Key
    pub fn key_pair(
        &mut self,
        seed: &Ecc384Seed,
        nonce: &Array4x12,
        trng: &mut Trng,
        mut priv_key: Ecc384PrivKeyOut,
    ) -> CaliptraResult<Ecc384PubKey> {
        let ecc = self.ecc.regs_mut();

        // Wait for hardware ready
        wait::until(|| ecc.status().read().ready());

        // Configure hardware to route keys to user specified hardware blocks
        match &mut priv_key {
            Ecc384PrivKeyOut::Array4x12(_arr) => {
                KvAccess::begin_copy_to_arr(ecc.kv_wr_pkey_status(), ecc.kv_wr_pkey_ctrl())?;
            }
            Ecc384PrivKeyOut::Key(key) => {
                KvAccess::begin_copy_to_kv(ecc.kv_wr_pkey_status(), ecc.kv_wr_pkey_ctrl(), *key)?;
            }
        }

        // Copy seed to the hardware
        match seed {
            Ecc384Seed::Array4x12(arr) => KvAccess::copy_from_arr(arr, ecc.seed())?,
            Ecc384Seed::Key(key) => {
                KvAccess::copy_from_kv(*key, ecc.kv_rd_seed_status(), ecc.kv_rd_seed_ctrl())
                    .map_err(|err| err.into_read_seed_err())?
            }
        }

        // Copy nonce to the hardware
        KvAccess::copy_from_arr(nonce, ecc.nonce())?;

        // Generate an IV.
        let iv = trng.generate()?;
        KvAccess::copy_from_arr(&iv, ecc.iv())?;

        // Program the command register for key generation
        ecc.ctrl().write(|w| w.ctrl(|w| w.keygen()));

        // Wait for command to complete
        wait::until(|| ecc.status().read().valid());

        let mut perform_pct: bool = true;

        // Copy the private key
        match &mut priv_key {
            Ecc384PrivKeyOut::Array4x12(arr) => KvAccess::end_copy_to_arr(ecc.privkey_out(), arr)?,
            Ecc384PrivKeyOut::Key(key) => {
                KvAccess::end_copy_to_kv(ecc.kv_wr_pkey_status(), *key)
                    .map_err(|err| err.into_write_priv_key_err())?;
                perform_pct = key.usage.ecc_private_key();
            }
        }

        let pub_key = Ecc384PubKey {
            x: Array4x12::read_from_reg(ecc.pubkey_x()),
            y: Array4x12::read_from_reg(ecc.pubkey_y()),
        };

        // Pairwise consistency check.
        if perform_pct {
            let digest = Array4x12::new([0u32; 12]);
            match self.sign(&priv_key.into(), &pub_key, &digest, trng) {
                Ok(mut sig) => sig.zeroize(),
                Err(CaliptraError::DRIVER_ECC384_SIGN_VALIDATION_FAILED) => {
                    return Err(CaliptraError::DRIVER_ECC384_KEYGEN_PAIRWISE_CONSISTENCY_FAILURE)
                }
                Err(err) => return Err(err),
            }
        }
        self.zeroize_internal();

        Ok(pub_key)
    }

    fn sign_internal(
        &mut self,
        priv_key: &Ecc384PrivKeyIn,
        data: &Ecc384Scalar,
        trng: &mut Trng,
    ) -> CaliptraResult<Ecc384Signature> {
        let ecc = self.ecc.regs_mut();

        // Wait for hardware ready
        wait::until(|| ecc.status().read().ready());

        // Copy private key
        match priv_key {
            Ecc384PrivKeyIn::Array4x12(arr) => KvAccess::copy_from_arr(arr, ecc.privkey_in())?,
            Ecc384PrivKeyIn::Key(key) => {
                KvAccess::copy_from_kv(*key, ecc.kv_rd_pkey_status(), ecc.kv_rd_pkey_ctrl())
                    .map_err(|err| err.into_read_priv_key_err())?
            }
        }

        // Copy digest
        KvAccess::copy_from_arr(data, ecc.msg())?;

        // Generate an IV.
        let iv = trng.generate()?;
        KvAccess::copy_from_arr(&iv, ecc.iv())?;

        // Program the command register
        ecc.ctrl().write(|w| w.ctrl(|w| w.signing()));

        // Wait for command to complete
        wait::until(|| ecc.status().read().valid());

        // Copy signature
        let signature = Ecc384Signature {
            r: Array4x12::read_from_reg(ecc.sign_r()),
            s: Array4x12::read_from_reg(ecc.sign_s()),
        };

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
    /// * `Ecc384Signature` - Generate signature
    pub fn sign(
        &mut self,
        priv_key: &Ecc384PrivKeyIn,
        pub_key: &Ecc384PubKey,
        data: &Ecc384Scalar,
        trng: &mut Trng,
    ) -> CaliptraResult<Ecc384Signature> {
        let mut sig_result = self.sign_internal(priv_key, data, trng);
        let sig = okmutref(&mut sig_result)?;
        match self.verify(pub_key, data, sig)? {
            Ecc384Result::SigVerifyFailed => {
                sig.zeroize();
                return Err(CaliptraError::DRIVER_ECC384_SIGN_VALIDATION_FAILED);
            }
            Ecc384Result::Success => {}
        };
        sig_result
    }

    /// Verify signature with specified public key and digest
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key
    /// * `digest` - digest to verify
    /// * `signature` - Signature to verify
    ///
    ///  Note: Use this function only if glitch protection is not needed.
    ///        If glitch protection is needed, use `verify_r` instead.
    ///
    ///
    /// # Result
    ///
    /// *  `Ecc384Result` - Ecc384Result::Success if the signature verification passed else an error code.
    pub fn verify(
        &mut self,
        pub_key: &Ecc384PubKey,
        digest: &Ecc384Scalar,
        signature: &Ecc384Signature,
    ) -> CaliptraResult<Ecc384Result> {
        // Get the verify r result
        let mut verify_r = self.verify_r(pub_key, digest, signature)?;

        // compare the hardware generate `r` with one in signature
        let result = if verify_r == signature.r {
            Ecc384Result::Success
        } else {
            Ecc384Result::SigVerifyFailed
        };

        verify_r.0.fill(0);
        Ok(result)
    }

    /// Returns the R value of the signature with specified public key and digest.
    ///  Caller is expected to compare the returned R value against the provided signature's
    ///  R value to determine whether the signature is valid.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key
    /// * `digest` - digest to verify
    /// * `signature` - Signature to verify
    ///
    /// # Result
    ///
    /// *  `Array4xN<12, 48>` - verify R value
    pub fn verify_r(
        &mut self,
        pub_key: &Ecc384PubKey,
        digest: &Ecc384Scalar,
        signature: &Ecc384Signature,
    ) -> CaliptraResult<Array4xN<12, 48>> {
        // If R or S are not in the range [1, N-1], signature check must fail
        if !Self::scalar_range_check(&signature.r) || !Self::scalar_range_check(&signature.s) {
            return Err(CaliptraError::DRIVER_ECC384_SCALAR_RANGE_CHECK_FAILED);
        }

        let ecc = self.ecc.regs_mut();

        // Wait for hardware ready
        wait::until(|| ecc.status().read().ready());

        // Copy public key to registers
        pub_key.x.write_to_reg(ecc.pubkey_x());
        pub_key.y.write_to_reg(ecc.pubkey_y());

        // Copy digest to registers
        digest.write_to_reg(ecc.msg());

        // Copy signature to registers
        signature.r.write_to_reg(ecc.sign_r());
        signature.s.write_to_reg(ecc.sign_s());

        // Program the command register
        ecc.ctrl().write(|w| w.ctrl(|w| w.verifying()));

        // Wait for command to complete
        wait::until(|| ecc.status().read().valid());

        // Copy the random value
        let verify_r = Array4x12::read_from_reg(ecc.verify_r());

        self.zeroize_internal();

        Ok(verify_r)
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        self.ecc.regs_mut().ctrl().write(|w| w.zeroize(true));
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
        let mut ecc = EccReg::new();
        ecc.regs_mut().ctrl().write(|w| w.zeroize(true));
    }
}

/// ECC-384 key access error trait
trait Ecc384KeyAccessErr {
    /// Convert to read seed operation error
    fn into_read_seed_err(self) -> CaliptraError;

    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError;

    /// Convert to read private key operation error
    fn into_read_priv_key_err(self) -> CaliptraError;

    /// Convert to write private key operation error
    fn into_write_priv_key_err(self) -> CaliptraError;
}

impl Ecc384KeyAccessErr for KvAccessErr {
    /// Convert to read seed operation error
    fn into_read_seed_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_READ_SEED_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_READ_SEED_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_READ_SEED_KV_UNKNOWN,
        }
    }

    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_READ_DATA_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_READ_DATA_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_READ_DATA_KV_UNKNOWN,
        }
    }

    /// Convert to reads private key operation error
    fn into_read_priv_key_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_READ_PRIV_KEY_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_READ_PRIV_KEY_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_READ_PRIV_KEY_KV_UNKNOWN,
        }
    }

    /// Convert to write private key operation error
    fn into_write_priv_key_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_WRITE_PRIV_KEY_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_WRITE_PRIV_KEY_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_WRITE_PRIV_KEY_KV_UNKNOWN,
        }
    }
}
