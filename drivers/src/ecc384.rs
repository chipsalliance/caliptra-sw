/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384.rs

Abstract:

    File contains API for ECC-384 Cryptography operations

--*/

use crate::CptrResult;
use caliptra_registers::ecc;

/// ECC-384 coordinate size in bytes
pub const ECC_384_COORD_SIZE: usize = 48;

/// ECC-384 coordinate size in words
pub const ECC_384_WORD_SIZE: usize = ECC_384_COORD_SIZE / core::mem::size_of::<u32>();

/// ECC-384 Coordinate
pub type Ecc384Scalar = [u8; ECC_384_COORD_SIZE];

/// ECC-384 Private Key
pub type Ecc384PrivKey = Ecc384Scalar;

/// ECC-384 Public Key
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Ecc384PubKey {
    /// X coordinate
    pub x: Ecc384Scalar,

    /// Y coordinate
    pub y: Ecc384Scalar,
}

impl Default for Ecc384PubKey {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self {
            x: [0u8; ECC_384_COORD_SIZE],
            y: [0u8; ECC_384_COORD_SIZE],
        }
    }
}

/// ECC-384 Signature
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Ecc384Signature {
    /// Random point
    pub r: Ecc384Scalar,

    /// Proof
    pub s: Ecc384Scalar,
}

impl Default for Ecc384Signature {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self {
            r: [0u8; ECC_384_COORD_SIZE],
            s: [0u8; ECC_384_COORD_SIZE],
        }
    }
}

#[inline(never)]
fn read_scalar<TReg: ureg::ReadableReg<ReadVal = u32>, TMmio: ureg::Mmio>(
    reg_array: ureg::Array<ECC_384_WORD_SIZE, ureg::RegRef<TReg, TMmio>>,
) -> Ecc384Scalar {
    let mut result = [0u8; ECC_384_COORD_SIZE];
    for i in 0..ECC_384_WORD_SIZE {
        // TODO: Don't reverse the bytes once RTL is updated
        *<&mut [u8; 4]>::try_from(&mut result[(ECC_384_WORD_SIZE - 1 - i) * 4..][..4]).unwrap() =
            reg_array.at(i).read().to_be_bytes();
    }
    result
}

#[inline(never)]
fn write_scalar<
    TReg: ureg::ResettableReg + ureg::WritableReg<WriteVal = u32>,
    TMmio: ureg::Mmio,
>(
    reg_array: ureg::Array<ECC_384_WORD_SIZE, ureg::RegRef<TReg, TMmio>>,
    src: &Ecc384Scalar,
) {
    for i in 0..ECC_384_WORD_SIZE {
        reg_array.at(i).write(|_| {
            // TODO: Don't reverse the bytes once RTL is updated
            u32::from_be_bytes(
                src[(ECC_384_WORD_SIZE - 1 - i) * 4..][..4]
                    .try_into()
                    .unwrap(),
            )
        });
    }
}

/// Elliptic Curve P-384 API
pub enum Ecc384 {}

impl Ecc384 {
    /// Generate ECC-384 Key Pair
    ///
    /// # Arguments
    ///
    /// * `seed` - seed for deterministic ECC Key Pair generation
    ///
    /// # Returns
    /// A tuple of private key and public key (private_key, public_key)
    ///
    pub fn gen_key_pair(seed: &Ecc384Scalar) -> CptrResult<(Ecc384PrivKey, Ecc384PubKey)> {
        // Wait for hardware ready
        Self::_wait_for_hw_ready();

        let regs = ecc::RegisterBlock::ecc_reg();

        // Copy the seed to register
        write_scalar(regs.seed(), seed);

        // Program the command register
        regs.ctrl().write(|w| w.ctrl(|w| w.keygen()));

        // Wait for command to complete
        Self::_wait_for_cmd();

        let priv_key: Ecc384PrivKey = read_scalar(regs.privkey());

        let pub_key = Ecc384PubKey {
            x: read_scalar(regs.pubkey_x()),
            y: read_scalar(regs.pubkey_y()),
        };
        Ok((priv_key, pub_key))
    }

    /// Sign the digest with specified private key
    ///
    /// # Arguments
    ///
    /// * `priv_key` - Private key
    /// * `digest` - Digest to sign
    ///
    /// # Result
    ///
    /// *  Ecc384Signature - Signature
    pub fn sign(
        priv_key: &Ecc384PrivKey,
        digest: &Ecc384Scalar,
        signature: &mut Ecc384Signature,
    ) -> CptrResult<()> {
        // Wait for hardware ready
        Self::_wait_for_hw_ready();

        let regs = ecc::RegisterBlock::ecc_reg();

        // Copy private key
        // [TODO] Replace with copy_from_byte_slice once RTL is updated.
        write_scalar(regs.privkey(), priv_key);

        // Copy digest
        // [TODO] Replace with copy_from_byte_slice once RTL is updated.
        write_scalar(regs.msg(), digest);

        // Program the command register
        regs.ctrl().write(|w| w.ctrl(|w| w.signing()));

        // Wait for command to complete
        Self::_wait_for_cmd();

        // Copy signature
        signature.r = read_scalar(regs.sign_r());
        signature.s = read_scalar(regs.sign_s());

        Ok(())
    }

    /// Verify signature with specified public key and digest
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key
    /// * `digest` - digest to verify
    /// * `signature` - Signature to verify
    ///
    /// # Result
    ///
    /// *  `bool` - True if the signature verification passed else false
    pub fn verify(
        pub_key: &Ecc384PubKey,
        digest: &Ecc384Scalar,
        signature: &Ecc384Signature,
    ) -> CptrResult<bool> {
        // Wait for hardware ready
        Self::_wait_for_hw_ready();

        let regs = ecc::RegisterBlock::ecc_reg();

        // Copy public key to registers
        write_scalar(regs.pubkey_x(), &pub_key.x);
        write_scalar(regs.pubkey_y(), &pub_key.y);

        // Copy digest to registers
        write_scalar(regs.msg(), digest);

        // Copy signature to registers
        write_scalar(regs.sign_r(), &signature.r);
        write_scalar(regs.sign_s(), &signature.s);

        // Program the command register
        regs.ctrl().write(|w| w.ctrl(|w| w.verifying()));

        // Wait for command to complete
        Self::_wait_for_cmd();

        // Copy the random value
        let verify_r = read_scalar(regs.verify_r());

        // compare the hardware generate `r` with one in signature
        if verify_r == signature.r {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[inline]
    fn _wait_for_hw_ready() {
        let regs = ecc::RegisterBlock::ecc_reg();
        while !regs.status().read().ready() {}
    }

    #[inline]
    fn _wait_for_cmd() {
        let regs = ecc::RegisterBlock::ecc_reg();
        while !regs.status().read().valid() {}
    }
}
