/*++

Licensed under the Apache-2.0 license.

File Name:

    sha3.rs

Abstract:

    File contains API for SHAKE and SHA3 Cryptography operations

--*/

use crate::{wait, Array4xN, CaliptraError, CaliptraResult};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_registers::kmac::{regs::CfgShadowedWriteVal, Kmac as KmacReg};

#[allow(unused)]
#[derive(Copy, Clone)]
pub enum Sha3Mode {
    Sha3,
    Shake,
}

impl Sha3Mode {
    fn reg_value(&self) -> u32 {
        match self {
            Self::Sha3 => 0b00,
            Self::Shake => 0b10, // TODO: This does not match the RDL
        }
    }

    fn get_rate(&self, strength: Sha3KStrength) -> u32 {
        match self {
            Self::Sha3 => {
                match strength {
                    Sha3KStrength::L224 => 1152,
                    Sha3KStrength::L256 => 1088,
                    Sha3KStrength::L384 => 832,
                    Sha3KStrength::L512 => 576,
                    _ => 0, // Invalid config
                }
            }
            Self::Shake => {
                match strength {
                    Sha3KStrength::L128 => 1344,
                    Sha3KStrength::L256 => 1088,
                    _ => 0, // Invalid config
                }
            }
        }
    }
}

#[allow(unused)]
#[derive(Copy, Clone)]
pub enum Sha3KStrength {
    L128,
    L224,
    L256,
    L384,
    L512,
}

impl Sha3KStrength {
    fn reg_value(&self) -> u32 {
        match self {
            Self::L128 => 0x0,
            Self::L224 => 0x1,
            Self::L256 => 0x2,
            Self::L384 => 0x3,
            Self::L512 => 0x4,
        }
    }
}

#[allow(unused)]
#[derive(Copy, Clone)]
pub enum Sha3Cmd {
    Start,
    Process,
    Run,
    Done,
}

impl Sha3Cmd {
    fn reg_value(&self) -> u32 {
        match self {
            Self::Start => 0x1D,
            Self::Process => 0x2E,
            Self::Run => 0x31,
            Self::Done => 0x16,
        }
    }
}

pub struct Sha3 {
    sha3: KmacReg,
}

impl Sha3 {
    pub fn new(sha3: KmacReg) -> Self {
        Self { sha3 }
    }

    // Additional modes may be added by simply creating analogous functions for the two below
    //      - (shake/sha)(128/224/256/384/512)_digest_init()
    //      - (shake/sha)(128/224/256/384/512)_digest()

    /// Initialize multi-step SHAKE-256 digest operation
    ///
    /// # Returns
    ///
    /// * `Sha3DigestOp` - Object representing the digest operation
    pub fn shake256_digest_init(&mut self) -> CaliptraResult<Sha3DigestOp<'_>> {
        let mut op = Sha3DigestOp {
            sha3: self,
            mode: Sha3Mode::Shake,
            strength: Sha3KStrength::L256,
            state: Sha3DigestState::Init,
        };

        op.init()?;

        Ok(op)
    }

    /// Calculate the SHAKE-256 digest for specified data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    /// # Returns
    ///
    /// * `Array4xN` - Array containing the digest. Size depends on expected return type (Array4x8, Array4x16, etc.)
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn shake256_digest<const W: usize, const B: usize>(
        &mut self,
        data: &[u8],
    ) -> CaliptraResult<Array4xN<W, B>> {
        self.digest_generic(Sha3Mode::Shake, Sha3KStrength::L256, [data].iter())
    }

    /// Calculate the SHA3-256 digest for specified data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    /// # Returns
    ///
    /// * `Array4x8` - Array containing the digest.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn sha3_256_digest(&mut self, data: &[u8]) -> CaliptraResult<crate::Array4x8> {
        self.digest_generic(Sha3Mode::Sha3, Sha3KStrength::L256, [data].iter())
    }

    // Similar to `sha3_256_digest` but allows passing an iterator of slices to avoid copying data.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn sha3_256_digest_ext<I, T>(&mut self, data: I) -> CaliptraResult<crate::Array4x8>
    where
        I: Iterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.digest_generic(Sha3Mode::Sha3, Sha3KStrength::L256, data)
    }

    // Helper function to be called by a mode-specific public function
    // Performs a digest using a single, provided slice of data
    fn digest_generic<const W: usize, const B: usize, I, T>(
        &mut self,
        mode: Sha3Mode,
        strength: Sha3KStrength,
        data: I,
    ) -> CaliptraResult<Array4xN<W, B>>
    where
        I: Iterator<Item = T>,
        T: AsRef<[u8]>,
    {
        // START
        self.digest_start(mode, strength)?;

        // UPDATE
        // Stream data
        for item in data {
            self.stream_msg(item.as_ref())?;
        }

        // FINALIZE
        self.finalize()?;

        // READ DIGEST
        let digest = self.read_digest(mode, strength)?;

        // Complete and zeroize
        self.zeroize_internal();

        Ok(digest)
    }

    // Initialize the digest operation and wait for the absorb state to be set
    fn digest_start(&mut self, mode: Sha3Mode, strength: Sha3KStrength) -> CaliptraResult<()> {
        let reg = self.sha3.regs_mut();

        // INIT
        // Ensure HW is in the right state
        wait::until(|| reg.status().read().sha3_idle());

        // Configure mode and strength/length
        let write_val = CfgShadowedWriteVal::from(0)
            .mode(mode.reg_value())
            .kstrength(strength.reg_value())
            .state_endianness(true);
        // Need to write same value twice to this shadowed reg per spec
        reg.cfg_shadowed().write(|_| write_val);
        reg.cfg_shadowed().write(|_| write_val);

        // Issue start cmd
        reg.cmd().write(|w| w.cmd(Sha3Cmd::Start.reg_value()));

        // Wait for absorb state
        wait::until(|| reg.status().read().sha3_absorb());

        Ok(())
    }

    // Stream data to the input FIFO
    fn stream_msg(&mut self, src: &[u8]) -> CaliptraResult<()> {
        let reg = self.sha3.regs_mut();

        // Ensure FIFO empty is set to indicate FIFO is writable
        // Spec makes it clear HW can empty this faster than FW can write, so not monitoring FIFO used space between writes
        wait::until(|| reg.status().read().fifo_empty());

        // TODO: There may be an existing function that can handle this.
        //       It needs to handle volatile writes by dword and leftover bytes individually (not padded to a dword)
        //       Ideally, it would also not increment the destination address (or just make sure we don't exceed mem range)

        // Break off bytes if not a dword multiple
        let (src_dwords, src_bytes) = src.split_at(src.len() & !3);

        // Write 4-byte chunks as u32 dwords
        for chunk in src_dwords.chunks_exact(4) {
            let src_dword = u32::from_ne_bytes(chunk.try_into().unwrap());
            reg.msg_fifo().at(0).write(|_| src_dword);
        }

        // Write any remaining bytes individually
        let dst_u8 = reg.msg_fifo().at(0).ptr as *mut u8;
        for &src_byte in src_bytes {
            unsafe {
                dst_u8.write_volatile(src_byte);
            }
        }

        Ok(())
    }

    // Start HW process of generating digest
    fn finalize(&mut self) -> CaliptraResult<()> {
        let reg = self.sha3.regs_mut();

        // Issue process cmd
        reg.cmd().write(|w| w.cmd(Sha3Cmd::Process.reg_value()));

        Ok(())
    }

    // Wait for digest to be complete and read out the data
    // Digest size returned depends on expected return type
    fn read_digest<const W: usize, const B: usize>(
        &mut self,
        mode: Sha3Mode,
        strength: Sha3KStrength,
    ) -> CaliptraResult<Array4xN<W, B>> {
        let reg = self.sha3.regs_mut();

        // Wait for completion
        wait::until(|| reg.status().read().sha3_squeeze());

        // Error checking so we don't exceed the rate for the type
        // NOTE: This HW does support larger digests, but another RUN command needs to be issued to do so
        //       There was no need for this at the time this was written
        if (W * core::mem::size_of::<u32>()) as u32 > mode.get_rate(strength) {
            return Err(CaliptraError::DRIVER_SHA3_DIGEST_EXCEEDS_RATE);
        }

        // Read out digest
        let digest = Array4xN::<W, B>::read_from_reg(reg.state().truncate::<W>());

        Ok(digest)
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        self.sha3
            .regs_mut()
            .cmd()
            .write(|w| w.cmd(Sha3Cmd::Done.reg_value()));
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
        let mut sha3 = KmacReg::new();
        sha3.regs_mut()
            .cmd()
            .write(|w| w.cmd(Sha3Cmd::Done.reg_value()));
    }
}

/// SHA3 Digest state
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Sha3DigestState {
    /// Initial state
    Init,

    /// Pending state
    Pending,

    /// Final state
    Final,
}

/// Multi step SHA3 digest operation
pub struct Sha3DigestOp<'a> {
    /// SHA3/SHAKE Engine
    sha3: &'a mut Sha3,

    mode: Sha3Mode,

    strength: Sha3KStrength,

    /// State
    state: Sha3DigestState,
}

impl Sha3DigestOp<'_> {
    // Start the hash operation
    fn init(&mut self) -> CaliptraResult<()> {
        if self.state != Sha3DigestState::Init {
            return Err(CaliptraError::DRIVER_SHA3_INVALID_STATE_ERR);
        }

        // Call init
        self.sha3.digest_start(self.mode, self.strength)?;

        self.state = Sha3DigestState::Pending;

        Ok(())
    }

    /// Update the digest with data
    pub fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.state != Sha3DigestState::Pending {
            return Err(CaliptraError::DRIVER_SHA3_INVALID_STATE_ERR);
        }

        self.sha3.stream_msg(data)?;

        Ok(())
    }

    /// Finalize the digest operation
    pub fn finalize<const W: usize, const B: usize>(&mut self) -> CaliptraResult<Array4xN<W, B>> {
        if self.state != Sha3DigestState::Pending {
            return Err(CaliptraError::DRIVER_SHA3_INVALID_STATE_ERR);
        }

        // Update State
        self.state = Sha3DigestState::Final;

        self.sha3.finalize()?;

        let digest = self.sha3.read_digest(self.mode, self.strength)?;

        self.sha3.zeroize_internal();

        Ok(digest)
    }
}
