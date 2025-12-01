/*++

Licensed under the Apache-2.0 license.

File Name:

    otp_fc.rs

Abstract:

    File contains the axi subsystem fuse controller.

--*/

use bitfield::size_of;
use caliptra_emu_bus::{BusError, ReadOnlyRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::RvSize;
use smlang::statemachine;
use tock_registers::register_bitfields;

use crate::SocRegistersInternal;

register_bitfields! {
    u32,

    /// Status Register
    pub Status [
        DAI_ERROR OFFSET(7) NUMBITS(1) [],
        /// Data Access Interface Idle Status
        DAI_IDLE OFFSET(22) NUMBITS(1) [
            Busy = 0,
            Idle = 1
        ]
    ]
}

#[derive(PartialEq)]
pub enum DaiCmd {
    Write = 0x2,
    Digest = 0x4,
    Zeroize = 0x8,
}

impl TryFrom<u32> for DaiCmd {
    type Error = ();

    fn try_from(val: u32) -> Result<Self, Self::Error> {
        match val {
            0x2 => Ok(DaiCmd::Write),
            0x4 => Ok(DaiCmd::Digest),
            0x8 => Ok(DaiCmd::Zeroize),
            _ => Err(()),
        }
    }
}

statemachine! {
    transitions: {
        *Idle + Write [is_valid_write] / start_write = Writing,
        Idle + Digest [is_valid_digest] / start_digest = Computing,
        Idle + Zeroize [is_valid_zeroize] / start_zeroize = Zeroizing,

        Writing + Complete / finish_write = Idle,
        Computing + Complete / finish_digest = Idle,
        Zeroizing + Complete / finish_zeroize = Idle,
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Granularity {
    Bits32,
    Bits64,
}

// [TODO][CAP2] Used for both UDS (flow correct) and field entropy (needs implementation).
// 80 bytes (UDS) + 96 bytes (FE partitions) = 176 bytes (0xB0)
const FUSE_BANK_SIZE_BYTES: usize = 176;

pub struct Context {
    pub address: Option<u32>,
    pub wdata0: Option<u32>,
    pub wdata1: Option<u32>,
    pub rdata0: Option<u32>,
    pub rdata1: Option<u32>,
    pub fuse_bank: [u32; FUSE_BANK_SIZE_BYTES / size_of::<u32>()],
    pub dai_error: bool,
    pub soc_reg: SocRegistersInternal,
}

impl Context {
    fn new(soc_reg: SocRegistersInternal) -> Self {
        Self {
            address: None,
            wdata0: None,
            wdata1: None,
            rdata0: None,
            rdata1: None,
            fuse_bank: [0; FUSE_BANK_SIZE_BYTES / size_of::<u32>()],
            dai_error: false,
            soc_reg,
        }
    }

    fn granularity(&self) -> Granularity {
        // Get granularity from generic_input_wires[0] bit 31
        // Bit 31 = 0 → 64-bit granularity
        // Bit 31 = 1 → 32-bit granularity
        let input_wires = self.soc_reg.get_generic_input_wires();
        if (input_wires[0] >> 31) & 1 == 0 {
            Granularity::Bits64
        } else {
            Granularity::Bits32
        }
    }
}

impl StateMachineContext for Context {
    fn is_valid_write(&self) -> Result<bool, ()> {
        // Check that we have a valid address and required write data
        match (self.address, self.wdata0) {
            (None, _) | (_, None) => Err(()),
            (Some(addr), Some(_)) => {
                // Check address bounds
                if (addr as usize) >= self.fuse_bank.len() * 4 {
                    return Err(());
                }
                // For 64-bit writes, we need wdata1 too
                if self.granularity() == Granularity::Bits64 && self.wdata1.is_none() {
                    return Err(());
                }
                Ok(true)
            }
        }
    }

    fn is_valid_zeroize(&self) -> Result<bool, ()> {
        // Check that we have a valid address
        match self.address {
            None => Err(()),
            Some(addr) => {
                // Check address bounds
                if (addr as usize) >= self.fuse_bank.len() * 4 {
                    return Err(());
                }
                Ok(true)
            }
        }
    }

    // Validate digest command parameters.
    // The digest operation is only valid when the address points to the base of the UDS fuses (relative address 0).
    fn is_valid_digest(&self) -> Result<bool, ()> {
        match self.address {
            None => Err(()),
            Some(0) => Ok(true),
            Some(_) => Err(()),
        }
    }

    fn start_write(&mut self) -> Result<(), ()> {
        if let (Some(addr), Some(wdata0)) = (self.address, self.wdata0) {
            let idx = (addr as usize) / 4;
            self.fuse_bank[idx] = wdata0;
            self.rdata0 = Some(wdata0);
            if self.granularity() == Granularity::Bits64 && idx + 1 < self.fuse_bank.len() {
                if let Some(wdata1) = self.wdata1 {
                    self.fuse_bank[idx + 1] = wdata1;
                    self.rdata1 = Some(wdata1);
                }
            }
            // Reset the options after command is handled
            self.address = None;
            self.wdata0 = None;
            self.wdata1 = None;
        }
        Ok(())
    }

    fn start_digest(&mut self) -> Result<(), ()> {
        use sha2::{Digest, Sha512};

        // Compute SHA-512 hash of fuse bank contents
        let mut hasher = Sha512::new();
        for word in self.fuse_bank.iter() {
            hasher.update(word.to_be_bytes());
        }
        let hash = hasher.finalize();

        // Convert 64-byte hash into 16 u32 words
        let mut uds_seed = [0u32; 16];
        for (i, chunk) in hash.chunks(4).enumerate() {
            uds_seed[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        // Set the UDS seed in SoC registers
        self.soc_reg.set_uds_seed(&uds_seed);

        // Zeroize the fuse bank
        self.fuse_bank.fill(0);
        Ok(())
    }

    fn finish_write(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn finish_digest(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn start_zeroize(&mut self) -> Result<(), ()> {
        if let Some(addr) = self.address {
            let idx = (addr as usize) / 4;

            // Determine if this is a marker or digest address (which are always 64-bit)
            // We need to check if the address aligns with marker or digest locations
            // For UDS: digest at offset 64, marker at offset 72
            // For FE partitions: each partition is 24 bytes (8 seed + 8 digest + 8 marker)
            //   FE0: starts at 80, digest at 88, marker at 96
            //   FE1: starts at 104, digest at 112, marker at 120
            //   FE2: starts at 128, digest at 136, marker at 144
            //   FE3: starts at 152, digest at 160, marker at 168

            // Check if address is a digest or marker address (always ends at +0 or +8 from base)
            // Digest addresses: 64, 88, 112, 136, 160
            // Marker addresses: 72, 96, 120, 144, 168
            let is_marker_or_digest =
                matches!(addr, 64 | 72 | 88 | 96 | 112 | 120 | 136 | 144 | 160 | 168);

            // Zeroize the word at the address (set to 0xFFFFFFFF)
            self.fuse_bank[idx] = 0xFFFFFFFF;

            // Set rdata0 to show zeroized value
            self.rdata0 = Some(0xFFFFFFFF);

            // For 64-bit granularity OR marker/digest addresses, also zeroize the next word
            if (self.granularity() == Granularity::Bits64 || is_marker_or_digest)
                && idx + 1 < self.fuse_bank.len()
            {
                self.fuse_bank[idx + 1] = 0xFFFFFFFF;
                self.rdata1 = Some(0xFFFFFFFF);
            }

            // Reset address after command is handled
            self.address = None;
        }
        Ok(())
    }

    fn finish_zeroize(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

/// Fuse controller
#[derive(Bus)]
pub struct FuseController {
    #[register(offset = 0x10, read_fn = read_status)]
    status: ReadOnlyRegister<u32, Status::Register>,

    #[register(offset = 0x60, write_fn = write_cmd)]
    direct_access_cmd: WriteOnlyRegister<u32>,

    #[register(offset = 0x64, write_fn = write_address)]
    direct_access_address: WriteOnlyRegister<u32>,

    #[register(offset = 0x68, write_fn = write_wdata0)]
    direct_access_wdata_0: WriteOnlyRegister<u32>,

    #[register(offset = 0x6c, write_fn = write_wdata1)]
    direct_access_wdata_1: WriteOnlyRegister<u32>,

    #[register(offset = 0x70, read_fn = read_rdata0)]
    direct_access_rdata_0: ReadOnlyRegister<u32>,

    #[register(offset = 0x74, read_fn = read_rdata1)]
    direct_access_rdata_1: ReadOnlyRegister<u32>,
    state_machine: StateMachine<Context>,
}

impl FuseController {
    // The fuse banks is emulated as part of this peripheral
    pub const FUSE_BANK_OFFSET: u64 = 0x800;

    pub fn new(soc_reg: SocRegistersInternal) -> Self {
        Self {
            status: ReadOnlyRegister::new(Status::DAI_IDLE::Idle.value),
            direct_access_cmd: WriteOnlyRegister::new(0),
            direct_access_address: WriteOnlyRegister::new(0),
            direct_access_wdata_0: WriteOnlyRegister::new(0),
            direct_access_wdata_1: WriteOnlyRegister::new(0),
            direct_access_rdata_0: ReadOnlyRegister::new(0),
            direct_access_rdata_1: ReadOnlyRegister::new(0),
            state_machine: StateMachine::new(Context::new(soc_reg)),
        }
    }

    pub fn read_status(&self, _size: RvSize) -> Result<u32, BusError> {
        let mut value = match self.state_machine.state() {
            States::Idle => Status::DAI_IDLE::Idle,
            _ => Status::DAI_IDLE::Busy,
        }
        .value;
        if self.state_machine.context.dai_error {
            value |= Status::DAI_ERROR::SET.value;
        }
        Ok(value)
    }

    pub fn write_cmd(&mut self, _size: RvSize, val: u32) -> Result<(), BusError> {
        if let Ok(cmd) = DaiCmd::try_from(val) {
            // Reset error state before new command
            self.state_machine.context.dai_error = false;

            let event = match cmd {
                DaiCmd::Write => Events::Write,
                DaiCmd::Digest => Events::Digest,
                DaiCmd::Zeroize => Events::Zeroize,
            };
            if self.state_machine.process_event(event).is_err() {
                self.state_machine.context.dai_error = true;
            } else {
                // Simulate HW delay before completing
                let _ = self.state_machine.process_event(Events::Complete);
            }
        }
        Ok(())
    }

    pub fn write_address(&mut self, _size: RvSize, val: u32) -> Result<(), BusError> {
        // Only use lowest 12 bits and make relative to FUSE_BANK_OFFSET
        let masked_addr = (val & 0xFFF) as u64;
        if masked_addr < Self::FUSE_BANK_OFFSET {
            return Err(BusError::StoreAccessFault);
        }
        let relative_addr = (masked_addr - Self::FUSE_BANK_OFFSET) as u32;
        self.state_machine.context.address = Some(relative_addr);
        Ok(())
    }

    pub fn write_wdata0(&mut self, _size: RvSize, val: u32) -> Result<(), BusError> {
        self.state_machine.context.wdata0 = Some(val);
        self.state_machine.context.rdata0 = Some(val);
        Ok(())
    }

    pub fn write_wdata1(&mut self, _size: RvSize, val: u32) -> Result<(), BusError> {
        self.state_machine.context.wdata1 = Some(val);
        self.state_machine.context.rdata1 = Some(val);
        Ok(())
    }

    pub fn read_rdata0(&self, _size: RvSize) -> Result<u32, BusError> {
        Ok(self.state_machine.context.rdata0.unwrap_or(0))
    }

    pub fn read_rdata1(&self, _size: RvSize) -> Result<u32, BusError> {
        Ok(self.state_machine.context.rdata1.unwrap_or(0))
    }
}
