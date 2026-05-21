/*++

Licensed under the Apache-2.0 license.

File Name:

    otp_fc.rs

Abstract:

    File contains the axi subsystem fuse controller.

--*/

use bitfield::size_of;
use caliptra_emu_bus::{Bus, BusError, ReadOnlyRegister, WriteOnlyRegister};
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
}

impl TryFrom<u32> for DaiCmd {
    type Error = ();

    fn try_from(val: u32) -> Result<Self, Self::Error> {
        match val {
            0x2 => Ok(DaiCmd::Write),
            0x4 => Ok(DaiCmd::Digest),
            _ => Err(()),
        }
    }
}

statemachine! {
    transitions: {
        *Idle + Write [is_valid_write] / start_write = Writing,
        Idle + Digest [is_valid_digest] / start_digest = Computing,

        Writing + Complete / finish_write = Idle,
        Computing + Complete / finish_digest = Idle,
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Granularity {
    Bits32,
    Bits64,
}

// Fuse bank layout (from UDS seed base address):
//   UDS:           64 bytes (16 x u32)
//   UDS digest:     8 bytes ( 2 x u32)
//   FE partitions:  4 x (8 bytes data + 8 bytes digest) = 64 bytes
//   Total:         136 bytes (34 x u32)
const FUSE_BANK_SIZE_BYTES: usize = 136;
const UDS_SIZE_BYTES: usize = 64;

pub struct Context {
    pub address: Option<u32>,
    pub wdata0: Option<u32>,
    pub wdata1: Option<u32>,
    pub fuse_bank: [u32; FUSE_BANK_SIZE_BYTES / size_of::<u32>()],
    pub granularity: Granularity,
    pub dai_error: bool,
    pub soc_reg: SocRegistersInternal,
}

impl Context {
    fn new(granularity: Granularity, soc_reg: SocRegistersInternal) -> Self {
        Self {
            address: None,
            wdata0: None,
            wdata1: None,
            fuse_bank: [0; FUSE_BANK_SIZE_BYTES / size_of::<u32>()],
            granularity,
            dai_error: false,
            soc_reg,
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
                if self.granularity == Granularity::Bits64 && self.wdata1.is_none() {
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
        if let (Some(addr), Some(data)) = (self.address, self.wdata0) {
            let idx = (addr as usize) / 4;
            self.fuse_bank[idx] = data;
            if self.granularity == Granularity::Bits64 && idx + 1 < self.fuse_bank.len() {
                if let Some(wdata1) = self.wdata1 {
                    self.fuse_bank[idx + 1] = wdata1;
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

        // Compute SHA-512 hash of UDS portion of fuse bank (first 64 bytes)
        let mut hasher = Sha512::new();
        let uds_words = UDS_SIZE_BYTES / size_of::<u32>();
        for word in self.fuse_bank[..uds_words].iter() {
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

    state_machine: StateMachine<Context>,
}

impl FuseController {
    /// Register offset for ss_uds_seed_base_addr_l in the SoC register block
    const SS_UDS_SEED_BASE_ADDR_L_OFFSET: u32 = 0x520;

    pub fn new(soc_reg: SocRegistersInternal) -> Self {
        // [TODO][CAP2] get actual granularity from soc_reg HWCFG
        let granularity = Granularity::Bits64;

        Self {
            status: ReadOnlyRegister::new(Status::DAI_IDLE::Idle.value),
            direct_access_cmd: WriteOnlyRegister::new(0),
            direct_access_address: WriteOnlyRegister::new(0),
            direct_access_wdata_0: WriteOnlyRegister::new(0),
            direct_access_wdata_1: WriteOnlyRegister::new(0),
            state_machine: StateMachine::new(Context::new(granularity, soc_reg)),
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
        // Read the UDS seed base address from SoC registers to determine the
        // fuse bank base. The firmware writes (dest & 0xFFF) where dest is
        // computed relative to this base.
        let uds_base = self
            .state_machine
            .context
            .soc_reg
            .read(RvSize::Word, Self::SS_UDS_SEED_BASE_ADDR_L_OFFSET)
            .map_err(|_| BusError::StoreAccessFault)?;
        let base_offset = uds_base & 0xFFF;
        let masked_addr = val & 0xFFF;
        if masked_addr < base_offset {
            return Err(BusError::StoreAccessFault);
        }
        let relative_addr = masked_addr - base_offset;
        self.state_machine.context.address = Some(relative_addr);
        Ok(())
    }

    pub fn write_wdata0(&mut self, _size: RvSize, val: u32) -> Result<(), BusError> {
        self.state_machine.context.wdata0 = Some(val);
        Ok(())
    }

    pub fn write_wdata1(&mut self, _size: RvSize, val: u32) -> Result<(), BusError> {
        self.state_machine.context.wdata1 = Some(val);
        Ok(())
    }
}
