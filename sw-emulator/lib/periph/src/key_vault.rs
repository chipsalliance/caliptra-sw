/*++

Licensed under the Apache-2.0 license.

File Name:

    key_vault.rs

Abstract:

    File contains Key Vault Implementation

--*/

use bitfield::bitfield;
use caliptra_emu_bus::{Bus, BusError, ReadWriteMemory, ReadWriteRegisterArray};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::cell::RefCell;
use std::rc::Rc;
use tock_registers::interfaces::Readable;
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

#[derive(Clone)]
pub struct KeyVault {
    regs: Rc<RefCell<KeyVaultRegs>>,
}

impl KeyVault {
    const PCR_COUNT: u32 = 8;
    const PCR_SIZE: usize = 64;
    const PCR_CONTROL_REG_OFFSET: u32 = 0x000;
    const PCR_CONTROL_REG_WIDTH: u32 = 0x4;
    const PCR_CONTROL_REG_START_OFFSET: u32 = Self::PCR_CONTROL_REG_OFFSET;
    const PCR_CONTROL_REG_END_OFFSET: u32 =
        Self::PCR_CONTROL_REG_START_OFFSET + (Self::PCR_COUNT - 1) * Self::PCR_CONTROL_REG_WIDTH;

    const PCR_REG_OFFSET: u32 = 0x200;
    const PCR_REG_WIDTH: u32 = 64;
    const PCR_REG_START_OFFSET: u32 = Self::PCR_REG_OFFSET;
    const PCR_REG_END_OFFSET: u32 =
        Self::PCR_REG_START_OFFSET + (Self::PCR_COUNT - 1) * Self::PCR_REG_WIDTH;

    const KEY_COUNT: u32 = 8;
    const KEY_SIZE: usize = 64;
    const KEY_CONTROL_REG_OFFSET: u32 = 0x400;
    const KEY_CONTROL_REG_WIDTH: u32 = 0x4;
    const KEY_CONTROL_REG_START_OFFSET: u32 = Self::KEY_CONTROL_REG_OFFSET;
    const KEY_CONTROL_REG_END_OFFSET: u32 =
        Self::KEY_CONTROL_REG_START_OFFSET + (Self::KEY_COUNT - 1) * Self::KEY_CONTROL_REG_WIDTH;

    const STICKY_DATAVAULT_CTRL_REG_COUNT: u32 = 10;
    const STICKY_DATAVAULT_CTRL_REG_WIDTH: u32 = 4;
    const STICKY_DATAVAULT_CTRL_REG_START_OFFSET: u32 = 0x804;
    const STICKY_DATAVAULT_CTRL_REG_END_OFFSET: u32 = Self::STICKY_DATAVAULT_CTRL_REG_START_OFFSET
        + (Self::STICKY_DATAVAULT_CTRL_REG_COUNT - 1) * Self::STICKY_DATAVAULT_CTRL_REG_WIDTH;

    const NONSTICKY_DATAVAULT_CTRL_REG_COUNT: u32 = 10;
    const NONSTICKY_DATAVAULT_CTRL_REG_WIDTH: u32 = 4;
    const NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET: u32 = 0x82c;
    const NONSTICKY_DATAVAULT_CTRL_REG_END_OFFSET: u32 =
        Self::NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET
            + (Self::NONSTICKY_DATAVAULT_CTRL_REG_COUNT - 1)
                * Self::NONSTICKY_DATAVAULT_CTRL_REG_WIDTH;

    const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT: u32 = 10;
    const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH: u32 = 4;
    const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET: u32 = 0x854;
    const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_END_OFFSET: u32 =
        Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
            + (Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT - 1)
                * Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH;

    const STICKY_DATAVAULT_ENTRY_COUNT: u32 = 10;
    const STICKY_DATAVAULT_ENTRY_WIDTH: u32 = 48;
    const STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET: u32 = 0x900;
    const STICKY_DATAVAULT_ENTRY_WORD_END_OFFSET: u32 =
        Self::STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
            + Self::STICKY_DATAVAULT_ENTRY_COUNT * Self::STICKY_DATAVAULT_ENTRY_WIDTH
            - 4;

    const NONSTICKY_DATAVAULT_ENTRY_COUNT: u32 = 10;
    const NONSTICKY_DATAVAULT_ENTRY_WIDTH: u32 = 48;
    const NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET: u32 = 0xc00;
    const NONSTICKY_DATAVAULT_ENTRY_WORD_END_OFFSET: u32 =
        Self::NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
            + Self::NONSTICKY_DATAVAULT_ENTRY_COUNT * Self::NONSTICKY_DATAVAULT_ENTRY_WIDTH
            - 4;

    const NONSTICKY_LOCKABLE_SCRATCH_REG_COUNT: u32 = 10;
    const NONSTICKY_LOCKABLE_SCRATCH_REG_WIDTH: u32 = 4;
    const NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET: u32 = 0xf00;
    const NONSTICKY_LOCKABLE_SCRATCH_REG_END_OFFSET: u32 =
        Self::NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
            + (Self::NONSTICKY_LOCKABLE_SCRATCH_REG_COUNT - 1)
                * Self::NONSTICKY_LOCKABLE_SCRATCH_REG_WIDTH;

    const NONSTICKY_GENERIC_SCRATCH_REG_COUNT: u32 = 8;
    const NONSTICKY_GENERIC_SCRATCH_REG_WIDTH: u32 = 4;
    const NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET: u32 = 0xf28;
    const NONSTICKY_GENERIC_SCRATCH_REG_END_OFFSET: u32 =
        Self::NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET
            + (Self::NONSTICKY_GENERIC_SCRATCH_REG_COUNT - 1)
                * Self::NONSTICKY_GENERIC_SCRATCH_REG_WIDTH;

    const STICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT: u32 = 8;
    const STICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH: u32 = 4;
    const STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET: u32 = 0xf48;
    const STICKY_LOCKABLE_SCRATCH_CTRL_REG_END_OFFSET: u32 =
        Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
            + (Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT - 1)
                * Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH;

    const STICKY_LOCKABLE_SCRATCH_REG_COUNT: u32 = 8;
    const STICKY_LOCKABLE_SCRATCH_REG_WIDTH: u32 = 4;
    const STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET: u32 = 0xf68;
    const STICKY_LOCKABLE_SCRATCH_REG_END_OFFSET: u32 =
        Self::STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
            + (Self::STICKY_LOCKABLE_SCRATCH_REG_COUNT - 1)
                * Self::STICKY_LOCKABLE_SCRATCH_REG_WIDTH;

    /// Create a new instance of KeyVault
    pub fn new() -> Self {
        Self {
            regs: Rc::new(RefCell::new(KeyVaultRegs::new())),
        }
    }

    /// Internal emulator interface to read key from key vault
    pub fn read_key(
        &self,
        key_id: u32,
        desired_usage: KeyUsage,
    ) -> Result<[u8; Self::KEY_SIZE], BusError> {
        self.regs.borrow().read_key(key_id, desired_usage)
    }

    /// Internal emulator interface to write key to key vault
    pub fn write_key(
        &mut self,
        key_id: u32,
        key: &[u8; Self::KEY_SIZE],
        key_usage: u32,
    ) -> Result<(), BusError> {
        self.regs.borrow_mut().write_key(key_id, key, key_usage)
    }

    /// Internal emulator interface to read pcr from key vault
    pub fn read_pcr(&self, key_id: u32) -> [u8; Self::PCR_SIZE] {
        self.regs.borrow().read_pcr(key_id)
    }
}

impl Bus for KeyVault {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match addr {
            Self::STICKY_DATAVAULT_CTRL_REG_START_OFFSET
                ..=Self::STICKY_DATAVAULT_CTRL_REG_END_OFFSET => self
                .regs
                .borrow_mut()
                .read_sticky_datavault_ctrl(addr - Self::STICKY_DATAVAULT_CTRL_REG_START_OFFSET),

            Self::NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET
                ..=Self::NONSTICKY_DATAVAULT_CTRL_REG_END_OFFSET => {
                self.regs.borrow_mut().read_nonsticky_datavault_ctrl(
                    addr - Self::NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET,
                )
            }

            Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                ..=Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_END_OFFSET => {
                self.regs.borrow_mut().read_nonsticky_lockable_scratch_ctrl(
                    addr - Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET,
                )
            }

            Self::STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                ..=Self::STICKY_DATAVAULT_ENTRY_WORD_END_OFFSET => self
                .regs
                .borrow_mut()
                .read_sticky_datavault_entry(addr - Self::STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET),

            Self::NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                ..=Self::NONSTICKY_DATAVAULT_ENTRY_WORD_END_OFFSET => {
                self.regs.borrow_mut().read_nonsticky_datavault_entry(
                    addr - Self::NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET,
                )
            }

            Self::NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
                ..=Self::NONSTICKY_LOCKABLE_SCRATCH_REG_END_OFFSET => {
                self.regs.borrow_mut().read_nonsticky_lockable_scratch(
                    addr - Self::NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET,
                )
            }

            Self::NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET
                ..=Self::NONSTICKY_GENERIC_SCRATCH_REG_END_OFFSET => {
                self.regs.borrow_mut().read_nonsticky_generic_scratch(
                    addr - Self::NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET,
                )
            }

            Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                ..=Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_END_OFFSET => {
                self.regs.borrow_mut().read_sticky_lockable_scratch_ctrl(
                    addr - Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET,
                )
            }

            Self::STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
                ..=Self::STICKY_LOCKABLE_SCRATCH_REG_END_OFFSET => {
                self.regs.borrow_mut().read_sticky_lockable_scratch(
                    addr - Self::STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET,
                )
            }

            _ => self.regs.borrow_mut().read(size, addr),
        }
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            Self::PCR_CONTROL_REG_START_OFFSET..=Self::PCR_CONTROL_REG_END_OFFSET => {
                self.regs
                    .borrow_mut()
                    .write_pcr_ctrl(addr - Self::PCR_CONTROL_REG_START_OFFSET, val);
                Ok(())
            }

            Self::PCR_REG_START_OFFSET..=Self::PCR_REG_END_OFFSET => self
                .regs
                .borrow_mut()
                .write_pcr(addr - Self::PCR_REG_START_OFFSET, val),

            Self::KEY_CONTROL_REG_START_OFFSET..=Self::KEY_CONTROL_REG_END_OFFSET => {
                self.regs
                    .borrow_mut()
                    .write_key_ctrl(addr - Self::KEY_CONTROL_REG_START_OFFSET, val);
                Ok(())
            }

            Self::STICKY_DATAVAULT_CTRL_REG_START_OFFSET
                ..=Self::STICKY_DATAVAULT_CTRL_REG_END_OFFSET => {
                self.regs.borrow_mut().write_sticky_datavault_ctrl(
                    addr - Self::STICKY_DATAVAULT_CTRL_REG_START_OFFSET,
                    val,
                );
                Ok(())
            }

            Self::NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET
                ..=Self::NONSTICKY_DATAVAULT_CTRL_REG_END_OFFSET => {
                self.regs.borrow_mut().write_nonsticky_datavault_ctrl(
                    addr - Self::NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET,
                    val,
                );
                Ok(())
            }

            Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                ..=Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_END_OFFSET => {
                self.regs
                    .borrow_mut()
                    .write_nonsticky_lockable_scratch_ctrl(
                        addr - Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET,
                        val,
                    );
                Ok(())
            }

            Self::STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                ..=Self::STICKY_DATAVAULT_ENTRY_WORD_END_OFFSET => {
                self.regs.borrow_mut().write_sticky_datavault_entry(
                    addr - Self::STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET,
                    val,
                )
            }

            Self::NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                ..=Self::NONSTICKY_DATAVAULT_ENTRY_WORD_END_OFFSET => {
                self.regs.borrow_mut().write_nonsticky_datavault_entry(
                    addr - Self::NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET,
                    val,
                )
            }

            Self::NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
                ..=Self::NONSTICKY_LOCKABLE_SCRATCH_REG_END_OFFSET => {
                self.regs.borrow_mut().write_nonsticky_lockable_scratch(
                    addr - Self::NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET,
                    val,
                )
            }

            Self::NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET
                ..=Self::NONSTICKY_GENERIC_SCRATCH_REG_END_OFFSET => {
                self.regs.borrow_mut().write_nonsticky_generic_scratch(
                    addr - Self::NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET,
                    val,
                );
                Ok(())
            }

            Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                ..=Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_END_OFFSET => {
                self.regs.borrow_mut().write_sticky_lockable_scratch_ctrl(
                    addr - Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET,
                    val,
                );
                Ok(())
            }

            Self::STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
                ..=Self::STICKY_LOCKABLE_SCRATCH_REG_END_OFFSET => {
                self.regs.borrow_mut().write_sticky_lockable_scratch(
                    addr - Self::STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET,
                    val,
                )
            }

            _ => self.regs.borrow_mut().write(size, addr, val),
        }
    }
}

bitfield! {
    /// Key Usage
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    pub struct KeyUsage(u32);

    /// Flag indicating if the key can be used as HMAC key
    pub hmac_key, set_hmac_key: 0;

    /// Flag indicating if the key can be used as HMAC data
    pub hmac_data, set_hmac_data: 1;

    /// Flag indicating if the key can be used as SHA data
    pub sha_data, set_sha_data: 2;

    /// Flag indicating if the key can be used aas ECC Private Key
    pub ecc_private_key, set_ecc_private_key: 3;

    /// Flag indicating if the key can be used aas ECC Key Generation Seed
    pub ecc_key_gen_seed, set_ecc_key_gen_seed: 4;

    /// Flag indicating if the key can be used aas ECC data part of signature
    /// generation and verification process
    pub ecc_data, set_ecc_data:5;
}

impl From<KeyUsage> for u32 {
    /// Converts to this type from the input type.
    fn from(key_usage: KeyUsage) -> Self {
        key_usage.0
    }
}

register_bitfields! [
    u32,

    /// KV Control Register Fields
    pub KV_CONTROL [
        WRITE_LOCK OFFSET(0) NUMBITS(1) [],
        USE_LOCK OFFSET(1) NUMBITS(1) [],
        CLEAR OFFSET(2) NUMBITS(1) [],
        RSVD0 OFFSET(3) NUMBITS(1) [],
        RSVD1 OFFSET(4) NUMBITS(4) [],
        USAGE OFFSET(8) NUMBITS(6) [],
        RSVD OFFSET(14) NUMBITS(18) [],
    ],

    /// Clear Secrets Register Fields
    pub CLEAR_SECRETS [
        SEL_DEBUG_VALUE OFFSET(0) NUMBITS(1) [],
        WR_DEBUG_VALUES OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
    ],

    /// DataVault Control Register Fields
    pub DV_CONTROL [
        LOCK_ENTRY OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Scratch Control Register Fields
    pub SCRATCH_CONTROL [
        LOCK_ENTRY OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],
];

/// Key Vault Peripheral
#[derive(Bus)]
pub struct KeyVaultRegs {
    /// PCR Control Registers
    #[peripheral(offset = 0x0000_0000, mask = 0x0000_00FF)]
    pcr_control: ReadWriteRegisterArray<u32, { Self::PCR_COUNT as usize }, KV_CONTROL::Register>,

    /// PCR Registers
    #[peripheral(offset = 0x0000_0200, mask = 0x0000_01FF)]
    pcrs: ReadWriteMemory<{ Self::PCR_REG_SIZE }>,

    /// Key Control Registers
    #[peripheral(offset = 0x0000_0400, mask = 0x0000_00FF)]
    key_control: ReadWriteRegisterArray<u32, { Self::KEY_COUNT as usize }, KV_CONTROL::Register>,

    /// Key Registers
    keys: ReadWriteMemory<{ Self::KEY_REG_SIZE }>,

    /// Sticky Data Vault Control Registers
    #[peripheral(offset = 0x0000_0804, mask = 0x0000_00FF)]
    sticky_datavault_control: ReadWriteRegisterArray<
        u32,
        { Self::STICKY_DATAVAULT_CTRL_REG_COUNT as usize },
        DV_CONTROL::Register,
    >,

    /// Non-Sticky Data Vault Control Registers
    #[peripheral(offset = 0x0000_082c, mask = 0x0000_00FF)]
    nonsticky_datavault_control: ReadWriteRegisterArray<
        u32,
        { Self::NONSTICKY_DATAVAULT_CTRL_REG_COUNT as usize },
        DV_CONTROL::Register,
    >,

    /// Non-Sticky Lockable Scratch Registers
    #[peripheral(offset = 0x0000_0854, mask = 0x0000_00FF)]
    nonsticky_lockable_scratch_control: ReadWriteRegisterArray<
        u32,
        { Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT as usize },
        SCRATCH_CONTROL::Register,
    >,

    /// Sticky DataVault Entry Registers.
    #[peripheral(offset = 0x0000_0900, mask = 0x0000_01FF)]
    sticky_datavault_entry: ReadWriteMemory<{ Self::STICKY_DATAVAULT_SIZE }>,

    /// Non-Sticky DataVault Entry Registers.
    #[peripheral(offset = 0x0000_0c00, mask = 0x0000_01FF)]
    nonsticky_datavault_entry: ReadWriteMemory<{ Self::NONSTICKY_DATAVAULT_SIZE }>,

    /// Non-Sticky Lockable Scratch Registers.
    #[peripheral(offset = 0x0000_0f00, mask = 0x0000_00FF)]
    nonsticky_lockable_scratch:
        ReadWriteRegisterArray<u32, { Self::NONSTICKY_LOCKABLE_SCRATCH_REG_COUNT as usize }>,

    /// Non-Sticky Generic Scratch Registers.
    #[peripheral(offset = 0x0000_0f28, mask = 0x0000_00FF)]
    nonsticky_generic_scratch:
        ReadWriteRegisterArray<u32, { Self::NONSTICKY_GENERIC_SCRATCH_REG_COUNT as usize }>,

    /// Sticky Lockable Scratch Control Registers.
    #[peripheral(offset = 0x0000_0f48, mask = 0x0000_00FF)]
    sticky_lockable_scratch_control: ReadWriteRegisterArray<
        u32,
        { Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT as usize },
        SCRATCH_CONTROL::Register,
    >,

    /// Sticky Lockable Scratch Registers.
    #[peripheral(offset = 0x0000_0f68, mask = 0x0000_00FF)]
    sticky_lockable_scratch:
        ReadWriteRegisterArray<u32, { Self::STICKY_LOCKABLE_SCRATCH_REG_COUNT as usize }>,
}

impl KeyVaultRegs {
    /// PCR Count
    const PCR_COUNT: u32 = 8;

    /// PCR Size
    const PCR_SIZE: usize = 64;

    /// PCR Register Size
    const PCR_REG_SIZE: usize = 0x200;

    /// PCR Control register reset value
    const PCR_CONTROL_REG_RESET_VAL: u32 = 0x0000_7E00;

    /// Key Count
    const KEY_COUNT: u32 = 8;

    /// Key Size
    const KEY_SIZE: usize = 64;

    /// Key Memory Size
    const KEY_REG_SIZE: usize = 0x200;

    /// Key control register reset value
    const KEY_CONTROL_REG_RESET_VAL: u32 = 0x0000_7E00;

    /// Sticky DataVault Control Register Rest Value.
    const STICKY_DATAVAULT_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Sticky DataVault Control Register Count.
    const STICKY_DATAVAULT_CTRL_REG_COUNT: u32 = 10;

    /// Non-Sticky DataVault Control Register Rest Value.
    const NONSTICKY_DATAVAULT_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Non-Sticky DataVault Control Register Count.
    const NONSTICKY_DATAVAULT_CTRL_REG_COUNT: u32 = 10;

    /// Non-Sticky Lockable Scratch  Control Register Reset Value.
    const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Non-Sticky Lockable Scratch Control Register Count.
    const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT: u32 = 10;

    /// Sticky DataVault Entry Size.
    const STICKY_DATAVAULT_ENTRY_SIZE: usize = 48;

    /// Sticky DataVault Size.
    const STICKY_DATAVAULT_SIZE: usize = 0x1e0;

    /// Non-Sticky DataVault Entry Size.
    const NONSTICKY_DATAVAULT_ENTRY_SIZE: usize = 48;

    /// Non-Sticky Entry Size.
    const NONSTICKY_DATAVAULT_SIZE: usize = 0x1e0;

    /// Non-Sticky Lockable Scratch Register Count.
    const NONSTICKY_LOCKABLE_SCRATCH_REG_COUNT: u32 = 10;

    /// Non-Sticky Generic Scratch Register Count.
    const NONSTICKY_GENERIC_SCRATCH_REG_COUNT: u32 = 8;

    /// Sticky Lockable Scratch Control Register Reset Value.
    const STICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Sticky Lockable Scratch Control Register Count.
    const STICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT: u32 = 8;

    /// Sticky Lockable Scratch Register Count.
    const STICKY_LOCKABLE_SCRATCH_REG_COUNT: u32 = 8;

    /// Create a new instance of KeyVault registers
    pub fn new() -> Self {
        Self {
            pcr_control: ReadWriteRegisterArray::new(Self::PCR_CONTROL_REG_RESET_VAL),
            pcrs: ReadWriteMemory::new(),
            key_control: ReadWriteRegisterArray::new(Self::KEY_CONTROL_REG_RESET_VAL),
            keys: ReadWriteMemory::new(),
            sticky_datavault_control: ReadWriteRegisterArray::new(
                Self::STICKY_DATAVAULT_CTRL_REG_RESET_VAL,
            ),
            nonsticky_datavault_control: ReadWriteRegisterArray::new(
                Self::NONSTICKY_DATAVAULT_CTRL_REG_RESET_VAL,
            ),
            nonsticky_lockable_scratch_control: ReadWriteRegisterArray::new(
                Self::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL,
            ),
            sticky_datavault_entry: ReadWriteMemory::new(),
            nonsticky_datavault_entry: ReadWriteMemory::new(),
            nonsticky_lockable_scratch: ReadWriteRegisterArray::new(0),
            nonsticky_generic_scratch: ReadWriteRegisterArray::new(0),
            sticky_lockable_scratch_control: ReadWriteRegisterArray::new(
                Self::STICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL,
            ),
            sticky_lockable_scratch: ReadWriteRegisterArray::new(0),
        }
    }

    pub fn write_pcr_ctrl(&mut self, addr: RvAddr, val: u32) {
        let pcr_id = addr as usize >> 2;
        let pcr_ctrl_reg = &mut self.pcr_control[pcr_id];
        let val_reg = InMemoryRegister::<u32, KV_CONTROL::Register>::new(val);

        pcr_ctrl_reg.modify(
            KV_CONTROL::WRITE_LOCK.val(
                pcr_ctrl_reg.read(KV_CONTROL::WRITE_LOCK) | val_reg.read(KV_CONTROL::WRITE_LOCK),
            ),
        );

        pcr_ctrl_reg.modify(KV_CONTROL::USAGE.val(val_reg.read(KV_CONTROL::USAGE)));

        if val_reg.is_set(KV_CONTROL::CLEAR) {
            let pcr_min = pcr_id * Self::PCR_SIZE;
            let pcr_max = pcr_min + Self::PCR_SIZE;
            self.pcrs.data_mut()[pcr_min..pcr_max].fill(0);
        }
    }

    pub fn write_key_ctrl(&mut self, addr: RvAddr, val: u32) {
        let key_id = addr as usize >> 2;
        let key_ctrl_reg = &mut self.key_control[key_id];
        let val_reg = InMemoryRegister::<u32, KV_CONTROL::Register>::new(val);

        key_ctrl_reg.modify(
            KV_CONTROL::WRITE_LOCK.val(
                key_ctrl_reg.read(KV_CONTROL::WRITE_LOCK) | val_reg.read(KV_CONTROL::WRITE_LOCK),
            ),
        );

        key_ctrl_reg.modify(
            KV_CONTROL::USE_LOCK
                .val(key_ctrl_reg.read(KV_CONTROL::USE_LOCK) | val_reg.read(KV_CONTROL::USE_LOCK)),
        );

        key_ctrl_reg.modify(KV_CONTROL::USAGE.val(val_reg.read(KV_CONTROL::USAGE)));

        if val_reg.is_set(KV_CONTROL::CLEAR) {
            let key_min = key_id * Self::KEY_SIZE;
            let key_max = key_min + Self::KEY_SIZE;
            self.keys.data_mut()[key_min..key_max].fill(0);
        }
    }

    pub fn read_key(
        &self,
        key_id: u32,
        desired_usage: KeyUsage,
    ) -> Result<[u8; Self::KEY_SIZE], BusError> {
        let key_ctrl_reg = &self.key_control[key_id as usize];
        if (key_ctrl_reg.read(KV_CONTROL::USE_LOCK) != 0)
            || ((key_ctrl_reg.read(KV_CONTROL::USAGE) & u32::from(desired_usage)) == 0)
        {
            Err(BusError::LoadAccessFault)?
        }
        let key_start = key_id as usize * Self::KEY_SIZE;
        let key_end = key_id as usize * Self::KEY_SIZE + Self::KEY_SIZE;
        let mut key = [0u8; Self::KEY_SIZE];
        key.copy_from_slice(&self.keys.data()[key_start..key_end]);
        Ok(key)
    }

    pub fn write_key(
        &mut self,
        key_id: u32,
        key: &[u8; Self::KEY_SIZE],
        key_usage: u32,
    ) -> Result<(), BusError> {
        let key_ctrl_reg = &mut self.key_control[key_id as usize];
        if key_ctrl_reg.read(KV_CONTROL::WRITE_LOCK) != 0
            || key_ctrl_reg.read(KV_CONTROL::USE_LOCK) != 0
        {
            Err(BusError::StoreAccessFault)?
        }
        let key_start = key_id as usize * Self::KEY_SIZE;
        let key_end = key_start + Self::KEY_SIZE;
        self.keys.data_mut()[key_start..key_end].copy_from_slice(key);

        // Update the key usage.
        key_ctrl_reg.modify(KV_CONTROL::USAGE.val(key_usage));

        Ok(())
    }

    pub fn read_pcr(&self, key_id: u32) -> [u8; Self::PCR_SIZE] {
        let key_start = key_id as usize * Self::PCR_SIZE;
        let key_end = key_start + Self::PCR_SIZE;
        let mut key = [0u8; Self::PCR_SIZE];
        key.copy_from_slice(&self.pcrs.data()[key_start..key_end]);
        key
    }

    pub fn write_pcr(&mut self, addr: RvAddr, val: u32) -> Result<(), BusError> {
        let pcr_id = addr as usize / Self::PCR_SIZE;
        let pcr_ctrl_reg = &mut self.pcr_control[pcr_id];
        if pcr_ctrl_reg.read(KV_CONTROL::WRITE_LOCK) != 0 {
            Err(BusError::StoreAccessFault)?
        }
        let pcr_word_start = addr as usize;
        let pcr_word_end = pcr_word_start + RvSize::Word as usize;
        self.pcrs.data_mut()[pcr_word_start..pcr_word_end].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    pub fn read_sticky_datavault_ctrl(&mut self, addr: RvAddr) -> Result<RvData, BusError> {
        Ok(self.sticky_datavault_control[addr as usize >> 2].get())
    }

    pub fn write_sticky_datavault_ctrl(&mut self, addr: RvAddr, val: u32) {
        let ctrl_reg = &mut self.sticky_datavault_control[addr as usize >> 2];
        let val_reg = InMemoryRegister::<u32, DV_CONTROL::Register>::new(val);

        ctrl_reg.modify(
            DV_CONTROL::LOCK_ENTRY
                .val(ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) | val_reg.read(DV_CONTROL::LOCK_ENTRY)),
        );
    }

    fn make_word(&self, arr: &[u8]) -> RvData {
        let mut res: RvData = 0;
        for idx in 0..4 {
            res = res | ((arr[idx] as RvData) << idx * 8);
        }
        res
    }

    pub fn read_sticky_datavault_entry(&mut self, addr: RvAddr) -> Result<RvData, BusError> {
        let dv_entry_word_start = addr as usize;
        let dv_entry_word_end = dv_entry_word_start + RvSize::Word as usize;
        Ok(self
            .make_word(&self.sticky_datavault_entry.data()[dv_entry_word_start..dv_entry_word_end]))
    }

    pub fn write_sticky_datavault_entry(&mut self, addr: RvAddr, val: u32) -> Result<(), BusError> {
        let ctrl_reg =
            &mut self.sticky_datavault_control[addr as usize / Self::STICKY_DATAVAULT_ENTRY_SIZE];
        if ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }
        let dv_entry_word_start = addr as usize;
        let dv_entry_word_end = dv_entry_word_start + RvSize::Word as usize;
        self.sticky_datavault_entry.data_mut()[dv_entry_word_start..dv_entry_word_end]
            .copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    pub fn read_nonsticky_datavault_ctrl(&mut self, addr: RvAddr) -> Result<RvData, BusError> {
        Ok(self.nonsticky_datavault_control[addr as usize >> 2].get())
    }

    pub fn write_nonsticky_datavault_ctrl(&mut self, addr: RvAddr, val: u32) {
        let ctrl_reg = &mut self.nonsticky_datavault_control[addr as usize >> 2];
        let val_reg = InMemoryRegister::<u32, DV_CONTROL::Register>::new(val);

        ctrl_reg.modify(
            DV_CONTROL::LOCK_ENTRY
                .val(ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) | val_reg.read(DV_CONTROL::LOCK_ENTRY)),
        );
    }

    pub fn read_nonsticky_datavault_entry(&mut self, addr: RvAddr) -> Result<RvData, BusError> {
        let dv_entry_word_start = addr as usize;
        let dv_entry_word_end = dv_entry_word_start + RvSize::Word as usize;
        Ok(self.make_word(
            &self.nonsticky_datavault_entry.data()[dv_entry_word_start..dv_entry_word_end],
        ))
    }

    pub fn write_nonsticky_datavault_entry(
        &mut self,
        addr: RvAddr,
        val: u32,
    ) -> Result<(), BusError> {
        let ctrl_reg = &mut self.nonsticky_datavault_control
            [addr as usize / Self::NONSTICKY_DATAVAULT_ENTRY_SIZE];
        if ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }
        let dv_entry_word_start = addr as usize;
        let dv_entry_word_end = dv_entry_word_start + RvSize::Word as usize;
        self.nonsticky_datavault_entry.data_mut()[dv_entry_word_start..dv_entry_word_end]
            .copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    pub fn read_nonsticky_lockable_scratch_ctrl(
        &mut self,
        addr: RvAddr,
    ) -> Result<RvData, BusError> {
        Ok(self.nonsticky_lockable_scratch_control[addr as usize >> 2].get())
    }

    pub fn write_nonsticky_lockable_scratch_ctrl(&mut self, addr: RvAddr, val: u32) {
        let ctrl_reg = &mut self.nonsticky_lockable_scratch_control[addr as usize >> 2];
        let val_reg = InMemoryRegister::<u32, SCRATCH_CONTROL::Register>::new(val);

        ctrl_reg.modify(SCRATCH_CONTROL::LOCK_ENTRY.val(
            ctrl_reg.read(SCRATCH_CONTROL::LOCK_ENTRY) | val_reg.read(SCRATCH_CONTROL::LOCK_ENTRY),
        ));
    }

    pub fn read_nonsticky_lockable_scratch(&mut self, addr: RvAddr) -> Result<RvData, BusError> {
        Ok(self.nonsticky_lockable_scratch[addr as usize >> 2].get())
    }

    pub fn write_nonsticky_lockable_scratch(
        &mut self,
        addr: RvAddr,
        val: u32,
    ) -> Result<(), BusError> {
        let reg_idx = addr as usize >> 2;
        let ctrl_reg = &mut self.nonsticky_lockable_scratch_control[reg_idx];
        if ctrl_reg.read(SCRATCH_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }

        self.nonsticky_lockable_scratch[reg_idx].set(val);
        Ok(())
    }

    pub fn read_nonsticky_generic_scratch(&mut self, addr: RvAddr) -> Result<RvData, BusError> {
        Ok(self.nonsticky_generic_scratch[addr as usize >> 2].get())
    }

    pub fn write_nonsticky_generic_scratch(&mut self, addr: RvAddr, val: u32) {
        self.nonsticky_generic_scratch[addr as usize >> 2].set(val);
    }

    pub fn read_sticky_lockable_scratch_ctrl(&mut self, addr: RvAddr) -> Result<RvData, BusError> {
        Ok(self.sticky_lockable_scratch_control[addr as usize >> 2].get())
    }

    pub fn write_sticky_lockable_scratch_ctrl(&mut self, addr: RvAddr, val: u32) {
        let ctrl_reg = &mut self.sticky_lockable_scratch_control[addr as usize >> 2];
        let val_reg = InMemoryRegister::<u32, SCRATCH_CONTROL::Register>::new(val);

        ctrl_reg.modify(SCRATCH_CONTROL::LOCK_ENTRY.val(
            ctrl_reg.read(SCRATCH_CONTROL::LOCK_ENTRY) | val_reg.read(SCRATCH_CONTROL::LOCK_ENTRY),
        ));
    }

    pub fn read_sticky_lockable_scratch(&mut self, addr: RvAddr) -> Result<RvData, BusError> {
        Ok(self.sticky_lockable_scratch[addr as usize >> 2].get())
    }

    pub fn write_sticky_lockable_scratch(
        &mut self,
        addr: RvAddr,
        val: u32,
    ) -> Result<(), BusError> {
        let reg_idx = addr as usize >> 2;
        let ctrl_reg = &mut self.sticky_lockable_scratch_control[reg_idx];
        if ctrl_reg.read(SCRATCH_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }

        self.sticky_lockable_scratch[reg_idx].set(val);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tock_registers::interfaces::Writeable;

    const OFFSET_KEY_CONTROL: RvAddr = 0x400;
    const OFFSET_KEYS: RvAddr = 0x600;
    const KEY_CONTROL_RESET_VAL: u32 = 0x0000_7E00;
    const KEY_SIZE: u32 = 64;
    const KEY_CONTROL_REG_WIDTH: u32 = 0x4;

    #[test]
    fn test_key_ctrl_reset_state() {
        let mut vault = KeyVault::new();
        for idx in 0u32..8 {
            assert_eq!(
                vault
                    .read(RvSize::Word, OFFSET_KEY_CONTROL + (idx << 2))
                    .ok(),
                Some(KEY_CONTROL_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_key_read_write() {
        let mut vault = KeyVault::new();
        for idx in 0u32..8 {
            assert_eq!(
                vault
                    .write(RvSize::Word, OFFSET_KEYS + (idx * KEY_SIZE), u32::MAX)
                    .ok(),
                None
            );

            assert_eq!(
                vault
                    .read(RvSize::Word, OFFSET_KEYS + (idx * KEY_SIZE))
                    .ok(),
                None
            );
        }
    }

    #[test]
    fn test_key_private_read_write() {
        let expected: [u8; 64] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b, 0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x1a, 0x79,
            0x05, 0xea, 0x5a, 0x02, 0x05, 0xea, 0x5a, 0x02,
        ];

        let mut vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true); // dummy usage.

        for idx in 0..8 {
            vault
                .write_key(idx, &expected, u32::from(key_usage))
                .unwrap();
            let returned = vault.read_key(idx, key_usage).unwrap();
            assert_eq!(&returned, &expected);
        }
    }

    #[test]
    fn test_key_private_read_blocked() {
        let expected: [u8; 64] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b, 0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x1a, 0x79,
            0x05, 0xea, 0x5a, 0x02, 0x05, 0xea, 0x5a, 0x02,
        ];

        let mut vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true); // dummy usage.

        for key_id in 0..8 {
            let val_reg = InMemoryRegister::<u32, KV_CONTROL::Register>::new(0);
            assert_eq!(
                vault
                    .write(
                        RvSize::Word,
                        OFFSET_KEY_CONTROL + (key_id * KEY_CONTROL_REG_WIDTH),
                        val_reg.get()
                    )
                    .ok(),
                Some(())
            );

            assert_eq!(
                vault
                    .write_key(key_id, &expected, u32::from(key_usage))
                    .is_ok(),
                true
            );

            // Block read access to the key.
            val_reg.write(KV_CONTROL::USE_LOCK.val(1));
            assert_eq!(
                vault
                    .write(
                        RvSize::Word,
                        OFFSET_KEY_CONTROL + (key_id * KEY_CONTROL_REG_WIDTH),
                        val_reg.get()
                    )
                    .ok(),
                Some(())
            );

            assert_eq!(
                vault.read_key(key_id, key_usage).err(),
                Some(BusError::LoadAccessFault)
            );
        }
    }

    #[test]
    fn test_key_private_write_blocked() {
        let expected: [u8; 64] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b, 0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x1a, 0x79,
            0x05, 0xea, 0x5a, 0x02, 0x05, 0xea, 0x5a, 0x02,
        ];

        let mut vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true); // dummy usage.
        let val_reg = InMemoryRegister::<u32, KV_CONTROL::Register>::new(0);
        val_reg.write(KV_CONTROL::WRITE_LOCK.val(1) + KV_CONTROL::USAGE.val(u32::from(key_usage))); // Key write disabled.

        for key_id in 0..8 {
            assert_eq!(
                vault
                    .write(
                        RvSize::Word,
                        OFFSET_KEY_CONTROL + (key_id * KEY_CONTROL_REG_WIDTH),
                        val_reg.get()
                    )
                    .ok(),
                Some(())
            );

            assert_eq!(
                vault
                    .write_key(key_id, &expected, u32::from(key_usage))
                    .err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }

    #[test]
    fn test_key_clear() {
        let expected: [u8; 64] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b, 0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x1a, 0x79,
            0x05, 0xea, 0x5a, 0x02, 0x05, 0xea, 0x5a, 0x02,
        ];

        let cleared_key: [u8; 64] = [0; 64];

        let mut vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true); // dummy usage.
        let val_reg = InMemoryRegister::<u32, KV_CONTROL::Register>::new(0);
        val_reg.write(KV_CONTROL::CLEAR.val(1) + KV_CONTROL::USAGE.val(u32::from(key_usage))); // Clear key.

        for key_id in 0..8 {
            assert_eq!(
                vault
                    .write_key(key_id, &expected, u32::from(key_usage))
                    .ok(),
                Some(())
            );
            assert_eq!(&vault.read_key(key_id, key_usage).unwrap(), &expected);

            // Clear the key.
            assert_eq!(
                vault
                    .write(
                        RvSize::Word,
                        OFFSET_KEY_CONTROL + (key_id * KEY_CONTROL_REG_WIDTH),
                        val_reg.get()
                    )
                    .ok(),
                Some(())
            );

            assert_eq!(&vault.read_key(key_id, key_usage).unwrap(), &cleared_key);
        }
    }

    #[test]
    fn test_sticky_dv_entry_ctrl_reset_state() {
        let mut vault = KeyVault::new();
        for ctrl_reg_idx in 0u32..KeyVault::STICKY_DATAVAULT_CTRL_REG_COUNT {
            let ctrl_reg_addr = KeyVault::STICKY_DATAVAULT_CTRL_REG_START_OFFSET
                + (ctrl_reg_idx * KeyVault::STICKY_DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, ctrl_reg_addr).ok(),
                Some(KeyVaultRegs::STICKY_DATAVAULT_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_sticky_dv_entry_read_write() {
        let mut vault = KeyVault::new();
        for dv_entry_idx in 0u32..KeyVault::STICKY_DATAVAULT_ENTRY_COUNT {
            // Test Read/Write
            for word_offset in 0u32..KeyVault::STICKY_DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = KeyVault::STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * KeyVault::STICKY_DATAVAULT_ENTRY_WIDTH)
                    + (word_offset * 4);

                assert_eq!(
                    vault.write(RvSize::Word, dv_word_addr, 0xCAFEB0BA).ok(),
                    Some(())
                );
                assert_eq!(
                    vault.read(RvSize::Word, dv_word_addr).ok(),
                    Some(0xCAFEB0BA)
                );
            }

            // Test Lock.
            let ctrl_reg_addr = KeyVault::STICKY_DATAVAULT_CTRL_REG_START_OFFSET
                + (dv_entry_idx * KeyVault::STICKY_DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(vault.write(RvSize::Word, ctrl_reg_addr, 0x1).ok(), Some(()));
            assert_eq!(vault.read(RvSize::Word, ctrl_reg_addr).ok(), Some(0x1));

            for word_offset in 0u32..KeyVault::STICKY_DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = KeyVault::STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * KeyVault::STICKY_DATAVAULT_ENTRY_WIDTH)
                    + (word_offset * 4);

                assert_eq!(
                    vault.write(RvSize::Word, dv_word_addr, u32::MAX).err(),
                    Some(BusError::StoreAccessFault)
                );
            }
        }
    }

    #[test]
    fn test_nonsticky_dv_entry_ctrl_reset_state() {
        let mut vault = KeyVault::new();
        for ctrl_reg_idx in 0u32..KeyVault::NONSTICKY_DATAVAULT_CTRL_REG_COUNT {
            let ctrl_reg_addr = KeyVault::NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET
                + (ctrl_reg_idx * KeyVault::NONSTICKY_DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, ctrl_reg_addr).ok(),
                Some(KeyVaultRegs::NONSTICKY_DATAVAULT_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_nonsticky_dv_entry_read_write() {
        let mut vault = KeyVault::new();
        for dv_entry_idx in 0u32..KeyVault::NONSTICKY_DATAVAULT_ENTRY_COUNT {
            // Test Read/Write
            for word_offset in 0u32..KeyVault::NONSTICKY_DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = KeyVault::NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * KeyVault::NONSTICKY_DATAVAULT_ENTRY_WIDTH)
                    + (word_offset * 4);

                assert_eq!(
                    vault.write(RvSize::Word, dv_word_addr, 0xDEADBEEF).ok(),
                    Some(())
                );
                assert_eq!(
                    vault.read(RvSize::Word, dv_word_addr).ok(),
                    Some(0xDEADBEEF)
                );
            }

            // Test Lock.
            let ctrl_reg_addr = KeyVault::NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET
                + (dv_entry_idx * KeyVault::NONSTICKY_DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(vault.write(RvSize::Word, ctrl_reg_addr, 0x1).ok(), Some(()));
            assert_eq!(vault.read(RvSize::Word, ctrl_reg_addr).ok(), Some(0x1));

            for word_offset in 0u32..KeyVault::NONSTICKY_DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = KeyVault::NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * KeyVault::NONSTICKY_DATAVAULT_ENTRY_WIDTH)
                    + (word_offset * 4);

                assert_eq!(
                    vault.write(RvSize::Word, dv_word_addr, u32::MAX).err(),
                    Some(BusError::StoreAccessFault)
                );
            }
        }
    }

    #[test]
    fn test_nonsticky_lockable_scratch_ctrl_reset_state() {
        let mut vault = KeyVault::new();
        for ctrl_reg_idx in 0u32..KeyVault::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT {
            let addr = KeyVault::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (ctrl_reg_idx * KeyVault::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, addr).ok(),
                Some(KeyVaultRegs::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_nonsticky_lockable_scratch_read_write() {
        let mut vault = KeyVault::new();
        for reg_idx in 0u32..KeyVault::NONSTICKY_LOCKABLE_SCRATCH_REG_COUNT {
            // Test Read/Write
            let reg_addr = KeyVault::NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
                + (reg_idx * KeyVault::NONSTICKY_LOCKABLE_SCRATCH_REG_WIDTH);

            assert_eq!(
                vault.write(RvSize::Word, reg_addr, 0xBADF00D).ok(),
                Some(())
            );
            assert_eq!(vault.read(RvSize::Word, reg_addr).ok(), Some(0xBADF00D));

            // Test Lock.
            let ctrl_reg_addr = KeyVault::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (reg_idx * KeyVault::NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
            assert_eq!(vault.write(RvSize::Word, ctrl_reg_addr, 0x1).ok(), Some(()));
            assert_eq!(vault.read(RvSize::Word, ctrl_reg_addr).ok(), Some(0x1));

            assert_eq!(
                vault.write(RvSize::Word, reg_addr, u32::MAX).err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }

    #[test]
    fn test_sticky_lockable_scratch_ctrl_reset_state() {
        let mut vault = KeyVault::new();
        for ctrl_reg_idx in 0u32..KeyVault::STICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT {
            let addr = KeyVault::STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (ctrl_reg_idx * KeyVault::STICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, addr).ok(),
                Some(KeyVaultRegs::STICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_sticky_lockable_scratch_read_write() {
        let mut vault = KeyVault::new();
        for reg_idx in 0u32..KeyVault::STICKY_LOCKABLE_SCRATCH_REG_COUNT {
            // Test Read/Write
            let reg_addr = KeyVault::STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
                + (reg_idx * KeyVault::STICKY_LOCKABLE_SCRATCH_REG_WIDTH);

            assert_eq!(vault.write(RvSize::Word, reg_addr, 0xDADB0D).ok(), Some(()));
            assert_eq!(vault.read(RvSize::Word, reg_addr).ok(), Some(0xDADB0D));

            // Test Lock.
            let ctrl_reg_addr = KeyVault::STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (reg_idx * KeyVault::STICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
            assert_eq!(vault.write(RvSize::Word, ctrl_reg_addr, 0x1).ok(), Some(()));
            assert_eq!(vault.read(RvSize::Word, ctrl_reg_addr).ok(), Some(0x1));

            assert_eq!(
                vault.write(RvSize::Word, reg_addr, u32::MAX).err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }

    #[test]
    fn test_nonsticky_generic_scratch_read_write() {
        let mut vault = KeyVault::new();
        for reg_idx in 0u32..KeyVault::NONSTICKY_GENERIC_SCRATCH_REG_COUNT {
            let reg_addr = KeyVault::NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET
                + (reg_idx * KeyVault::NONSTICKY_GENERIC_SCRATCH_REG_WIDTH);

            assert_eq!(
                vault.write(RvSize::Word, reg_addr, 0xFEEDF00D).ok(),
                Some(())
            );
            assert_eq!(vault.read(RvSize::Word, reg_addr).ok(), Some(0xFEEDF00D));
        }
    }
}
