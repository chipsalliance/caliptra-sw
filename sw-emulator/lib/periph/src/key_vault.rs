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
use tock_registers::{register_bitfields, LocalRegisterCopy};

mod constants {
    #![allow(unused)]

    // Key Vault
    pub const KEY_CONTROL_REG_START_OFFSET: u32 = crate::KeyVault::KEY_CONTROL_REG_OFFSET;
    pub const KEY_CONTROL_REG_END_OFFSET: u32 = KEY_CONTROL_REG_START_OFFSET
        + (crate::KeyVault::KEY_COUNT - 1) * crate::KeyVault::KEY_CONTROL_REG_WIDTH;

    // PCR Vault
    pub const PCR_SIZE: usize = 48;
    pub const PCR_SIZE_WORDS: usize = PCR_SIZE / 4;
    pub const PCR_COUNT: u32 = 32;
    pub const PCR_CONTROL_REG_OFFSET: u32 = 0x2000;
    pub const PCR_CONTROL_REG_WIDTH: u32 = 0x4;
    pub const PCR_CONTROL_REG_START_OFFSET: u32 = PCR_CONTROL_REG_OFFSET;
    pub const PCR_CONTROL_REG_END_OFFSET: u32 =
        PCR_CONTROL_REG_START_OFFSET + (PCR_COUNT - 1) * PCR_CONTROL_REG_WIDTH;

    // Sticky Data Vault
    pub const STICKY_DATAVAULT_CTRL_REG_COUNT: u32 = 10;
    pub const STICKY_DATAVAULT_CTRL_REG_WIDTH: u32 = 4;
    pub const STICKY_DATAVAULT_CTRL_REG_START_OFFSET: u32 = 0x4000;
    pub const STICKY_DATAVAULT_CTRL_REG_END_OFFSET: u32 = STICKY_DATAVAULT_CTRL_REG_START_OFFSET
        + (STICKY_DATAVAULT_CTRL_REG_COUNT - 1) * STICKY_DATAVAULT_CTRL_REG_WIDTH;

    pub const STICKY_DATAVAULT_ENTRY_COUNT: u32 = 10;
    pub const STICKY_DATAVAULT_ENTRY_WIDTH: u32 = 48;
    pub const STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET: u32 = 0x4028;
    pub const STICKY_DATAVAULT_ENTRY_WORD_END_OFFSET: u32 = STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
        + STICKY_DATAVAULT_ENTRY_COUNT * STICKY_DATAVAULT_ENTRY_WIDTH
        - 4;

    // Non-Sticky Data Vault
    pub const NONSTICKY_DATAVAULT_CTRL_REG_COUNT: u32 = 10;
    pub const NONSTICKY_DATAVAULT_CTRL_REG_WIDTH: u32 = 4;
    pub const NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET: u32 = 0x4208;
    pub const NONSTICKY_DATAVAULT_CTRL_REG_END_OFFSET: u32 =
        NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET
            + (NONSTICKY_DATAVAULT_CTRL_REG_COUNT - 1) * NONSTICKY_DATAVAULT_CTRL_REG_WIDTH;

    pub const NONSTICKY_DATAVAULT_ENTRY_COUNT: u32 = 10;
    pub const NONSTICKY_DATAVAULT_ENTRY_WIDTH: u32 = 48;
    pub const NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET: u32 = 0x4230;
    pub const NONSTICKY_DATAVAULT_ENTRY_WORD_END_OFFSET: u32 =
        NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
            + NONSTICKY_DATAVAULT_ENTRY_COUNT * NONSTICKY_DATAVAULT_ENTRY_WIDTH
            - 4;

    // Non-Sticky Lockable Scratch
    pub const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT: u32 = 10;
    pub const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH: u32 = 4;
    pub const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET: u32 = 0x4410;
    pub const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_END_OFFSET: u32 =
        NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
            + (NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT - 1)
                * NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH;

    pub const NONSTICKY_LOCKABLE_SCRATCH_REG_COUNT: u32 = 10;
    pub const NONSTICKY_LOCKABLE_SCRATCH_REG_WIDTH: u32 = 4;
    pub const NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET: u32 = 0x4438;
    pub const NONSTICKY_LOCKABLE_SCRATCH_REG_END_OFFSET: u32 =
        NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
            + (NONSTICKY_LOCKABLE_SCRATCH_REG_COUNT - 1) * NONSTICKY_LOCKABLE_SCRATCH_REG_WIDTH;

    // Non-Sticky Generic Scratch
    pub const NONSTICKY_GENERIC_SCRATCH_REG_COUNT: u32 = 8;
    pub const NONSTICKY_GENERIC_SCRATCH_REG_WIDTH: u32 = 4;
    pub const NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET: u32 = 0x4460;
    pub const NONSTICKY_GENERIC_SCRATCH_REG_END_OFFSET: u32 =
        NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET
            + (NONSTICKY_GENERIC_SCRATCH_REG_COUNT - 1) * NONSTICKY_GENERIC_SCRATCH_REG_WIDTH;

    // Sticky Lockable Scratch
    pub const STICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT: u32 = 8;
    pub const STICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH: u32 = 4;
    pub const STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET: u32 = 0x4480;
    pub const STICKY_LOCKABLE_SCRATCH_CTRL_REG_END_OFFSET: u32 =
        STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
            + (STICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT - 1) * STICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH;

    pub const STICKY_LOCKABLE_SCRATCH_REG_COUNT: u32 = 8;
    pub const STICKY_LOCKABLE_SCRATCH_REG_WIDTH: u32 = 4;
    pub const STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET: u32 = 0x44a0;
    pub const STICKY_LOCKABLE_SCRATCH_REG_END_OFFSET: u32 = STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
        + (STICKY_LOCKABLE_SCRATCH_REG_COUNT - 1) * STICKY_LOCKABLE_SCRATCH_REG_WIDTH;

    /// PCR Register Size
    pub const PCR_REG_SIZE: usize = 0x600;

    /// PCR Control register reset value
    pub const PCR_CONTROL_REG_RESET_VAL: u32 = 0;

    /// Key Memory Size
    pub const KEY_REG_SIZE: usize = 0x600;

    /// Key control register reset value
    pub const KEY_CONTROL_REG_RESET_VAL: u32 = 0;

    /// Sticky DataVault Control Register Rest Value.
    pub const STICKY_DATAVAULT_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Non-Sticky DataVault Control Register Rest Value.
    pub const NONSTICKY_DATAVAULT_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Non-Sticky Lockable Scratch  Control Register Reset Value.
    pub const NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Sticky DataVault Entry Size.
    pub const STICKY_DATAVAULT_ENTRY_SIZE_WORDS: usize = 48 >> 2;

    /// Sticky DataVault Size.
    pub const STICKY_DATAVAULT_SIZE_WORDS: usize = 0x1e0 >> 2;

    /// Non-Sticky DataVault Entry Size.
    pub const NONSTICKY_DATAVAULT_ENTRY_SIZE_WORDS: usize = 48 >> 2;

    /// Non-Sticky Entry Size.
    pub const NONSTICKY_DATAVAULT_SIZE_WORDS: usize = 0x1e0 >> 2;

    /// Sticky Lockable Scratch Control Register Reset Value.
    pub const STICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL: u32 = 0x0;
}

#[derive(Clone)]
pub struct KeyVault {
    regs: Rc<RefCell<KeyVaultRegs>>,
}

impl KeyVault {
    pub const KEY_COUNT: u32 = 32;
    pub const KEY_SIZE: usize = 48;
    pub const KEY_CONTROL_REG_OFFSET: u32 = 0;
    pub const KEY_CONTROL_REG_WIDTH: u32 = 0x4;

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
    ) -> Result<[u8; KeyVault::KEY_SIZE], BusError> {
        self.regs.borrow().read_key(key_id, desired_usage)
    }

    /// Internal emulator interface to write key to key vault
    pub fn write_key(
        &mut self,
        key_id: u32,
        key: &[u8; KeyVault::KEY_SIZE],
        key_usage: u32,
    ) -> Result<(), BusError> {
        self.regs.borrow_mut().write_key(key_id, key, key_usage)
    }

    /// Internal emulator interface to read pcr from key vault
    pub fn read_pcr(&self, pcr_id: u32) -> [u8; constants::PCR_SIZE] {
        self.regs.borrow().read_pcr(pcr_id)
    }

    /// Internal emulator interface to write pcr to key vault
    pub fn write_pcr(
        &mut self,
        pcr_id: u32,
        pcr: &[u8; constants::PCR_SIZE],
    ) -> Result<(), BusError> {
        self.regs.borrow_mut().write_pcr(pcr_id, pcr)
    }
}
impl Default for KeyVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus for KeyVault {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.regs.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.regs.borrow_mut().write(size, addr, val)
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
        RSVD1 OFFSET(4) NUMBITS(5) [],
        USAGE OFFSET(9) NUMBITS(6) [],
        LAST_DWORD OFFSET(15) NUMBITS(4) [],
        RSVD OFFSET(19) NUMBITS(13) [],
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

    /// PCR Control Register Fields
    pub PV_CONTROL [
        LOCK OFFSET(0) NUMBITS(1) [],
        CLEAR OFFSET(1) NUMBITS(1) [],
        RSVD0 OFFSET(2) NUMBITS(1) [],
        RSVD1 OFFSET(3) NUMBITS(5) [],
        RSVD OFFSET(8) NUMBITS(24) [],
    ],
];

use constants::*;

/// Key Vault Peripheral
#[derive(Bus)]
pub struct KeyVaultRegs {
    /// Key Control Registers
    #[register_array(offset = 0x0000_0000, write_fn = write_key_ctrl)]
    key_control:
        ReadWriteRegisterArray<u32, { KeyVault::KEY_COUNT as usize }, KV_CONTROL::Register>,

    /// Key Registers
    keys: ReadWriteMemory<{ KEY_REG_SIZE }>,

    /// PCR Control Registers
    #[register_array(offset = 0x0000_2000, write_fn = write_pcr_ctrl)]
    pcr_control: ReadWriteRegisterArray<u32, { PCR_COUNT as usize }, PV_CONTROL::Register>,

    /// PCR Registers
    pcrs: ReadWriteMemory<{ PCR_REG_SIZE }>,

    /// Sticky Data Vault Control Registers
    #[register_array(offset = 0x0000_4000, write_fn = write_sticky_datavault_ctrl)]
    sticky_datavault_control: ReadWriteRegisterArray<
        u32,
        { STICKY_DATAVAULT_CTRL_REG_COUNT as usize },
        DV_CONTROL::Register,
    >,

    /// Sticky DataVault Entry Registers.
    #[register_array(offset = 0x0000_4028, write_fn = write_sticky_datavault_entry)]
    sticky_datavault_entry: [u32; STICKY_DATAVAULT_SIZE_WORDS],

    /// Non-Sticky Data Vault Control Registers
    #[register_array(offset = 0x0000_4208, write_fn = write_nonsticky_datavault_ctrl)]
    nonsticky_datavault_control: ReadWriteRegisterArray<
        u32,
        { NONSTICKY_DATAVAULT_CTRL_REG_COUNT as usize },
        DV_CONTROL::Register,
    >,

    /// Non-Sticky DataVault Entry Registers.
    #[register_array(offset = 0x0000_4230, write_fn = write_nonsticky_datavault_entry)]
    nonsticky_datavault_entry: [u32; NONSTICKY_DATAVAULT_SIZE_WORDS],

    /// Non-Sticky Lockable Scratch Control Registers
    #[register_array(offset = 0x0000_4410, write_fn = write_nonsticky_lockable_scratch_ctrl)]
    nonsticky_lockable_scratch_control: ReadWriteRegisterArray<
        u32,
        { NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT as usize },
        DV_CONTROL::Register,
    >,

    /// Non-Sticky Lockable Scratch Registers.
    #[register_array(offset = 0x0000_4438, write_fn = write_nonsticky_lockable_scratch)]
    nonsticky_lockable_scratch:
        ReadWriteRegisterArray<u32, { NONSTICKY_LOCKABLE_SCRATCH_REG_COUNT as usize }>,

    /// Non-Sticky Generic Scratch Registers.
    #[register_array(offset = 0x0000_4460)]
    nonsticky_generic_scratch:
        ReadWriteRegisterArray<u32, { NONSTICKY_GENERIC_SCRATCH_REG_COUNT as usize }>,

    /// Sticky Lockable Scratch Control Registers.
    #[register_array(offset = 0x0000_4480, write_fn = write_sticky_lockable_scratch_ctrl)]
    sticky_lockable_scratch_control: ReadWriteRegisterArray<
        u32,
        { STICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT as usize },
        DV_CONTROL::Register,
    >,

    /// Sticky Lockable Scratch Registers.
    #[register_array(offset = 0x0000_44a0, write_fn = write_sticky_lockable_scratch)]
    sticky_lockable_scratch:
        ReadWriteRegisterArray<u32, { STICKY_LOCKABLE_SCRATCH_REG_COUNT as usize }>,
}

impl KeyVaultRegs {
    /// Create a new instance of KeyVault registers
    pub fn new() -> Self {
        Self {
            pcr_control: ReadWriteRegisterArray::new(PCR_CONTROL_REG_RESET_VAL),
            pcrs: ReadWriteMemory::new(),
            key_control: ReadWriteRegisterArray::new(KEY_CONTROL_REG_RESET_VAL),
            keys: ReadWriteMemory::new(),
            sticky_datavault_control: ReadWriteRegisterArray::new(
                STICKY_DATAVAULT_CTRL_REG_RESET_VAL,
            ),
            nonsticky_datavault_control: ReadWriteRegisterArray::new(
                NONSTICKY_DATAVAULT_CTRL_REG_RESET_VAL,
            ),
            nonsticky_lockable_scratch_control: ReadWriteRegisterArray::new(
                NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL,
            ),
            sticky_datavault_entry: [0; STICKY_DATAVAULT_SIZE_WORDS],
            nonsticky_datavault_entry: [0; NONSTICKY_DATAVAULT_SIZE_WORDS],
            nonsticky_lockable_scratch: ReadWriteRegisterArray::new(0),
            nonsticky_generic_scratch: ReadWriteRegisterArray::new(0),
            sticky_lockable_scratch_control: ReadWriteRegisterArray::new(
                STICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL,
            ),
            sticky_lockable_scratch: ReadWriteRegisterArray::new(0),
        }
    }

    fn write_pcr_ctrl(&mut self, _size: RvSize, index: usize, val: u32) -> Result<(), BusError> {
        let val = LocalRegisterCopy::<u32, PV_CONTROL::Register>::new(val);
        let pcr_ctrl_reg = &mut self.pcr_control[index];

        pcr_ctrl_reg.modify(
            PV_CONTROL::LOCK.val(pcr_ctrl_reg.read(PV_CONTROL::LOCK) | val.read(PV_CONTROL::LOCK)),
        );

        if pcr_ctrl_reg.read(PV_CONTROL::LOCK) == 0 && val.is_set(PV_CONTROL::CLEAR) {
            self.pcrs.data_mut()[index * PCR_SIZE_WORDS..][..PCR_SIZE_WORDS].fill(0);
        }
        Ok(())
    }

    fn write_key_ctrl(&mut self, _size: RvSize, index: usize, val: u32) -> Result<(), BusError> {
        let val = LocalRegisterCopy::<u32, KV_CONTROL::Register>::new(val);
        let key_ctrl_reg = &mut self.key_control[index];

        key_ctrl_reg.modify(
            KV_CONTROL::WRITE_LOCK
                .val(key_ctrl_reg.read(KV_CONTROL::WRITE_LOCK) | val.read(KV_CONTROL::WRITE_LOCK)),
        );

        key_ctrl_reg.modify(
            KV_CONTROL::USE_LOCK
                .val(key_ctrl_reg.read(KV_CONTROL::USE_LOCK) | val.read(KV_CONTROL::USE_LOCK)),
        );

        key_ctrl_reg.modify(KV_CONTROL::USAGE.val(val.read(KV_CONTROL::USAGE)));

        if key_ctrl_reg.read(KV_CONTROL::WRITE_LOCK) == 0 && val.is_set(KV_CONTROL::CLEAR) {
            let key_min = index * KeyVault::KEY_SIZE;
            let key_max = key_min + KeyVault::KEY_SIZE;
            self.keys.data_mut()[key_min..key_max].fill(0);
        }
        Ok(())
    }

    pub fn read_key(
        &self,
        key_id: u32,
        desired_usage: KeyUsage,
    ) -> Result<[u8; KeyVault::KEY_SIZE], BusError> {
        let key_ctrl_reg = &self.key_control[key_id as usize];
        if (key_ctrl_reg.read(KV_CONTROL::USE_LOCK) != 0)
            || ((key_ctrl_reg.read(KV_CONTROL::USAGE) & u32::from(desired_usage)) == 0)
        {
            Err(BusError::LoadAccessFault)?
        }
        let key_start = key_id as usize * KeyVault::KEY_SIZE;
        let key_end = key_id as usize * KeyVault::KEY_SIZE + KeyVault::KEY_SIZE;
        let mut key = [0u8; KeyVault::KEY_SIZE];
        key.copy_from_slice(&self.keys.data()[key_start..key_end]);
        Ok(key)
    }

    pub fn write_key(
        &mut self,
        key_id: u32,
        key: &[u8; KeyVault::KEY_SIZE],
        key_usage: u32,
    ) -> Result<(), BusError> {
        let key_ctrl_reg = &mut self.key_control[key_id as usize];
        if key_ctrl_reg.read(KV_CONTROL::WRITE_LOCK) != 0
            || key_ctrl_reg.read(KV_CONTROL::USE_LOCK) != 0
        {
            Err(BusError::StoreAccessFault)?
        }
        let key_start = key_id as usize * KeyVault::KEY_SIZE;
        let key_end = key_start + KeyVault::KEY_SIZE;
        self.keys.data_mut()[key_start..key_end].copy_from_slice(key);

        // Update the key usage.
        key_ctrl_reg.modify(KV_CONTROL::USAGE.val(key_usage));

        Ok(())
    }

    pub fn read_pcr(&self, pcr_id: u32) -> [u8; constants::PCR_SIZE] {
        let pcr_start = pcr_id as usize * constants::PCR_SIZE;
        let pcr_end = pcr_start + constants::PCR_SIZE;
        let mut key = [0u8; constants::PCR_SIZE];
        key.copy_from_slice(&self.pcrs.data()[pcr_start..pcr_end]);
        key
    }

    pub fn write_pcr(
        &mut self,
        pcr_id: u32,
        pcr: &[u8; constants::PCR_SIZE],
    ) -> Result<(), BusError> {
        let pcr_ctrl_reg = &mut self.pcr_control[pcr_id as usize];
        if pcr_ctrl_reg.read(PV_CONTROL::LOCK) != 0 {
            Err(BusError::StoreAccessFault)?
        }

        let pcr_start = pcr_id as usize * constants::PCR_SIZE;
        let pcr_end = pcr_start + constants::PCR_SIZE;
        self.pcrs.data_mut()[pcr_start..pcr_end].copy_from_slice(pcr);
        Ok(())
    }

    fn write_sticky_datavault_ctrl(
        &mut self,
        _size: RvSize,
        index: usize,
        val: u32,
    ) -> Result<(), BusError> {
        let val = LocalRegisterCopy::<u32, DV_CONTROL::Register>::new(val);

        let ctrl_reg = &mut self.sticky_datavault_control[index];
        ctrl_reg.modify(
            DV_CONTROL::LOCK_ENTRY
                .val(ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) | val.read(DV_CONTROL::LOCK_ENTRY)),
        );
        Ok(())
    }

    fn write_sticky_datavault_entry(
        &mut self,
        _size: RvSize,
        word_index: usize,
        val: u32,
    ) -> Result<(), BusError> {
        let ctrl_reg =
            &mut self.sticky_datavault_control[word_index / STICKY_DATAVAULT_ENTRY_SIZE_WORDS];
        if ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }
        self.sticky_datavault_entry[word_index] = val;
        Ok(())
    }

    pub fn write_nonsticky_datavault_ctrl(
        &mut self,
        _size: RvSize,
        index: usize,
        val: u32,
    ) -> Result<(), BusError> {
        let val = LocalRegisterCopy::<u32, DV_CONTROL::Register>::new(val);

        let ctrl_reg = &mut self.nonsticky_datavault_control[index];

        ctrl_reg.modify(
            DV_CONTROL::LOCK_ENTRY
                .val(ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) | val.read(DV_CONTROL::LOCK_ENTRY)),
        );
        Ok(())
    }

    pub fn write_nonsticky_datavault_entry(
        &mut self,
        _size: RvSize,
        word_index: usize,
        val: u32,
    ) -> Result<(), BusError> {
        let ctrl_reg = &mut self.nonsticky_datavault_control
            [word_index / (NONSTICKY_DATAVAULT_ENTRY_SIZE_WORDS)];
        if ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }
        self.nonsticky_datavault_entry[word_index] = val;
        Ok(())
    }

    pub fn write_nonsticky_lockable_scratch_ctrl(
        &mut self,
        _size: RvSize,
        index: usize,
        val: u32,
    ) -> Result<(), BusError> {
        let val_reg = LocalRegisterCopy::<u32, DV_CONTROL::Register>::new(val);
        let ctrl_reg = &mut self.nonsticky_lockable_scratch_control[index];

        ctrl_reg.modify(
            DV_CONTROL::LOCK_ENTRY
                .val(ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) | val_reg.read(DV_CONTROL::LOCK_ENTRY)),
        );
        Ok(())
    }

    pub fn write_nonsticky_lockable_scratch(
        &mut self,
        _size: RvSize,
        word_index: usize,
        val: u32,
    ) -> Result<(), BusError> {
        let ctrl_reg = &mut self.nonsticky_lockable_scratch_control[word_index];
        if ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }

        self.nonsticky_lockable_scratch[word_index].set(val);
        Ok(())
    }

    pub fn write_sticky_lockable_scratch_ctrl(
        &mut self,
        _size: RvSize,
        index: usize,
        val: u32,
    ) -> Result<(), BusError> {
        let val = LocalRegisterCopy::<u32, DV_CONTROL::Register>::new(val);
        let ctrl_reg = &mut self.sticky_lockable_scratch_control[index];

        ctrl_reg.modify(
            DV_CONTROL::LOCK_ENTRY
                .val(ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) | val.read(DV_CONTROL::LOCK_ENTRY)),
        );
        Ok(())
    }

    pub fn write_sticky_lockable_scratch(
        &mut self,
        _size: RvSize,
        word_index: usize,
        val: u32,
    ) -> Result<(), BusError> {
        let ctrl_reg = &mut self.sticky_lockable_scratch_control[word_index];
        if ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }
        self.sticky_lockable_scratch[word_index].set(val);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFSET_KEYS: RvAddr = 0x600;

    #[test]
    fn test_key_ctrl_reset_state() {
        let mut vault = KeyVault::new();
        for idx in 0u32..KeyVault::KEY_COUNT {
            assert_eq!(
                vault
                    .read(RvSize::Word, KeyVault::KEY_CONTROL_REG_OFFSET + (idx << 2))
                    .ok(),
                Some(KEY_CONTROL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_key_read_write() {
        let mut vault = KeyVault::new();
        for idx in 0u32..KeyVault::KEY_COUNT {
            let addr = OFFSET_KEYS + (idx * KeyVault::KEY_SIZE as u32);
            assert_eq!(vault.write(RvSize::Word, addr, u32::MAX).ok(), None);

            assert_eq!(vault.read(RvSize::Word, addr).ok(), None);
        }
    }

    #[test]
    fn test_key_private_read_write() {
        let expected: [u8; KeyVault::KEY_SIZE] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b,
        ];

        let mut vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true); // dummy usage.

        for idx in 0..KeyVault::KEY_COUNT {
            vault
                .write_key(idx, &expected, u32::from(key_usage))
                .unwrap();
            let returned = vault.read_key(idx, key_usage).unwrap();
            assert_eq!(&returned, &expected);
        }
    }

    #[test]
    fn test_pcr_private_read_write() {
        let expected: [u8; constants::PCR_SIZE] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b,
        ];

        let mut vault = KeyVault::new();

        for idx in 0..constants::PCR_COUNT {
            vault.write_pcr(idx, &expected).unwrap();
            let returned = vault.read_pcr(idx);
            assert_eq!(&returned, &expected);
        }
    }

    #[test]
    fn test_key_private_read_blocked() {
        let expected: [u8; KeyVault::KEY_SIZE] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b,
        ];

        let mut vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true); // dummy usage.

        for key_id in 0..KeyVault::KEY_COUNT {
            let mut val_reg = LocalRegisterCopy::<u32, KV_CONTROL::Register>::new(0);
            let key_control_addr =
                KeyVault::KEY_CONTROL_REG_OFFSET + (key_id * KeyVault::KEY_CONTROL_REG_WIDTH);
            assert_eq!(
                vault
                    .write(RvSize::Word, key_control_addr, val_reg.get())
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
                    .write(RvSize::Word, key_control_addr, val_reg.get())
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
        let expected: [u8; KeyVault::KEY_SIZE] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b,
        ];

        let mut vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true); // dummy usage.
        let mut val_reg = LocalRegisterCopy::<u32, KV_CONTROL::Register>::new(0);
        val_reg.write(KV_CONTROL::WRITE_LOCK.val(1) + KV_CONTROL::USAGE.val(u32::from(key_usage))); // Key write disabled.

        for key_id in 0..KeyVault::KEY_COUNT {
            assert_eq!(
                vault
                    .write(
                        RvSize::Word,
                        KeyVault::KEY_CONTROL_REG_OFFSET
                            + (key_id * KeyVault::KEY_CONTROL_REG_WIDTH),
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
        let expected: [u8; KeyVault::KEY_SIZE] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b,
        ];

        let cleared_key: [u8; KeyVault::KEY_SIZE] = [0; KeyVault::KEY_SIZE];

        let mut vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true); // dummy usage.
        let mut val_reg = LocalRegisterCopy::<u32, KV_CONTROL::Register>::new(0);
        val_reg.write(KV_CONTROL::CLEAR.val(1) + KV_CONTROL::USAGE.val(u32::from(key_usage))); // Clear key.

        for key_id in 0..KeyVault::KEY_COUNT {
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
                        KeyVault::KEY_CONTROL_REG_OFFSET
                            + (key_id * KeyVault::KEY_CONTROL_REG_WIDTH),
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
        for ctrl_reg_idx in 0u32..STICKY_DATAVAULT_CTRL_REG_COUNT {
            let ctrl_reg_addr = STICKY_DATAVAULT_CTRL_REG_START_OFFSET
                + (ctrl_reg_idx * STICKY_DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, ctrl_reg_addr).ok(),
                Some(STICKY_DATAVAULT_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_sticky_dv_entry_read_write() {
        let mut vault = KeyVault::new();
        for dv_entry_idx in 0u32..STICKY_DATAVAULT_ENTRY_COUNT {
            // Test Read/Write
            for word_offset in 0u32..STICKY_DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * STICKY_DATAVAULT_ENTRY_WIDTH)
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
            let ctrl_reg_addr = STICKY_DATAVAULT_CTRL_REG_START_OFFSET
                + (dv_entry_idx * STICKY_DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(vault.write(RvSize::Word, ctrl_reg_addr, 0x1).ok(), Some(()));
            assert_eq!(vault.read(RvSize::Word, ctrl_reg_addr).ok(), Some(0x1));

            for word_offset in 0u32..STICKY_DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = STICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * STICKY_DATAVAULT_ENTRY_WIDTH)
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
        for ctrl_reg_idx in 0u32..NONSTICKY_DATAVAULT_CTRL_REG_COUNT {
            let ctrl_reg_addr = NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET
                + (ctrl_reg_idx * NONSTICKY_DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, ctrl_reg_addr).ok(),
                Some(NONSTICKY_DATAVAULT_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_nonsticky_dv_entry_read_write() {
        let mut vault = KeyVault::new();
        for dv_entry_idx in 0u32..NONSTICKY_DATAVAULT_ENTRY_COUNT {
            // Test Read/Write
            for word_offset in 0u32..NONSTICKY_DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * NONSTICKY_DATAVAULT_ENTRY_WIDTH)
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
            let ctrl_reg_addr = NONSTICKY_DATAVAULT_CTRL_REG_START_OFFSET
                + (dv_entry_idx * NONSTICKY_DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(vault.write(RvSize::Word, ctrl_reg_addr, 0x1).ok(), Some(()));
            assert_eq!(vault.read(RvSize::Word, ctrl_reg_addr).ok(), Some(0x1));

            for word_offset in 0u32..NONSTICKY_DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = NONSTICKY_DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * NONSTICKY_DATAVAULT_ENTRY_WIDTH)
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
        for ctrl_reg_idx in 0u32..NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT {
            let addr = NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (ctrl_reg_idx * NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, addr).ok(),
                Some(NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_nonsticky_lockable_scratch_read_write() {
        let mut vault = KeyVault::new();
        for reg_idx in 0u32..NONSTICKY_LOCKABLE_SCRATCH_REG_COUNT {
            // Test Read/Write
            let reg_addr = NONSTICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
                + (reg_idx * NONSTICKY_LOCKABLE_SCRATCH_REG_WIDTH);

            assert_eq!(
                vault.write(RvSize::Word, reg_addr, 0xBADF00D).ok(),
                Some(())
            );
            assert_eq!(vault.read(RvSize::Word, reg_addr).ok(), Some(0xBADF00D));

            // Test Lock.
            let ctrl_reg_addr = NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (reg_idx * NONSTICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
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
        for ctrl_reg_idx in 0u32..STICKY_LOCKABLE_SCRATCH_CTRL_REG_COUNT {
            let addr = STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (ctrl_reg_idx * STICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, addr).ok(),
                Some(STICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_sticky_lockable_scratch_read_write() {
        let mut vault = KeyVault::new();
        for reg_idx in 0u32..STICKY_LOCKABLE_SCRATCH_REG_COUNT {
            // Test Read/Write
            let reg_addr = STICKY_LOCKABLE_SCRATCH_REG_START_OFFSET
                + (reg_idx * STICKY_LOCKABLE_SCRATCH_REG_WIDTH);

            assert_eq!(vault.write(RvSize::Word, reg_addr, 0xDADB0D).ok(), Some(()));
            assert_eq!(vault.read(RvSize::Word, reg_addr).ok(), Some(0xDADB0D));

            // Test Lock.
            let ctrl_reg_addr = STICKY_LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (reg_idx * STICKY_LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
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
        for reg_idx in 0u32..NONSTICKY_GENERIC_SCRATCH_REG_COUNT {
            let reg_addr = NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET
                + (reg_idx * NONSTICKY_GENERIC_SCRATCH_REG_WIDTH);

            assert_eq!(
                vault.write(RvSize::Word, reg_addr, 0xFEEDF00D).ok(),
                Some(())
            );
            assert_eq!(vault.read(RvSize::Word, reg_addr).ok(), Some(0xFEEDF00D));
        }
    }
}
