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

pub mod constants {
    #![allow(unused)]

    // Key Vault
    pub const KEY_CONTROL_REG_START_OFFSET: u32 = crate::KeyVault::KEY_CONTROL_REG_OFFSET;
    pub const KEY_CONTROL_REG_END_OFFSET: u32 = KEY_CONTROL_REG_START_OFFSET
        + (crate::KeyVault::KEY_COUNT - 1) * crate::KeyVault::KEY_CONTROL_REG_WIDTH;

    // PCR Vault
    pub const PCR_SIZE_BYTES: usize = 48;
    pub const PCR_SIZE_WORDS: usize = PCR_SIZE_BYTES / 4;
    pub const PCR_COUNT: u32 = 32;
    pub const PCR_CONTROL_REG_OFFSET: u32 = 0x2000;
    pub const PCR_CONTROL_REG_WIDTH: u32 = 0x4;
    pub const PCR_CONTROL_REG_START_OFFSET: u32 = PCR_CONTROL_REG_OFFSET;
    pub const PCR_CONTROL_REG_END_OFFSET: u32 =
        PCR_CONTROL_REG_START_OFFSET + (PCR_COUNT - 1) * PCR_CONTROL_REG_WIDTH;
    pub const PCR_REG_OFFSET: u32 = 0x2600;

    // Sticky Data Vault. Unlocked on Cold Reset.
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

    // Lockable Data Vault. Unlocked on Warm Reset.
    pub const DATAVAULT_CTRL_REG_COUNT: u32 = 10;
    pub const DATAVAULT_CTRL_REG_WIDTH: u32 = 4;
    pub const DATAVAULT_CTRL_REG_START_OFFSET: u32 = 0x4208;
    pub const DATAVAULT_CTRL_REG_END_OFFSET: u32 =
        DATAVAULT_CTRL_REG_START_OFFSET + (DATAVAULT_CTRL_REG_COUNT - 1) * DATAVAULT_CTRL_REG_WIDTH;

    pub const DATAVAULT_ENTRY_COUNT: u32 = 10;
    pub const DATAVAULT_ENTRY_WIDTH: u32 = 48;
    pub const DATAVAULT_ENTRY_WORD_START_OFFSET: u32 = 0x4230;
    pub const DATAVAULT_ENTRY_WORD_END_OFFSET: u32 =
        DATAVAULT_ENTRY_WORD_START_OFFSET + DATAVAULT_ENTRY_COUNT * DATAVAULT_ENTRY_WIDTH - 4;

    // Lockable Scratch. Unlocked on Warm Reset.
    pub const LOCKABLE_SCRATCH_CTRL_REG_COUNT: u32 = 10;
    pub const LOCKABLE_SCRATCH_CTRL_REG_WIDTH: u32 = 4;
    pub const LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET: u32 = 0x4410;
    pub const LOCKABLE_SCRATCH_CTRL_REG_END_OFFSET: u32 = LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
        + (LOCKABLE_SCRATCH_CTRL_REG_COUNT - 1) * LOCKABLE_SCRATCH_CTRL_REG_WIDTH;

    pub const LOCKABLE_SCRATCH_REG_COUNT: u32 = 10;
    pub const LOCKABLE_SCRATCH_REG_WIDTH: u32 = 4;
    pub const LOCKABLE_SCRATCH_REG_START_OFFSET: u32 = 0x4438;
    pub const LOCKABLE_SCRATCH_REG_END_OFFSET: u32 = LOCKABLE_SCRATCH_REG_START_OFFSET
        + (LOCKABLE_SCRATCH_REG_COUNT - 1) * LOCKABLE_SCRATCH_REG_WIDTH;

    // Non-Sticky Generic Scratch. Unlocked and Cleared on Warm Reset.
    pub const NONSTICKY_GENERIC_SCRATCH_REG_COUNT: u32 = 8;
    pub const NONSTICKY_GENERIC_SCRATCH_REG_WIDTH: u32 = 4;
    pub const NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET: u32 = 0x4460;
    pub const NONSTICKY_GENERIC_SCRATCH_REG_END_OFFSET: u32 =
        NONSTICKY_GENERIC_SCRATCH_REG_START_OFFSET
            + (NONSTICKY_GENERIC_SCRATCH_REG_COUNT - 1) * NONSTICKY_GENERIC_SCRATCH_REG_WIDTH;

    // Sticky Lockable Scratch. Unlocked on Cold Reset.
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
    pub const PCR_REG_SIZE_WORDS: usize = 0x600 >> 2;

    /// PCR Control register reset value
    pub const PCR_CONTROL_REG_RESET_VAL: u32 = 0;

    /// Key Memory Size
    pub const KEY_REG_SIZE: usize = 0x800;

    /// Key control register reset value
    pub const KEY_CONTROL_REG_RESET_VAL: u32 = 0;

    /// Sticky DataVault Control Register Reset Value.
    pub const STICKY_DATAVAULT_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Non-Sticky DataVault Control Register Reset Value.
    pub const DATAVAULT_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Non-Sticky Lockable Scratch  Control Register Reset Value.
    pub const LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL: u32 = 0x0;

    /// Sticky DataVault Entry Size.
    pub const STICKY_DATAVAULT_ENTRY_SIZE_WORDS: usize = 48 >> 2;

    /// Sticky DataVault Size.
    pub const STICKY_DATAVAULT_SIZE_WORDS: usize = 0x1e0 >> 2;

    /// Non-Sticky DataVault Entry Size.
    pub const NONSTICKY_DATAVAULT_ENTRY_SIZE_WORDS: usize = 48 >> 2;

    /// Non-Sticky Entry Size.
    pub const DATAVAULT_SIZE_WORDS: usize = 0x1e0 >> 2;

    /// Sticky Lockable Scratch Control Register Reset Value.
    pub const STICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL: u32 = 0x0;
}

#[derive(Clone)]
pub struct KeyVault {
    regs: Rc<RefCell<KeyVaultRegs>>,
}

impl KeyVault {
    pub const PCR_SIZE: usize = 48;
    pub const KEY_COUNT: u32 = 24;
    pub const KEY_SIZE: usize = 64;
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

    /// Internal emulator interface to read key from key vault, make sure not to export the keys
    pub fn read_key_locked(
        &self,
        key_id: u32,
        desired_usage: KeyUsage,
    ) -> Result<[u8; KeyVault::KEY_SIZE], BusError> {
        self.regs.borrow().read_key_locked(key_id, desired_usage)
    }

    pub fn read_key_as_data(
        &self,
        key_id: u32,
        desired_usage: KeyUsage,
    ) -> Result<Vec<u8>, BusError> {
        self.regs.borrow().read_key_as_data(key_id, desired_usage)
    }

    /// Internal emulator interface to write key to key vault
    pub fn write_key(&mut self, key_id: u32, key: &[u8], key_usage: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().write_key(key_id, key, key_usage)
    }

    /// Internal emulator interface to read pcr from key vault
    pub fn read_pcr(&self, pcr_id: u32) -> [u8; constants::PCR_SIZE_BYTES] {
        self.regs.borrow().read_pcr(pcr_id)
    }

    /// Internal emulator interface to write pcr to key vault
    pub fn write_pcr(
        &mut self,
        pcr_id: u32,
        pcr: &[u8; constants::PCR_SIZE_BYTES],
    ) -> Result<(), BusError> {
        self.regs.borrow_mut().write_pcr(pcr_id, pcr)
    }

    pub fn clear_keys_with_debug_values(&mut self, sel_debug_value: bool) {
        self.regs
            .borrow_mut()
            .clear_with_debug_values(sel_debug_value);
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

    fn warm_reset(&mut self) {
        self.regs.borrow_mut().warm_reset();
    }

    fn update_reset(&mut self) {
        self.regs.borrow_mut().update_reset();
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

    /// Flag indicating if the key can be used as MLDSA seed
    pub mldsa_seed, set_mldsa_key_gen_seed: 2;

    /// Flag indicating if the key can be used aas ECC Private Key
    pub ecc_private_key, set_ecc_private_key: 3;

    /// Flag indicating if the key can be used aas ECC Key Generation Seed
    pub ecc_key_gen_seed, set_ecc_key_gen_seed: 4;
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

use crate::helpers::{bytes_from_words_le, words_from_bytes_le};

/// Key Vault Peripheral
#[derive(Bus)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
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
    #[register_array(offset = 0x0000_2600)]
    pcrs: [u32; PCR_REG_SIZE_WORDS],

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
    datavault_control:
        ReadWriteRegisterArray<u32, { DATAVAULT_CTRL_REG_COUNT as usize }, DV_CONTROL::Register>,

    /// Non-Sticky DataVault Entry Registers.
    #[register_array(offset = 0x0000_4230, write_fn = write_nonsticky_datavault_entry)]
    datavault_entry: [u32; DATAVAULT_SIZE_WORDS],

    /// Non-Sticky Lockable Scratch Control Registers
    #[register_array(offset = 0x0000_4410, write_fn = write_nonsticky_lockable_scratch_ctrl)]
    lockable_scratch_control: ReadWriteRegisterArray<
        u32,
        { LOCKABLE_SCRATCH_CTRL_REG_COUNT as usize },
        DV_CONTROL::Register,
    >,

    /// Non-Sticky Lockable Scratch Registers.
    #[register_array(offset = 0x0000_4438, write_fn = write_nonsticky_lockable_scratch)]
    lockable_scratch: ReadWriteRegisterArray<u32, { LOCKABLE_SCRATCH_REG_COUNT as usize }>,

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
            pcrs: [0; PCR_REG_SIZE_WORDS],
            key_control: ReadWriteRegisterArray::new(KEY_CONTROL_REG_RESET_VAL),
            keys: ReadWriteMemory::new(),
            sticky_datavault_control: ReadWriteRegisterArray::new(
                STICKY_DATAVAULT_CTRL_REG_RESET_VAL,
            ),
            datavault_control: ReadWriteRegisterArray::new(DATAVAULT_CTRL_REG_RESET_VAL),
            lockable_scratch_control: ReadWriteRegisterArray::new(
                LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL,
            ),
            sticky_datavault_entry: [0; STICKY_DATAVAULT_SIZE_WORDS],
            datavault_entry: [0; DATAVAULT_SIZE_WORDS],
            lockable_scratch: ReadWriteRegisterArray::new(0),
            nonsticky_generic_scratch: ReadWriteRegisterArray::new(0),
            sticky_lockable_scratch_control: ReadWriteRegisterArray::new(
                STICKY_LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL,
            ),
            sticky_lockable_scratch: ReadWriteRegisterArray::new(0),
        }
    }

    fn unlock_vault_registers(&mut self) {
        // Unlock PCRs.
        for pcr_ctrl_reg in self.pcr_control.iter_mut() {
            pcr_ctrl_reg.modify(PV_CONTROL::LOCK::CLEAR);
        }

        // Unlock KV.
        for kv_ctrl_reg in self.key_control.iter_mut() {
            kv_ctrl_reg.modify(KV_CONTROL::WRITE_LOCK::CLEAR + KV_CONTROL::USE_LOCK::CLEAR);
        }

        // Unlock DV.
        for dv_ctrl_reg in self.datavault_control.iter_mut() {
            dv_ctrl_reg.modify(DV_CONTROL::LOCK_ENTRY::CLEAR);
        }

        // Unlock lockable scratch registers.
        for lockable_scratch_ctrl_reg in self.lockable_scratch_control.iter_mut() {
            lockable_scratch_ctrl_reg.modify(DV_CONTROL::LOCK_ENTRY::CLEAR);
        }
    }

    /// Called by Bus::warm_reset() to indicate a warm reset
    fn warm_reset(&mut self) {
        self.unlock_vault_registers();
    }

    /// Called by Bus::update_reset() to indicate an update reset
    fn update_reset(&mut self) {
        self.unlock_vault_registers();
    }

    fn write_pcr_ctrl(&mut self, _size: RvSize, index: usize, val: u32) -> Result<(), BusError> {
        let val = LocalRegisterCopy::<u32, PV_CONTROL::Register>::new(val);
        let pcr_ctrl_reg = &mut self.pcr_control[index];

        pcr_ctrl_reg.modify(
            PV_CONTROL::LOCK.val(pcr_ctrl_reg.read(PV_CONTROL::LOCK) | val.read(PV_CONTROL::LOCK)),
        );

        if pcr_ctrl_reg.read(PV_CONTROL::LOCK) == 0 && val.is_set(PV_CONTROL::CLEAR) {
            let pcr_start = index * constants::PCR_SIZE_WORDS;
            self.pcrs[pcr_start..(pcr_start + PCR_SIZE_WORDS)].fill(0);
        }
        Ok(())
    }

    // Does not write to usage, usage bits aren't directly writable outside of
    // key creation.
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

    pub fn read_key_locked(
        &self,
        key_id: u32,
        desired_usage: KeyUsage,
    ) -> Result<[u8; KeyVault::KEY_SIZE], BusError> {
        let key_ctrl_reg = &self.key_control[key_id as usize];
        if (key_ctrl_reg.read(KV_CONTROL::USAGE) & u32::from(desired_usage)) == 0 {
            Err(BusError::LoadAccessFault)?
        }
        let key_start = key_id as usize * KeyVault::KEY_SIZE;
        let key_end = key_id as usize * KeyVault::KEY_SIZE + KeyVault::KEY_SIZE;
        let mut key = [0u8; KeyVault::KEY_SIZE];
        key.copy_from_slice(&self.keys.data()[key_start..key_end]);
        Ok(key)
    }

    pub fn read_key_as_data(
        &self,
        key_id: u32,
        desired_usage: KeyUsage,
    ) -> Result<Vec<u8>, BusError> {
        let mut result: Vec<u8> = self.read_key(key_id, desired_usage)?.into();
        let key_ctrl_reg = &self.key_control[key_id as usize];
        let last_dword = key_ctrl_reg.read(KV_CONTROL::LAST_DWORD);
        result.resize((last_dword + 1) as usize * 4, 0);
        Ok(result)
    }

    pub fn write_key(&mut self, key_id: u32, key: &[u8], key_usage: u32) -> Result<(), BusError> {
        if key.len() > KeyVault::KEY_SIZE || key.len() % 4 != 0 {
            Err(BusError::StoreAccessFault)?
        }
        let key_wordlen = key.len() / 4;
        let key_ctrl_reg = &mut self.key_control[key_id as usize];
        if key_ctrl_reg.read(KV_CONTROL::WRITE_LOCK) != 0
            || key_ctrl_reg.read(KV_CONTROL::USE_LOCK) != 0
        {
            Err(BusError::StoreAccessFault)?
        }
        let key_start = key_id as usize * KeyVault::KEY_SIZE;
        let key_end = key_start + key.len();
        self.keys.data_mut()[key_start..key_end].copy_from_slice(key);

        // Update the key usage.
        key_ctrl_reg.modify(KV_CONTROL::USAGE.val(key_usage));

        // Update the last dword in the key
        key_ctrl_reg.modify(KV_CONTROL::LAST_DWORD.val(key_wordlen as u32 - 1));

        Ok(())
    }

    pub fn clear_with_debug_values(&mut self, sel_debug_value: bool) {
        let fill_byte = if sel_debug_value { 0x55 } else { 0xaa };
        self.keys.data_mut().fill(fill_byte);
    }

    pub fn read_pcr(&self, pcr_id: u32) -> [u8; constants::PCR_SIZE_BYTES] {
        let pcr_start = pcr_id as usize * constants::PCR_SIZE_WORDS;
        let mut pcr = [0u32; constants::PCR_SIZE_WORDS];
        pcr.copy_from_slice(&self.pcrs[pcr_start..(pcr_start + constants::PCR_SIZE_WORDS)]);
        bytes_from_words_le(&pcr)
    }

    pub fn write_pcr(
        &mut self,
        pcr_id: u32,
        pcr: &[u8; constants::PCR_SIZE_BYTES],
    ) -> Result<(), BusError> {
        let pcr_start = pcr_id as usize * constants::PCR_SIZE_WORDS;
        self.pcrs[pcr_start..(pcr_start + constants::PCR_SIZE_WORDS)]
            .copy_from_slice(words_from_bytes_le(pcr).as_slice());

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

        let ctrl_reg = &mut self.datavault_control[index];

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
        let ctrl_reg =
            &mut self.datavault_control[word_index / (NONSTICKY_DATAVAULT_ENTRY_SIZE_WORDS)];
        if ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }
        self.datavault_entry[word_index] = val;
        Ok(())
    }

    pub fn write_nonsticky_lockable_scratch_ctrl(
        &mut self,
        _size: RvSize,
        index: usize,
        val: u32,
    ) -> Result<(), BusError> {
        let val_reg = LocalRegisterCopy::<u32, DV_CONTROL::Register>::new(val);
        let ctrl_reg = &mut self.lockable_scratch_control[index];

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
        let ctrl_reg = &mut self.lockable_scratch_control[word_index];
        if ctrl_reg.read(DV_CONTROL::LOCK_ENTRY) != 0 {
            Err(BusError::StoreAccessFault)?
        }

        self.lockable_scratch[word_index].set(val);
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
        let expected: &[u8] = &[
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
                .write_key(idx, expected, u32::from(key_usage))
                .unwrap();
            let returned = vault.read_key(idx, key_usage).unwrap();
            assert_eq!(&returned[..expected.len()], expected);
        }
    }

    #[test]
    fn test_key_private_read_write_small() {
        // In this case, only 8 of the total 12 words in the key-entry are
        // written to, so when they are retrieved as data, only those 8 words
        // should be returned.
        let expected: [u8; 32] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea,
        ];

        let mut vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true); // dummy usage.

        for idx in 0..KeyVault::KEY_COUNT {
            vault
                .write_key(idx, &expected, u32::from(key_usage))
                .unwrap();
            let returned = vault.read_key_as_data(idx, key_usage).unwrap();
            assert_eq!(&returned, &expected);

            assert_eq!(
                vault.read_key(idx, key_usage).unwrap(),
                [
                    0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78,
                    0x54, 0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba,
                    0x20, 0x17, 0x1a, 0x79, 0x05, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ]
            );
        }
    }

    #[test]
    fn test_key_clear_with_debug_values() {
        let mut vault = KeyVault::new();

        vault.clear_keys_with_debug_values(false);
        let key_mem: Vec<u8> = vault.regs.borrow().keys.data().to_vec();
        assert_eq!(key_mem, vec![0xaa; key_mem.len()]);

        vault.clear_keys_with_debug_values(true);
        let key_mem: Vec<u8> = vault.regs.borrow().keys.data().to_vec();
        assert_eq!(key_mem, vec![0x55; key_mem.len()]);
    }

    #[test]
    fn test_pcr_read_write() {
        let expected: [u8; constants::PCR_SIZE_BYTES] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b,
        ];

        let mut vault = KeyVault::new();

        for pcr_id in 0..constants::PCR_COUNT {
            vault.write_pcr(pcr_id, &expected).unwrap();

            // Test private read.
            let returned = vault.read_pcr(pcr_id);
            assert_eq!(&returned, &expected);

            // Test public read.
            let mut pcr: [u32; PCR_SIZE_WORDS] = [0u32; PCR_SIZE_WORDS];
            let pcr_start_word_addr = PCR_REG_OFFSET + (pcr_id * PCR_SIZE_BYTES as u32);
            for (word_idx, pcr_word) in pcr.iter_mut().enumerate().take(PCR_SIZE_WORDS) {
                let result = vault.read(
                    RvSize::Word,
                    pcr_start_word_addr + (word_idx as u32 * RvSize::Word as u32),
                );
                assert!(result.is_ok());
                *pcr_word = result.unwrap();
            }
            assert_eq!(&bytes_from_words_le(&pcr), &expected);
        }
    }

    #[test]
    fn test_pcr_lock_clear() {
        let expected: [u8; constants::PCR_SIZE_BYTES] = [
            0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54,
            0x62, 0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17,
            0x1a, 0x79, 0x05, 0xea, 0x5a, 0x02, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11,
            0x5c, 0x36, 0x3a, 0xa3, 0xc7, 0x9b,
        ];
        let cleared_pcr: [u8; constants::PCR_SIZE_BYTES] = [0u8; constants::PCR_SIZE_BYTES];

        let mut vault = KeyVault::new();
        let mut val_reg = LocalRegisterCopy::<u32, PV_CONTROL::Register>::new(0);

        for pcr_id in 0..constants::PCR_COUNT {
            vault.write_pcr(pcr_id, &expected).unwrap();

            // Test private read.
            let returned = vault.read_pcr(pcr_id);
            assert_eq!(&returned, &expected);

            let pcr_control_addr = PCR_CONTROL_REG_OFFSET + (pcr_id * PCR_CONTROL_REG_WIDTH);

            // Clear the PCR.
            val_reg.write(PV_CONTROL::CLEAR.val(1));
            assert_eq!(
                vault
                    .write(RvSize::Word, pcr_control_addr, val_reg.get())
                    .ok(),
                Some(())
            );
            let returned = vault.read_pcr(pcr_id);
            assert_eq!(&returned, &cleared_pcr);

            // Lock PCR
            vault.write_pcr(pcr_id, &expected).unwrap();
            val_reg.write(PV_CONTROL::LOCK.val(1));
            assert_eq!(
                vault
                    .write(RvSize::Word, pcr_control_addr, val_reg.get())
                    .ok(),
                Some(())
            );

            // Try clearing the PCR. This should be a no-op.
            val_reg.write(PV_CONTROL::CLEAR.val(1));
            assert_eq!(
                vault
                    .write(RvSize::Word, pcr_control_addr, val_reg.get())
                    .ok(),
                Some(())
            );
            let returned = vault.read_pcr(pcr_id);
            assert_eq!(&returned, &expected);

            // Unlock PCR. This should be a no-op.
            val_reg.write(PV_CONTROL::LOCK.val(0));
            assert_eq!(
                vault
                    .write(RvSize::Word, pcr_control_addr, val_reg.get())
                    .ok(),
                Some(())
            );

            // Try clearing the PCR again. This should again be a no-op.
            val_reg.write(PV_CONTROL::CLEAR.val(1));
            assert_eq!(
                vault
                    .write(RvSize::Word, pcr_control_addr, val_reg.get())
                    .ok(),
                Some(())
            );
            let returned = vault.read_pcr(pcr_id);
            assert_eq!(&returned, &expected);
        }
    }

    #[test]
    fn test_key_private_read_blocked() {
        let expected: &[u8] = &[
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

            assert!(vault
                .write_key(key_id, expected, u32::from(key_usage))
                .is_ok());

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
        let expected: &[u8] = &[
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
                    .write_key(key_id, expected, u32::from(key_usage))
                    .err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }

    #[test]
    fn test_key_clear() {
        let expected: &[u8] = &[
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
                vault.write_key(key_id, expected, u32::from(key_usage)).ok(),
                Some(())
            );
            let key = vault.read_key(key_id, key_usage).unwrap();
            assert_eq!(&key[..expected.len()], expected);

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
    fn test_dv_entry_ctrl_reset_state() {
        let mut vault = KeyVault::new();
        for ctrl_reg_idx in 0u32..DATAVAULT_CTRL_REG_COUNT {
            let ctrl_reg_addr =
                DATAVAULT_CTRL_REG_START_OFFSET + (ctrl_reg_idx * DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, ctrl_reg_addr).ok(),
                Some(DATAVAULT_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_dv_entry_read_write() {
        let mut vault = KeyVault::new();
        for dv_entry_idx in 0u32..DATAVAULT_ENTRY_COUNT {
            // Test Read/Write
            for word_offset in 0u32..DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * DATAVAULT_ENTRY_WIDTH)
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
            let ctrl_reg_addr =
                DATAVAULT_CTRL_REG_START_OFFSET + (dv_entry_idx * DATAVAULT_CTRL_REG_WIDTH);
            assert_eq!(vault.write(RvSize::Word, ctrl_reg_addr, 0x1).ok(), Some(()));
            assert_eq!(vault.read(RvSize::Word, ctrl_reg_addr).ok(), Some(0x1));

            for word_offset in 0u32..DATAVAULT_ENTRY_WIDTH / 4 {
                let dv_word_addr = DATAVAULT_ENTRY_WORD_START_OFFSET
                    + (dv_entry_idx * DATAVAULT_ENTRY_WIDTH)
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
        for ctrl_reg_idx in 0u32..LOCKABLE_SCRATCH_CTRL_REG_COUNT {
            let addr = LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (ctrl_reg_idx * LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
            assert_eq!(
                vault.read(RvSize::Word, addr).ok(),
                Some(LOCKABLE_SCRATCH_CTRL_REG_RESET_VAL)
            );
        }
    }

    #[test]
    fn test_lockable_scratch_read_write() {
        let mut vault = KeyVault::new();
        for reg_idx in 0u32..LOCKABLE_SCRATCH_REG_COUNT {
            // Test Read/Write
            let reg_addr =
                LOCKABLE_SCRATCH_REG_START_OFFSET + (reg_idx * LOCKABLE_SCRATCH_REG_WIDTH);

            assert_eq!(
                vault.write(RvSize::Word, reg_addr, 0xBADF00D).ok(),
                Some(())
            );
            assert_eq!(vault.read(RvSize::Word, reg_addr).ok(), Some(0xBADF00D));

            // Test Lock.
            let ctrl_reg_addr = LOCKABLE_SCRATCH_CTRL_REG_START_OFFSET
                + (reg_idx * LOCKABLE_SCRATCH_CTRL_REG_WIDTH);
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
