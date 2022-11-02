/*++

Licensed under the Apache-2.0 license.

File Name:

    key_vault.rs

Abstract:

    File contains Key Vault Implementation

--*/

use caliptra_emu_bus::{Bus, BusError, ReadWriteRegisterArray, WriteOnlyMemory};
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
    const KEY_CONTROL_OFFSET: u32 = 0;
    const KEY_CONTROL_MIN: u32 = Self::KEY_CONTROL_OFFSET;
    const KEY_CONTROL_MAX: u32 = Self::KEY_CONTROL_OFFSET + 7 * 4;
    const KEY_SIZE: usize = 64;

    /// Create a new instance of KeyVault
    pub fn new() -> Self {
        Self {
            regs: Rc::new(RefCell::new(KeyVaultRegs::new())),
        }
    }

    pub fn read_key(&self, key_id: u32) -> [u8; Self::KEY_SIZE] {
        self.regs.borrow().read_key(key_id)
    }

    pub fn write_key(&mut self, key_id: u32, key: &[u8; Self::KEY_SIZE]) {
        self.regs.borrow_mut().write_key(key_id, key)
    }
}

impl Bus for KeyVault {
    /// Read data of specified size from given address
    fn read(&self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.regs.borrow().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            Self::KEY_CONTROL_MIN..=Self::KEY_CONTROL_MAX => {
                let key_id = addr as usize >> 2;
                self.regs.borrow_mut().update_key(key_id, val);
                Ok(())
            }
            _ => self.regs.borrow_mut().write(size, addr, val),
        }
    }
}

register_bitfields! [
    u32,

    /// Key Control Register Fields
    pub KEY_CONTROL [
        READ_LOCK OFFSET(0) NUMBITS(1) [],
        WRITE_LOCK OFFSET(1) NUMBITS(1) [],
        USE_LOCK OFFSET(2) NUMBITS(1) [],
        CLEAR OFFSET(3) NUMBITS(1) [],
        HMAC_KEY_USE OFFSET(9) NUMBITS(1) [],
        HMAC_DATA_USE OFFSET(10) NUMBITS(1) [],
        SHA_DATA_USE OFFSET(11) NUMBITS(1) [],
        ECC_PRIV_KEY_USE OFFSET(12) NUMBITS(1) [],
        ECC_SEED_USE OFFSET(13) NUMBITS(1) [],
        ECC_DATA_USE OFFSET(14) NUMBITS(1) [],
    ],
];

/// Key Vault Peripheral
#[derive(Bus)]
pub struct KeyVaultRegs {
    /// Key Control Register
    #[peripheral(offset = 0x0000_0000, mask = 0x0000_001F)]
    key_control: ReadWriteRegisterArray<u32, 8, KEY_CONTROL::Register>,

    /// Keys
    #[peripheral(offset = 0x0000_0020, mask = 0x0000_001FF)]
    keys: WriteOnlyMemory<{ Self::KEY_STORE_SIZE }>,
}

impl KeyVaultRegs {
    /// Key Memory Size
    const KEY_STORE_SIZE: usize = 0x200;

    /// Key Size
    const KEY_SIZE: usize = 64;

    /// Key control register reset value
    const KEY_CONTROL_RESET_VAL: u32 = 0x0000_7E00;

    /// Zero Key
    const KEY_ZERO: [u8; Self::KEY_SIZE] = [0u8; Self::KEY_SIZE];

    /// Create a new instance of KeyVault registers
    pub fn new() -> Self {
        Self {
            key_control: ReadWriteRegisterArray::new(Self::KEY_CONTROL_RESET_VAL),
            keys: WriteOnlyMemory::new(),
        }
    }

    pub fn update_key(&mut self, key_id: usize, val: u32) {
        let key_ctrl_reg = &mut self.key_control[key_id];
        let val_reg = InMemoryRegister::<u32, KEY_CONTROL::Register>::new(val);

        key_ctrl_reg.modify(
            KEY_CONTROL::READ_LOCK.val(
                key_ctrl_reg.read(KEY_CONTROL::READ_LOCK) | val_reg.read(KEY_CONTROL::READ_LOCK),
            ),
        );

        key_ctrl_reg.modify(KEY_CONTROL::WRITE_LOCK.val(
            key_ctrl_reg.read(KEY_CONTROL::WRITE_LOCK) | val_reg.read(KEY_CONTROL::WRITE_LOCK),
        ));

        key_ctrl_reg.modify(
            KEY_CONTROL::USE_LOCK.val(
                key_ctrl_reg.read(KEY_CONTROL::USE_LOCK) | val_reg.read(KEY_CONTROL::USE_LOCK),
            ),
        );

        if val_reg.is_set(KEY_CONTROL::CLEAR) {
            let key_min = key_id << 6;
            let key_max = key_min + Self::KEY_SIZE;
            self.keys.data_mut()[key_min..key_max].copy_from_slice(&Self::KEY_ZERO);
        }
    }

    pub fn read_key(&self, key_id: u32) -> [u8; Self::KEY_SIZE] {
        let key_start = key_id as usize * Self::KEY_SIZE;
        let key_end = key_id as usize * Self::KEY_SIZE + Self::KEY_SIZE;
        let mut key = [0u8; Self::KEY_SIZE];
        key.copy_from_slice(&self.keys.data()[key_start..key_end]);
        key
    }

    pub fn write_key(&mut self, key_id: u32, key: &[u8; Self::KEY_SIZE]) {
        let key_start = key_id as usize * Self::KEY_SIZE;
        let key_end = key_id as usize * Self::KEY_SIZE + Self::KEY_SIZE;
        self.keys.data_mut()[key_start..key_end].copy_from_slice(key);
    }
}

#[cfg(test)]
mod tests {}
