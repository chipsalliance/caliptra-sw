/*++

Licensed under the Apache-2.0 license.

File Name:

    key_vault.rs

Abstract:

    File contains Key Vault Implementation

--*/

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

    /// Create a new instance of KeyVault
    pub fn new() -> Self {
        Self {
            regs: Rc::new(RefCell::new(KeyVaultRegs::new())),
        }
    }

    /// Internal emulator interface to read key from key vault
    pub fn read_key(&self, key_id: u32) -> Result<[u8; Self::KEY_SIZE], BusError> {
        self.regs.borrow().read_key(key_id)
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
        self.regs.borrow_mut().read(size, addr)
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
            _ => self.regs.borrow_mut().write(size, addr, val),
        }
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

    /// Create a new instance of KeyVault registers
    pub fn new() -> Self {
        Self {
            pcr_control: ReadWriteRegisterArray::new(Self::PCR_CONTROL_REG_RESET_VAL),
            pcrs: ReadWriteMemory::new(),
            key_control: ReadWriteRegisterArray::new(Self::KEY_CONTROL_REG_RESET_VAL),
            keys: ReadWriteMemory::new(),
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

    pub fn read_key(&self, key_id: u32) -> Result<[u8; Self::KEY_SIZE], BusError> {
        let key_ctrl_reg = &self.key_control[key_id as usize];
        if key_ctrl_reg.read(KV_CONTROL::USE_LOCK) != 0 {
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

        for idx in 0..8 {
            vault.write_key(idx, &expected, 0).unwrap();
            let returned = vault.read_key(idx).unwrap();
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

            assert_eq!(vault.write_key(key_id, &expected, 0).is_ok(), true);

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
                vault.read_key(key_id).err(),
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
        let val_reg = InMemoryRegister::<u32, KV_CONTROL::Register>::new(0);
        val_reg.write(KV_CONTROL::WRITE_LOCK.val(1)); // Key write disabled.

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
                vault.write_key(key_id, &expected, 0).err(),
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
        let val_reg = InMemoryRegister::<u32, KV_CONTROL::Register>::new(0);
        val_reg.write(KV_CONTROL::CLEAR.val(1)); // Clear key.

        for key_id in 0..8 {
            assert_eq!(vault.write_key(key_id, &expected, 0).ok(), Some(()));
            assert_eq!(&vault.read_key(key_id).unwrap(), &expected);

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

            assert_eq!(&vault.read_key(key_id).unwrap(), &cleared_key);
        }
    }
}
