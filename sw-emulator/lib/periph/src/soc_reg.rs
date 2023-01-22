/*++

Licensed under the Apache-2.0 license.

File Name:

    soc_reg.rs

Abstract:

    File contains SOC Register implementation

--*/

use caliptra_emu_bus::BusError::{LoadAccessFault, StoreAccessFault};
use caliptra_emu_bus::{Bus, BusError, ReadOnlyMemory};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::cell::RefCell;
use std::rc::Rc;

/// Unique device secret size
const UDS_SIZE: usize = 48;

/// Field entropy size
const FIELD_ENTROPY_SIZE: usize = 128;

/// Deobfuscation engine key size
const DOE_KEY_SIZE: usize = 32;

/// SOC Register peripheral
#[derive(Clone)]
pub struct SocRegisters {
    regs: Rc<RefCell<SocRegistersImpl>>,
}

impl SocRegisters {
    /// Create an instance of SOC register peripheral
    pub fn new() -> Self {
        Self {
            regs: Rc::new(RefCell::new(SocRegistersImpl::new())),
        }
    }

    /// Get Unique device secret
    pub fn uds(&self) -> [u8; UDS_SIZE] {
        self.regs.borrow().uds.data().clone()
    }

    // Get field entropy
    pub fn field_entropy(&self) -> [u8; FIELD_ENTROPY_SIZE] {
        self.regs.borrow().field_entropy.data().clone()
    }

    /// Get deobfuscation engine key
    pub fn doe_key(&self) -> [u8; DOE_KEY_SIZE] {
        self.regs.borrow().doe_key.data().clone()
    }

    /// Clear secrets
    pub fn clear_secrets(&mut self) {
        self.regs.borrow_mut().clear_secrets();
    }
}

impl Bus for SocRegisters {
    /// Read data of specified size from given address
    fn read(&mut self, _size: RvSize, _addr: RvAddr) -> Result<RvData, BusError> {
        Err(LoadAccessFault)?
    }

    /// Write data of specified size to given address
    fn write(&mut self, _size: RvSize, _addr: RvAddr, _val: RvData) -> Result<(), BusError> {
        Err(StoreAccessFault)?
    }
}

/// SOC Register implementation
#[derive(Bus)]
struct SocRegistersImpl {
    /// Unique device secret
    uds: ReadOnlyMemory<UDS_SIZE>,

    /// Field entropy
    field_entropy: ReadOnlyMemory<FIELD_ENTROPY_SIZE>,

    /// Deobfuscation engine key
    doe_key: ReadOnlyMemory<DOE_KEY_SIZE>,
}

impl SocRegistersImpl {
    /// Default Deobfuscation engine key
    const DOE_KEY: [u8; DOE_KEY_SIZE] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77,
        0x81, 0x1F, 0x35, 0x2C, 0x7, 0x3B, 0x61, 0x8, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x9, 0x14,
        0xDF, 0xF4,
    ];

    /// Default unique device secret
    const UDS: [u8; UDS_SIZE] = [
        0xF5, 0x8C, 0x4C, 0x4, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB,
        0xD6, 0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D, 0x67, 0x9F, 0x77, 0x7B, 0xC6, 0x70,
        0x2C, 0x7D, 0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA, 0xCF, 0xA5, 0x30, 0xE2, 0x63, 0x4,
        0x23, 0x14, 0x61,
    ];

    /// Create an instance of SOC register implementation
    pub fn new() -> Self {
        let mut regs = Self {
            uds: ReadOnlyMemory::new(),
            field_entropy: ReadOnlyMemory::new(),
            doe_key: ReadOnlyMemory::new(),
        };

        regs.uds.data_mut().copy_from_slice(&Self::UDS);
        regs.doe_key.data_mut().copy_from_slice(&Self::DOE_KEY);
        regs.field_entropy.data_mut().fill(0xFF);
        regs
    }

    /// Clear secrets
    pub fn clear_secrets(&mut self) {
        self.uds.data_mut().fill(0);
        self.field_entropy.data_mut().fill(0);
        self.doe_key.data_mut().fill(0);
    }
}
