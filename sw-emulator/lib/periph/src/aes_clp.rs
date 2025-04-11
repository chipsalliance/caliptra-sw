// Licensed under the Apache-2.0 license

use caliptra_emu_bus::ReadOnlyRegister;
use caliptra_emu_bus::{Clock, Event, Timer};
use caliptra_emu_derive::Bus;
use std::rc::Rc;
use std::sync::mpsc;

use crate::KeyVault;

/// AES peripheral implementation
#[derive(Bus)]
pub struct AesClp {
    // AES Component Name registers
    #[register(offset = 0x0)]
    aes_name_0: ReadOnlyRegister<u32>,

    #[register(offset = 0x4)]
    aes_name_1: ReadOnlyRegister<u32>,

    // AES Component Version registers
    #[register(offset = 0x8)]
    aes_version_0: ReadOnlyRegister<u32>,

    #[register(offset = 0xC)]
    aes_version_1: ReadOnlyRegister<u32>,

    // Entropy Interface Seed registers
    #[register_array(offset = 0x110, item_size = 4, len = 9)]
    entropy_if_seed: [u32; 9],

    // AES Key Vault Control registers
    #[register(offset = 0x200)]
    aes_kv_rd_key_ctrl: u32,

    #[register(offset = 0x204)]
    aes_kv_rd_key_status: ReadOnlyRegister<u32>,

    /// Timer
    _timer: Timer,

    /// Key Vault
    _key_vault: KeyVault,
}

impl AesClp {
    /// Create a new AES CLP peripheral instance
    pub fn new(clock: &Clock, _key_vault: KeyVault) -> Self {
        Self {
            _timer: Timer::new(clock),
            _key_vault,
            // Initialize with default values
            aes_name_0: ReadOnlyRegister::new(0x41455300), // "AES\0"
            aes_name_1: ReadOnlyRegister::new(0x434C5000), // "CLP\0"
            aes_version_0: ReadOnlyRegister::new(0x00000001), // Version 1.0
            aes_version_1: ReadOnlyRegister::new(0x00000000),
            entropy_if_seed: [0; 9],
            aes_kv_rd_key_ctrl: 0,
            aes_kv_rd_key_status: ReadOnlyRegister::new(0),
        }
    }

    /// Handle incoming events
    pub fn incoming_event(&mut self, _event: Rc<Event>) {
        // No event handling needed for now
    }

    /// Register for outgoing events
    pub fn register_outgoing_events(&mut self, _sender: mpsc::Sender<Event>) {
        // No events to register for now
    }
}
