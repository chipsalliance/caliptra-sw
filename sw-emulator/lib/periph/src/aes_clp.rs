// Licensed under the Apache-2.0 license

use crate::hmac::{KeyReadControl, KeyReadStatus, KEY_RW_TICKS};
use crate::{KeyUsage, KeyVault};
use caliptra_emu_bus::{
    ActionHandle, BusError, Clock, Event, ReadOnlyRegister, ReadWriteRegister, Timer,
};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc;
use tock_registers::interfaces::{ReadWriteable, Readable};
use tock_registers::registers::InMemoryRegister;

/// AES peripheral implementation
#[derive(Bus)]
#[poll_fn(poll)]
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
    #[register(offset = 0x200, write_fn = on_write_key_read_control)]
    aes_kv_rd_key_ctrl: ReadWriteRegister<u32, KeyReadControl::Register>,

    #[register(offset = 0x204)]
    aes_kv_rd_key_status: ReadOnlyRegister<u32, KeyReadStatus::Register>,

    /// Timer
    timer: Timer,

    /// Key Vault
    key_vault: KeyVault,

    /// Key read complete action
    op_key_read_complete_action: Option<ActionHandle>,

    key: Rc<RefCell<Option<[u8; 32]>>>,
}

impl AesClp {
    /// Create a new AES CLP peripheral instance
    pub fn new(clock: &Clock, key_vault: KeyVault, key: Rc<RefCell<Option<[u8; 32]>>>) -> Self {
        Self {
            timer: Timer::new(clock),
            key_vault,
            // Initialize with default values
            aes_name_0: ReadOnlyRegister::new(0x41455300), // "AES\0"
            aes_name_1: ReadOnlyRegister::new(0x434C5000), // "CLP\0"
            aes_version_0: ReadOnlyRegister::new(0x00000001), // Version 1.0
            aes_version_1: ReadOnlyRegister::new(0x00000000),
            entropy_if_seed: [0; 9],
            aes_kv_rd_key_ctrl: ReadWriteRegister::new(0),
            aes_kv_rd_key_status: ReadOnlyRegister::new(KeyReadStatus::READY::SET.value),
            op_key_read_complete_action: None,
            key,
        }
    }

    /// On Write callback for `key_read_control` register
    pub fn on_write_key_read_control(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the key control register
        let key_read_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(val);

        self.aes_kv_rd_key_ctrl.reg.modify(
            KeyReadControl::KEY_READ_EN.val(key_read_ctrl.read(KeyReadControl::KEY_READ_EN))
                + KeyReadControl::KEY_ID.val(key_read_ctrl.read(KeyReadControl::KEY_ID)),
        );

        if key_read_ctrl.is_set(KeyReadControl::KEY_READ_EN) {
            self.aes_kv_rd_key_status.reg.modify(
                KeyReadStatus::READY::CLEAR
                    + KeyReadStatus::VALID::CLEAR
                    + KeyReadStatus::ERROR::CLEAR,
            );

            self.op_key_read_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        Ok(())
    }

    fn key_read_complete(&mut self) {
        let key_id = self.aes_kv_rd_key_ctrl.reg.read(KeyReadControl::KEY_ID);

        let mut key_usage = KeyUsage::default();
        key_usage.set_aes_key(true);

        let result = self.key_vault.read_key(key_id, key_usage);
        let (key_read_result, key) = match result.err() {
            Some(BusError::LoadAccessFault)
            | Some(BusError::LoadAddrMisaligned)
            | Some(BusError::InstrAccessFault) => (KeyReadStatus::ERROR::KV_READ_FAIL.value, None),
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                (KeyReadStatus::ERROR::KV_WRITE_FAIL.value, None)
            }
            None => (
                KeyReadStatus::ERROR::KV_SUCCESS.value,
                Some(result.unwrap()),
            ),
        };

        if let Some(key) = &key {
            *self.key.borrow_mut() = Some(key.to_vec()[..32].try_into().unwrap());
            // make sure the AES peripheral picks up the new key
            self.timer.schedule_poll_in(1);
        }

        self.aes_kv_rd_key_status.reg.modify(
            KeyReadStatus::READY::SET
                + KeyReadStatus::VALID::SET
                + KeyReadStatus::ERROR.val(key_read_result),
        );
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_key_read_complete_action) {
            self.key_read_complete();
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
