// Licensed under the Apache-2.0 license

use caliptra_emu_bus::Event;
use caliptra_emu_bus::{ReadOnlyRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use std::rc::Rc;
use std::sync::mpsc;

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

    // Interrupt registers
    // Global Interrupt Enable
    #[register(offset = 0x400)]
    global_intr_en_r: u32,

    // Error Interrupt Enable
    #[register(offset = 0x404)]
    error_intr_en_r: u32,

    // Notification Interrupt Enable
    #[register(offset = 0x408)]
    notif_intr_en_r: u32,

    // Error Global Interrupt
    #[register(offset = 0x40C)]
    error_global_intr_r: ReadOnlyRegister<u32>,

    // Notification Global Interrupt
    #[register(offset = 0x410)]
    notif_global_intr_r: ReadOnlyRegister<u32>,

    // Error Internal Interrupt
    #[register(offset = 0x414)]
    error_internal_intr_r: u32,

    // Notification Internal Interrupt
    #[register(offset = 0x418)]
    notif_internal_intr_r: u32,

    // Error Interrupt Trigger
    #[register(offset = 0x41C)]
    error_intr_trig_r: WriteOnlyRegister<u32>,

    // Notification Interrupt Trigger
    #[register(offset = 0x420)]
    notif_intr_trig_r: WriteOnlyRegister<u32>,

    // Error Interrupt Counters
    #[register(offset = 0x100)]
    error0_intr_count_r: u32,

    #[register(offset = 0x104)]
    error1_intr_count_r: u32,

    #[register(offset = 0x108)]
    error2_intr_count_r: u32,

    #[register(offset = 0x10C)]
    error3_intr_count_r: u32,

    // Notification Interrupt Counters
    #[register(offset = 0x180)]
    notif_cmd_done_intr_count_r: u32,

    // Interrupt Count Incrementors (reserved for hardware)
    #[register(offset = 0x200)]
    error0_intr_count_incr_r: ReadOnlyRegister<u32>,

    #[register(offset = 0x204)]
    error1_intr_count_incr_r: ReadOnlyRegister<u32>,

    #[register(offset = 0x208)]
    error2_intr_count_incr_r: ReadOnlyRegister<u32>,

    #[register(offset = 0x20C)]
    error3_intr_count_incr_r: ReadOnlyRegister<u32>,

    #[register(offset = 0x210)]
    notif_cmd_done_intr_count_incr_r: ReadOnlyRegister<u32>,
}

impl AesClp {
    /// Create a new AES CLP peripheral instance
    pub fn new() -> Self {
        Self {
            // Initialize with default values
            aes_name_0: ReadOnlyRegister::new(0x41455300), // "AES\0"
            aes_name_1: ReadOnlyRegister::new(0x434C5000), // "CLP\0"
            aes_version_0: ReadOnlyRegister::new(0x00000001), // Version 1.0
            aes_version_1: ReadOnlyRegister::new(0x00000000),
            entropy_if_seed: [0; 9],
            aes_kv_rd_key_ctrl: 0,
            aes_kv_rd_key_status: ReadOnlyRegister::new(0),
            global_intr_en_r: 0,
            error_intr_en_r: 0,
            notif_intr_en_r: 0,
            error_global_intr_r: ReadOnlyRegister::new(0),
            notif_global_intr_r: ReadOnlyRegister::new(0),
            error_internal_intr_r: 0,
            notif_internal_intr_r: 0,
            error_intr_trig_r: WriteOnlyRegister::new(0),
            notif_intr_trig_r: WriteOnlyRegister::new(0),
            error0_intr_count_r: 0,
            error1_intr_count_r: 0,
            error2_intr_count_r: 0,
            error3_intr_count_r: 0,
            notif_cmd_done_intr_count_r: 0,
            error0_intr_count_incr_r: ReadOnlyRegister::new(0),
            error1_intr_count_incr_r: ReadOnlyRegister::new(0),
            error2_intr_count_incr_r: ReadOnlyRegister::new(0),
            error3_intr_count_incr_r: ReadOnlyRegister::new(0),
            notif_cmd_done_intr_count_incr_r: ReadOnlyRegister::new(0),
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
