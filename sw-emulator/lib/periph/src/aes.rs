// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{BusError, Clock, Event, ReadWriteRegister, Timer};
use caliptra_emu_bus::{ReadOnlyRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use std::rc::Rc;
use std::sync::mpsc;
use tock_registers::register_bitfields;

register_bitfields! [
    u32,

    /// Status
    Status [
        IDLE OFFSET(0) NUMBITS(1) [],
        STALL OFFSET(1) NUMBITS(1) [],
        OUTPUT_LOST OFFSET(2) NUMBITS(1) [],
        OUTPUT_VALID OFFSET(3) NUMBITS(1) [],
        INPUT_READY OFFSET(4) NUMBITS(1) [],
        ALERT_RECOV_CTRL_UPDATE_ERROR OFFSET(5) NUMBITS(1) [],
        ALERT_FATAL_FAULT OFFSET(6) NUMBITS(1) [],
    ],
];

/// AES peripheral implementation
#[derive(Bus)]
pub struct Aes {
    #[register_array(offset = 0x4, item_size = 4, len = 8)]
    key_share0: [u32; 8],

    #[register_array(offset = 0x24, item_size = 4, len = 8)]
    key_share1: [u32; 8],

    #[register_array(offset = 0x44, item_size = 4, len = 4)]
    iv: [u32; 4],

    #[register_array(offset = 0x54, item_size = 4, len = 4)]
    data_in: [u32; 4],

    #[register_array(offset = 0x64, item_size = 4, len = 4)]
    data_out: [u32; 4],

    #[register(offset = 0x74, write_fn = write_ctrl_shadowed)]
    ctrl_shadowed: ReadWriteRegister<u32>,

    #[register(offset = 0x78)]
    _ctrl_aux_shadowed: ReadWriteRegister<u32>,

    #[register(offset = 0x7c)]
    _ctrl_aux_regwen: ReadWriteRegister<u32>,

    #[register(offset = 0x80)]
    trigger: WriteOnlyRegister<u32>,

    #[register(offset = 0x84)]
    status: ReadOnlyRegister<u32, Status::Register>,

    #[register(offset = 0x88, write_fn = write_ctrl_gcm_shadowed)]
    ctrl_gcm_shadowed: ReadOnlyRegister<u32>,

    /// Timer
    _timer: Timer,
}

impl Aes {
    /// Create a new AES CLP peripheral instance
    pub fn new(clock: &Clock) -> Self {
        Self {
            _timer: Timer::new(clock),
            key_share0: [0; 8],
            key_share1: [0; 8],
            iv: [0; 4],
            data_in: [0; 4],
            data_out: [0; 4],
            ctrl_shadowed: ReadWriteRegister::new(0),
            _ctrl_aux_shadowed: ReadWriteRegister::new(0),
            _ctrl_aux_regwen: ReadWriteRegister::new(0),
            trigger: WriteOnlyRegister::new(0),
            status: ReadOnlyRegister::new(
                (Status::INPUT_READY.val(1) + Status::OUTPUT_VALID.val(1) + Status::IDLE.val(1))
                    .into(),
            ),
            ctrl_gcm_shadowed: ReadOnlyRegister::new(0),
        }
    }

    fn write_ctrl_shadowed(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Ok(())
    }

    fn write_ctrl_gcm_shadowed(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Ok(())
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
