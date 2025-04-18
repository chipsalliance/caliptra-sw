// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{BusError, Event, ReadWriteRegister};
use caliptra_emu_bus::{ReadOnlyRegister, WriteOnlyRegister};
use caliptra_emu_crypto::Aes256Gcm;
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use rand::Rng;
use std::rc::Rc;
use std::sync::mpsc;
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::register_bitfields;

register_bitfields! [
    u32,
    Status [
        IDLE OFFSET(0) NUMBITS(1) [],
        STALL OFFSET(1) NUMBITS(1) [],
        OUTPUT_LOST OFFSET(2) NUMBITS(1) [],
        OUTPUT_VALID OFFSET(3) NUMBITS(1) [],
        INPUT_READY OFFSET(4) NUMBITS(1) [],
        ALERT_RECOV_CTRL_UPDATE_ERROR OFFSET(5) NUMBITS(1) [],
        ALERT_FATAL_FAULT OFFSET(6) NUMBITS(1) [],
    ],
    Ctrl [
        OP OFFSET(0) NUMBITS(2) [
            ENCRYPT = 1,
            DECRYPT = 2,
        ],
        MODE OFFSET(2) NUMBITS(6) [
            ECB = 1,
            CBC = 2,
            CFB = 4,
            OFB = 8,
            CTR = 16,
            GCM = 32,
            NONE = 0x3f,
        ],
        KEY_LEN OFFSET(8) NUMBITS(3) [
            KEY_128 = 1,
            KEY_192 = 2,
            KEY_256 = 4,
        ],
        SIDELOAD OFFSET(11) NUMBITS(1) [],
        PRNG_RESEED_RATE OFFSET(12) NUMBITS(3) [],
        MANUAL_OPERATION OFFSET(15) NUMBITS(1) [
            DISABLED = 0,
            ENABLED = 1,
        ],
    ],
    GcmCtrl [
        PHASE OFFSET(0) NUMBITS(6) [
            INIT = 1,
            RESTORE = 2,
            AAD = 4,
            TEXT = 8,
            SAVE = 16,
            TAG = 32,
        ],
        NUM_VALID_BYTES OFFSET(6) NUMBITS(5) [],
    ],
    Trigger [
        START OFFSET(0) NUMBITS(1) [],
        KEY_IV_DATA_IN_CLEAR OFFSET(1) NUMBITS(1) [],
        DATA_OUT_CLEAR OFFSET(2) NUMBITS(1) [],
        PRNG_RESEED OFFSET(3) NUMBITS(1) [],
    ],
];

/// AES peripheral implementation
#[derive(Bus)]
#[warm_reset_fn(warm_reset)]
pub struct Aes {
    #[register_array(offset = 0x4, item_size = 4, len = 8)]
    key_share0: [u32; 8],

    #[register_array(offset = 0x24, item_size = 4, len = 8)]
    key_share1: [u32; 8],

    #[register_array(offset = 0x44, item_size = 4, len = 4)]
    iv: [u32; 4],

    #[register_array(offset = 0x54, item_size = 4, len = 4, write_fn = write_data_in)]
    data_in: [u32; 4],

    #[register_array(offset = 0x64, item_size = 4, len = 4)]
    data_out: [u32; 4],

    #[register(offset = 0x74)]
    ctrl_shadowed: ReadWriteRegister<u32, Ctrl::Register>,

    #[register(offset = 0x78)]
    _ctrl_aux_shadowed: ReadWriteRegister<u32>,

    #[register(offset = 0x7c)]
    _ctrl_aux_regwen: ReadWriteRegister<u32>,

    #[register(offset = 0x80, write_fn = write_trigger)]
    trigger: WriteOnlyRegister<u32, Trigger::Register>,

    #[register(offset = 0x84)]
    status: ReadOnlyRegister<u32, Status::Register>,

    #[register(offset = 0x88, write_fn = write_ctrl_gcm_shadowed)]
    ctrl_gcm_shadowed: ReadOnlyRegister<u32, GcmCtrl::Register>,

    aad: Vec<u8>,
    buffer: Vec<u8>,
    data_in_written: [bool; 4],
}

impl Default for Aes {
    fn default() -> Self {
        Self::new()
    }
}

impl Aes {
    /// Create a new AES CLP peripheral instance
    pub fn new() -> Self {
        Self {
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
            aad: vec![],
            buffer: vec![],
            data_in_written: [false; 4],
        }
    }

    fn write_trigger(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.trigger.reg.set(val);

        if self.trigger.reg.is_set(Trigger::KEY_IV_DATA_IN_CLEAR) {
            rand::thread_rng().fill(&mut self.key_share0[..]);
            rand::thread_rng().fill(&mut self.key_share1[..]);
            rand::thread_rng().fill(&mut self.iv[..]);
            rand::thread_rng().fill(&mut self.data_in[..]);
            self.data_in_written.fill(false);
            self.aad.clear();
            self.buffer.clear();
        }
        if self.trigger.reg.is_set(Trigger::DATA_OUT_CLEAR) {
            rand::thread_rng().fill(&mut self.data_out[..]);
        } else {
            self.data_out.fill(0);
        }
        self.trigger.reg.set(0);
        Ok(())
    }

    fn warm_reset(&mut self) {
        self.key_share0.fill(0);
        self.key_share1.fill(0);
        self.iv.fill(0);
        self.data_in.fill(0);
        self.data_out.fill(0);
        self.ctrl_shadowed.reg.set(0);
        self._ctrl_aux_shadowed.reg.set(0);
        self._ctrl_aux_regwen.reg.set(0);
        self.trigger.reg.set(0);
        self.status.reg.set(
            (Status::INPUT_READY.val(1) + Status::OUTPUT_VALID.val(1) + Status::IDLE.val(1)).into(),
        );
        self.ctrl_gcm_shadowed.reg.set(0);
        self.aad.clear();
        self.buffer.clear();
        self.data_in_written.fill(false);
    }

    fn write_ctrl_gcm_shadowed(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.ctrl_gcm_shadowed.reg.set(val);

        match self.gcm_phase() {
            GcmCtrl::PHASE::Value::INIT => {
                self.buffer.clear();
                self.aad.clear();
                self.data_in_written.fill(false);
                self.data_in.fill(0);
                self.data_out.fill(0);
            }
            GcmCtrl::PHASE::Value::RESTORE => todo!(),
            GcmCtrl::PHASE::Value::AAD => {}
            GcmCtrl::PHASE::Value::TEXT => {}
            GcmCtrl::PHASE::Value::SAVE => todo!(),
            GcmCtrl::PHASE::Value::TAG => {}
        }
        Ok(())
    }

    fn gcm_phase(&self) -> GcmCtrl::PHASE::Value {
        self.ctrl_gcm_shadowed
            .reg
            .read_as_enum(GcmCtrl::PHASE)
            .unwrap_or(GcmCtrl::PHASE::Value::INIT)
    }

    fn is_encrypt(&self) -> bool {
        self.ctrl_shadowed
            .reg
            .read_as_enum(Ctrl::OP)
            .unwrap_or(Ctrl::OP::Value::ENCRYPT)
            == Ctrl::OP::Value::ENCRYPT
    }

    fn key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        for i in 0..8 {
            let word = (self.key_share0[i] ^ self.key_share1[i]).to_le_bytes();
            key[i * 4..(i + 1) * 4].copy_from_slice(&word);
        }
        key
    }

    fn iv(&self) -> [u8; 12] {
        let mut iv = [0u8; 12];
        for i in 0..3 {
            let word = self.iv[i].to_le_bytes();
            iv[i * 4..(i + 1) * 4].copy_from_slice(&word);
        }
        iv
    }

    fn update_data_out(&mut self) {
        // populate the data_out register
        // TODO: use a proper streaming AES implementation
        let key = self.key();
        let iv = self.iv();

        match self.gcm_phase() {
            GcmCtrl::PHASE::Value::TEXT => {
                // in GCM encryption and decryption result in the same output
                let (_, output, _) =
                    Aes256Gcm::encrypt(&key, Some(&iv), &self.aad, &self.buffer).unwrap();
                let len = output.len();
                self.data_out[0] =
                    u32::from_le_bytes(output[len - 16..len - 12].try_into().unwrap());
                self.data_out[1] =
                    u32::from_le_bytes(output[len - 12..len - 8].try_into().unwrap());
                self.data_out[2] = u32::from_le_bytes(output[len - 8..len - 4].try_into().unwrap());
                self.data_out[3] = u32::from_le_bytes(output[len - 4..].try_into().unwrap());
            }
            GcmCtrl::PHASE::Value::TAG => {
                let tag = if self.is_encrypt() {
                    let (_, _, tag) =
                        Aes256Gcm::encrypt(&key, Some(&iv), &self.aad, &self.buffer).unwrap();
                    tag
                } else {
                    // the hardware doesn't care if the tag is correct, but returns what it would be
                    // so "encrypt" the ciphertext to get the plaintext
                    let (_, plaintext, _) =
                        Aes256Gcm::encrypt(&key, Some(&iv), &self.aad, &self.buffer).unwrap();
                    // now encrypt again to get the correct tag
                    let (_, _, tag) =
                        Aes256Gcm::encrypt(&key, Some(&iv), &self.aad, &plaintext).unwrap();
                    tag
                };
                self.data_out[0] = u32::from_le_bytes(tag[0..4].try_into().unwrap());
                self.data_out[1] = u32::from_le_bytes(tag[4..8].try_into().unwrap());
                self.data_out[2] = u32::from_le_bytes(tag[8..12].try_into().unwrap());
                self.data_out[3] = u32::from_le_bytes(tag[12..16].try_into().unwrap());
            }
            _ => {}
        }
    }

    fn write_data_in(&mut self, size: RvSize, idx: usize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.data_in[idx] = val;
        self.data_in_written[idx] = true;
        // All data_in registers have been written
        if self.data_in_written.iter().copied().all(|x| x) {
            self.data_in_written = [false; 4];
            // copy to the buffer
            match self.gcm_phase() {
                GcmCtrl::PHASE::Value::AAD => {
                    for i in 0..4 {
                        self.aad
                            .extend_from_slice(&self.data_in[i].to_le_bytes()[..]);
                    }
                }
                GcmCtrl::PHASE::Value::TEXT => {
                    for i in 0..4 {
                        self.buffer
                            .extend_from_slice(&self.data_in[i].to_le_bytes()[..]);
                    }
                }
                _ => {}
            }
            self.update_data_out();
        }
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
