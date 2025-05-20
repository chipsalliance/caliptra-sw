// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{BusError, Event, ReadWriteRegister};
use caliptra_emu_bus::{ReadOnlyRegister, WriteOnlyRegister};
use caliptra_emu_crypto::{Aes256Cbc, Aes256Ctr, Aes256Gcm, GHash, AES_256_BLOCK_SIZE};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use rand::Rng;
use std::collections::VecDeque;
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
    #[register_array(offset = 0x4, item_size = 4, len = 8, write_fn = write_key_share0)]
    key_share0: [u32; 8],

    #[register_array(offset = 0x24, item_size = 4, len = 8, write_fn = write_key_share1)]
    key_share1: [u32; 8],

    #[register_array(offset = 0x44, item_size = 4, len = 4, write_fn = write_iv)]
    iv: [u32; 4],

    #[register_array(offset = 0x54, item_size = 4, len = 4, write_fn = write_data_in)]
    data_in: [u32; 4],

    #[register_array(offset = 0x64, item_size = 4, len = 4, read_fn = read_data_out)]
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

    data_in_written: [bool; 4],
    ghash: GHash,
    cbc: Aes256Cbc,
    ctr: Aes256Ctr,
    data_out_read: [bool; 4],
    data_out_block_queue: VecDeque<u32>,
}

impl Default for Aes {
    fn default() -> Self {
        Self::new()
    }
}

impl Aes {
    /// Create a new AES peripheral instance
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
            data_in_written: [false; 4],
            ghash: GHash::default(),
            cbc: Aes256Cbc::default(),
            ctr: Aes256Ctr::default(),
            data_out_read: [true; 4],
            data_out_block_queue: VecDeque::new(),
        }
    }

    fn write_trigger(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be word-aligned
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
            self.ghash = GHash::default();
            self.cbc = Aes256Cbc::default();
            self.data_out_read.fill(true);
            self.data_out_block_queue.clear();
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
        self.data_in_written.fill(false);
        self.ghash = GHash::default();
        self.cbc = Aes256Cbc::default();
        self.data_out_read.fill(true);
        self.data_out_block_queue.clear();
    }

    fn write_ctrl_gcm_shadowed(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be word-aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.ctrl_gcm_shadowed.reg.set(val);

        match self.gcm_phase() {
            GcmCtrl::PHASE::Value::INIT => {
                self.data_in_written.fill(false);
                self.data_in.fill(0);
                self.data_out.fill(0);
                self.ghash = GHash::new(&self.key());
                self.iv.fill(0);
                self.iv[3] = 1;
            }
            GcmCtrl::PHASE::Value::RESTORE => {}
            GcmCtrl::PHASE::Value::AAD => {}
            GcmCtrl::PHASE::Value::TEXT => {}
            GcmCtrl::PHASE::Value::SAVE => {
                let ghash = self.ghash.state();
                self.data_out[0] = u32::from_le_bytes(ghash[0..4].try_into().unwrap());
                self.data_out[1] = u32::from_le_bytes(ghash[4..8].try_into().unwrap());
                self.data_out[2] = u32::from_le_bytes(ghash[8..12].try_into().unwrap());
                self.data_out[3] = u32::from_le_bytes(ghash[12..16].try_into().unwrap());
            }
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

    fn gcm_iv(&self) -> [u8; 12] {
        let mut iv = [0u8; 12];
        for i in 0..3 {
            let word = self.iv[i].to_le_bytes();
            iv[i * 4..(i + 1) * 4].copy_from_slice(&word);
        }
        iv
    }

    fn iv(&self) -> [u8; 16] {
        let mut iv = [0u8; 16];
        for i in 0..4 {
            let word = self.iv[i].to_le_bytes();
            iv[i * 4..(i + 1) * 4].copy_from_slice(&word);
        }
        iv
    }

    fn read_data_out(&mut self, size: RvSize, index: usize) -> Result<RvData, BusError> {
        // Writes have to be word-aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }
        if index >= 4 {
            Err(BusError::LoadAccessFault)?
        }
        self.data_out_read[index] = true;
        match self.mode() {
            Ctrl::MODE::Value::CBC => {
                // block modes write data out only after 2 blocks are written
                if self.data_out_read.iter().copied().all(|x| x) {
                    if self.data_out_block_queue.is_empty() {
                        Err(BusError::LoadAccessFault)?
                    }
                    self.data_out_read.fill(false);
                    self.data_out[0] = self.data_out_block_queue.pop_front().unwrap();
                    self.data_out[1] = self.data_out_block_queue.pop_front().unwrap();
                    self.data_out[2] = self.data_out_block_queue.pop_front().unwrap();
                    self.data_out[3] = self.data_out_block_queue.pop_front().unwrap();
                }
            }
            // streaming modes can directly read the register
            Ctrl::MODE::Value::CTR | Ctrl::MODE::Value::GCM => (),
            _ => todo!(),
        }

        let data = self.data_out[index];
        Ok(data)
    }

    fn update_cbc(&mut self, data: &[u8]) {
        assert_eq!(data.len(), 16);
        let data: &[u8; 16] = data.try_into().unwrap();
        let output = if self.is_encrypt() {
            self.cbc.encrypt_block(data)
        } else {
            self.cbc.decrypt_block(data)
        };
        self.data_out_block_queue
            .push_back(u32::from_le_bytes(output[0..4].try_into().unwrap()));
        self.data_out_block_queue
            .push_back(u32::from_le_bytes(output[4..8].try_into().unwrap()));
        self.data_out_block_queue
            .push_back(u32::from_le_bytes(output[8..12].try_into().unwrap()));
        self.data_out_block_queue
            .push_back(u32::from_le_bytes(output[12..16].try_into().unwrap()));
    }

    fn update_ctr(&mut self, data: &[u8]) {
        assert_eq!(data.len(), 16);
        let data: &[u8; 16] = data.try_into().unwrap();
        let output = self.ctr.crypt_block(data);
        self.data_out[0] = u32::from_le_bytes(output[0..4].try_into().unwrap());
        self.data_out[1] = u32::from_le_bytes(output[4..8].try_into().unwrap());
        self.data_out[2] = u32::from_le_bytes(output[8..12].try_into().unwrap());
        self.data_out[3] = u32::from_le_bytes(output[12..16].try_into().unwrap());
    }

    fn update_gcm(&mut self, data: &[u8]) {
        let num_valid = self.ctrl_gcm_shadowed.reg.read(GcmCtrl::NUM_VALID_BYTES) as usize;
        let num_valid = if num_valid == 0 || num_valid > 16 {
            16
        } else {
            num_valid
        };
        let mut buffer = [0u8; 16];
        buffer[..num_valid].copy_from_slice(&data[..num_valid]);
        let buffer = &buffer;
        // populate the data_out and iv registers
        // There is not proper AES streaming implementation, so we do this the slow way
        // and recompute the GHASH ourselves.
        let key = self.key();
        let gcm_iv = self.gcm_iv();

        match self.gcm_phase() {
            GcmCtrl::PHASE::Value::AAD => {
                self.ghash.update(buffer);
            }
            GcmCtrl::PHASE::Value::RESTORE => {
                let mut state = [0u8; AES_256_BLOCK_SIZE];
                state[0..4].copy_from_slice(&self.data_in[0].to_le_bytes());
                state[4..8].copy_from_slice(&self.data_in[1].to_le_bytes());
                state[8..12].copy_from_slice(&self.data_in[2].to_le_bytes());
                state[12..16].copy_from_slice(&self.data_in[3].to_le_bytes());
                self.ghash.restore(state);
            }
            GcmCtrl::PHASE::Value::TEXT => {
                // in GCM encryption and decryption result in the same output
                if self.iv[3] == 0 {
                    self.iv[3] = 2;
                }
                let output = Aes256Gcm::crypt_block(&key, &gcm_iv, self.iv[3] as usize - 2, buffer);

                self.data_out[0] = u32::from_le_bytes(output[0..4].try_into().unwrap());
                self.data_out[1] = u32::from_le_bytes(output[4..8].try_into().unwrap());
                self.data_out[2] = u32::from_le_bytes(output[8..12].try_into().unwrap());
                self.data_out[3] = u32::from_le_bytes(output[12..16].try_into().unwrap());

                // update GHASH
                let ciphertext = if self.is_encrypt() { &output } else { buffer };
                let mut ciphertext = *ciphertext;
                if num_valid != 16 {
                    ciphertext[num_valid..].fill(0);
                }
                self.ghash.update(&ciphertext);
                self.iv[3] += 1;
            }
            GcmCtrl::PHASE::Value::TAG => {
                self.ghash.update(buffer);
                let tag = self.ghash.finalize(&key, &gcm_iv);
                self.data_out[0] = u32::from_le_bytes(tag[0..4].try_into().unwrap());
                self.data_out[1] = u32::from_le_bytes(tag[4..8].try_into().unwrap());
                self.data_out[2] = u32::from_le_bytes(tag[8..12].try_into().unwrap());
                self.data_out[3] = u32::from_le_bytes(tag[12..16].try_into().unwrap());
            }
            _ => {}
        }
    }

    fn mode(&self) -> Ctrl::MODE::Value {
        self.ctrl_shadowed
            .reg
            .read_as_enum(Ctrl::MODE)
            .unwrap_or(Ctrl::MODE::Value::NONE)
    }

    fn write_data_in(&mut self, size: RvSize, idx: usize, val: RvData) -> Result<(), BusError> {
        // Writes have to be word-aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.data_in[idx] = val;
        self.data_in_written[idx] = true;

        // All data_in registers have been written
        if self.data_in_written.iter().copied().all(|x| x) {
            self.data_in_written = [false; 4];
            let mut buffer: Vec<u8> = vec![];
            for i in 0..4 {
                buffer.extend_from_slice(&self.data_in[i].to_le_bytes()[..]);
            }
            match self.mode() {
                Ctrl::MODE::Value::CBC => {
                    self.update_cbc(&buffer);
                }
                Ctrl::MODE::Value::CTR => {
                    self.update_ctr(&buffer);
                }
                Ctrl::MODE::Value::GCM => {
                    self.update_gcm(&buffer);
                }
                _ => todo!(),
            }
        }
        Ok(())
    }

    fn write_key_share0(&mut self, size: RvSize, idx: usize, val: RvData) -> Result<(), BusError> {
        // Writes have to be word-aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.key_share0[idx] = val;
        match self.mode() {
            Ctrl::MODE::Value::CBC => {
                self.cbc = Aes256Cbc::new(&self.iv(), &self.key());
            }
            Ctrl::MODE::Value::GCM => {
                self.ghash = GHash::new(&self.key());
            }
            _ => (),
        }
        Ok(())
    }

    fn write_key_share1(&mut self, size: RvSize, idx: usize, val: RvData) -> Result<(), BusError> {
        // Writes have to be word-aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.key_share1[idx] = val;
        match self.mode() {
            Ctrl::MODE::Value::CBC => {
                self.cbc = Aes256Cbc::new(&self.iv(), &self.key());
            }
            Ctrl::MODE::Value::GCM => {
                self.ghash = GHash::new(&self.key());
            }
            _ => (),
        }
        Ok(())
    }

    fn write_iv(&mut self, size: RvSize, idx: usize, val: RvData) -> Result<(), BusError> {
        // Writes have to be word-aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.iv[idx] = val;

        match self.mode() {
            Ctrl::MODE::Value::CBC => {
                self.cbc = Aes256Cbc::new(&self.iv(), &self.key());
            }
            Ctrl::MODE::Value::CTR => {
                self.ctr = Aes256Ctr::new(&self.iv(), &self.key());
            }
            Ctrl::MODE::Value::GCM => {
                if idx == 3 {
                    // hardware quirk: IV[3] is loaded as big-endian, unlike all other registers
                    self.iv[3] = val.swap_bytes();
                    if val == 0 {
                        self.iv[3] = 2;
                    }
                } else {
                    self.iv[idx] = val;
                }
            }
            _ => todo!(),
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
