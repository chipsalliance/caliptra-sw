/*++

Licensed under the Apache-2.0 license.

File Name:

    asym_ecc384.rs

Abstract:

    File contains ECC384 peripheral implementation.

--*/

use crate::{KeyUsage, KeyVault};
use caliptra_emu_bus::{BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer, TimerAction};
use caliptra_emu_crypto::{Ecc384, Ecc384PubKey, Ecc384Signature};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

/// ECC-384 Key Generation seed
const ECC384_SEED_SIZE: usize = 48;

/// ECC-384 Coordinate size
const ECC384_COORD_SIZE: usize = 48;

/// ECC384 Initialization Vector size
const ECC384_IV_SIZE: usize = 48;

/// The number of CPU clock cycles it takes to perform ECC operation
const ECC384_OP_TICKS: u64 = 1000;

/// The number of CPU clock cycles read and write keys from key vault
const KEY_RW_TICKS: u64 = 100;

register_bitfields! [
    u32,

    /// Control Register Fields
    Control [
        CTRL OFFSET(0) NUMBITS(2) [
            IDLE = 0b00,
            GEN_KEY = 0b01,
            SIGN = 0b10,
            VERIFY = 0b11,
        ],
        ZEROIZE OFFSET(2) NUMBITS(1) [],
    ],

    /// Status Register Fields
    Status[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
    ],

    /// Key Control Register Fields
    KeyReadControl[
        KEY_READ_EN OFFSET(0) NUMBITS(1) [],
        KEY_ID OFFSET(1) NUMBITS(5) [],
        PCR_HASH_EXTEND OFFSET(6) NUMBITS(1) [],
        RSVD OFFSET(7) NUMBITS(25) [],
    ],

    /// Key Status Register Fields
    KeyReadStatus[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        ERROR OFFSET(2) NUMBITS(8) [
            KV_SUCCESS = 0,
            KV_READ_FAIL = 1,
            KV_WRITE_FAIL= 2,
        ],
        RSVD OFFSET(10) NUMBITS(22) [],
    ],

    /// Private Key Write Control Register Fields
    KeyWriteControl[
        KEY_WRITE_EN OFFSET(0) NUMBITS(1) [],
        KEY_ID OFFSET(1) NUMBITS(5) [],
        USAGE OFFSET(6) NUMBITS(6) [],
        RSVD OFFSET(12) NUMBITS(20) [],
    ],

    // Tag Status Register Fields
    KeyWriteStatus[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        ERROR OFFSET(2) NUMBITS(8) [
            KV_SUCCESS = 0,
            KV_READ_FAIL = 1,
            KV_WRITE_FAIL= 2,
        ],
        RSVD OFFSET(10) NUMBITS(22) [],
    ],
];

pub fn words_from_bytes_le(arr: &[u8; 48]) -> [u32; 12] {
    let mut result = [0u32; 12];
    for i in 0..result.len() {
        result[i] = u32::from_le_bytes(arr[i * 4..][..4].try_into().unwrap())
    }
    result
}
pub fn bytes_from_words_le(arr: &[u32; 12]) -> [u8; 48] {
    let mut result = [0u8; 48];
    for i in 0..arr.len() {
        result[i * 4..][..4].copy_from_slice(&arr[i].to_le_bytes());
    }
    result
}

#[derive(Bus)]
#[poll_fn(poll)]
pub struct AsymEcc384 {
    /// Name 0 register
    #[register(offset = 0x0000_0000)]
    name0: ReadOnlyRegister<u32>,

    /// Name 1 register
    #[register(offset = 0x0000_0004)]
    name1: ReadOnlyRegister<u32>,

    /// Version 0 register
    #[register(offset = 0x0000_0008)]
    version0: ReadOnlyRegister<u32>,

    /// Version 1 register
    #[register(offset = 0x0000_000C)]
    version1: ReadOnlyRegister<u32>,

    /// Control register
    #[register(offset = 0x0000_0010, write_fn = on_write_control)]
    control: ReadWriteRegister<u32, Control::Register>,

    /// Status register
    #[register(offset = 0x0000_0018)]
    status: ReadOnlyRegister<u32, Status::Register>,

    /// Side Channel Attack Counter measure configuration registers
    #[register(offset = 0x0000_0020)]
    sca_cfg: ReadWriteRegister<u32, Status::Register>,

    /// Seed size
    #[register_array(offset = 0x0000_0080)]
    seed: [u32; ECC384_SEED_SIZE / 4],

    /// Hash size
    #[register_array(offset = 0x0000_0100)]
    hash: [u32; ECC384_SEED_SIZE / 4],

    /// Private Key
    #[register_array(offset = 0x0000_0180)]
    priv_key: [u32; ECC384_COORD_SIZE / 4],

    /// Public Key X coordinate
    #[register_array(offset = 0x0000_0200)]
    pub_key_x: [u32; ECC384_COORD_SIZE / 4],

    /// Public Key Y coordinate
    #[register_array(offset = 0x0000_0280)]
    pub_key_y: [u32; ECC384_COORD_SIZE / 4],

    /// Signature R coordinate
    #[register_array(offset = 0x0000_0300)]
    sig_r: [u32; ECC384_COORD_SIZE / 4],

    /// Signature S coordinate
    #[register_array(offset = 0x0000_0380)]
    sig_s: [u32; ECC384_COORD_SIZE / 4],

    /// Verify R coordinate
    #[register_array(offset = 0x0000_0400, write_fn = write_access_fault)]
    verify_r: [u32; ECC384_COORD_SIZE / 4],

    /// Initialization vector for blinding and counter measures
    #[register_array(offset = 0x0000_0480)]
    iv: [u32; ECC384_IV_SIZE / 4],

    /// Key Read Control Register
    #[register(offset = 0x0000_0600, write_fn = on_write_key_read_control)]
    key_read_ctrl: ReadWriteRegister<u32, KeyReadControl::Register>,

    /// Key Read Status Register
    #[register(offset = 0x0000_0604)]
    key_read_status: ReadOnlyRegister<u32, KeyReadStatus::Register>,

    /// Seed Read Control Register
    #[register(offset = 0x0000_0608, write_fn = on_write_seed_read_control)]
    seed_read_ctrl: ReadWriteRegister<u32, KeyReadControl::Register>,

    /// Seed Read Status Register
    #[register(offset = 0x0000_060c)]
    seed_read_status: ReadOnlyRegister<u32, KeyReadStatus::Register>,

    /// Msg Read Control Register
    #[register(offset = 0x0000_0610, write_fn = on_write_msg_read_control)]
    msg_read_ctrl: ReadWriteRegister<u32, KeyReadControl::Register>,

    /// Msg Read Status Register
    #[register(offset = 0x0000_0614)]
    msg_read_status: ReadOnlyRegister<u32, KeyReadStatus::Register>,

    /// Key Write Control Register
    #[register(offset = 0x0000_0618, write_fn = on_write_key_write_control)]
    key_write_ctrl: ReadWriteRegister<u32, KeyWriteControl::Register>,

    /// Key Write Status Register
    #[register(offset = 0x0000_061c)]
    key_write_status: ReadOnlyRegister<u32, KeyWriteStatus::Register>,

    /// Key Vault
    key_vault: KeyVault,

    /// Timer
    timer: Timer,

    /// Operation complete callback
    op_complete_action: Option<TimerAction>,

    /// Key read complete action
    op_key_read_complete_action: Option<TimerAction>,

    /// Seed read complete action
    op_seed_read_complete_action: Option<TimerAction>,

    /// Msg read complete action
    op_msg_read_complete_action: Option<TimerAction>,

    /// Key write complete action
    op_key_write_complete_action: Option<TimerAction>,
}

impl AsymEcc384 {
    /// NAME0 Register Value
    const NAME0_VAL: RvData = 0x73656370; //0x63737065; // secp

    /// NAME1 Register Value
    const NAME1_VAL: RvData = 0x2D333834; // -384

    /// VERSION0 Register Value
    const VERSION0_VAL: RvData = 0x30302E31; // 1.0

    /// VERSION1 Register Value
    const VERSION1_VAL: RvData = 0x00000000;

    /// Create a new instance of ECC-384 Engine
    pub fn new(clock: &Clock, key_vault: KeyVault) -> Self {
        Self {
            name0: ReadOnlyRegister::new(Self::NAME0_VAL),
            name1: ReadOnlyRegister::new(Self::NAME1_VAL),
            version0: ReadOnlyRegister::new(Self::VERSION0_VAL),
            version1: ReadOnlyRegister::new(Self::VERSION1_VAL),
            control: ReadWriteRegister::new(0),
            status: ReadOnlyRegister::new(Status::READY::SET.value),
            sca_cfg: ReadWriteRegister::new(0),
            seed: Default::default(),
            hash: Default::default(),
            priv_key: Default::default(),
            pub_key_x: Default::default(),
            pub_key_y: Default::default(),
            sig_r: Default::default(),
            sig_s: Default::default(),
            verify_r: Default::default(),
            iv: Default::default(),
            key_read_ctrl: ReadWriteRegister::new(0),
            key_read_status: ReadOnlyRegister::new(KeyReadStatus::READY::SET.value),
            seed_read_ctrl: ReadWriteRegister::new(0),
            seed_read_status: ReadOnlyRegister::new(KeyReadStatus::READY::SET.value),
            msg_read_ctrl: ReadWriteRegister::new(0),
            msg_read_status: ReadOnlyRegister::new(KeyReadStatus::READY::SET.value),
            key_write_ctrl: ReadWriteRegister::new(0),
            key_write_status: ReadOnlyRegister::new(KeyWriteStatus::READY::SET.value),
            key_vault,
            timer: Timer::new(clock),
            op_complete_action: None,
            op_key_read_complete_action: None,
            op_seed_read_complete_action: None,
            op_msg_read_complete_action: None,
            op_key_write_complete_action: None,
        }
    }

    /// On Write callback for `control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_control(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the control register
        self.control.reg.set(val);

        // Reset the Ready and Valid status bits
        self.status
            .reg
            .modify(Status::READY::CLEAR + Status::VALID::CLEAR);

        match self.control.reg.read_as_enum(Control::CTRL) {
            Some(Control::CTRL::Value::GEN_KEY)
            | Some(Control::CTRL::Value::SIGN)
            | Some(Control::CTRL::Value::VERIFY) => {
                self.op_complete_action = Some(self.timer.schedule_poll_in(ECC384_OP_TICKS));
            }
            _ => {}
        }

        Ok(())
    }

    /// On Write callback for `key_read_control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_key_read_control(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the key control register
        let key_read_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(val);

        self.key_read_ctrl.reg.modify(
            KeyReadControl::KEY_READ_EN.val(key_read_ctrl.read(KeyReadControl::KEY_READ_EN))
                + KeyReadControl::KEY_ID.val(key_read_ctrl.read(KeyReadControl::KEY_ID)),
        );

        if key_read_ctrl.is_set(KeyReadControl::KEY_READ_EN) {
            self.key_read_status.reg.modify(
                KeyReadStatus::READY::CLEAR
                    + KeyReadStatus::VALID::CLEAR
                    + KeyReadStatus::ERROR::CLEAR,
            );

            self.op_key_read_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        Ok(())
    }

    /// On Write callback for `seed_read_control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_seed_read_control(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the key control register
        let seed_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(val);

        self.seed_read_ctrl.reg.modify(
            KeyReadControl::KEY_READ_EN.val(seed_ctrl.read(KeyReadControl::KEY_READ_EN))
                + KeyReadControl::KEY_ID.val(seed_ctrl.read(KeyReadControl::KEY_ID)),
        );

        if seed_ctrl.is_set(KeyReadControl::KEY_READ_EN) {
            self.seed_read_status.reg.modify(
                KeyReadStatus::READY::CLEAR
                    + KeyReadStatus::VALID::CLEAR
                    + KeyReadStatus::ERROR::CLEAR,
            );

            self.op_seed_read_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        Ok(())
    }

    /// On Write callback for `msg_read_control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_msg_read_control(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the msg read control register
        let msg_read_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(val);

        self.msg_read_ctrl.reg.modify(
            KeyReadControl::KEY_READ_EN.val(msg_read_ctrl.read(KeyReadControl::KEY_READ_EN))
                + KeyReadControl::KEY_ID.val(msg_read_ctrl.read(KeyReadControl::KEY_ID)),
        );

        if msg_read_ctrl.is_set(KeyReadControl::KEY_READ_EN) {
            self.msg_read_status.reg.modify(
                KeyReadStatus::READY::CLEAR
                    + KeyReadStatus::VALID::CLEAR
                    + KeyReadStatus::ERROR::CLEAR,
            );

            self.op_msg_read_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        Ok(())
    }

    /// On Write callback for `key_write_control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_key_write_control(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the Tag control register
        let key_write_ctrl = InMemoryRegister::<u32, KeyWriteControl::Register>::new(val);

        self.key_write_ctrl.reg.modify(
            KeyWriteControl::KEY_WRITE_EN.val(key_write_ctrl.read(KeyWriteControl::KEY_WRITE_EN))
                + KeyWriteControl::KEY_ID.val(key_write_ctrl.read(KeyWriteControl::KEY_ID))
                + KeyWriteControl::USAGE.val(key_write_ctrl.read(KeyWriteControl::USAGE)),
        );

        Ok(())
    }

    fn write_access_fault(
        &self,
        _size: RvSize,
        _index: usize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
        } else if self.timer.fired(&mut self.op_key_read_complete_action) {
            self.key_read_complete();
        } else if self.timer.fired(&mut self.op_seed_read_complete_action) {
            self.seed_read_complete();
        } else if self.timer.fired(&mut self.op_msg_read_complete_action) {
            self.msg_read_complete();
        } else if self.timer.fired(&mut self.op_key_write_complete_action) {
            self.key_write_complete();
        }
    }

    fn op_complete(&mut self) {
        match self.control.reg.read_as_enum(Control::CTRL) {
            Some(Control::CTRL::Value::GEN_KEY) => self.gen_key(),
            Some(Control::CTRL::Value::SIGN) => self.sign(),
            Some(Control::CTRL::Value::VERIFY) => self.verify(),
            _ => {}
        }

        self.status
            .reg
            .modify(Status::READY::SET + Status::VALID::SET);
    }

    fn key_read_complete(&mut self) {
        let key_id = self.key_read_ctrl.reg.read(KeyReadControl::KEY_ID);

        let mut key_usage = KeyUsage::default();
        key_usage.set_ecc_private_key(true);

        let result = self.key_vault.read_key(key_id, key_usage);
        let (key_read_result, key) = match result.err() {
            Some(BusError::LoadAccessFault) | Some(BusError::LoadAddrMisaligned) => {
                (KeyReadStatus::ERROR::KV_READ_FAIL.value, None)
            }
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                (KeyReadStatus::ERROR::KV_WRITE_FAIL.value, None)
            }
            None => (
                KeyReadStatus::ERROR::KV_SUCCESS.value,
                Some(result.unwrap()),
            ),
        };

        if let Some(key) = key {
            self.priv_key = words_from_bytes_le(key[..ECC384_COORD_SIZE].try_into().unwrap());
        }

        self.key_read_status.reg.modify(
            KeyReadStatus::READY::SET
                + KeyReadStatus::VALID::SET
                + KeyReadStatus::ERROR.val(key_read_result),
        );
    }

    fn seed_read_complete(&mut self) {
        let key_id = self.seed_read_ctrl.reg.read(KeyReadControl::KEY_ID);

        let mut key_usage = KeyUsage::default();
        key_usage.set_ecc_key_gen_seed(true);

        let result = self.key_vault.read_key(key_id, key_usage);
        let (seed_read_result, seed) = match result.err() {
            Some(BusError::LoadAccessFault) | Some(BusError::LoadAddrMisaligned) => {
                (KeyReadStatus::ERROR::KV_READ_FAIL.value, None)
            }
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                (KeyReadStatus::ERROR::KV_WRITE_FAIL.value, None)
            }
            None => (
                KeyReadStatus::ERROR::KV_SUCCESS.value,
                Some(result.unwrap()),
            ),
        };

        if let Some(seed) = seed {
            self.seed = words_from_bytes_le(seed[..ECC384_SEED_SIZE].try_into().unwrap());
        }

        self.seed_read_status.reg.modify(
            KeyReadStatus::READY::SET
                + KeyReadStatus::VALID::SET
                + KeyReadStatus::ERROR.val(seed_read_result),
        );
    }

    fn msg_read_complete(&mut self) {
        let key_id = self.msg_read_ctrl.reg.read(KeyReadControl::KEY_ID);

        let mut key_usage = KeyUsage::default();
        key_usage.set_ecc_data(true);

        let result = self.key_vault.read_key(key_id, key_usage);
        let (msg_read_result, msg) = match result.err() {
            Some(BusError::LoadAccessFault) | Some(BusError::LoadAddrMisaligned) => {
                (KeyReadStatus::ERROR::KV_READ_FAIL.value, None)
            }
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                (KeyReadStatus::ERROR::KV_WRITE_FAIL.value, None)
            }
            None => (
                KeyReadStatus::ERROR::KV_SUCCESS.value,
                Some(result.unwrap()),
            ),
        };

        if let Some(msg) = msg {
            self.hash = words_from_bytes_le(msg[..ECC384_SEED_SIZE].try_into().unwrap());
        }

        self.msg_read_status.reg.modify(
            KeyReadStatus::READY::SET
                + KeyReadStatus::VALID::SET
                + KeyReadStatus::ERROR.val(msg_read_result),
        );
    }

    fn key_write_complete(&mut self) {
        let key_id = self.key_write_ctrl.reg.read(KeyWriteControl::KEY_ID);

        // Store the key in the key-vault.
        let key_write_result = match self
            .key_vault
            .write_key(
                key_id,
                &bytes_from_words_le(&self.priv_key),
                self.key_write_ctrl.reg.read(KeyWriteControl::USAGE),
            )
            .err()
        {
            Some(BusError::LoadAccessFault) | Some(BusError::LoadAddrMisaligned) => {
                KeyWriteStatus::ERROR::KV_READ_FAIL.value
            }
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                KeyWriteStatus::ERROR::KV_WRITE_FAIL.value
            }
            None => KeyWriteStatus::ERROR::KV_SUCCESS.value,
        };

        self.key_write_status.reg.modify(
            KeyWriteStatus::READY::SET
                + KeyWriteStatus::VALID::SET
                + KeyWriteStatus::ERROR.val(key_write_result),
        );
    }

    /// Generate ECC Key Pair
    fn gen_key(&mut self) {
        let (priv_key, pub_key) = Ecc384::gen_key_pair(&bytes_from_words_le(&self.seed));
        self.priv_key = words_from_bytes_le(&priv_key);

        // Check if key write control is enabled.
        if self
            .key_write_ctrl
            .reg
            .is_set(KeyWriteControl::KEY_WRITE_EN)
        {
            self.key_write_status.reg.modify(
                KeyWriteStatus::READY::CLEAR
                    + KeyWriteStatus::VALID::CLEAR
                    + KeyWriteStatus::ERROR::CLEAR,
            );

            self.op_key_write_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        self.pub_key_x = words_from_bytes_le(&pub_key.x);
        self.pub_key_y = words_from_bytes_le(&pub_key.y);
    }

    /// Sign the hash register
    fn sign(&mut self) {
        let signature = Ecc384::sign(
            &bytes_from_words_le(&self.priv_key),
            &bytes_from_words_le(&self.hash),
        );
        self.sig_r = words_from_bytes_le(&signature.r);
        self.sig_s = words_from_bytes_le(&signature.s);
    }

    /// Verify the ECC Signature
    fn verify(&mut self) {
        let verify_r = Ecc384::verify(
            &Ecc384PubKey {
                x: bytes_from_words_le(&self.pub_key_x),
                y: bytes_from_words_le(&self.pub_key_y),
            },
            &bytes_from_words_le(&self.hash),
            &Ecc384Signature {
                r: bytes_from_words_le(&self.sig_r),
                s: bytes_from_words_le(&self.sig_s),
            },
        );
        self.verify_r = words_from_bytes_le(&verify_r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_crypto::EndianessTransform;
    use caliptra_emu_types::RvAddr;
    use tock_registers::registers::InMemoryRegister;

    const OFFSET_NAME0: RvAddr = 0x0;
    const OFFSET_NAME1: RvAddr = 0x4;
    const OFFSET_VERSION0: RvAddr = 0x8;
    const OFFSET_VERSION1: RvAddr = 0xC;
    const OFFSET_CONTROL: RvAddr = 0x10;
    const OFFSET_STATUS: RvAddr = 0x18;
    const OFFSET_SEED: RvAddr = 0x80;
    const OFFSET_HASH: RvAddr = 0x100;
    const OFFSET_PRIV_KEY: RvAddr = 0x180;
    const OFFSET_PUB_KEY_X: RvAddr = 0x200;
    const OFFSET_PUB_KEY_Y: RvAddr = 0x280;
    const OFFSET_SIG_R: RvAddr = 0x300;
    const OFFSET_SIG_S: RvAddr = 0x380;

    const OFFSET_KEY_READ_CONTROL: RvAddr = 0x600;
    const OFFSET_KEY_READ_STATUS: RvAddr = 0x604;
    const OFFSET_SEED_CONTROL: RvAddr = 0x608;
    const OFFSET_SEED_STATUS: RvAddr = 0x60c;
    const OFFSET_MSG_CONTROL: RvAddr = 0x610;
    const OFFSET_MSG_STATUS: RvAddr = 0x614;
    const OFFSET_KEY_WRITE_CONTROL: RvAddr = 0x618;
    const OFFSET_KEY_WRITE_STATUS: RvAddr = 0x61c;

    const PRIV_KEY: [u8; 48] = [
        0xc9, 0x8, 0x58, 0x5a, 0x48, 0x6c, 0x3b, 0x3d, 0x8b, 0xbe, 0x50, 0xeb, 0x7d, 0x2e, 0xb8,
        0xa0, 0x3a, 0xa0, 0x4e, 0x3d, 0x8b, 0xde, 0x2c, 0x31, 0xa8, 0xa2, 0xa1, 0xe3, 0x34, 0x9d,
        0xc2, 0x1c, 0xbb, 0xe6, 0xc9, 0xa, 0xe2, 0xf7, 0x49, 0x12, 0x88, 0x84, 0xb6, 0x22, 0xbb,
        0x72, 0xb4, 0xc5,
    ];

    const PUB_KEY_X: [u8; 48] = [
        0x9, 0x82, 0x33, 0xca, 0x56, 0x7a, 0x3f, 0x14, 0xbe, 0x78, 0x49, 0x4, 0xc6, 0x92, 0x1d,
        0x43, 0x3b, 0x4f, 0x85, 0x3a, 0x52, 0x37, 0x42, 0xe4, 0xbc, 0x98, 0x76, 0x7e, 0x23, 0xca,
        0x3d, 0xa6, 0x65, 0x6b, 0xec, 0x46, 0xa7, 0xb1, 0x11, 0x9e, 0x63, 0xd2, 0x66, 0xca, 0x62,
        0x54, 0x97, 0x7f,
    ];

    const PUB_KEY_Y: [u8; 48] = [
        0x75, 0xd0, 0xb4, 0x1, 0xc8, 0xba, 0xc3, 0x9a, 0xc5, 0xfb, 0xf, 0x2b, 0x3b, 0x95, 0x37,
        0x2c, 0x41, 0xd9, 0xde, 0x40, 0x55, 0xfd, 0xdb, 0x6, 0xf7, 0x48, 0x49, 0x74, 0x8d, 0xa,
        0xed, 0x85, 0x9b, 0x65, 0x50, 0xca, 0x75, 0xc, 0x3c, 0xd1, 0x18, 0x51, 0xe0, 0x50, 0xbb,
        0x7d, 0x20, 0xb2,
    ];

    const SIG_R: [u8; 48] = [
        0x36, 0xf8, 0x50, 0x14, 0x6f, 0x40, 0x4, 0x43, 0x84, 0x8c, 0xae, 0x3, 0x57, 0x59, 0x10,
        0x32, 0xe6, 0xa3, 0x95, 0xde, 0x66, 0xe7, 0x26, 0x1a, 0x3, 0x80, 0x49, 0xfb, 0xee, 0x15,
        0xdb, 0x19, 0x5d, 0xbd, 0x97, 0x86, 0x94, 0x39, 0x29, 0x2a, 0x4f, 0x57, 0x92, 0xe4, 0x3a,
        0x12, 0x31, 0xb7,
    ];

    const SIG_S: [u8; 48] = [
        0xee, 0xea, 0x42, 0x94, 0x82, 0xfd, 0x8f, 0xa9, 0xd4, 0xd5, 0xf9, 0x60, 0xa0, 0x9e, 0xdf,
        0xa6, 0xc7, 0x65, 0xef, 0xe5, 0xff, 0x4c, 0x17, 0xa5, 0x12, 0xe6, 0x94, 0xfa, 0xcc, 0x45,
        0xd3, 0xf6, 0xfc, 0x3d, 0x3b, 0x5c, 0x62, 0x73, 0x9c, 0x1f, 0xb, 0x9f, 0xca, 0xe3, 0x26,
        0xf5, 0x4b, 0x43,
    ];

    fn make_word(idx: usize, arr: &[u8]) -> RvData {
        let mut res: RvData = 0;
        for i in 0..4 {
            res |= (arr[idx + i] as RvData) << (i * 8);
        }
        res
    }

    #[test]
    fn test_name() {
        let mut ecc = AsymEcc384::new(&Clock::new(), KeyVault::new());

        let name0 = ecc.read(RvSize::Word, OFFSET_NAME0).unwrap();
        let name0 = String::from_utf8_lossy(&name0.to_be_bytes()).to_string();
        assert_eq!(name0, "secp");

        let name1 = ecc.read(RvSize::Word, OFFSET_NAME1).unwrap();
        let name1 = String::from_utf8_lossy(&name1.to_be_bytes()).to_string();
        assert_eq!(name1, "-384");
    }

    #[test]
    fn test_version() {
        let mut ecc = AsymEcc384::new(&Clock::new(), KeyVault::new());

        let version0 = ecc.read(RvSize::Word, OFFSET_VERSION0).unwrap();
        let version0 = String::from_utf8_lossy(&version0.to_le_bytes()).to_string();
        assert_eq!(version0, "1.00");

        let version1 = ecc.read(RvSize::Word, OFFSET_VERSION1).unwrap();
        let version1 = String::from_utf8_lossy(&version1.to_le_bytes()).to_string();
        assert_eq!(version1, "\0\0\0\0");
    }

    #[test]
    fn test_control() {
        let mut ecc = AsymEcc384::new(&Clock::new(), KeyVault::new());
        assert_eq!(ecc.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status() {
        let mut ecc = AsymEcc384::new(&Clock::new(), KeyVault::new());
        assert_eq!(ecc.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_gen_key() {
        let clock = Clock::new();
        let mut ecc = AsymEcc384::new(&clock, KeyVault::new());

        let mut seed = [0u8; 48];
        seed.to_big_endian(); // Change DWORDs to big-endian.

        for i in (0..seed.len()).step_by(4) {
            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_SEED + i as RvAddr, make_word(i, &seed))
                    .ok(),
                Some(())
            );
        }

        assert_eq!(
            ecc.write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::GEN_KEY.into())
                .ok(),
            Some(())
        );

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ecc.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_poll(1, &mut ecc);
        }

        let mut priv_key = bytes_from_words_le(&ecc.priv_key);
        priv_key.to_little_endian(); // Change DWORDs to little-endian.

        let mut pub_key_x = bytes_from_words_le(&ecc.pub_key_x);
        pub_key_x.to_little_endian(); // Change DWORDs to little-endian.

        let mut pub_key_y = bytes_from_words_le(&ecc.pub_key_y);
        pub_key_y.to_little_endian(); // Change DWORDs to little-endian.

        assert_eq!(&priv_key, &PRIV_KEY);
        assert_eq!(&pub_key_x, &PUB_KEY_X);
        assert_eq!(&pub_key_y, &PUB_KEY_Y);
    }

    #[test]
    fn test_gen_key_kv_seed() {
        // Test for getting the seed from the key-vault.
        for key_id in 0..KeyVault::KEY_COUNT {
            let clock = Clock::new();
            let mut seed = [0u8; 48];
            seed.to_big_endian(); // Change DWORDs to big-endian.

            let mut key_vault = KeyVault::new();
            let mut key_usage = KeyUsage::default();
            key_usage.set_ecc_key_gen_seed(true);

            key_vault
                .write_key(key_id, &seed, u32::from(key_usage))
                .unwrap();
            let mut ecc = AsymEcc384::new(&clock, key_vault);

            // Instruct seed to be read from key-vault.
            let seed_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(0);
            seed_ctrl
                .modify(KeyReadControl::KEY_ID.val(key_id) + KeyReadControl::KEY_READ_EN.val(1));

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_SEED_CONTROL, seed_ctrl.get())
                    .ok(),
                Some(())
            );

            // Wait for ecc periph to retrieve the seed from key-vault.
            loop {
                let seed_read_status = InMemoryRegister::<u32, KeyReadStatus::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_SEED_STATUS).unwrap(),
                );

                if seed_read_status.is_set(KeyReadStatus::VALID) {
                    assert_eq!(
                        seed_read_status.read(KeyReadStatus::ERROR),
                        KeyReadStatus::ERROR::KV_SUCCESS.value
                    );
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::GEN_KEY.into())
                    .ok(),
                Some(())
            );

            loop {
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );
                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }

            let mut priv_key = bytes_from_words_le(&ecc.priv_key);
            priv_key.to_little_endian(); // Change DWORDs to little-endian.

            let mut pub_key_x = bytes_from_words_le(&ecc.pub_key_x);
            pub_key_x.to_little_endian(); // Change DWORDs to little-endian.

            let mut pub_key_y = bytes_from_words_le(&ecc.pub_key_y);
            pub_key_y.to_little_endian(); // Change DWORDs to little-endian.

            assert_eq!(&priv_key, &PRIV_KEY);
            assert_eq!(&pub_key_x, &PUB_KEY_X);
            assert_eq!(&pub_key_y, &PUB_KEY_Y);
        }
    }

    #[test]
    fn test_gen_key_kv_privkey() {
        // Test for storing the generated private key in the key-vault.
        for key_id in 0..KeyVault::KEY_COUNT {
            let clock = Clock::new();
            let mut seed = [0u8; 48];
            seed.to_big_endian(); // Change DWORDs to big-endian.

            let mut ecc = AsymEcc384::new(&clock, KeyVault::new());

            for i in (0..seed.len()).step_by(4) {
                assert_eq!(
                    ecc.write(RvSize::Word, OFFSET_SEED + i as RvAddr, make_word(i, &seed))
                        .ok(),
                    Some(())
                );
            }

            // Instruct private key to be stored in the key-vault.
            let mut key_usage = KeyUsage::default();
            key_usage.set_ecc_private_key(true);
            let key_write_ctrl = InMemoryRegister::<u32, KeyWriteControl::Register>::new(0);
            key_write_ctrl.modify(
                KeyWriteControl::KEY_ID.val(key_id)
                    + KeyWriteControl::KEY_WRITE_EN.val(1)
                    + KeyWriteControl::USAGE.val(u32::from(key_usage)),
            );

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_KEY_WRITE_CONTROL, key_write_ctrl.get())
                    .ok(),
                Some(())
            );

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::GEN_KEY.into())
                    .ok(),
                Some(())
            );

            loop {
                let key_write_status = InMemoryRegister::<u32, KeyWriteStatus::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_KEY_WRITE_STATUS).unwrap(),
                );
                if key_write_status.is_set(KeyWriteStatus::VALID) {
                    assert_eq!(
                        key_write_status.read(KeyWriteStatus::ERROR),
                        KeyWriteStatus::ERROR::KV_SUCCESS.value
                    );
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }

            loop {
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );
                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }

            let mut key_usage = KeyUsage::default();
            key_usage.set_ecc_private_key(true);
            let mut priv_key: [u8; 48] = ecc.key_vault.read_key(key_id, key_usage).unwrap()[..48]
                .try_into()
                .unwrap();
            priv_key.to_little_endian(); // Change DWORDs to little-endian.

            let mut pub_key_x = bytes_from_words_le(&ecc.pub_key_x);
            pub_key_x.to_little_endian(); // Change DWORDs to little-endian.

            let mut pub_key_y = bytes_from_words_le(&ecc.pub_key_y);
            pub_key_y.to_little_endian(); // Change DWORDs to little-endian.

            assert_eq!(&priv_key, &PRIV_KEY);
            assert_eq!(&pub_key_x, &PUB_KEY_X);
            assert_eq!(&pub_key_y, &PUB_KEY_Y);
        }
    }

    #[test]
    fn test_sign() {
        let clock = Clock::new();
        let mut ecc = AsymEcc384::new(&clock, KeyVault::new());

        let mut hash = [0u8; KeyVault::KEY_SIZE];
        hash.to_big_endian(); // Change DWORDs to big-endian.

        for i in (0..hash.len()).step_by(4) {
            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_HASH + i as RvAddr, make_word(i, &hash))
                    .ok(),
                Some(())
            );
        }

        let mut priv_key = PRIV_KEY;
        priv_key.to_big_endian(); // Change DWORDs to big-endian.

        for i in (0..PRIV_KEY.len()).step_by(4) {
            assert_eq!(
                ecc.write(
                    RvSize::Word,
                    OFFSET_PRIV_KEY + i as RvAddr,
                    make_word(i, &priv_key)
                )
                .ok(),
                Some(())
            );
        }

        assert_eq!(
            ecc.write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::SIGN.into())
                .ok(),
            Some(())
        );

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ecc.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_poll(1, &mut ecc);
        }

        let mut sig_r = bytes_from_words_le(&ecc.sig_r);
        sig_r.to_little_endian(); // Change DWORDs to little-endian.

        let mut sig_s = bytes_from_words_le(&ecc.sig_s);
        sig_s.to_little_endian(); // Change DWORDs to little-endian.

        assert_eq!(&sig_r, &SIG_R);
        assert_eq!(&sig_s, &SIG_S);
    }

    #[test]
    fn test_sign_kv_privkey() {
        // Test for getting the private key from the key-vault.
        for key_id in 0..8 {
            let clock = Clock::new();
            let mut priv_key = PRIV_KEY;
            priv_key.to_big_endian(); // Change DWORDs to big-endian.

            let mut key_vault = KeyVault::new();
            let mut key_usage = KeyUsage::default();
            key_usage.set_ecc_private_key(true);
            key_vault
                .write_key(key_id, &priv_key, u32::from(key_usage))
                .unwrap();

            let mut ecc = AsymEcc384::new(&clock, key_vault);

            let mut hash = [0u8; 48];
            hash.to_big_endian(); // Change DWORDs to big-endian.

            for i in (0..hash.len()).step_by(4) {
                assert_eq!(
                    ecc.write(RvSize::Word, OFFSET_HASH + i as RvAddr, make_word(i, &hash))
                        .ok(),
                    Some(())
                );
            }

            // Instruct private key to be read from key-vault.
            let key_read_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(0);
            key_read_ctrl
                .modify(KeyReadControl::KEY_ID.val(key_id) + KeyReadControl::KEY_READ_EN.val(1));

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_KEY_READ_CONTROL, key_read_ctrl.get())
                    .ok(),
                Some(())
            );

            // Wait for ecc periph to retrieve the private key from the key-vault.
            loop {
                let key_read_status = InMemoryRegister::<u32, KeyReadStatus::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_KEY_READ_STATUS).unwrap(),
                );
                if key_read_status.is_set(KeyReadStatus::VALID) {
                    assert_eq!(
                        key_read_status.read(KeyReadStatus::ERROR),
                        KeyReadStatus::ERROR::KV_SUCCESS.value
                    );
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::SIGN.into())
                    .ok(),
                Some(())
            );

            loop {
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );
                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }

            let mut sig_r = bytes_from_words_le(&ecc.sig_r);
            sig_r.to_little_endian(); // Change DWORDs to little-endian.

            let mut sig_s = bytes_from_words_le(&ecc.sig_s);
            sig_s.to_little_endian(); // Change DWORDs to little-endian.

            assert_eq!(&sig_r, &SIG_R);
            assert_eq!(&sig_s, &SIG_S);
        }
    }

    #[test]
    fn test_sign_kv_privkey_not_allowed() {
        // Negative test for retrieving disallowed private key from the key-vault.
        for key_id in 0..8 {
            let clock = Clock::new();
            let mut priv_key = PRIV_KEY;
            priv_key.to_big_endian(); // Change DWORDs to big-endian.

            let mut key_vault = KeyVault::new();
            let mut key_usage = KeyUsage::default();
            key_usage.set_ecc_private_key(true);
            key_vault
                .write_key(key_id, &priv_key, !(u32::from(key_usage)))
                .unwrap();

            let mut ecc = AsymEcc384::new(&clock, key_vault);

            let mut hash = [0u8; 48];
            hash.to_big_endian(); // Change DWORDs to big-endian.

            for i in (0..hash.len()).step_by(4) {
                assert_eq!(
                    ecc.write(RvSize::Word, OFFSET_HASH + i as RvAddr, make_word(i, &hash))
                        .ok(),
                    Some(())
                );
            }

            // Instruct private key to be read from key-vault.
            let key_read_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(0);
            key_read_ctrl
                .modify(KeyReadControl::KEY_ID.val(key_id) + KeyReadControl::KEY_READ_EN.val(1));

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_KEY_READ_CONTROL, key_read_ctrl.get())
                    .ok(),
                Some(())
            );

            // Wait for ecc periph to retrieve the private key from the key-vault.
            loop {
                let key_read_status = InMemoryRegister::<u32, KeyReadStatus::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_KEY_READ_STATUS).unwrap(),
                );
                if key_read_status.is_set(KeyReadStatus::VALID) {
                    assert_eq!(
                        key_read_status.read(KeyReadStatus::ERROR),
                        KeyReadStatus::ERROR::KV_READ_FAIL.value
                    );
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }
        }
    }

    #[test]
    fn test_sign_kv_msg() {
        // Test for getting the message (hash) from the key-vault.
        for key_id in 0..8 {
            let clock = Clock::new();
            let mut hash = [0u8; 48];
            hash.to_big_endian(); // Change DWORDs to big-endian.

            let mut key_vault = KeyVault::new();
            let mut key_usage = KeyUsage::default();
            key_usage.set_ecc_data(true);

            key_vault
                .write_key(key_id, &hash, u32::from(key_usage))
                .unwrap();

            let mut ecc = AsymEcc384::new(&clock, key_vault);

            // Instruct hash to be read from key-vault.
            let msg_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(0);
            msg_ctrl
                .modify(KeyReadControl::KEY_ID.val(key_id) + KeyReadControl::KEY_READ_EN.val(1));

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_MSG_CONTROL, msg_ctrl.get())
                    .ok(),
                Some(())
            );

            // Wait for ecc periph to retrieve the private key from the key-vault.
            loop {
                let msg_read_status = InMemoryRegister::<u32, KeyReadStatus::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_MSG_STATUS).unwrap(),
                );
                if msg_read_status.is_set(KeyReadStatus::VALID) {
                    assert_eq!(
                        msg_read_status.read(KeyReadStatus::ERROR),
                        KeyReadStatus::ERROR::KV_SUCCESS.value
                    );
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }

            let mut priv_key = PRIV_KEY;
            priv_key.to_big_endian(); // Change DWORDs to big-endian.

            for i in (0..PRIV_KEY.len()).step_by(4) {
                assert_eq!(
                    ecc.write(
                        RvSize::Word,
                        OFFSET_PRIV_KEY + i as RvAddr,
                        make_word(i, &priv_key)
                    )
                    .ok(),
                    Some(())
                );
            }

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::SIGN.into())
                    .ok(),
                Some(())
            );

            loop {
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );
                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }

            let mut sig_r = bytes_from_words_le(&ecc.sig_r);
            sig_r.to_little_endian(); // Change DWORDs to little-endian.

            let mut sig_s = bytes_from_words_le(&ecc.sig_s);
            sig_s.to_little_endian(); // Change DWORDs to little-endian.

            assert_eq!(&sig_r, &SIG_R);
            assert_eq!(&sig_s, &SIG_S);
        }
    }

    #[test]
    fn test_sign_kv_msg_not_allowed() {
        // Negative test for retrieving a disallowed message (hash) from the key-vault.
        for key_id in 0..8 {
            let clock = Clock::new();
            let mut hash = [0u8; 48];
            hash.to_big_endian(); // Change DWORDs to big-endian.

            let mut key_vault = KeyVault::new();
            let mut key_usage = KeyUsage::default();
            key_usage.set_ecc_data(true);

            key_vault
                .write_key(key_id, &hash, !(u32::from(key_usage)))
                .unwrap();

            let mut ecc = AsymEcc384::new(&clock, key_vault);

            // Instruct hash to be read from key-vault.
            let msg_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(0);
            msg_ctrl
                .modify(KeyReadControl::KEY_ID.val(key_id) + KeyReadControl::KEY_READ_EN.val(1));

            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_MSG_CONTROL, msg_ctrl.get())
                    .ok(),
                Some(())
            );

            // Wait for ecc periph to retrieve the private key from the key-vault.
            loop {
                let msg_read_status = InMemoryRegister::<u32, KeyReadStatus::Register>::new(
                    ecc.read(RvSize::Word, OFFSET_MSG_STATUS).unwrap(),
                );
                if msg_read_status.is_set(KeyReadStatus::VALID) {
                    assert_eq!(
                        msg_read_status.read(KeyReadStatus::ERROR),
                        KeyReadStatus::ERROR::KV_READ_FAIL.value
                    );
                    break;
                }
                clock.increment_and_poll(1, &mut ecc);
            }
        }
    }

    #[test]
    fn test_verify() {
        let clock = Clock::new();
        let mut ecc = AsymEcc384::new(&clock, KeyVault::new());

        let hash = [0u8; KeyVault::KEY_SIZE];
        for i in (0..hash.len()).step_by(4) {
            assert_eq!(
                ecc.write(RvSize::Word, OFFSET_HASH + i as RvAddr, make_word(i, &hash))
                    .ok(),
                Some(())
            );
        }

        let mut pub_key_x_reverse = PUB_KEY_X;
        pub_key_x_reverse.to_big_endian();

        for i in (0..pub_key_x_reverse.len()).step_by(4) {
            assert_eq!(
                ecc.write(
                    RvSize::Word,
                    OFFSET_PUB_KEY_X + i as RvAddr,
                    make_word(i, &pub_key_x_reverse)
                )
                .ok(),
                Some(())
            );
        }

        let mut pub_key_y_reverse = PUB_KEY_Y;
        pub_key_y_reverse.to_big_endian();

        for i in (0..pub_key_y_reverse.len()).step_by(4) {
            assert_eq!(
                ecc.write(
                    RvSize::Word,
                    OFFSET_PUB_KEY_Y + i as RvAddr,
                    make_word(i, &pub_key_y_reverse)
                )
                .ok(),
                Some(())
            );
        }

        let mut sig_r_reverse = SIG_R;
        sig_r_reverse.to_big_endian();

        for i in (0..sig_r_reverse.len()).step_by(4) {
            assert_eq!(
                ecc.write(
                    RvSize::Word,
                    OFFSET_SIG_R + i as RvAddr,
                    make_word(i, &sig_r_reverse)
                )
                .ok(),
                Some(())
            );
        }

        let mut sig_s_reverse = SIG_S;
        sig_s_reverse.to_big_endian();

        for i in (0..sig_s_reverse.len()).step_by(4) {
            assert_eq!(
                ecc.write(
                    RvSize::Word,
                    OFFSET_SIG_S + i as RvAddr,
                    make_word(i, &sig_s_reverse)
                )
                .ok(),
                Some(())
            );
        }

        assert_eq!(
            ecc.write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::VERIFY.into())
                .ok(),
            Some(())
        );

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ecc.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_poll(1, &mut ecc);
        }

        let mut sig_s_reverse = bytes_from_words_le(&ecc.verify_r);
        sig_s_reverse.to_little_endian();

        assert_eq!(&sig_s_reverse, &SIG_R);
    }
}
