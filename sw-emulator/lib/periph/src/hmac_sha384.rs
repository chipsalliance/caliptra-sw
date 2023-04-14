/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_sha384.rs

Abstract:

    File contains HMACSha384 peripheral implementation.

--*/

use crate::{KeyUsage, KeyVault};
use caliptra_emu_bus::{
    ActionHandle, BusError, Clock, ReadOnlyMemory, ReadOnlyRegister, ReadWriteMemory,
    ReadWriteRegister, Timer, WriteOnlyMemory,
};
use caliptra_emu_crypto::EndianessTransform;
use caliptra_emu_crypto::{Hmac512, Hmac512Mode};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

register_bitfields! [
    u32,

    /// Control Register Fields
    Control [
        INIT OFFSET(0) NUMBITS(1) [],
        NEXT OFFSET(1) NUMBITS(1) [],
        ZEROIZE OFFSET(2) NUMBITS(1) [],
        RSVD OFFSET(3) NUMBITS(29) [],
    ],

    /// Status Register Fields
    Status[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
    ],

    /// Key Read Control Register Fields
    KeyReadControl[
        KEY_READ_EN OFFSET(0) NUMBITS(1) [],
        KEY_ID OFFSET(1) NUMBITS(5) [],
        PCR_HASH_EXTEND OFFSET(6) NUMBITS(1) [],
        RSVD OFFSET(7) NUMBITS(25) [],
    ],

    /// Key Read Status Register Fields
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

    /// Tag Write Control Register Fields
    TagWriteControl[
        KEY_WRITE_EN OFFSET(0) NUMBITS(1) [],
        KEY_ID OFFSET(1) NUMBITS(5) [],
        USAGE OFFSET(6) NUMBITS(6) [],
        RSVD OFFSET(12) NUMBITS(20) [],
    ],

    // Tag Status Register Fields
    TagWriteStatus[
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

/// HMAC Key Size.
const HMAC_KEY_SIZE: usize = 48;

/// HMAC Block Size
const HMAC_BLOCK_SIZE: usize = 128;

/// HMAC Tag Size
const HMAC_TAG_SIZE: usize = 48;

/// The number of CPU clock cycles it takes to perform initialization action.
const INIT_TICKS: u64 = 1000;

/// The number of CPU clock cycles it takes to perform the hash update action.
const UPDATE_TICKS: u64 = 1000;

/// The number of CPU clock cycles read and write keys from key vault
const KEY_RW_TICKS: u64 = 100;

/// HMAC-SHA-384 Peripheral
#[derive(Bus)]
#[poll_fn(poll)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
pub struct HmacSha384 {
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

    /// HMAC Key Register
    #[peripheral(offset = 0x0000_0040, mask = 0x0000_003f)]
    key: WriteOnlyMemory<HMAC_KEY_SIZE>,

    /// HMAC Block Register
    #[peripheral(offset = 0x0000_0080, mask = 0x0000_007f)]
    block: ReadWriteMemory<HMAC_BLOCK_SIZE>,

    /// HMAC Tag Register
    #[peripheral(offset = 0x0000_0100, mask = 0x0000_00ff)]
    tag: ReadOnlyMemory<HMAC_TAG_SIZE>,

    /// Key Read Control Register
    #[register(offset = 0x0000_0600, write_fn = on_write_key_read_control)]
    key_read_ctrl: ReadWriteRegister<u32, KeyReadControl::Register>,

    /// Key Read Status Register
    #[register(offset = 0x0000_0604)]
    key_read_status: ReadOnlyRegister<u32, KeyReadStatus::Register>,

    /// Block Read Control Register
    #[register(offset = 0x0000_0608, write_fn = on_write_block_read_control)]
    block_read_ctrl: ReadWriteRegister<u32, KeyReadControl::Register>,

    /// Block Read Status Register
    #[register(offset = 0x0000_060c)]
    block_read_status: ReadOnlyRegister<u32, KeyReadStatus::Register>,

    /// Tag Write Control Register
    #[register(offset = 0x0000_0610, write_fn = on_write_tag_write_control)]
    tag_write_ctrl: ReadWriteRegister<u32, TagWriteControl::Register>,

    /// Tag Write Status Register
    #[register(offset = 0x0000_0614)]
    tag_write_status: ReadOnlyRegister<u32, TagWriteStatus::Register>,

    /// HMAC engine
    hmac: Hmac512<HMAC_KEY_SIZE>,

    /// Key Vault
    key_vault: KeyVault,

    /// Timer
    timer: Timer,

    /// Operation complete action
    op_complete_action: Option<ActionHandle>,

    /// Key read complete action
    op_key_read_complete_action: Option<ActionHandle>,

    /// Block read complete action
    op_block_read_complete_action: Option<ActionHandle>,

    /// Tag write complete action
    op_tag_write_complete_action: Option<ActionHandle>,
}

impl HmacSha384 {
    /// NAME0 Register Value
    const NAME0_VAL: RvData = 0x63616d68; // hmac

    /// NAME1 Register Value
    const NAME1_VAL: RvData = 0x32616873; // sha2

    /// VERSION0 Register Value
    const VERSION0_VAL: RvData = 0x30302E31; // 1.0

    /// VERSION1 Register Value
    const VERSION1_VAL: RvData = 0x00000000;

    /// Create a new instance of HMAC-SHA-384 Engine
    ///
    /// # Arguments
    ///
    /// * `clock` - Clock
    /// * `key_vault` - Key Vault
    ///
    /// # Returns
    ///
    /// * `Self` - Instance of HMAC-SHA-384 Engine
    pub fn new(clock: &Clock, key_vault: KeyVault) -> Self {
        Self {
            hmac: Hmac512::<HMAC_KEY_SIZE>::new(Hmac512Mode::Sha384),
            name0: ReadOnlyRegister::new(Self::NAME0_VAL),
            name1: ReadOnlyRegister::new(Self::NAME1_VAL),
            version0: ReadOnlyRegister::new(Self::VERSION0_VAL),
            version1: ReadOnlyRegister::new(Self::VERSION1_VAL),
            control: ReadWriteRegister::new(0),
            status: ReadOnlyRegister::new(Status::READY::SET.value),
            key: WriteOnlyMemory::new(),
            block: ReadWriteMemory::new(),
            tag: ReadOnlyMemory::new(),
            key_read_ctrl: ReadWriteRegister::new(0),
            key_read_status: ReadOnlyRegister::new(KeyReadStatus::READY::SET.value),
            block_read_ctrl: ReadWriteRegister::new(0),
            block_read_status: ReadOnlyRegister::new(KeyReadStatus::READY::SET.value),
            tag_write_ctrl: ReadWriteRegister::new(0),
            tag_write_status: ReadOnlyRegister::new(TagWriteStatus::READY::SET.value),
            key_vault,
            timer: Timer::new(clock),
            op_complete_action: None,
            op_key_read_complete_action: None,
            op_block_read_complete_action: None,
            op_tag_write_complete_action: None,
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

        if self.control.reg.is_set(Control::INIT) {
            // Initialize the HMAC engine with key and initial data block
            self.hmac.init(self.key.data(), self.block.data());

            // Schedule a future call to poll() complete the operation.
            self.op_complete_action = Some(self.timer.schedule_poll_in(INIT_TICKS));
        } else if self.control.reg.is_set(Control::NEXT) {
            // Update a HMAC engine with a new block
            self.hmac.update(self.block.data());

            // Schedule a future call to poll() complete the operation.
            self.op_complete_action = Some(self.timer.schedule_poll_in(UPDATE_TICKS));
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

    /// On Write callback for `block_read_control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_block_read_control(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the block control register
        let block_read_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(val);

        self.block_read_ctrl.reg.modify(
            KeyReadControl::KEY_READ_EN.val(block_read_ctrl.read(KeyReadControl::KEY_READ_EN))
                + KeyReadControl::KEY_ID.val(block_read_ctrl.read(KeyReadControl::KEY_ID)),
        );

        if block_read_ctrl.is_set(KeyReadControl::KEY_READ_EN) {
            self.block_read_status.reg.modify(
                KeyReadStatus::READY::CLEAR
                    + KeyReadStatus::VALID::CLEAR
                    + KeyReadStatus::ERROR::CLEAR,
            );

            self.op_block_read_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        Ok(())
    }

    /// On Write callback for `tag_write_control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_tag_write_control(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the Tag control register
        let tag_write_ctrl = InMemoryRegister::<u32, TagWriteControl::Register>::new(val);

        self.tag_write_ctrl.reg.modify(
            TagWriteControl::KEY_WRITE_EN.val(tag_write_ctrl.read(TagWriteControl::KEY_WRITE_EN))
                + TagWriteControl::KEY_ID.val(tag_write_ctrl.read(TagWriteControl::KEY_ID))
                + TagWriteControl::USAGE.val(tag_write_ctrl.read(TagWriteControl::USAGE)),
        );

        Ok(())
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
        } else if self.timer.fired(&mut self.op_key_read_complete_action) {
            self.key_read_complete();
        } else if self.timer.fired(&mut self.op_block_read_complete_action) {
            self.block_read_complete();
        } else if self.timer.fired(&mut self.op_tag_write_complete_action) {
            self.tag_write_complete();
        }
    }

    /// Called by Bus::warm_reset() to indicate a warm reset
    fn warm_reset(&mut self) {
        // TODO: Reset registers
    }

    /// Called by Bus::update_reset() to indicate an update reset
    fn update_reset(&mut self) {
        // TODO: Reset registers
    }

    fn op_complete(&mut self) {
        // Retrieve the tag
        self.hmac.tag(self.tag.data_mut());

        // Check if tag control is enabled.
        if self
            .tag_write_ctrl
            .reg
            .is_set(TagWriteControl::KEY_WRITE_EN)
        {
            self.tag_write_status.reg.modify(
                TagWriteStatus::READY::CLEAR
                    + TagWriteStatus::VALID::CLEAR
                    + TagWriteStatus::ERROR::CLEAR,
            );

            self.op_tag_write_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        // Update Ready and Valid status bits
        self.status
            .reg
            .modify(Status::READY::SET + Status::VALID::SET);
    }

    fn key_read_complete(&mut self) {
        let key_id = self.key_read_ctrl.reg.read(KeyReadControl::KEY_ID);

        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_key(true);

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

        if let Some(key) = &key {
            self.key.data_mut().copy_from_slice(&key[..HMAC_KEY_SIZE]);
        }

        self.key_read_status.reg.modify(
            KeyReadStatus::READY::SET
                + KeyReadStatus::VALID::SET
                + KeyReadStatus::ERROR.val(key_read_result),
        );
    }

    fn block_read_complete(&mut self) {
        let key_id = self.block_read_ctrl.reg.read(KeyReadControl::KEY_ID);

        // Clear the block
        self.block.data_mut().fill(0);

        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_data(true);

        let result = self.key_vault.read_key(key_id, key_usage);
        let (block_read_result, data) = match result.err() {
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

        if let Some(data) = &data {
            self.format_block(data);
        }

        self.block_read_status.reg.modify(
            KeyReadStatus::READY::SET
                + KeyReadStatus::VALID::SET
                + KeyReadStatus::ERROR.val(block_read_result),
        );
    }

    /// Adds padding and total data size to the block.
    /// Stores the formatted block in peripheral's internal block data structure.
    ///
    /// # Arguments
    ///
    /// * `data_len` - Size of the data
    /// * `data` - Data to hash. This is in big-endian format.
    ///
    /// # Error
    ///
    /// * `None`
    fn format_block(&mut self, data: &[u8; KeyVault::KEY_SIZE]) {
        let mut block_arr = [0u8; HMAC_BLOCK_SIZE];
        block_arr[..data.len()].copy_from_slice(&data[..data.len()]);
        block_arr.to_little_endian();

        // Add block padding.
        block_arr[data.len()] = 0b1000_0000;

        // Add block length.
        let len = ((HMAC_BLOCK_SIZE + data.len()) as u128) * 8;
        block_arr[HMAC_BLOCK_SIZE - 16..].copy_from_slice(&len.to_be_bytes());

        block_arr.to_big_endian();
        self.block.data_mut().copy_from_slice(&block_arr);
    }

    fn tag_write_complete(&mut self) {
        let key_id = self.tag_write_ctrl.reg.read(TagWriteControl::KEY_ID);

        // Store the tag in the key-vault.
        // Tag is in big-endian format and is stored in the same format.
        let tag_write_result = match self
            .key_vault
            .write_key(
                key_id,
                self.tag.data(),
                self.tag_write_ctrl.reg.read(TagWriteControl::USAGE),
            )
            .err()
        {
            Some(BusError::LoadAccessFault) | Some(BusError::LoadAddrMisaligned) => {
                TagWriteStatus::ERROR::KV_READ_FAIL.value
            }
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                TagWriteStatus::ERROR::KV_WRITE_FAIL.value
            }
            None => TagWriteStatus::ERROR::KV_SUCCESS.value,
        };

        self.tag_write_status.reg.modify(
            TagWriteStatus::READY::SET
                + TagWriteStatus::VALID::SET
                + TagWriteStatus::ERROR.val(tag_write_result),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_vault;
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
    const OFFSET_KEY: RvAddr = 0x40;
    const OFFSET_BLOCK: RvAddr = 0x80;
    const OFFSET_TAG: RvAddr = 0x100;

    const OFFSET_KEY_CONTROL: RvAddr = 0x600;
    const OFFSET_KEY_STATUS: RvAddr = 0x604;
    const OFFSET_BLOCK_CONTROL: RvAddr = 0x608;
    const OFFSET_BLOCK_STATUS: RvAddr = 0x60c;
    const OFFSET_TAG_CONTROL: RvAddr = 0x610;
    const OFFSET_TAG_STATUS: RvAddr = 0x614;

    #[test]
    fn test_name() {
        let mut hmac = HmacSha384::new(&Clock::new(), KeyVault::new());

        let name0 = hmac.read(RvSize::Word, OFFSET_NAME0).unwrap();
        let name0 = String::from_utf8_lossy(&name0.to_le_bytes()).to_string();
        assert_eq!(name0, "hmac");

        let name1 = hmac.read(RvSize::Word, OFFSET_NAME1).unwrap();
        let name1 = String::from_utf8_lossy(&name1.to_le_bytes()).to_string();
        assert_eq!(name1, "sha2");
    }

    #[test]
    fn test_version() {
        let mut hmac = HmacSha384::new(&Clock::new(), KeyVault::new());

        let version0 = hmac.read(RvSize::Word, OFFSET_VERSION0).unwrap();
        let version0 = String::from_utf8_lossy(&version0.to_le_bytes()).to_string();
        assert_eq!(version0, "1.00");

        let version1 = hmac.read(RvSize::Word, OFFSET_VERSION1).unwrap();
        let version1 = String::from_utf8_lossy(&version1.to_le_bytes()).to_string();
        assert_eq!(version1, "\0\0\0\0");
    }

    #[test]
    fn test_control() {
        let mut hmac = HmacSha384::new(&Clock::new(), KeyVault::new());
        assert_eq!(hmac.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status() {
        let mut hmac = HmacSha384::new(&Clock::new(), KeyVault::new());
        assert_eq!(hmac.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_key() {
        let mut hmac = HmacSha384::new(&Clock::new(), KeyVault::new());
        for addr in (OFFSET_KEY..(OFFSET_KEY + HMAC_KEY_SIZE as u32)).step_by(4) {
            assert_eq!(hmac.write(RvSize::Word, addr, 0xFF).ok(), Some(()));
            assert_eq!(
                hmac.read(RvSize::Word, addr).err(),
                Some(BusError::LoadAccessFault)
            );
        }
    }

    #[test]
    fn test_block() {
        let mut hmac = HmacSha384::new(&Clock::new(), KeyVault::new());
        for addr in (OFFSET_BLOCK..(OFFSET_BLOCK + HMAC_BLOCK_SIZE as u32)).step_by(4) {
            assert_eq!(hmac.write(RvSize::Word, addr, u32::MAX).ok(), Some(()));
            assert_eq!(hmac.read(RvSize::Word, addr).ok(), Some(u32::MAX));
        }
    }

    #[test]
    fn test_tag() {
        let mut hmac = HmacSha384::new(&Clock::new(), KeyVault::new());
        for addr in (OFFSET_TAG..(OFFSET_TAG + HMAC_TAG_SIZE as u32)).step_by(4) {
            assert_eq!(hmac.read(RvSize::Word, addr).ok(), Some(0));
            assert_eq!(
                hmac.write(RvSize::Word, addr, 0xFF).err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }

    enum KeyVaultAction {
        KeyFromVault(u32),
        BlockFromVault(u32),
        TagToVault(u32),
        KeyReadDisallowed(bool),
        KeyDisallowedForHMAC(bool),
        BlockReadDisallowed(bool),
        BlockDisallowedForHMAC(bool),
        TagWriteFailTest(bool),
    }

    fn test_hmac(
        key: &mut [u8; HMAC_KEY_SIZE],
        data: &[u8],
        result: &[u8],
        keyvault_actions: &[KeyVaultAction],
    ) {
        fn make_word(idx: usize, arr: &[u8]) -> RvData {
            let mut res: RvData = 0;
            for i in 0..4 {
                res |= (arr[idx + i] as RvData) << (i * 8);
            }
            res
        }

        let totalblocks = ((data.len() + 16) + HMAC_BLOCK_SIZE) / HMAC_BLOCK_SIZE;
        let totalbytes = totalblocks * HMAC_BLOCK_SIZE;
        let mut block_arr = vec![0; totalbytes];
        let mut key_via_kv: bool = false;
        let mut block_via_kv: bool = false;
        let mut tag_to_kv: bool = false;
        let mut key_id: u32 = u32::MAX;
        let mut block_id: u32 = u32::MAX;
        let mut tag_id: u32 = u32::MAX;
        let mut tag_le: [u8; 48] = [0; 48];
        let mut key_read_disallowed = false;
        let mut key_disallowed_for_hmac = false;
        let mut block_read_disallowed = false;
        let mut tag_write_fail_test = false;
        let mut block_disallowed_for_hmac = false;

        for (_idx, action) in keyvault_actions.iter().enumerate() {
            match action {
                KeyVaultAction::KeyFromVault(id) => {
                    key_via_kv = true;
                    key_id = *id;
                }
                KeyVaultAction::BlockFromVault(id) => {
                    block_via_kv = true;
                    block_id = *id;
                }
                KeyVaultAction::TagToVault(id) => {
                    tag_to_kv = true;
                    tag_id = *id;
                }
                KeyVaultAction::KeyReadDisallowed(val) => {
                    key_read_disallowed = *val;
                }
                KeyVaultAction::KeyDisallowedForHMAC(val) => {
                    key_disallowed_for_hmac = *val;
                }
                KeyVaultAction::BlockReadDisallowed(val) => {
                    block_read_disallowed = *val;
                }
                KeyVaultAction::BlockDisallowedForHMAC(val) => {
                    block_disallowed_for_hmac = *val;
                }
                KeyVaultAction::TagWriteFailTest(val) => {
                    tag_write_fail_test = *val;
                }
            }
        }

        if block_via_kv {
            assert_eq!(data.len(), HMAC_KEY_SIZE);
        } else {
            // Compute the total bytes and total blocks required for the final message.
            block_arr[..data.len()].copy_from_slice(data);
            block_arr[data.len()] = 1 << 7;

            let len: u128 = (HMAC_BLOCK_SIZE + data.len()) as u128;
            let len = len * 8;

            block_arr[totalbytes - 16..].copy_from_slice(&len.to_be_bytes());

            block_arr.to_big_endian();
        }

        let clock = Clock::new();
        key.to_big_endian();
        let mut key_vault = KeyVault::new();

        if key_via_kv {
            key_vault.write_key(key_id, key, 0x3F).unwrap();

            if key_read_disallowed {
                let val_reg = InMemoryRegister::<u32, key_vault::KV_CONTROL::Register>::new(0);
                val_reg.write(key_vault::KV_CONTROL::USE_LOCK.val(1)); // Key read disabled.
                assert_eq!(
                    key_vault
                        .write(
                            RvSize::Word,
                            KeyVault::KEY_CONTROL_REG_OFFSET
                                + (key_id * KeyVault::KEY_CONTROL_REG_WIDTH),
                            val_reg.get()
                        )
                        .ok(),
                    Some(())
                );
            } else if key_disallowed_for_hmac {
                let mut key_usage = KeyUsage::default();
                key_usage.set_hmac_key(true);
                let val_reg = InMemoryRegister::<u32, key_vault::KV_CONTROL::Register>::new(0);
                val_reg.write(key_vault::KV_CONTROL::USAGE.val(!(u32::from(key_usage)))); // Key disallowed for hmac.
                assert_eq!(
                    key_vault
                        .write(
                            RvSize::Word,
                            KeyVault::KEY_CONTROL_REG_OFFSET
                                + (key_id * KeyVault::KEY_CONTROL_REG_WIDTH),
                            val_reg.get()
                        )
                        .ok(),
                    Some(())
                );
            }
        }

        if block_via_kv {
            let mut block: [u8; KeyVault::KEY_SIZE] = [0; KeyVault::KEY_SIZE];
            block[..data.len()].copy_from_slice(data);
            block.to_big_endian(); // Keys are stored in big-endian format.
            let mut key_usage = KeyUsage::default();
            key_usage.set_hmac_data(true);
            key_vault
                .write_key(block_id, &block, u32::from(key_usage))
                .unwrap();

            if block_read_disallowed {
                let val_reg = InMemoryRegister::<u32, key_vault::KV_CONTROL::Register>::new(0);
                val_reg.write(key_vault::KV_CONTROL::USE_LOCK.val(1)); // Key read disabled.
                assert_eq!(
                    key_vault
                        .write(
                            RvSize::Word,
                            KeyVault::KEY_CONTROL_REG_OFFSET
                                + (block_id * KeyVault::KEY_CONTROL_REG_WIDTH),
                            val_reg.get()
                        )
                        .ok(),
                    Some(())
                );
            } else if block_disallowed_for_hmac {
                let mut key_usage = KeyUsage::default();
                key_usage.set_hmac_data(true);
                let val_reg = InMemoryRegister::<u32, key_vault::KV_CONTROL::Register>::new(0);
                val_reg.write(key_vault::KV_CONTROL::USAGE.val(!(u32::from(key_usage)))); // Block disallowed for HMAC use.
                assert_eq!(
                    key_vault
                        .write(
                            RvSize::Word,
                            KeyVault::KEY_CONTROL_REG_OFFSET
                                + (block_id * KeyVault::KEY_CONTROL_REG_WIDTH),
                            val_reg.get()
                        )
                        .ok(),
                    Some(())
                );
            }
        }

        // For negative tag write test, make the key-slot uneditable.
        if tag_write_fail_test {
            assert!(tag_to_kv);
            let val_reg = InMemoryRegister::<u32, key_vault::KV_CONTROL::Register>::new(0);
            val_reg.write(key_vault::KV_CONTROL::WRITE_LOCK.val(1)); // Key write disabled.
            assert_eq!(
                key_vault
                    .write(
                        RvSize::Word,
                        KeyVault::KEY_CONTROL_REG_OFFSET
                            + (tag_id * KeyVault::KEY_CONTROL_REG_WIDTH),
                        val_reg.get()
                    )
                    .ok(),
                Some(())
            );
        }

        let mut hmac = HmacSha384::new(&clock, key_vault);

        if tag_to_kv {
            // Instruct tag to be read from key-vault.
            let mut key_usage = KeyUsage::default();
            key_usage.set_hmac_data(true);
            let tag_ctrl = InMemoryRegister::<u32, TagWriteControl::Register>::new(0);
            tag_ctrl.modify(
                TagWriteControl::KEY_ID.val(tag_id)
                    + TagWriteControl::KEY_WRITE_EN.val(1)
                    + TagWriteControl::USAGE.val(u32::from(key_usage)),
            );

            assert_eq!(
                hmac.write(RvSize::Word, OFFSET_TAG_CONTROL, tag_ctrl.get())
                    .ok(),
                Some(())
            );
        }

        if !key_via_kv {
            for i in (0..key.len()).step_by(4) {
                assert_eq!(
                    hmac.write(RvSize::Word, OFFSET_KEY + i as RvAddr, make_word(i, key))
                        .ok(),
                    Some(())
                );
            }
        } else {
            // Instruct key to be read from key-vault.
            let key_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(0);
            key_ctrl
                .modify(KeyReadControl::KEY_ID.val(key_id) + KeyReadControl::KEY_READ_EN.val(1));

            assert_eq!(
                hmac.write(RvSize::Word, OFFSET_KEY_CONTROL, key_ctrl.get())
                    .ok(),
                Some(())
            );

            // Wait for hmac periph to retrieve the key from key-vault.
            loop {
                let key_read_status = InMemoryRegister::<u32, KeyReadStatus::Register>::new(
                    hmac.read(RvSize::Word, OFFSET_KEY_STATUS).unwrap(),
                );

                if key_read_status.is_set(KeyReadStatus::VALID) {
                    if key_read_status.read(KeyReadStatus::ERROR)
                        != KeyReadStatus::ERROR::KV_SUCCESS.value
                    {
                        assert!((key_read_disallowed || key_disallowed_for_hmac));
                        return;
                    }
                    break;
                }
                clock.increment_and_process_timer_actions(1, &mut hmac);
            }
        }

        // Process each block via the HMAC engine.
        for idx in 0..totalblocks {
            if !block_via_kv {
                for i in (0..HMAC_BLOCK_SIZE).step_by(4) {
                    assert_eq!(
                        hmac.write(
                            RvSize::Word,
                            OFFSET_BLOCK + i as RvAddr,
                            make_word((idx * HMAC_BLOCK_SIZE) + i, &block_arr)
                        )
                        .ok(),
                        Some(())
                    );
                }
            } else {
                // There will always be a single block retrieved from key-vault for HMAC384.
                assert_eq!(totalblocks, 1);

                // Instruct block to be read from key-vault.
                let block_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(0);
                block_ctrl.modify(
                    KeyReadControl::KEY_ID.val(block_id) + KeyReadControl::KEY_READ_EN.val(1),
                );
                assert_eq!(
                    hmac.write(RvSize::Word, OFFSET_BLOCK_CONTROL, block_ctrl.get())
                        .ok(),
                    Some(())
                );

                // Wait for hmac periph to retrieve the block from the key-vault.
                loop {
                    let block_read_status = InMemoryRegister::<u32, KeyReadStatus::Register>::new(
                        hmac.read(RvSize::Word, OFFSET_BLOCK_STATUS).unwrap(),
                    );

                    if block_read_status.is_set(KeyReadStatus::VALID) {
                        if block_read_status.read(KeyReadStatus::ERROR)
                            != KeyReadStatus::ERROR::KV_SUCCESS.value
                        {
                            assert!((block_read_disallowed || block_disallowed_for_hmac));
                            return;
                        }

                        break;
                    }
                    clock.increment_and_process_timer_actions(1, &mut hmac);
                }
            }

            if idx == 0 {
                assert_eq!(
                    hmac.write(RvSize::Word, OFFSET_CONTROL, Control::INIT::SET.into())
                        .ok(),
                    Some(())
                );
            } else {
                assert_eq!(
                    hmac.write(RvSize::Word, OFFSET_CONTROL, Control::NEXT::SET.into())
                        .ok(),
                    Some(())
                );
            }

            loop {
                if !tag_to_kv {
                    let status = InMemoryRegister::<u32, Status::Register>::new(
                        hmac.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                    );

                    if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                        break;
                    }
                } else {
                    let tag_write_status = InMemoryRegister::<u32, TagWriteStatus::Register>::new(
                        hmac.read(RvSize::Word, OFFSET_TAG_STATUS).unwrap(),
                    );

                    if tag_write_status.is_set(TagWriteStatus::VALID) {
                        if tag_write_status.read(TagWriteStatus::ERROR)
                            != TagWriteStatus::ERROR::KV_SUCCESS.value
                        {
                            assert!(tag_write_fail_test);
                            return;
                        }
                        break;
                    }
                }

                clock.increment_and_process_timer_actions(1, &mut hmac);
            }
        }

        if tag_to_kv {
            let mut key_usage = KeyUsage::default();
            key_usage.set_hmac_data(true);
            tag_le.clone_from_slice(
                &hmac.key_vault.read_key(tag_id, key_usage).unwrap()[..HMAC_TAG_SIZE],
            );
        } else {
            tag_le.clone_from_slice(hmac.tag.data());
        }

        tag_le.to_little_endian();

        assert_eq!(tag_le, result);
    }

    #[test]
    fn test_hmac_sha384_1() {
        let mut key: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let data: [u8; 28] = [
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
            0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
        ];

        let result: [u8; 48] = [
            0x2c, 0x73, 0x53, 0x97, 0x4f, 0x18, 0x42, 0xfd, 0x66, 0xd5, 0x3c, 0x45, 0x2c, 0xa4,
            0x21, 0x22, 0xb2, 0x8c, 0x0b, 0x59, 0x4c, 0xfb, 0x18, 0x4d, 0xa8, 0x6a, 0x36, 0x8e,
            0x9b, 0x8e, 0x16, 0xf5, 0x34, 0x95, 0x24, 0xca, 0x4e, 0x82, 0x40, 0x0c, 0xbd, 0xe0,
            0x68, 0x6d, 0x40, 0x33, 0x71, 0xc9,
        ];

        let kv_actions: Vec<KeyVaultAction> = vec![];
        test_hmac(&mut key, &data, &result, &kv_actions);
    }

    #[test]
    fn test_hmac_sha384_2() {
        let mut key: [u8; 48] = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];

        let data: [u8; 8] = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65];

        let result: [u8; 48] = [
            0xb6, 0xa8, 0xd5, 0x63, 0x6f, 0x5c, 0x6a, 0x72, 0x24, 0xf9, 0x97, 0x7d, 0xcf, 0x7e,
            0xe6, 0xc7, 0xfb, 0x6d, 0x0c, 0x48, 0xcb, 0xde, 0xe9, 0x73, 0x7a, 0x95, 0x97, 0x96,
            0x48, 0x9b, 0xdd, 0xbc, 0x4c, 0x5d, 0xf6, 0x1d, 0x5b, 0x32, 0x97, 0xb4, 0xfb, 0x68,
            0xda, 0xb9, 0xf1, 0xb5, 0x82, 0xc2,
        ];

        test_hmac(&mut key, &data, &result, &[]);
    }

    #[test]
    fn test_hmac_sha384_multi_block() {
        let mut key: [u8; 48] = [
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        ];

        let data: [u8; 130] = [
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
            0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62,
            0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
            0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
            0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
            0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
            0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
            0x77, 0x78, 0x79, 0x7A,
        ];

        let result: [u8; 48] = [
            0x70, 0xF1, 0xF6, 0x3C, 0x8C, 0x0A, 0x0D, 0xFE, 0x09, 0x65, 0xE7, 0x3D, 0x79, 0x62,
            0x93, 0xFD, 0x6E, 0xCD, 0x56, 0x43, 0xB4, 0x20, 0x15, 0x46, 0x58, 0x7E, 0xBD, 0x46,
            0xCD, 0x07, 0xE3, 0xEA, 0xE2, 0x51, 0x4A, 0x61, 0xC1, 0x61, 0x44, 0x24, 0xE7, 0x71,
            0xCC, 0x4B, 0x7C, 0xCA, 0xC8, 0xC3,
        ];

        test_hmac(&mut key, &data, &result, &[]);
    }

    #[test]
    fn test_hmac_sha384_exact_single_block() {
        let key: [u8; 48] = [
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        ];

        let data: [u8; 112] = [
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
            0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62,
            0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
            0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
            0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
            0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        ];

        let result: [u8; 48] = [
            0xE3, 0x6F, 0xAF, 0x45, 0x0A, 0x8A, 0x13, 0x94, 0x71, 0x41, 0x56, 0xBF, 0x7B, 0xF0,
            0x48, 0xC5, 0x70, 0xB2, 0x57, 0x09, 0x5F, 0x17, 0xF3, 0xA4, 0x4D, 0xCF, 0xD2, 0xE4,
            0xD1, 0x2E, 0x85, 0x59, 0xBB, 0x42, 0x6C, 0xBF, 0x58, 0x1D, 0x31, 0x33, 0xC0, 0xE4,
            0xCE, 0x60, 0xA8, 0xFE, 0x93, 0xD1,
        ];

        test_hmac(&mut key.clone(), &data, &result, &[]);
    }

    #[test]
    fn test_hmac_sha384_kv_key_read() {
        let key: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let data: [u8; 28] = [
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
            0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
        ];

        let result: [u8; 48] = [
            0x2c, 0x73, 0x53, 0x97, 0x4f, 0x18, 0x42, 0xfd, 0x66, 0xd5, 0x3c, 0x45, 0x2c, 0xa4,
            0x21, 0x22, 0xb2, 0x8c, 0x0b, 0x59, 0x4c, 0xfb, 0x18, 0x4d, 0xa8, 0x6a, 0x36, 0x8e,
            0x9b, 0x8e, 0x16, 0xf5, 0x34, 0x95, 0x24, 0xca, 0x4e, 0x82, 0x40, 0x0c, 0xbd, 0xe0,
            0x68, 0x6d, 0x40, 0x33, 0x71, 0xc9,
        ];

        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[KeyVaultAction::KeyFromVault(key_id)],
            );
        }
    }

    #[test]
    fn test_hmac_sha384_kv_key_read_fail() {
        let key: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let data: [u8; 28] = [
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
            0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
        ];

        let result: [u8; 48] = [
            0x2c, 0x73, 0x53, 0x97, 0x4f, 0x18, 0x42, 0xfd, 0x66, 0xd5, 0x3c, 0x45, 0x2c, 0xa4,
            0x21, 0x22, 0xb2, 0x8c, 0x0b, 0x59, 0x4c, 0xfb, 0x18, 0x4d, 0xa8, 0x6a, 0x36, 0x8e,
            0x9b, 0x8e, 0x16, 0xf5, 0x34, 0x95, 0x24, 0xca, 0x4e, 0x82, 0x40, 0x0c, 0xbd, 0xe0,
            0x68, 0x6d, 0x40, 0x33, 0x71, 0xc9,
        ];

        // [Test] Key is read-protected.
        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[
                    KeyVaultAction::KeyFromVault(key_id),
                    KeyVaultAction::KeyReadDisallowed(true),
                ],
            );
        }

        // [Test] Key cannot be used as a HMAC384 key.
        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[
                    KeyVaultAction::KeyFromVault(key_id),
                    KeyVaultAction::KeyDisallowedForHMAC(true),
                ],
            );
        }
    }

    #[test]
    fn test_hmac_sha384_kv_block_read() {
        let key: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let data: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let result: [u8; 48] = [
            0x3d, 0x59, 0x72, 0x7a, 0x2b, 0x50, 0x28, 0xa7, 0x75, 0x79, 0xad, 0xe2, 0xd6, 0xe7,
            0x56, 0x18, 0x58, 0x72, 0xb2, 0x51, 0xeb, 0xc9, 0xe0, 0x00, 0x2e, 0x84, 0x0c, 0xc7,
            0x17, 0xb2, 0x39, 0xce, 0x09, 0x59, 0x9e, 0x78, 0x6c, 0x2f, 0x64, 0x79, 0x6f, 0xf9,
            0x5b, 0xc6, 0xec, 0xb6, 0xba, 0xa9,
        ];

        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[KeyVaultAction::BlockFromVault(key_id)],
            );
        }
    }

    #[test]
    fn test_hmac_sha384_kv_block_read_fail() {
        let key: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let data: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let result: [u8; 48] = [
            0x3d, 0x59, 0x72, 0x7a, 0x2b, 0x50, 0x28, 0xa7, 0x75, 0x79, 0xad, 0xe2, 0xd6, 0xe7,
            0x56, 0x18, 0x58, 0x72, 0xb2, 0x51, 0xeb, 0xc9, 0xe0, 0x00, 0x2e, 0x84, 0x0c, 0xc7,
            0x17, 0xb2, 0x39, 0xce, 0x09, 0x59, 0x9e, 0x78, 0x6c, 0x2f, 0x64, 0x79, 0x6f, 0xf9,
            0x5b, 0xc6, 0xec, 0xb6, 0xba, 0xa9,
        ];

        // [Test] Block is read-protected.
        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[
                    KeyVaultAction::BlockFromVault(key_id),
                    KeyVaultAction::BlockReadDisallowed(true),
                ],
            );
        }

        // [Test] Key cannot be used as a HMAC384 block.
        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[
                    KeyVaultAction::BlockFromVault(key_id),
                    KeyVaultAction::BlockDisallowedForHMAC(true),
                ],
            );
        }
    }

    #[test]
    fn test_hmac_sha384_kv_tag_write() {
        let key: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let data: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let result: [u8; 48] = [
            0x3d, 0x59, 0x72, 0x7a, 0x2b, 0x50, 0x28, 0xa7, 0x75, 0x79, 0xad, 0xe2, 0xd6, 0xe7,
            0x56, 0x18, 0x58, 0x72, 0xb2, 0x51, 0xeb, 0xc9, 0xe0, 0x00, 0x2e, 0x84, 0x0c, 0xc7,
            0x17, 0xb2, 0x39, 0xce, 0x09, 0x59, 0x9e, 0x78, 0x6c, 0x2f, 0x64, 0x79, 0x6f, 0xf9,
            0x5b, 0xc6, 0xec, 0xb6, 0xba, 0xa9,
        ];

        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[KeyVaultAction::TagToVault(key_id)],
            );
        }
    }

    #[test]
    fn test_hmac_sha384_kv_tag_write_fail() {
        let key: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let data: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let result: [u8; 48] = [
            0x3d, 0x59, 0x72, 0x7a, 0x2b, 0x50, 0x28, 0xa7, 0x75, 0x79, 0xad, 0xe2, 0xd6, 0xe7,
            0x56, 0x18, 0x58, 0x72, 0xb2, 0x51, 0xeb, 0xc9, 0xe0, 0x00, 0x2e, 0x84, 0x0c, 0xc7,
            0x17, 0xb2, 0x39, 0xce, 0x09, 0x59, 0x9e, 0x78, 0x6c, 0x2f, 0x64, 0x79, 0x6f, 0xf9,
            0x5b, 0xc6, 0xec, 0xb6, 0xba, 0xa9,
        ];

        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[
                    KeyVaultAction::TagToVault(key_id),
                    KeyVaultAction::TagWriteFailTest(true),
                ],
            );
        }
    }

    #[test]
    fn test_hmac_sha384_kv_key_read_block_read() {
        let key: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let data: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let result: [u8; 48] = [
            0x3d, 0x59, 0x72, 0x7a, 0x2b, 0x50, 0x28, 0xa7, 0x75, 0x79, 0xad, 0xe2, 0xd6, 0xe7,
            0x56, 0x18, 0x58, 0x72, 0xb2, 0x51, 0xeb, 0xc9, 0xe0, 0x00, 0x2e, 0x84, 0x0c, 0xc7,
            0x17, 0xb2, 0x39, 0xce, 0x09, 0x59, 0x9e, 0x78, 0x6c, 0x2f, 0x64, 0x79, 0x6f, 0xf9,
            0x5b, 0xc6, 0xec, 0xb6, 0xba, 0xa9,
        ];

        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[
                    KeyVaultAction::KeyFromVault(key_id),
                    KeyVaultAction::BlockFromVault((key_id + 1) % 8),
                ],
            );
        }
    }

    #[test]
    fn test_hmac_sha384_kv_key_read_block_read_tag_write() {
        let key: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let data: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];

        let result: [u8; 48] = [
            0x3d, 0x59, 0x72, 0x7a, 0x2b, 0x50, 0x28, 0xa7, 0x75, 0x79, 0xad, 0xe2, 0xd6, 0xe7,
            0x56, 0x18, 0x58, 0x72, 0xb2, 0x51, 0xeb, 0xc9, 0xe0, 0x00, 0x2e, 0x84, 0x0c, 0xc7,
            0x17, 0xb2, 0x39, 0xce, 0x09, 0x59, 0x9e, 0x78, 0x6c, 0x2f, 0x64, 0x79, 0x6f, 0xf9,
            0x5b, 0xc6, 0xec, 0xb6, 0xba, 0xa9,
        ];

        for key_id in 0..8 {
            test_hmac(
                &mut key.clone(),
                &data,
                &result,
                &[
                    KeyVaultAction::KeyFromVault(key_id),
                    KeyVaultAction::BlockFromVault((key_id + 1) % 8),
                    KeyVaultAction::TagToVault((key_id + 2) % 8),
                ],
            );
        }
    }
}
