/*++

Licensed under the Apache-2.0 license.

File Name:

    hash_sha512.rs

Abstract:

    File contains SHA512 peripheral implementation.

--*/

use crate::helpers::words_from_bytes_le;
use crate::key_vault::KeyUsage;
use crate::KeyVault;
use caliptra_emu_bus::{
    ActionHandle, BusError, Clock, ReadOnlyMemory, ReadOnlyRegister, ReadWriteRegister, Timer,
};
use caliptra_emu_crypto::EndianessTransform;
use caliptra_emu_crypto::{Sha512, Sha512Mode};
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
        MODE OFFSET(2) NUMBITS(2) [],
        ZEROIZE OFFSET(4) NUMBITS(1) [],
        LAST OFFSET(5) NUMBITS(1) [],
        RSVD OFFSET(6) NUMBITS(26) [],
    ],

    /// Status Register Fields
    Status[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
    ],

    /// Block Read Control Register Fields
    BlockReadControl[
        KEY_READ_EN OFFSET(0) NUMBITS(1) [],
        KEY_ID OFFSET(1) NUMBITS(5) [],
        PCR_HASH_EXTEND OFFSET(6) NUMBITS(1) [],
        RSVD OFFSET(7) NUMBITS(25) [],
    ],

    /// Block Read Status Register Fields
    BlockReadStatus[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        ERROR OFFSET(2) NUMBITS(8) [
            KV_SUCCESS = 0,
            KV_READ_FAIL = 1,
            KV_WRITE_FAIL= 2,
        ],
        RSVD OFFSET(10) NUMBITS(22) [],
    ],

    /// Hash Write Control Register Fields
    HashWriteControl[
        KEY_WRITE_EN OFFSET(0) NUMBITS(1) [],
        KEY_ID OFFSET(1) NUMBITS(5) [],
        USAGE OFFSET(6) NUMBITS(6) [],
        RSVD OFFSET(12) NUMBITS(20) [],
    ],

    /// Hash Write Status Register Fields
    HashWriteStatus[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        ERROR OFFSET(2) NUMBITS(8) [
            KV_SUCCESS = 0,
            KV_READ_FAIL = 1,
            KV_WRITE_FAIL= 2,
        ],
    ],
];

const SHA512_BLOCK_SIZE: usize = 128;
const SHA512_BLOCK_SIZE_WORDS: usize = 128 >> 2;

const SHA512_HASH_SIZE: usize = 64;

/// The number of CPU clock cycles it takes to perform initialization action.
const INIT_TICKS: u64 = 1000;

/// The number of CPU clock cycles it takes to perform the hash update action.
const UPDATE_TICKS: u64 = 1000;

/// The number of CPU clock cycles read and write keys from key vault
const KEY_RW_TICKS: u64 = 100;

fn sha512_block_words_from_bytes_le(
    arr: &[u8; SHA512_BLOCK_SIZE],
) -> [u32; SHA512_BLOCK_SIZE_WORDS] {
    let mut result = [0u32; SHA512_BLOCK_SIZE_WORDS];
    for i in 0..result.len() {
        result[i] = u32::from_le_bytes(arr[i * 4..][..4].try_into().unwrap())
    }
    result
}
fn sha512_block_bytes_from_words_le(
    arr: &[u32; SHA512_BLOCK_SIZE_WORDS],
) -> [u8; SHA512_BLOCK_SIZE] {
    let mut result = [0u8; SHA512_BLOCK_SIZE];
    for i in 0..arr.len() {
        result[i * 4..][..4].copy_from_slice(&arr[i].to_le_bytes());
    }
    result
}

/// SHA-512 Peripheral
#[derive(Bus)]
#[poll_fn(poll)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
pub struct HashSha512 {
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

    /// SHA512 Block Memory
    #[register_array(offset = 0x0000_0080, write_fn = write_block)]
    block: [u32; SHA512_BLOCK_SIZE_WORDS],

    /// SHA512 Hash Memory
    #[peripheral(offset = 0x0000_0100, mask = 0x0000_00ff)]
    hash: ReadOnlyMemory<SHA512_HASH_SIZE>,

    /// Block Read Control register
    #[register(offset = 0x0000_0600, write_fn = on_write_block_read_control)]
    block_read_ctrl: ReadWriteRegister<u32, BlockReadControl::Register>,

    /// Block Read Status register
    #[register(offset = 0x0000_0604)]
    block_read_status: ReadOnlyRegister<u32, BlockReadStatus::Register>,

    /// Hash Write Control register
    #[register(offset = 0x0000_0608, write_fn = on_write_hash_write_control)]
    hash_write_ctrl: ReadWriteRegister<u32, HashWriteControl::Register>,

    /// Hash Write Status register
    #[register(offset = 0x0000_060c)]
    hash_write_status: ReadOnlyRegister<u32, HashWriteStatus::Register>,

    /// SHA512 engine
    sha512: Sha512,

    /// Key Vault
    key_vault: KeyVault,

    timer: Timer,

    /// Operation complete action
    op_complete_action: Option<ActionHandle>,

    /// Block read complete action
    op_block_read_complete_action: Option<ActionHandle>,

    /// Hash write complete action
    op_hash_write_complete_action: Option<ActionHandle>,
}

impl HashSha512 {
    /// NAME0 Register Value
    const NAME0_VAL: RvData = 0x323135; // 512

    /// NAME1 Register Value
    const NAME1_VAL: RvData = 0x32616873; // sha2

    /// VERSION0 Register Value
    const VERSION0_VAL: RvData = 0x30302E31; // 1.0

    /// VERSION1 Register Value
    const VERSION1_VAL: RvData = 0x00000000;

    /// Create a new instance of SHA-512 Engine
    pub fn new(clock: &Clock, key_vault: KeyVault) -> Self {
        Self {
            sha512: Sha512::new(Sha512Mode::Sha512), // Default SHA512 mode
            name0: ReadOnlyRegister::new(Self::NAME0_VAL),
            name1: ReadOnlyRegister::new(Self::NAME1_VAL),
            version0: ReadOnlyRegister::new(Self::VERSION0_VAL),
            version1: ReadOnlyRegister::new(Self::VERSION1_VAL),
            control: ReadWriteRegister::new(0),
            status: ReadOnlyRegister::new(Status::READY::SET.value),
            block_read_ctrl: ReadWriteRegister::new(0),
            block_read_status: ReadOnlyRegister::new(BlockReadStatus::READY::SET.value),
            hash_write_ctrl: ReadWriteRegister::new(0),
            hash_write_status: ReadOnlyRegister::new(HashWriteStatus::READY::SET.value),
            block: Default::default(),
            hash: ReadOnlyMemory::new(),
            key_vault,
            timer: Timer::new(clock),
            op_complete_action: None,
            op_block_read_complete_action: None,
            op_hash_write_complete_action: None,
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

        if self.control.reg.is_set(Control::INIT) || self.control.reg.is_set(Control::NEXT) {
            // Reset the Ready and Valid status bits
            self.status
                .reg
                .modify(Status::READY::CLEAR + Status::VALID::CLEAR);

            if self.control.reg.is_set(Control::INIT) {
                // Initialize the SHA512 engine with the mode.
                let mut mode = Sha512Mode::Sha512;
                let modebits = self.control.reg.read(Control::MODE);

                match modebits {
                    0 => {
                        mode = Sha512Mode::Sha224;
                    }
                    1 => {
                        mode = Sha512Mode::Sha256;
                    }
                    2 => {
                        mode = Sha512Mode::Sha384;
                    }
                    3 => {
                        mode = Sha512Mode::Sha512;
                    }
                    _ => Err(BusError::StoreAccessFault)?,
                }

                self.sha512.reset(mode);

                // Update the SHA512 engine with a new block
                self.sha512
                    .update(&sha512_block_bytes_from_words_le(&self.block));

                // Schedule a future call to poll() complete the operation.
                self.op_complete_action = Some(self.timer.schedule_poll_in(INIT_TICKS));
            } else if self.control.reg.is_set(Control::NEXT) {
                // Update the SHA512 engine with a new block
                self.sha512
                    .update(&sha512_block_bytes_from_words_le(&self.block));

                // Schedule a future call to poll() complete the operation.
                self.op_complete_action = Some(self.timer.schedule_poll_in(UPDATE_TICKS));
            }
        }

        if self.control.reg.is_set(Control::ZEROIZE) {
            self.zeroize();
        }

        Ok(())
    }

    /// On Write callback for `block` registers
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    fn write_block(&mut self, _size: RvSize, word_index: usize, val: u32) -> Result<(), BusError> {
        let pcr_hash_extend = self
            .block_read_ctrl
            .reg
            .read(BlockReadControl::PCR_HASH_EXTEND);

        // If PCR_HASH_EXTEND bit is set, skip updating the first 48 bytes in the block registers
        // as these contain the PCR retrieved from the PCR vault.
        if pcr_hash_extend == 0 || word_index >= 12 {
            self.block[word_index] = val;
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

        // Set the block read control register.
        let block_read_ctrl = InMemoryRegister::<u32, BlockReadControl::Register>::new(val);

        self.block_read_ctrl.reg.modify(
            BlockReadControl::KEY_READ_EN.val(block_read_ctrl.read(BlockReadControl::KEY_READ_EN))
                + BlockReadControl::KEY_ID.val(block_read_ctrl.read(BlockReadControl::KEY_ID))
                + BlockReadControl::PCR_HASH_EXTEND
                    .val(block_read_ctrl.read(BlockReadControl::PCR_HASH_EXTEND)),
        );

        if block_read_ctrl.is_set(BlockReadControl::KEY_READ_EN) {
            self.block_read_status.reg.modify(
                BlockReadStatus::READY::CLEAR
                    + BlockReadStatus::VALID::CLEAR
                    + BlockReadStatus::ERROR::CLEAR,
            );

            self.op_block_read_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        Ok(())
    }

    /// On Write callback for `hash_write_control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_hash_write_control(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the hash control register
        let hash_write_ctrl = InMemoryRegister::<u32, HashWriteControl::Register>::new(val);

        self.hash_write_ctrl.reg.modify(
            HashWriteControl::KEY_WRITE_EN
                .val(hash_write_ctrl.read(HashWriteControl::KEY_WRITE_EN))
                + HashWriteControl::KEY_ID.val(hash_write_ctrl.read(HashWriteControl::KEY_ID))
                + HashWriteControl::USAGE.val(hash_write_ctrl.read(HashWriteControl::USAGE)),
        );

        Ok(())
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
        } else if self.timer.fired(&mut self.op_block_read_complete_action) {
            self.block_read_complete();
        } else if self.timer.fired(&mut self.op_hash_write_complete_action) {
            self.hash_write_complete();
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
        // Retrieve the hash
        self.sha512.copy_hash(self.hash.data_mut());

        // Check if hash write control is enabled.
        if self
            .hash_write_ctrl
            .reg
            .is_set(HashWriteControl::KEY_WRITE_EN)
        {
            self.hash_write_status.reg.modify(
                HashWriteStatus::VALID::CLEAR
                    + HashWriteStatus::READY::CLEAR
                    + HashWriteStatus::ERROR::CLEAR,
            );

            self.op_hash_write_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        } else if self.control.reg.is_set(Control::LAST) {
            let pcr_id = self.block_read_ctrl.reg.read(BlockReadControl::KEY_ID);
            self.key_vault
                .write_pcr(pcr_id, array_ref![self.hash.data(), 0, KeyVault::KEY_SIZE])
                .unwrap();
        }

        // Update Ready and Valid status bits
        self.status
            .reg
            .modify(Status::READY::SET + Status::VALID::SET);

        // Reset the pcr_hash_extend bit. This is done so the next round
        // of block copy operation does not skip the first 48 bytes.
        self.block_read_ctrl
            .reg
            .modify(BlockReadControl::PCR_HASH_EXTEND::CLEAR);
    }

    fn block_read_complete(&mut self) {
        let key_id = self.block_read_ctrl.reg.read(BlockReadControl::KEY_ID);
        let pcr_hash_extend = self
            .block_read_ctrl
            .reg
            .read(BlockReadControl::PCR_HASH_EXTEND);

        // Clear the block
        self.block.fill(0);

        let result: Result<[u8; KeyVault::KEY_SIZE], BusError> = if pcr_hash_extend == 0 {
            let mut key_usage = KeyUsage::default();
            key_usage.set_sha_data(true);
            self.key_vault.read_key(key_id, key_usage)
        } else {
            Ok(self.key_vault.read_pcr(key_id))
        };
        let (block_read_result, data) = match result.err() {
            Some(BusError::LoadAccessFault)
            | Some(BusError::LoadAddrMisaligned)
            | Some(BusError::InstrAccessFault) => {
                (BlockReadStatus::ERROR::KV_READ_FAIL.value, None)
            }
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                (BlockReadStatus::ERROR::KV_WRITE_FAIL.value, None)
            }
            None => (BlockReadStatus::ERROR::KV_SUCCESS.value, result.ok()),
        };

        if let Some(data) = data {
            if pcr_hash_extend != 0 {
                // Copy the PCR (48 bytes) to the block registers.
                self.block[..KeyVault::KEY_SIZE / 4].copy_from_slice(&words_from_bytes_le(
                    &<[u8; KeyVault::KEY_SIZE]>::try_from(&data[..KeyVault::KEY_SIZE]).unwrap(),
                ));
            } else {
                self.format_block(&data);
            }
        }

        self.block_read_status.reg.modify(
            BlockReadStatus::VALID::SET
                + BlockReadStatus::READY::SET
                + BlockReadStatus::ERROR.val(block_read_result),
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
        let mut block_arr = [0u8; SHA512_BLOCK_SIZE];

        block_arr[..data.len()].copy_from_slice(&data[..data.len()]);
        block_arr.to_little_endian();

        // Add block padding.
        block_arr[data.len()] = 0b1000_0000;

        // Add block length.
        let len = (data.len() as u128) * 8;
        block_arr[SHA512_BLOCK_SIZE - 16..].copy_from_slice(&len.to_be_bytes());

        block_arr.to_big_endian();
        self.block = sha512_block_words_from_bytes_le(&block_arr[..].try_into().unwrap());
    }

    fn hash_write_complete(&mut self) {
        let key_id = self.hash_write_ctrl.reg.read(HashWriteControl::KEY_ID);
        // Store the key config and the key in the key-vault.
        let hash_write_result = match self
            .key_vault
            .write_key(
                key_id,
                array_ref![self.hash.data(), 0, KeyVault::KEY_SIZE],
                self.hash_write_ctrl.reg.read(HashWriteControl::USAGE),
            )
            .err()
        {
            Some(BusError::LoadAccessFault)
            | Some(BusError::LoadAddrMisaligned)
            | Some(BusError::InstrAccessFault) => HashWriteStatus::ERROR::KV_READ_FAIL.value,
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                HashWriteStatus::ERROR::KV_WRITE_FAIL.value
            }
            None => HashWriteStatus::ERROR::KV_SUCCESS.value,
        };

        self.hash_write_status.reg.modify(
            HashWriteStatus::READY::SET
                + HashWriteStatus::VALID::SET
                + HashWriteStatus::ERROR.val(hash_write_result),
        );
    }

    pub fn hash(&self) -> &[u8] {
        &self.hash.data()[..self.sha512.hash_len()]
    }

    fn zeroize(&mut self) {
        self.block.as_mut().fill(0);
        self.hash.data_mut().fill(0);
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
    const OFFSET_BLOCK: RvAddr = 0x80;
    const OFFSET_HASH: RvAddr = 0x100;

    const OFFSET_BLOCK_CONTROL: RvAddr = 0x600;
    const OFFSET_BLOCK_STATUS: RvAddr = 0x604;
    const OFFSET_HASH_CONTROL: RvAddr = 0x608;
    const OFFSET_HASH_STATUS: RvAddr = 0x60c;

    const SHA384_HASH_SIZE: usize = 48;

    #[test]
    fn test_name_read() {
        let mut sha512 = HashSha512::new(&Clock::new(), KeyVault::new());

        let name0 = sha512.read(RvSize::Word, OFFSET_NAME0).unwrap();
        let mut name0 = String::from_utf8_lossy(&name0.to_le_bytes()).to_string();
        name0.pop();
        assert_eq!(name0, "512");

        let name1 = sha512.read(RvSize::Word, OFFSET_NAME1).unwrap();
        let name1 = String::from_utf8_lossy(&name1.to_le_bytes()).to_string();
        assert_eq!(name1, "sha2");
    }

    #[test]
    fn test_version_read() {
        let mut sha512 = HashSha512::new(&Clock::new(), KeyVault::new());

        let version0 = sha512.read(RvSize::Word, OFFSET_VERSION0).unwrap();
        let version0 = String::from_utf8_lossy(&version0.to_le_bytes()).to_string();
        assert_eq!(version0, "1.00");

        let version1 = sha512.read(RvSize::Word, OFFSET_VERSION1).unwrap();
        let version1 = String::from_utf8_lossy(&version1.to_le_bytes()).to_string();
        assert_eq!(version1, "\0\0\0\0");
    }

    #[test]
    fn test_control_read() {
        let mut sha512 = HashSha512::new(&Clock::new(), KeyVault::new());
        assert_eq!(sha512.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status_read() {
        let mut sha512 = HashSha512::new(&Clock::new(), KeyVault::new());
        assert_eq!(sha512.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_block_read_write() {
        let mut sha512 = HashSha512::new(&Clock::new(), KeyVault::new());
        for addr in (OFFSET_BLOCK..(OFFSET_BLOCK + SHA512_BLOCK_SIZE as u32)).step_by(4) {
            assert_eq!(sha512.write(RvSize::Word, addr, u32::MAX).ok(), Some(()));
            assert_eq!(sha512.read(RvSize::Word, addr).ok(), Some(u32::MAX));
        }
    }

    #[test]
    fn test_hash_read_write() {
        let mut sha512 = HashSha512::new(&Clock::new(), KeyVault::new());
        for addr in (OFFSET_HASH..(OFFSET_HASH + SHA512_HASH_SIZE as u32)).step_by(4) {
            assert_eq!(sha512.read(RvSize::Word, addr).ok(), Some(0));
            assert_eq!(
                sha512.write(RvSize::Word, addr, 0xFF).err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }

    enum KeyVaultAction {
        BlockFromVault(u32),
        HashToVault(u32),
        BlockReadDisallowed(bool),
        BlockDisallowedForSHA(bool),
        HashWriteFailTest(bool),
    }

    fn make_word(idx: usize, arr: &[u8]) -> RvData {
        let mut res: RvData = 0;
        for i in 0..4 {
            res |= (arr[idx + i] as RvData) << (i * 8);
        }
        res
    }

    fn test_sha(
        data: &[u8],
        expected: &[u8],
        mode: Sha512Mode,
        keyvault_actions: &[KeyVaultAction],
    ) {
        let mut block_via_kv: bool = false;
        let mut block_id: u32 = u32::MAX;
        let mut hash_to_kv: bool = false;
        let mut hash_id: u32 = u32::MAX;
        // Compute the total bytes and total blocks required for the final message.
        let totalblocks = ((data.len() + 16) + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE;
        let totalbytes = totalblocks * SHA512_BLOCK_SIZE;
        let mut block_arr = vec![0; totalbytes];
        let mut block_read_disallowed = false;
        let mut hash_write_fail_test = false;
        let mut block_disallowed_for_sha = false;

        for (_idx, action) in keyvault_actions.iter().enumerate() {
            match action {
                KeyVaultAction::BlockFromVault(id) => {
                    block_via_kv = true;
                    block_id = *id;
                }
                KeyVaultAction::HashToVault(id) => {
                    hash_to_kv = true;
                    hash_id = *id;
                }
                KeyVaultAction::BlockReadDisallowed(val) => {
                    block_read_disallowed = *val;
                }
                KeyVaultAction::HashWriteFailTest(val) => {
                    hash_write_fail_test = *val;
                }
                KeyVaultAction::BlockDisallowedForSHA(val) => {
                    block_disallowed_for_sha = *val;
                }
            }
        }

        if block_via_kv {
            assert!(data.len() % 4 == 0);
            assert!(data.len() <= (SHA512_BLOCK_SIZE - (16 + 1)));
        } else {
            block_arr[..data.len()].copy_from_slice(data);
            block_arr[data.len()] = 1 << 7;

            let len: u128 = data.len() as u128;
            let len = len * 8;

            block_arr[totalbytes - 16..].copy_from_slice(&len.to_be_bytes());
            block_arr.to_big_endian();
        }

        let clock = Clock::new();
        let mut key_vault = KeyVault::new();

        // Add the test block to the key-vault.
        if block_via_kv {
            let mut block: [u8; KeyVault::KEY_SIZE] = [0; KeyVault::KEY_SIZE];
            block[..data.len()].copy_from_slice(data);
            block.to_big_endian(); // Keys are stored in big-endian format.
            let mut key_usage = KeyUsage::default();
            key_usage.set_sha_data(true);

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
            } else if block_disallowed_for_sha {
                let val_reg = InMemoryRegister::<u32, key_vault::KV_CONTROL::Register>::new(0);
                val_reg.write(key_vault::KV_CONTROL::USAGE.val(!(u32::from(key_usage)))); // Block disallowed for SHA use.
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

        // For negative hash write test, make the key-slot uneditable.
        if hash_write_fail_test {
            assert!(hash_to_kv);
            let val_reg = InMemoryRegister::<u32, key_vault::KV_CONTROL::Register>::new(0);
            val_reg.write(key_vault::KV_CONTROL::WRITE_LOCK.val(1)); // Key write disabled.
            assert_eq!(
                key_vault
                    .write(
                        RvSize::Word,
                        KeyVault::KEY_CONTROL_REG_OFFSET
                            + (hash_id * KeyVault::KEY_CONTROL_REG_WIDTH),
                        val_reg.get()
                    )
                    .ok(),
                Some(())
            );
        }

        let mut sha512 = HashSha512::new(&clock, key_vault);

        if hash_to_kv {
            // Instruct hash to be written to the key-vault.
            let mut key_usage = KeyUsage::default();
            key_usage.set_sha_data(true);
            let hash_ctrl = InMemoryRegister::<u32, HashWriteControl::Register>::new(0);
            hash_ctrl.modify(
                HashWriteControl::KEY_ID.val(hash_id)
                    + HashWriteControl::KEY_WRITE_EN.val(1)
                    + HashWriteControl::USAGE.val(u32::from(key_usage)),
            );

            assert_eq!(
                sha512
                    .write(RvSize::Word, OFFSET_HASH_CONTROL, hash_ctrl.get())
                    .ok(),
                Some(())
            );
        }

        // Process each block via the SHA engine.
        for idx in 0..totalblocks {
            if !block_via_kv {
                for i in (0..SHA512_BLOCK_SIZE).step_by(4) {
                    assert_eq!(
                        sha512
                            .write(
                                RvSize::Word,
                                OFFSET_BLOCK + i as RvAddr,
                                make_word((idx * SHA512_BLOCK_SIZE) + i, &block_arr)
                            )
                            .ok(),
                        Some(())
                    );
                }
            } else {
                // There will always be a single block retrieved from the key-vault for sha512.
                assert_eq!(totalblocks, 1);

                // Instruct block to be read from key-vault.
                let block_ctrl = InMemoryRegister::<u32, BlockReadControl::Register>::new(0);
                block_ctrl.modify(
                    BlockReadControl::KEY_ID.val(block_id) + BlockReadControl::KEY_READ_EN.val(1),
                );
                assert_eq!(
                    sha512
                        .write(RvSize::Word, OFFSET_BLOCK_CONTROL, block_ctrl.get())
                        .ok(),
                    Some(())
                );

                // Wait for sha512 periph to retrieve the block from the key-vault.
                loop {
                    let block_read_status = InMemoryRegister::<u32, BlockReadStatus::Register>::new(
                        sha512.read(RvSize::Word, OFFSET_BLOCK_STATUS).unwrap(),
                    );

                    if block_read_status.is_set(BlockReadStatus::VALID) {
                        // Check if "block read from kv" failure is expected.
                        if block_read_status.read(BlockReadStatus::ERROR)
                            != BlockReadStatus::ERROR::KV_SUCCESS.value
                        {
                            assert!((block_read_disallowed || block_disallowed_for_sha));
                            return;
                        }

                        break;
                    }
                    clock.increment_and_process_timer_actions(1, &mut sha512);
                }
            }

            if idx == 0 {
                let modebits = match mode {
                    Sha512Mode::Sha224 => 0,
                    Sha512Mode::Sha256 => 1,
                    Sha512Mode::Sha384 => 2,
                    Sha512Mode::Sha512 => 3,
                };

                let control: ReadWriteRegister<u32, Control::Register> = ReadWriteRegister::new(0);
                control.reg.modify(Control::MODE.val(modebits));
                control.reg.modify(Control::INIT::SET);

                assert_eq!(
                    sha512
                        .write(RvSize::Word, OFFSET_CONTROL, control.reg.get())
                        .ok(),
                    Some(())
                );
            } else {
                assert_eq!(
                    sha512
                        .write(RvSize::Word, OFFSET_CONTROL, Control::NEXT::SET.into())
                        .ok(),
                    Some(())
                );
            }

            loop {
                if !hash_to_kv {
                    let status = InMemoryRegister::<u32, Status::Register>::new(
                        sha512.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                    );

                    if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                        break;
                    }
                } else {
                    let hash_write_status = InMemoryRegister::<u32, HashWriteStatus::Register>::new(
                        sha512.read(RvSize::Word, OFFSET_HASH_STATUS).unwrap(),
                    );

                    if hash_write_status.is_set(HashWriteStatus::VALID) {
                        // Check if "hash write to kv" failure is expected.
                        if hash_write_status.read(HashWriteStatus::ERROR)
                            != HashWriteStatus::ERROR::KV_SUCCESS.value
                        {
                            assert!(hash_write_fail_test);
                            return;
                        }
                        break;
                    }
                }

                clock.increment_and_process_timer_actions(1, &mut sha512);
            }
        }

        let mut hash_le: [u8; SHA512_HASH_SIZE] = [0; SHA512_HASH_SIZE];
        if hash_to_kv {
            let mut key_usage = KeyUsage::default();
            key_usage.set_sha_data(true);
            hash_le[..KeyVault::KEY_SIZE]
                .copy_from_slice(&sha512.key_vault.read_key(hash_id, key_usage).unwrap()[..]);
        } else {
            hash_le[..sha512.hash().len()].clone_from_slice(sha512.hash());
        }
        hash_le.to_little_endian();
        assert_eq!(&hash_le[0..sha512.hash().len()], expected);
    }

    const SHA_512_TEST_BLOCK: [u8; 3] = [0x61, 0x62, 0x63];

    #[test]
    fn test_sha512() {
        let expected: [u8; SHA512_HASH_SIZE] = [
            0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20,
            0x41, 0x31, 0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2, 0x0A, 0x9E, 0xEE, 0xE6,
            0x4B, 0x55, 0xD3, 0x9A, 0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA,
            0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD, 0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
            0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
        ];

        test_sha(&SHA_512_TEST_BLOCK, &expected, Sha512Mode::Sha512, &[]);
    }

    #[test]
    fn test_sha512_multi_block() {
        const SHA_512_TEST_MULTI_BLOCK: [u8; 130] = [
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

        let expected: [u8; SHA512_HASH_SIZE] = [
            0xF5, 0x9F, 0x92, 0x3E, 0x98, 0xF9, 0x23, 0x19, 0x28, 0x53, 0xB6, 0xA5, 0xA0, 0x3F,
            0x58, 0xBB, 0x6A, 0x86, 0xF9, 0xB8, 0x43, 0xC4, 0x35, 0x2B, 0x4D, 0x71, 0xC2, 0x92,
            0x1B, 0x90, 0x59, 0x39, 0x66, 0xAD, 0x9E, 0xF4, 0xBE, 0xA6, 0x50, 0xDB, 0xB4, 0xEB,
            0xE2, 0x17, 0x0B, 0x80, 0x7E, 0xA1, 0xAB, 0xB6, 0xF3, 0xCF, 0x54, 0x90, 0x81, 0xFF,
            0xB9, 0x81, 0xC2, 0xC2, 0x3F, 0x88, 0x6D, 0x07,
        ];

        test_sha(
            &SHA_512_TEST_MULTI_BLOCK,
            &expected,
            Sha512Mode::Sha512,
            &[],
        );
    }

    #[test]
    fn test_sha384() {
        let expected: [u8; SHA384_HASH_SIZE] = [
            0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6,
            0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A,
            0x43, 0xFF, 0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA,
            0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
        ];

        test_sha(&SHA_512_TEST_BLOCK, &expected, Sha512Mode::Sha384, &[]);
    }

    #[test]
    fn test_sha512_224() {
        let expected: [u8; 28] = [
            0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54, 0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08,
            0x42, 0xE2, 0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4, 0x3E, 0x89, 0x24, 0xAA,
        ];

        test_sha(&SHA_512_TEST_BLOCK, &expected, Sha512Mode::Sha224, &[]);
    }

    #[test]
    fn test_sha512_256() {
        let expected: [u8; 32] = [
            0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9, 0x9B, 0x2E, 0x29, 0xB7, 0x6B, 0x4C,
            0x7D, 0xAB, 0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC, 0x6D, 0x46, 0xE0, 0xE2, 0xF1, 0x31,
            0x07, 0xE7, 0xAF, 0x23,
        ];

        test_sha(&SHA_512_TEST_BLOCK, &expected, Sha512Mode::Sha256, &[]);
    }

    #[test]
    fn test_sha384_kv_block_read() {
        let test_block: [u8; KeyVault::KEY_SIZE] = [
            0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb,
            0xaa, 0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29,
            0xbd, 0xb6, 0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7,
            0xa3, 0x59, 0x14, 0xfc, 0x1e, 0xcd,
        ];

        let expected: [u8; SHA384_HASH_SIZE] = [
            0x4a, 0x8a, 0x78, 0xb1, 0xa0, 0xa, 0x13, 0x33, 0xfc, 0x92, 0x32, 0x2f, 0xad, 0xd2,
            0x47, 0x47, 0xf2, 0xcd, 0x2f, 0x1, 0x8e, 0xff, 0xa3, 0x61, 0xff, 0x13, 0x33, 0x10,
            0x5b, 0x86, 0x6a, 0xc9, 0x39, 0xea, 0xd2, 0x67, 0x2b, 0xdb, 0xba, 0x4e, 0x18, 0x1c,
            0xb3, 0x4f, 0xb7, 0xeb, 0xa4, 0xf6,
        ];

        for key_id in 0..KeyVault::KEY_COUNT {
            test_sha(
                &test_block,
                &expected,
                Sha512Mode::Sha384,
                &[KeyVaultAction::BlockFromVault(key_id)],
            );
        }
    }

    #[test]
    fn test_sha384_kv_block_read_fail() {
        let test_block: [u8; KeyVault::KEY_SIZE] = [
            0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb,
            0xaa, 0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29,
            0xbd, 0xb6, 0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7,
            0xa3, 0x59, 0x14, 0xfc, 0x1e, 0xcd,
        ];

        let expected: [u8; SHA384_HASH_SIZE] = [
            0x4a, 0x8a, 0x78, 0xb1, 0xa0, 0xa, 0x13, 0x33, 0xfc, 0x92, 0x32, 0x2f, 0xad, 0xd2,
            0x47, 0x47, 0xf2, 0xcd, 0x2f, 0x1, 0x8e, 0xff, 0xa3, 0x61, 0xff, 0x13, 0x33, 0x10,
            0x5b, 0x86, 0x6a, 0xc9, 0x39, 0xea, 0xd2, 0x67, 0x2b, 0xdb, 0xba, 0x4e, 0x18, 0x1c,
            0xb3, 0x4f, 0xb7, 0xeb, 0xa4, 0xf6,
        ];

        // [Test] Block is read-protected.
        for key_id in 0..KeyVault::KEY_COUNT {
            test_sha(
                &test_block,
                &expected,
                Sha512Mode::Sha384,
                &[
                    KeyVaultAction::BlockFromVault(key_id),
                    KeyVaultAction::BlockReadDisallowed(true),
                ],
            );
        }

        // [Test] Key cannot be used as a SHA block.
        for key_id in 0..KeyVault::KEY_COUNT {
            test_sha(
                &test_block,
                &expected,
                Sha512Mode::Sha384,
                &[
                    KeyVaultAction::BlockFromVault(key_id),
                    KeyVaultAction::BlockDisallowedForSHA(true),
                ],
            );
        }
    }

    #[test]
    fn test_sha384_kv_hash_write() {
        let test_block: [u8; KeyVault::KEY_SIZE] = [
            0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb,
            0xaa, 0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29,
            0xbd, 0xb6, 0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7,
            0xa3, 0x59, 0x14, 0xfc, 0x1e, 0xcd,
        ];

        let expected: [u8; SHA384_HASH_SIZE] = [
            0x4a, 0x8a, 0x78, 0xb1, 0xa0, 0xa, 0x13, 0x33, 0xfc, 0x92, 0x32, 0x2f, 0xad, 0xd2,
            0x47, 0x47, 0xf2, 0xcd, 0x2f, 0x1, 0x8e, 0xff, 0xa3, 0x61, 0xff, 0x13, 0x33, 0x10,
            0x5b, 0x86, 0x6a, 0xc9, 0x39, 0xea, 0xd2, 0x67, 0x2b, 0xdb, 0xba, 0x4e, 0x18, 0x1c,
            0xb3, 0x4f, 0xb7, 0xeb, 0xa4, 0xf6,
        ];

        for key_id in 0..8 {
            test_sha(
                &test_block,
                &expected,
                Sha512Mode::Sha384,
                &[KeyVaultAction::HashToVault(key_id)],
            );
        }
    }

    #[test]
    fn test_sha384_kv_hash_write_fail() {
        let test_block: [u8; KeyVault::KEY_SIZE] = [
            0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb,
            0xaa, 0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29,
            0xbd, 0xb6, 0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7,
            0xa3, 0x59, 0x14, 0xfc, 0x1e, 0xcd,
        ];

        let expected: [u8; SHA384_HASH_SIZE] = [
            0x4a, 0x8a, 0x78, 0xb1, 0xa0, 0xa, 0x13, 0x33, 0xfc, 0x92, 0x32, 0x2f, 0xad, 0xd2,
            0x47, 0x47, 0xf2, 0xcd, 0x2f, 0x1, 0x8e, 0xff, 0xa3, 0x61, 0xff, 0x13, 0x33, 0x10,
            0x5b, 0x86, 0x6a, 0xc9, 0x39, 0xea, 0xd2, 0x67, 0x2b, 0xdb, 0xba, 0x4e, 0x18, 0x1c,
            0xb3, 0x4f, 0xb7, 0xeb, 0xa4, 0xf6,
        ];

        for key_id in 0..KeyVault::KEY_COUNT {
            test_sha(
                &test_block,
                &expected,
                Sha512Mode::Sha384,
                &[
                    KeyVaultAction::HashToVault(key_id),
                    KeyVaultAction::HashWriteFailTest(true),
                ],
            );
        }
    }

    #[test]
    fn test_sha384_kv_block_read_hash_write() {
        let test_block: [u8; KeyVault::KEY_SIZE] = [
            0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb,
            0xaa, 0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29,
            0xbd, 0xb6, 0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7,
            0xa3, 0x59, 0x14, 0xfc, 0x1e, 0xcd,
        ];

        let expected: [u8; SHA384_HASH_SIZE] = [
            0x4a, 0x8a, 0x78, 0xb1, 0xa0, 0xa, 0x13, 0x33, 0xfc, 0x92, 0x32, 0x2f, 0xad, 0xd2,
            0x47, 0x47, 0xf2, 0xcd, 0x2f, 0x1, 0x8e, 0xff, 0xa3, 0x61, 0xff, 0x13, 0x33, 0x10,
            0x5b, 0x86, 0x6a, 0xc9, 0x39, 0xea, 0xd2, 0x67, 0x2b, 0xdb, 0xba, 0x4e, 0x18, 0x1c,
            0xb3, 0x4f, 0xb7, 0xeb, 0xa4, 0xf6,
        ];

        for key_id in 0..KeyVault::KEY_COUNT {
            test_sha(
                &test_block,
                &expected,
                Sha512Mode::Sha384,
                &[
                    KeyVaultAction::BlockFromVault(key_id),
                    KeyVaultAction::HashToVault((key_id + 1) % KeyVault::KEY_COUNT),
                ],
            );
        }
    }

    fn test_pcr_hash_extend(data: &[u8], pcr_data: &mut [u8; KeyVault::KEY_SIZE], expected: &[u8]) {
        // Prime the PCR vault.
        let clock = Clock::new();
        let pcr_id = 0;
        let mut key_vault = KeyVault::new();
        pcr_data.change_endianess();
        assert!(key_vault.write_pcr(pcr_id, pcr_data).is_ok());
        pcr_data.change_endianess();

        let mut sha512 = HashSha512::new(&clock, key_vault);
        // Enable pcr hash extend.
        let block_ctrl = InMemoryRegister::<u32, BlockReadControl::Register>::new(0);
        block_ctrl.modify(
            BlockReadControl::KEY_ID.val(pcr_id)
                + BlockReadControl::KEY_READ_EN.val(1)
                + BlockReadControl::PCR_HASH_EXTEND.val(1),
        );
        assert_eq!(
            sha512
                .write(RvSize::Word, OFFSET_BLOCK_CONTROL, block_ctrl.get())
                .ok(),
            Some(())
        );
        // Wait for sha512 periph to retrieve the pcr from the key-vault.
        loop {
            let block_read_status = InMemoryRegister::<u32, BlockReadStatus::Register>::new(
                sha512.read(RvSize::Word, OFFSET_BLOCK_STATUS).unwrap(),
            );
            if block_read_status.is_set(BlockReadStatus::VALID) {
                break;
            }
            clock.increment_and_process_timer_actions(1, &mut sha512);
        }

        // Transfer the data to the block registers
        let actual_data_length = data.len() + pcr_data.len();
        let totalblocks = ((actual_data_length + 16) + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE;
        let totalbytes = totalblocks * SHA512_BLOCK_SIZE;
        let mut block_arr = vec![0; totalbytes];

        block_arr[..pcr_data.len()].copy_from_slice(pcr_data);
        block_arr[pcr_data.len()..actual_data_length].copy_from_slice(data);
        block_arr[data.len() + pcr_data.len()] = 1 << 7;
        let len: u128 = actual_data_length as u128;
        let len = len * 8;
        block_arr[totalbytes - 16..].copy_from_slice(&len.to_be_bytes());
        block_arr.to_big_endian();
        let mut last_block = false;
        for idx in 0..totalblocks {
            for i in (0..SHA512_BLOCK_SIZE).step_by(4) {
                assert_eq!(
                    sha512
                        .write(
                            RvSize::Word,
                            OFFSET_BLOCK + i as RvAddr,
                            make_word((idx * SHA512_BLOCK_SIZE) + i, &block_arr)
                        )
                        .ok(),
                    Some(())
                );
            }

            if idx == (totalblocks - 1) {
                last_block = true;
            }

            if idx == 0 {
                let control: ReadWriteRegister<u32, Control::Register> = ReadWriteRegister::new(0);
                control.reg.modify(
                    Control::MODE.val(Sha512Mode::Sha384.into())
                        + Control::INIT.val(1)
                        + Control::LAST.val(last_block as u32),
                );
                assert_eq!(
                    sha512
                        .write(RvSize::Word, OFFSET_CONTROL, control.reg.get())
                        .ok(),
                    Some(())
                );
            } else {
                let control: ReadWriteRegister<u32, Control::Register> = ReadWriteRegister::new(0);
                control
                    .reg
                    .modify(Control::NEXT.val(1) + Control::LAST.val(last_block as u32));

                assert_eq!(
                    sha512
                        .write(RvSize::Word, OFFSET_CONTROL, control.reg.get())
                        .ok(),
                    Some(())
                );
            }

            loop {
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    sha512.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );
                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_process_timer_actions(1, &mut sha512);
            }
        }

        // Read the hash from the PCR vault.
        let mut hash_le: [u8; SHA384_HASH_SIZE];
        hash_le = sha512.key_vault.read_pcr(pcr_id);
        hash_le.to_little_endian();
        assert_eq!(&hash_le[0..sha512.hash().len()], expected);
    }

    #[test]
    fn test_sha384_pcr_hash_extend_single_block() {
        let data: [u8; 48] = [
            0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb,
            0xaa, 0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29,
            0xbd, 0xb6, 0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7,
            0xa3, 0x59, 0x14, 0xfc, 0x1e, 0xcd,
        ];
        let mut pcr_data: [u8; 48] = [
            0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb,
            0xaa, 0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29,
            0xbd, 0xb6, 0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7,
            0xa3, 0x59, 0x14, 0xfc, 0x1e, 0xcd,
        ];
        let expected: [u8; 48] = [
            0x13, 0x77, 0x93, 0x7b, 0x0, 0x6b, 0x72, 0xab, 0x18, 0xc1, 0x26, 0x4d, 0x2, 0xa4, 0xd6,
            0xe2, 0xd9, 0xb6, 0x7e, 0xec, 0x63, 0x52, 0x52, 0x41, 0x30, 0x56, 0x51, 0x14, 0x8d,
            0xca, 0x13, 0xd1, 0x2b, 0x8f, 0xca, 0x88, 0xeb, 0x5, 0x5e, 0x20, 0x66, 0x5e, 0xa8,
            0x90, 0xa3, 0x1b, 0x8c, 0x8,
        ];

        test_pcr_hash_extend(&data, &mut pcr_data, &expected);
    }

    #[test]
    fn test_sha384_pcr_hash_extend_multi_block() {
        let data: [u8; 82] = [
            0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
            0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
            0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C,
            0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
            0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
        ];

        let mut pcr_data: [u8; 48] = [
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
            0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62,
            0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
        ];

        let expected: [u8; SHA384_HASH_SIZE] = [
            0x9c, 0x2f, 0x48, 0x76, 0xd, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb,
            0xaa, 0x5e, 0x58, 0x72, 0x6, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29,
            0xbd, 0xb6, 0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7,
            0xa3, 0x59, 0x14, 0xfc, 0x1e, 0xcd,
        ];

        test_pcr_hash_extend(&data, &mut pcr_data, &expected);
    }
}
