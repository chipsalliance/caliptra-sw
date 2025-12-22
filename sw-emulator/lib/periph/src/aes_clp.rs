// Licensed under the Apache-2.0 license

use crate::hmac::{KeyReadControl, KeyReadStatus, TagWriteControl, TagWriteStatus, KEY_RW_TICKS};
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
use zerocopy::IntoBytes;

#[derive(Debug, PartialEq)]
pub enum AesKeyReleaseState {
    Ready,
    /// Destination KV has been set
    Armed,
    /// 64 bytes of data have been decrypted.
    /// Signal ready for copy to KV.
    Complete,
}

pub struct AesKeyReleaseOp {
    /// Key release has been requested
    /// OCP LOCK Rule:
    /// If AES ECB Decrypt & Output KV == 23
    pub state: AesKeyReleaseState,
    /// AES Decryption result
    /// Per OCP spec MUST be 64 bytes (MEK size)
    pub output: [u8; 64],
    // Data staged
    // When 64 bytes have been staged, signal completion.
    pub staged_data: usize,
}

impl Default for AesKeyReleaseOp {
    fn default() -> Self {
        Self {
            state: AesKeyReleaseState::Ready,
            output: [0; 64],
            staged_data: 0,
        }
    }
}

impl AesKeyReleaseOp {
    pub fn clear(&mut self) {
        self.staged_data = 0;
        self.state = AesKeyReleaseState::Ready;
    }

    pub fn load_data(&mut self, aes_block: &[u32; 4]) {
        if self.state != AesKeyReleaseState::Armed {
            return;
        }

        self.output[self.staged_data..self.staged_data + 16].clone_from_slice(aes_block.as_bytes());
        self.staged_data += 16;
        if self.staged_data == self.output.len() {
            self.state = AesKeyReleaseState::Complete;
        }
    }
}

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

    #[register(offset = 0x208, write_fn = on_write_key_write_control)]
    aes_kv_wr_key_ctrl: ReadWriteRegister<u32, TagWriteControl::Register>,

    #[register(offset = 0x20c)]
    aes_kv_wr_status: ReadOnlyRegister<u32, TagWriteStatus::Register>,

    /// Timer
    timer: Timer,

    /// Key Vault
    key_vault: KeyVault,

    /// Key read complete action
    op_key_read_complete_action: Option<ActionHandle>,

    /// Key write complete action
    op_key_write_complete_action: Option<ActionHandle>,

    key: Rc<RefCell<Option<[u8; 32]>>>,
    key_destination: Rc<RefCell<AesKeyReleaseOp>>,
}

impl AesClp {
    /// Create a new AES CLP peripheral instance
    pub fn new(
        clock: &Clock,
        key_vault: KeyVault,
        key: Rc<RefCell<Option<[u8; 32]>>>,
        key_destination: Rc<RefCell<AesKeyReleaseOp>>,
    ) -> Self {
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
            aes_kv_wr_key_ctrl: ReadWriteRegister::new(0),
            aes_kv_wr_status: ReadOnlyRegister::new(KeyReadStatus::READY::SET.value),
            op_key_read_complete_action: None,
            op_key_write_complete_action: None,
            key,
            key_destination,
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

    /// On Write callback for `key_write_control` register
    pub fn on_write_key_write_control(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        // TODO(clundin): Check soc reg for `ocp_lock_in_progress` true. If false this should be an
        // error? Or Should never release the KV?
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the key control register
        let key_write_ctrl = InMemoryRegister::<u32, TagWriteControl::Register>::new(val);

        self.aes_kv_wr_key_ctrl.reg.modify(
            TagWriteControl::KEY_WRITE_EN.val(key_write_ctrl.read(TagWriteControl::KEY_WRITE_EN))
                + TagWriteControl::KEY_ID.val(key_write_ctrl.read(TagWriteControl::KEY_ID)),
        );

        if key_write_ctrl.is_set(TagWriteControl::KEY_WRITE_EN) {
            self.aes_kv_wr_status.reg.modify(
                TagWriteStatus::READY::CLEAR
                    + TagWriteStatus::VALID::CLEAR
                    + TagWriteStatus::ERROR::CLEAR,
            );

            let mut key_op = self.key_destination.borrow_mut();
            key_op.state = AesKeyReleaseState::Armed;
            self.op_key_write_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        Ok(())
    }

    fn key_write_complete(&mut self) {
        // TODO(clundin): Check soc reg for `ocp_lock_in_progress` true. If false this should be an
        // error? Or Should never release the KV?
        let key_id = self.aes_kv_wr_key_ctrl.reg.read(TagWriteControl::KEY_ID);

        let mut key_usage = KeyUsage::default();
        key_usage.set_aes_key(true);

        // AES Engine has not completed decryption.
        // Schedule another poll.
        let mut key_op = self.key_destination.borrow_mut();
        if key_op.state != AesKeyReleaseState::Complete {
            self.op_key_write_complete_action =
                Some(self.timer.schedule_poll_in(KEY_RW_TICKS * 10000));
            return;
        };

        let result = self
            .key_vault
            .write_key(key_id, &key_op.output, key_usage.into());

        key_op.clear();

        // TODO(clundin): Check Key here?
        let (key_write_result, _key) = match result.err() {
            Some(BusError::LoadAccessFault)
            | Some(BusError::LoadAddrMisaligned)
            | Some(BusError::InstrAccessFault) => (KeyReadStatus::ERROR::KV_READ_FAIL.value, None),
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                (KeyReadStatus::ERROR::KV_WRITE_FAIL.value, None)
            }
            None => {
                result.unwrap();
                (KeyReadStatus::ERROR::KV_SUCCESS.value, Some(()))
            }
        };

        self.aes_kv_wr_status.reg.modify(
            TagWriteStatus::READY::SET
                + TagWriteStatus::VALID::SET
                + TagWriteStatus::ERROR.val(key_write_result),
        );
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_key_read_complete_action) {
            self.key_read_complete();
        }
        if self.timer.fired(&mut self.op_key_write_complete_action) {
            self.key_write_complete();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Aes;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvAddr;
    use tock_registers::interfaces::Writeable;
    use tock_registers::registers::InMemoryRegister;

    const AES_KEY_SHARE0_OFFSET: RvAddr = 0x4;
    const AES_KEY_SHARE1_OFFSET: RvAddr = 0x24;
    const AES_DATA_IN_OFFSET: RvAddr = 0x54;
    const AES_CTRL_SHADOWED_OFFSET: RvAddr = 0x74;

    const AES_CLP_KV_WR_KEY_CTRL_OFFSET: RvAddr = 0x208;
    const AES_CLP_KV_WR_STATUS_OFFSET: RvAddr = 0x20c;

    const AES_KEY: [u8; 32] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77,
        0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14,
        0xDF, 0xF4,
    ];

    // AES Ciphertext to be decrypted. (64 bytes)
    const CIPHER_TEXT: [u8; 64] = [
        0xE5, 0x68, 0xF6, 0x81, 0x94, 0xCF, 0x76, 0xD6, 0x17, 0x4D, 0x4C, 0xC0, 0x43, 0x10, 0xA8,
        0x54, 0xE5, 0x68, 0xF6, 0x81, 0x94, 0xCF, 0x76, 0xD6, 0x17, 0x4D, 0x4C, 0xC0, 0x43, 0x10,
        0xA8, 0x54, 0xE5, 0x68, 0xF6, 0x81, 0x94, 0xCF, 0x76, 0xD6, 0x17, 0x4D, 0x4C, 0xC0, 0x43,
        0x10, 0xA8, 0x54, 0xE5, 0x68, 0xF6, 0x81, 0x94, 0xCF, 0x76, 0xD6, 0x17, 0x4D, 0x4C, 0xC0,
        0x43, 0x10, 0xA8, 0x54,
    ];

    const PLAIN_TEXT: [u8; 64] = [0; 64];

    fn make_word(idx: usize, arr: &[u8]) -> RvData {
        let mut res: RvData = 0;
        for i in 0..4 {
            res |= (arr[idx + i] as RvData) << (i * 8);
        }
        res
    }

    #[test]
    fn test_aes_key_release() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let aes_key = Rc::new(RefCell::new(None));
        let aes_destination = Rc::new(RefCell::new(AesKeyReleaseOp::default()));

        let mut aes = Aes::new(aes_key.clone(), aes_destination.clone());
        let mut aes_clp = AesClp::new(
            &clock,
            key_vault.clone(),
            aes_key.clone(),
            aes_destination.clone(),
        );

        // 1. Configure AES
        // Write Key
        for i in (0..AES_KEY.len()).step_by(4) {
            aes.write(
                RvSize::Word,
                AES_KEY_SHARE0_OFFSET + i as u32,
                make_word(i, &AES_KEY),
            )
            .unwrap();
            aes.write(RvSize::Word, AES_KEY_SHARE1_OFFSET + i as u32, 0)
                .unwrap();
        }

        // Configure AES for ECB Decryption
        let ctrl = InMemoryRegister::<u32, crate::aes::Ctrl::Register>::new(0);
        ctrl.write(
            crate::aes::Ctrl::OP::DECRYPT
                + crate::aes::Ctrl::MODE::ECB
                + crate::aes::Ctrl::KEY_LEN::KEY_256
                + crate::aes::Ctrl::MANUAL_OPERATION::ENABLED,
        );
        aes.write(RvSize::Word, AES_CTRL_SHADOWED_OFFSET, ctrl.get())
            .unwrap();

        // 2. Configure AesClp to write to KV slot 23
        let dest_key_id = 23;
        let key_write_ctrl = InMemoryRegister::<u32, TagWriteControl::Register>::new(0);
        key_write_ctrl
            .write(TagWriteControl::KEY_ID.val(dest_key_id) + TagWriteControl::KEY_WRITE_EN.val(1));

        aes_clp
            .write(
                RvSize::Word,
                AES_CLP_KV_WR_KEY_CTRL_OFFSET,
                key_write_ctrl.get(),
            )
            .unwrap();

        // Verify AesKeyReleaseOp is Armed
        assert_eq!(aes_destination.borrow().state, AesKeyReleaseState::Armed);

        // 3. Load 64 bytes of data into AES
        for chunk in CIPHER_TEXT.chunks(16) {
            for i in (0..chunk.len()).step_by(4) {
                aes.write(
                    RvSize::Word,
                    AES_DATA_IN_OFFSET + i as u32,
                    make_word(i, chunk),
                )
                .unwrap();
            }
        }

        // Verify AesKeyReleaseOp is Complete
        assert_eq!(aes_destination.borrow().state, AesKeyReleaseState::Complete);
        assert_eq!(aes_destination.borrow().output, PLAIN_TEXT);

        // 4. Step clock to let AesClp write to KeyVault
        // AesClp checks for completion in poll()
        clock.increment_and_process_timer_actions(KEY_RW_TICKS + 10, &mut aes_clp);

        // 5. Verify KeyVault content
        let mut key_usage = KeyUsage::default();
        key_usage.set_aes_key(true);
        let kv_key = key_vault.read_key(dest_key_id, key_usage).unwrap();

        assert_eq!(kv_key, PLAIN_TEXT);

        let status = aes_clp
            .read(RvSize::Word, AES_CLP_KV_WR_STATUS_OFFSET)
            .unwrap();
        let status_reg = InMemoryRegister::<u32, TagWriteStatus::Register>::new(status);
        assert!(status_reg.is_set(TagWriteStatus::VALID));
        assert_eq!(
            status_reg.read(TagWriteStatus::ERROR),
            TagWriteStatus::ERROR::KV_SUCCESS.value
        );
    }
}
