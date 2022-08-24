/*++

Licensed under the Apache-2.0 license.

File Name:

    sha512.rs

Abstract:

    File contains SHA512 peripheral implementation.

--*/

use caliptra_emu_bus::{
    BusError, Clock, ReadOnlyMemory, ReadOnlyRegister, ReadWriteMemory, ReadWriteRegister, Timer,
    TimerAction, WriteOnlyMemory,
};
use caliptra_emu_crypto::{Sha512, Sha512Mode};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

register_bitfields! [
    u32,

    /// Control Register Fields
    Control [
        INIT OFFSET(0) NUMBITS(1) [],
        NEXT OFFSET(1) NUMBITS(1) [],
        MODE OFFSET(2) NUMBITS(2) [],
        WORK_FACTOR OFFSET(7) NUMBITS(1) [],
    ],

    /// Status Register Fields
    Status[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
    ],
];

/// SHA512 Block Size
const SHA512_BLOCK_SIZE: usize = 128;

/// SHA512 Hash Size
const SHA512_HASH_SIZE: usize = 64;

/// The number of CPU clock cycles it takes to perform initialization action.
const INIT_TICKS: u64 = 1000;

/// The number of CPU clock cycles it takes to perform the hash update action.
const UPDATE_TICKS: u64 = 1000;

/// SHA-512 Peripheral
#[derive(Bus)]
#[poll_fn(poll)]
pub struct Sha512Periph {
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

    /// SHA512 Block Register
    #[peripheral(offset = 0x0000_0080, mask = 0x0000_007f)]
    block: ReadWriteMemory<SHA512_BLOCK_SIZE>,

    /// SHA512 Digest Register
    #[peripheral(offset = 0x0000_0100, mask = 0x0000_00ff)]
    hash: ReadOnlyMemory<SHA512_HASH_SIZE>,

    /// SHA512 engine
    sha512: Sha512,

    timer: Timer,

    op_complete_action: Option<TimerAction>,
}

impl Sha512Periph {
    /// NAME0 Register Value
    const NAME0_VAL: RvData = 0x323135; // 512

    /// NAME1 Register Value
    const NAME1_VAL: RvData = 0x32616873; // sha2

    /// VERSION0 Register Value
    const VERSION0_VAL: RvData = 0x30302E31; // 1.0

    /// VERSION1 Register Value
    const VERSION1_VAL: RvData = 0x00000000;

    /// Create a new instance of SHA-512 Engine
    pub fn new(clock: &Clock) -> Self {
        Self {
            sha512: Sha512::new(Sha512Mode::Sha512), // Default SHA512 mode
            name0: ReadOnlyRegister::new(Self::NAME0_VAL),
            name1: ReadOnlyRegister::new(Self::NAME1_VAL),
            version0: ReadOnlyRegister::new(Self::VERSION0_VAL),
            version1: ReadOnlyRegister::new(Self::VERSION1_VAL),
            control: ReadWriteRegister::new(0),
            status: ReadOnlyRegister::new(Status::READY::SET.value),
            block: ReadWriteMemory::new(),
            hash: ReadOnlyMemory::new(),
            timer: Timer::new(clock),
            op_complete_action: None,
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

        if self.control.reg.is_set(Control::INIT) {
            // Initialize the HMAC engine with key and initial data block
            //self.hmac.init(&self.key.data(), &self.block.data());
            let mut _mode = Sha512Mode::Sha512;

            // [TODO] Get the SHA512 mode
            // let vari = self.control.reg.get(Control::MODE); 

            // match vari { 

            // Sha512Mode::Sha512 => mode = Sha512Mode::Sha512,
            // Sha512Mode::Sha384 => mode = Sha512Mode::Sha384,
            // _ => Err(BusError::StoreAccessFault)?
            // }

            //self.sha512.reset(mode);

            // Schedule a future call to poll() complete the operation.
            self.op_complete_action = Some(self.timer.schedule_poll_in(INIT_TICKS));

        } else if self.control.reg.is_set(Control::NEXT) {
            // Update a HMAC engine with a new block
            self.sha512.update(&self.block.data());

            // Schedule a future call to poll() complete the operation.
            self.op_complete_action = Some(self.timer.schedule_poll_in(UPDATE_TICKS));
        }

        Ok(())
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            // Retrieve the hash
            self.sha512.hash(self.hash.data_mut());

            // Update Ready and Valid status bits
            self.status
                .reg
                .modify(Status::READY::SET + Status::VALID::SET);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
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

    #[test]
    fn test_name_read() {
        let sha512 = Sha512Periph::new(&Clock::new());

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
        let sha512 = Sha512Periph::new(&Clock::new());

        let version0 = sha512.read(RvSize::Word, OFFSET_VERSION0).unwrap();
        let version0 = String::from_utf8_lossy(&version0.to_le_bytes()).to_string();
        assert_eq!(version0, "1.00");

        let version1 = sha512.read(RvSize::Word, OFFSET_VERSION1).unwrap();
        let version1 = String::from_utf8_lossy(&version1.to_le_bytes()).to_string();
        assert_eq!(version1, "\0\0\0\0");
    }

    #[test]
    fn test_control_read() {
        let sha512 = Sha512Periph::new(&Clock::new());
        assert_eq!(sha512.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status_read() {
        let sha512 = Sha512Periph::new(&Clock::new());
        assert_eq!(sha512.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_block_read_write() {
        let mut sha512 = Sha512Periph::new(&Clock::new());
        for addr in (OFFSET_BLOCK..(OFFSET_BLOCK + SHA512_BLOCK_SIZE as u32)).step_by(4) {
            assert_eq!(sha512.write(RvSize::Word, addr, u32::MAX).ok(), Some(()));
            assert_eq!(sha512.read(RvSize::Word, addr).ok(), Some(u32::MAX));
        }
    }

    #[test]
    fn test_hash_read_write() {
        let mut sha512 = Sha512Periph::new(&Clock::new());
        for addr in (OFFSET_HASH..(OFFSET_HASH + SHA512_HASH_SIZE as u32)).step_by(4) {
            assert_eq!(sha512.read(RvSize::Word, addr).ok(), Some(0));
            assert_eq!(
                sha512.write(RvSize::Word, addr, 0xFF).err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }

    fn test_sha512(data: &[u8], result: &[u8]) {
        fn make_word(idx: usize, arr: &[u8]) -> RvData {
            let mut res: RvData = 0;
            for i in 0..4 {
                res = res | ((arr[idx + i] as RvData) << i * 8);
            }
            res
        }

        // Compute the total bytes required for the final message.
        let totalblocks = ((data.len() + 16) + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE;
        let totalbytes = totalblocks * SHA512_BLOCK_SIZE;

        let mut block_arr = vec![0; totalbytes];

        block_arr[..data.len()].copy_from_slice(&data);
        block_arr[data.len()] = 1 << 7;

        let len: u128 = data.len() as u128;
        let len = len * 8;
        block_arr[totalbytes - 16..].copy_from_slice(&len.to_be_bytes());

        let clock = Clock::new();
        let mut sha512 = Sha512Periph::new(&clock);

        // Process each block via the SHA engine.
        for idx in 0..totalblocks {

            for i in (0..SHA512_BLOCK_SIZE).step_by(4) {
                assert_eq!(
                    sha512.write(
                        RvSize::Word,
                        OFFSET_BLOCK + i as RvAddr,
                        make_word((idx * SHA512_BLOCK_SIZE) + i, &block_arr)
                    )
                    .ok(),
                    Some(())
                );
            }
    
            assert_eq!(
                sha512.write(RvSize::Word, OFFSET_CONTROL, Control::INIT::SET.into())
                    .ok(),
                Some(())
            );
    
            loop {
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    sha512.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );
    
                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_poll(1, &mut sha512);
            }
        }

        assert_eq!(sha512.hash.data(), result);
    }

    #[test]
    fn test_sha512_1() {

        let data: [u8; 128] = [
        0x61, 0x62, 0x63, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,         
        ];

        let result: [u8; 64] = [
            0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20,
            0x41, 0x31, 0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2, 0x0A, 0x9E, 0xEE, 0xE6,
            0x4B, 0x55, 0xD3, 0x9A, 0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA,
            0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD, 0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
            0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
        ];

        test_sha512(&data, &result);
    }

}