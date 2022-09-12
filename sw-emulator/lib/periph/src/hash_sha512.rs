/*++

Licensed under the Apache-2.0 license.

File Name:

    hash_sha512.rs

Abstract:

    File contains SHA512 peripheral implementation.

--*/

use caliptra_emu_bus::{
    BusError, Clock, ReadOnlyMemory, ReadOnlyRegister, ReadWriteMemory, ReadWriteRegister, Timer,
    TimerAction,
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

const SHA512_BLOCK_SIZE: usize = 128;

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

    /// SHA512 Block Memory
    #[peripheral(offset = 0x0000_0080, mask = 0x0000_007f)]
    block: ReadWriteMemory<SHA512_BLOCK_SIZE>,

    /// SHA512 Hash Memory
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
            self.sha512.update(&self.block.data());

            // Schedule a future call to poll() complete the operation.
            self.op_complete_action = Some(self.timer.schedule_poll_in(INIT_TICKS));
        } else if self.control.reg.is_set(Control::NEXT) {
            // Update the SHA512 engine with a new block
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

    pub fn hash(&self) -> &[u8] {
        &self.hash.data()[..self.sha512.hash_len()]
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

    fn test_sha(data: &[u8], expected: &[u8], mode: Sha512Mode) {
        println!("data len: {}", data.len());

        fn make_word(idx: usize, arr: &[u8]) -> RvData {
            let mut res: RvData = 0;
            for i in 0..4 {
                res = res | ((arr[idx + i] as RvData) << i * 8);
            }
            res
        }

        // Compute the total bytes and total blocks required for the final message.
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

            if idx == 0 {
                let modebits;

                match mode {
                    Sha512Mode::Sha224 => modebits = 0,
                    Sha512Mode::Sha256 => modebits = 1,
                    Sha512Mode::Sha384 => modebits = 2,
                    Sha512Mode::Sha512 => modebits = 3,
                }

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
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    sha512.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );

                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_poll(1, &mut sha512);
            }
        }

        assert_eq!(sha512.hash(), expected);
    }

    const SHA_512_TEST_BLOCK: [u8; 3] = [0x61, 0x62, 0x63];

    #[test]
    fn test_sha512() {
        let expected: [u8; 64] = [
            0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20,
            0x41, 0x31, 0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2, 0x0A, 0x9E, 0xEE, 0xE6,
            0x4B, 0x55, 0xD3, 0x9A, 0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA,
            0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD, 0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
            0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
        ];

        test_sha(&SHA_512_TEST_BLOCK, &expected, Sha512Mode::Sha512);
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

        let expected: [u8; 64] = [
            0xF5, 0x9F, 0x92, 0x3E, 0x98, 0xF9, 0x23, 0x19, 0x28, 0x53, 0xB6, 0xA5, 0xA0, 0x3F,
            0x58, 0xBB, 0x6A, 0x86, 0xF9, 0xB8, 0x43, 0xC4, 0x35, 0x2B, 0x4D, 0x71, 0xC2, 0x92,
            0x1B, 0x90, 0x59, 0x39, 0x66, 0xAD, 0x9E, 0xF4, 0xBE, 0xA6, 0x50, 0xDB, 0xB4, 0xEB,
            0xE2, 0x17, 0x0B, 0x80, 0x7E, 0xA1, 0xAB, 0xB6, 0xF3, 0xCF, 0x54, 0x90, 0x81, 0xFF,
            0xB9, 0x81, 0xC2, 0xC2, 0x3F, 0x88, 0x6D, 0x07,
        ];

        test_sha(&SHA_512_TEST_MULTI_BLOCK, &expected, Sha512Mode::Sha512);
    }

    #[test]
    fn test_sha384() {
        let expected: [u8; 48] = [
            0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6,
            0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A,
            0x43, 0xFF, 0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA,
            0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
        ];

        test_sha(&SHA_512_TEST_BLOCK, &expected, Sha512Mode::Sha384);
    }

    #[test]
    fn test_sha512_224() {
        let expected: [u8; 28] = [
            0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54, 0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08,
            0x42, 0xE2, 0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4, 0x3E, 0x89, 0x24, 0xAA,
        ];

        test_sha(&SHA_512_TEST_BLOCK, &expected, Sha512Mode::Sha224);
    }

    #[test]
    fn test_sha512_256() {
        let expected: [u8; 32] = [
            0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9, 0x9B, 0x2E, 0x29, 0xB7, 0x6B, 0x4C,
            0x7D, 0xAB, 0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC, 0x6D, 0x46, 0xE0, 0xE2, 0xF1, 0x31,
            0x07, 0xE7, 0xAF, 0x23,
        ];

        test_sha(&SHA_512_TEST_BLOCK, &expected, Sha512Mode::Sha256);
    }
}
