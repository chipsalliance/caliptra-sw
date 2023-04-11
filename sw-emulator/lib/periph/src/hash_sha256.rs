/*++

Licensed under the Apache-2.0 license.

File Name:

    hash_sha256.rs

Abstract:

    File contains SHA256 peripheral implementation.

--*/

use caliptra_emu_bus::{
    ActionHandle, BusError, Clock, ReadOnlyMemory, ReadOnlyRegister, ReadWriteMemory,
    ReadWriteRegister, Timer,
};
use caliptra_emu_crypto::{Sha256, Sha256Mode};
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
        MODE OFFSET(2) NUMBITS(1) [
            SHA256_224 = 0b00,
            SHA256 = 0b01,
        ],
        ZEROIZE OFFSET(3) NUMBITS(1) [],
        RSVD OFFSET(4) NUMBITS(28) [],
    ],

    /// Status Register Fields
    Status[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
    ],
];

const SHA256_BLOCK_SIZE: usize = 64;

const SHA256_HASH_SIZE: usize = 32;

/// The number of CPU clock cycles it takes to perform initialization action.
const INIT_TICKS: u64 = 1000;

/// The number of CPU clock cycles it takes to perform the hash update action.
const UPDATE_TICKS: u64 = 1000;

/// SHA-256 Peripheral
#[derive(Bus)]
#[poll_fn(poll)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
pub struct HashSha256 {
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

    /// SHA256 Block Memory
    #[peripheral(offset = 0x0000_0080, mask = 0x0000_007f)]
    block: ReadWriteMemory<SHA256_BLOCK_SIZE>,

    /// SHA256 Hash Memory
    #[peripheral(offset = 0x0000_0100, mask = 0x0000_00ff)]
    hash: ReadOnlyMemory<SHA256_HASH_SIZE>,

    /// SHA256 engine
    sha256: Sha256,

    timer: Timer,

    op_complete_action: Option<ActionHandle>,
}

impl HashSha256 {
    /// NAME0 Register Value
    const NAME0_VAL: RvData = 0x363532; // 256

    /// NAME1 Register Value
    const NAME1_VAL: RvData = 0x32616873; // sha2

    /// VERSION0 Register Value
    const VERSION0_VAL: RvData = 0x30302E31; // 1.0

    /// VERSION1 Register Value
    const VERSION1_VAL: RvData = 0x00000000;

    /// Create a new instance of SHA-512 Engine
    pub fn new(clock: &Clock) -> Self {
        Self {
            sha256: Sha256::new(Sha256Mode::Sha256), // Default SHA256 mode
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
            let mut mode = Sha256Mode::Sha256;
            let modebits = self.control.reg.read(Control::MODE);

            match modebits {
                0 => {
                    mode = Sha256Mode::Sha224;
                }
                1 => {
                    mode = Sha256Mode::Sha256;
                }
                _ => Err(BusError::StoreAccessFault)?,
            }

            self.sha256.reset(mode);

            // Update the SHA256 engine with a new block
            self.sha256.update(self.block.data());

            // Schedule a future call to poll() complete the operation.
            self.op_complete_action = Some(self.timer.schedule_poll_in(INIT_TICKS));
        } else if self.control.reg.is_set(Control::NEXT) {
            // Update the SHA512 engine with a new block
            self.sha256.update(self.block.data());

            // Schedule a future call to poll() complete the operation.
            self.op_complete_action = Some(self.timer.schedule_poll_in(UPDATE_TICKS));
        }

        Ok(())
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            // Retrieve the hash
            self.sha256.hash(self.hash.data_mut());

            // Update Ready and Valid status bits
            self.status
                .reg
                .modify(Status::READY::SET + Status::VALID::SET);
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

    pub fn hash(&self) -> &[u8] {
        &self.hash.data()[..self.sha256.hash_len()]
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
    const OFFSET_BLOCK: RvAddr = 0x80;
    const OFFSET_HASH: RvAddr = 0x100;

    #[test]
    fn test_name_read() {
        let mut sha256 = HashSha256::new(&Clock::new());

        let name0 = sha256.read(RvSize::Word, OFFSET_NAME0).unwrap();
        let mut name0 = String::from_utf8_lossy(&name0.to_le_bytes()).to_string();
        name0.pop();
        assert_eq!(name0, "256");

        let name1 = sha256.read(RvSize::Word, OFFSET_NAME1).unwrap();
        let name1 = String::from_utf8_lossy(&name1.to_le_bytes()).to_string();
        assert_eq!(name1, "sha2");
    }

    #[test]
    fn test_version_read() {
        let mut sha256 = HashSha256::new(&Clock::new());

        let version0 = sha256.read(RvSize::Word, OFFSET_VERSION0).unwrap();
        let version0 = String::from_utf8_lossy(&version0.to_le_bytes()).to_string();
        assert_eq!(version0, "1.00");

        let version1 = sha256.read(RvSize::Word, OFFSET_VERSION1).unwrap();
        let version1 = String::from_utf8_lossy(&version1.to_le_bytes()).to_string();
        assert_eq!(version1, "\0\0\0\0");
    }

    #[test]
    fn test_control_read() {
        let mut sha256 = HashSha256::new(&Clock::new());
        assert_eq!(sha256.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status_read() {
        let mut sha256 = HashSha256::new(&Clock::new());
        assert_eq!(sha256.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_block_read_write() {
        let mut sha256 = HashSha256::new(&Clock::new());
        for addr in (OFFSET_BLOCK..(OFFSET_BLOCK + SHA256_BLOCK_SIZE as u32)).step_by(4) {
            assert_eq!(sha256.write(RvSize::Word, addr, u32::MAX).ok(), Some(()));
            assert_eq!(sha256.read(RvSize::Word, addr).ok(), Some(u32::MAX));
        }
    }

    #[test]
    fn test_hash_read_write() {
        let mut sha256 = HashSha256::new(&Clock::new());
        for addr in (OFFSET_HASH..(OFFSET_HASH + SHA256_HASH_SIZE as u32)).step_by(4) {
            assert_eq!(sha256.read(RvSize::Word, addr).ok(), Some(0));
            assert_eq!(
                sha256.write(RvSize::Word, addr, 0xFF).err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }

    fn test_sha(data: &[u8], expected: &[u8], mode: Sha256Mode) {
        fn make_word(idx: usize, arr: &[u8]) -> RvData {
            let mut res: RvData = 0;
            for i in 0..4 {
                res |= (arr[idx + i] as RvData) << (i * 8);
            }
            res
        }

        // Compute the total bytes and total blocks required for the final message.
        let totalblocks = ((data.len() + 8) + SHA256_BLOCK_SIZE) / SHA256_BLOCK_SIZE;
        let totalbytes = totalblocks * SHA256_BLOCK_SIZE;

        let mut block_arr = vec![0; totalbytes];

        block_arr[..data.len()].copy_from_slice(data);
        block_arr[data.len()] = 1 << 7;

        let len: u64 = data.len() as u64;
        let len = len * 8;

        block_arr[totalbytes - 8..].copy_from_slice(&len.to_be_bytes());
        block_arr.to_big_endian();

        let clock = Clock::new();
        let mut sha256 = HashSha256::new(&clock);

        // Process each block via the SHA engine.
        for idx in 0..totalblocks {
            for i in (0..SHA256_BLOCK_SIZE).step_by(4) {
                assert_eq!(
                    sha256
                        .write(
                            RvSize::Word,
                            OFFSET_BLOCK + i as RvAddr,
                            make_word((idx * SHA256_BLOCK_SIZE) + i, &block_arr)
                        )
                        .ok(),
                    Some(())
                );
            }

            if idx == 0 {
                let modebits = match mode {
                    Sha256Mode::Sha224 => 0,
                    Sha256Mode::Sha256 => 1,
                };

                let control: ReadWriteRegister<u32, Control::Register> = ReadWriteRegister::new(0);
                control.reg.modify(Control::MODE.val(modebits));
                control.reg.modify(Control::INIT::SET);

                assert_eq!(
                    sha256
                        .write(RvSize::Word, OFFSET_CONTROL, control.reg.get())
                        .ok(),
                    Some(())
                );
            } else {
                assert_eq!(
                    sha256
                        .write(RvSize::Word, OFFSET_CONTROL, Control::NEXT::SET.into())
                        .ok(),
                    Some(())
                );
            }

            loop {
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    sha256.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );

                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_process_timer_actions(1, &mut sha256);
            }
        }

        let mut hash_le: [u8; 32] = [0; 32];
        hash_le[..sha256.hash().len()].clone_from_slice(sha256.hash());
        hash_le.to_little_endian();
        assert_eq!(&hash_le[0..sha256.hash().len()], expected);
    }

    #[rustfmt::skip]
    const SHA_256_TEST_BLOCK: [u8; 3] = [
        0x61, 0x62, 0x63, 
    ];

    #[test]
    fn test_sha256_224() {
        #[rustfmt::skip]
            let expected: [u8; 28] = [
            0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
            0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
        ];

        test_sha(&SHA_256_TEST_BLOCK, &expected, Sha256Mode::Sha224);
    }

    #[test]
    fn test_sha256_256() {
        #[rustfmt::skip]
            let expected: [u8; 32] = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x1, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
            0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x0, 0x15, 0xAD,
        ];

        test_sha(&SHA_256_TEST_BLOCK, &expected, Sha256Mode::Sha256);
    }

    #[test]
    fn test_sha256_multi_block() {
        const SHA_256_TEST_MULTI_BLOCK: [u8; 130] = [
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

        let expected: [u8; 32] = [
            0x06, 0xF9, 0xB1, 0xA7, 0xAC, 0x97, 0xBC, 0x8E, 0x6A, 0x83, 0x5C, 0x08, 0x98, 0x6F,
            0xE5, 0x38, 0xF0, 0x47, 0x8B, 0x03, 0x82, 0x6E, 0xFB, 0x4E, 0xED, 0x35, 0xDC, 0x51,
            0x7B, 0x43, 0x3B, 0x8A,
        ];

        test_sha(&SHA_256_TEST_MULTI_BLOCK, &expected, Sha256Mode::Sha256);
    }
}
