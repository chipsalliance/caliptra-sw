/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_sha384.rs

Abstract:

    File contains HMACSha384 peripheral implementation.

--*/

use caliptra_emu_bus::{
    BusError, ReadOnlyMemory, ReadOnlyRegister, ReadWriteMemory, ReadWriteRegister, WriteOnlyMemory,
};
use caliptra_emu_crypto::{Hmac512, Hmac512Mode};
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
    ],

    /// Status Register Fields
    Status[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
    ],
];

/// HMAC Key Size.
const HMAC_KEY_SIZE: usize = 48;

/// HMAC Block Size
const HMAC_BLOCK_SIZE: usize = 128;

/// HMAC Tag Size
const HMAC_TAG_SIZE: usize = 48;

/// HMAC-SHA-384 Peripheral
#[derive(Bus)]
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

    /// HMAC engine
    hmac: Hmac512<HMAC_KEY_SIZE>,
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
    pub fn new() -> Self {
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
            self.hmac.init(&self.key.data(), &self.block.data());

            // TODO: defer next two statements, once deferred processing engine is implemented

            // Retrieve the tag
            self.hmac.tag(self.tag.data_mut());

            // Update Ready and Valid status bits
            self.status
                .reg
                .modify(Status::READY::SET + Status::VALID::SET);
        } else if self.control.reg.is_set(Control::NEXT) {
            // Update a HMAC engine with a new block
            self.hmac.update(&self.block.data());

            // TODO: defer next two statements, once deferred processing engine is implemented

            // Retrieve the current tag
            self.hmac.tag(self.tag.data_mut());

            // Update Ready and Valid status bits
            self.status
                .reg
                .modify(Status::READY::SET + Status::VALID::SET);
        }

        Ok(())
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
    const OFFSET_KEY: RvAddr = 0x40;
    const OFFSET_BLOCK: RvAddr = 0x80;
    const OFFSET_TAG: RvAddr = 0x100;

    #[test]
    fn test_name() {
        let hmac = HmacSha384::new();

        let name0 = hmac.read(RvSize::Word, OFFSET_NAME0).unwrap();
        let name0 = String::from_utf8_lossy(&name0.to_le_bytes()).to_string();
        assert_eq!(name0, "hmac");

        let name1 = hmac.read(RvSize::Word, OFFSET_NAME1).unwrap();
        let name1 = String::from_utf8_lossy(&name1.to_le_bytes()).to_string();
        assert_eq!(name1, "sha2");
    }

    #[test]
    fn test_version() {
        let hmac = HmacSha384::new();

        let version0 = hmac.read(RvSize::Word, OFFSET_VERSION0).unwrap();
        let version0 = String::from_utf8_lossy(&version0.to_le_bytes()).to_string();
        assert_eq!(version0, "1.00");

        let version1 = hmac.read(RvSize::Word, OFFSET_VERSION1).unwrap();
        let version1 = String::from_utf8_lossy(&version1.to_le_bytes()).to_string();
        assert_eq!(version1, "\0\0\0\0");
    }

    #[test]
    fn test_control() {
        let hmac = HmacSha384::new();
        assert_eq!(hmac.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status() {
        let hmac = HmacSha384::new();
        assert_eq!(hmac.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_key() {
        let mut hmac = HmacSha384::new();
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
        let mut hmac = HmacSha384::new();
        for addr in (OFFSET_BLOCK..(OFFSET_BLOCK + HMAC_BLOCK_SIZE as u32)).step_by(4) {
            assert_eq!(hmac.write(RvSize::Word, addr, u32::MAX).ok(), Some(()));
            assert_eq!(hmac.read(RvSize::Word, addr).ok(), Some(u32::MAX));
        }
    }

    #[test]
    fn test_tag() {
        let mut hmac = HmacSha384::new();
        for addr in (OFFSET_TAG..(OFFSET_TAG + HMAC_TAG_SIZE as u32)).step_by(4) {
            assert_eq!(hmac.read(RvSize::Word, addr).ok(), Some(0));
            assert_eq!(
                hmac.write(RvSize::Word, addr, 0xFF).err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }

    fn test_hmac(key: &[u8; 48], data: &[u8], result: &[u8]) {
        fn make_word(idx: usize, arr: &[u8]) -> RvData {
            let mut res: RvData = 0;
            for i in 0..4 {
                res = res | ((arr[idx + i] as RvData) << i * 8);
            }
            res
        }

        let mut block = [0u8; HMAC_BLOCK_SIZE];
        block[..data.len()].copy_from_slice(&data);
        block[data.len()] = 1 << 7;

        let len: u128 = (HMAC_BLOCK_SIZE + data.len()) as u128;
        let len = len * 8;
        block[HMAC_BLOCK_SIZE - 16..].copy_from_slice(&len.to_be_bytes());

        let mut hmac = HmacSha384::new();

        for i in (0..key.len()).step_by(4) {
            assert_eq!(
                hmac.write(RvSize::Word, OFFSET_KEY + i as RvAddr, make_word(i, key))
                    .ok(),
                Some(())
            );
        }
        for i in (0..block.len()).step_by(4) {
            assert_eq!(
                hmac.write(
                    RvSize::Word,
                    OFFSET_BLOCK + i as RvAddr,
                    make_word(i, &block)
                )
                .ok(),
                Some(())
            );
        }

        assert_eq!(
            hmac.write(RvSize::Word, OFFSET_CONTROL, Control::INIT::SET.into())
                .ok(),
            Some(())
        );

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                hmac.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }
        }

        assert_eq!(hmac.tag.data(), result);
    }

    #[test]
    fn test_hmac_sha384_1() {
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

        test_hmac(&key, &data, &result);
    }

    #[test]
    fn test_hmac_sha384_2() {
        let key: [u8; 48] = [
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

        test_hmac(&key, &data, &result);
    }
}
