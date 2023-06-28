// Licensed under the Apache-2.0 license

use std::fmt::Write;

use caliptra_emu_bus::{
    testing::{FakeBus, Log},
    Bus, BusError, Ram,
};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};

struct MyCustomField(RvData);
impl From<RvData> for MyCustomField {
    fn from(val: RvData) -> Self {
        MyCustomField(val)
    }
}
impl From<MyCustomField> for RvData {
    fn from(val: MyCustomField) -> RvData {
        val.0
    }
}

#[derive(Bus)]
#[poll_fn(poll)]
#[allow(clippy::manual_non_exhaustive)]
struct MyBus {
    pub log: Log,

    #[peripheral(offset = 0x0000_0000, mask = 0x0fff_ffff)]
    pub rom: Ram,

    #[peripheral(offset = 0x1000_0000, mask = 0x0fff_ffff)]
    pub sram: Ram,

    #[peripheral(offset = 0x2000_0000, mask = 0x0fff_ffff)]
    pub dram: Ram,

    #[peripheral(offset = 0xaa00_0000, mask = 0x0000_ffff)]
    pub uart0: Ram,

    #[peripheral(offset = 0xaa01_0000, mask = 0x0000_ffff)]
    pub uart1: Ram,

    #[peripheral(offset = 0xaa02_0000, mask = 0x0000_00ff)]
    pub i2c0: Ram,

    #[peripheral(offset = 0xaa02_0400, mask = 0x0000_00ff)]
    pub i2c1: Ram,

    #[peripheral(offset = 0xaa02_0800, mask = 0x0000_00ff)]
    pub i2c2: Ram,

    #[peripheral(offset = 0xbb42_0000, mask = 0x0000_ffff)]
    pub spi0: Ram,

    #[peripheral(offset = 0xaa05_0000, mask = 0x0000_ffff)]
    pub fake: FakeBus,

    #[register(offset = 0xcafe_f0d0)]
    pub reg_u32: u32,

    #[register(offset = 0xcafe_f0d4)]
    pub reg_u16: u16,

    #[register(offset = 0xcafe_f0d8)]
    pub reg_u8: u8,

    #[register_array(offset = 0xcafe_f0f4)]
    pub reg_array: [u32; 5],

    #[register_array(offset = 0xcafe_f114, read_fn = reg_array_action0_read)]
    pub reg_array_action0: [u32; 2],

    #[register_array(offset = 0xcafe_f11c, write_fn = reg_array_action1_write)]
    pub reg_array_action1: [u32; 2],

    #[register(offset = 0xcafe_f0e0, read_fn = reg_action0_read)]
    pub reg_action0: u32,

    #[register(offset = 0xcafe_f0e4, write_fn = reg_action1_write)]
    pub reg_action1: u32,

    #[register(offset = 0xcafe_f0e8, read_fn = reg_action2_read, write_fn = reg_action2_write)]
    #[register(offset = 0xcafe_f0ec, read_fn = reg_action3_read, write_fn = reg_action3_write)]
    #[register_array(offset = 0xcafe_f134, item_size = 4, len = 5, read_fn = reg_array_action2_read, write_fn = reg_array_action2_write)]
    _fieldless_regs: (),
}
impl MyBus {
    fn reg_action0_read(&self, size: RvSize) -> Result<RvData, BusError> {
        write!(self.log.w(), "reg_action0 read {:?}; ", size).unwrap();
        Ok(0x4de0d4f5)
    }
    fn reg_action1_write(&self, size: RvSize, val: RvData) -> Result<(), BusError> {
        write!(self.log.w(), "reg_action1 write {size:?} 0x{val:08x}; ").unwrap();
        Ok(())
    }
    fn reg_action2_read(&self, size: RvSize) -> Result<MyCustomField, BusError> {
        write!(self.log.w(), "reg_action2 read {size:?}; ").unwrap();
        Ok(MyCustomField(0xba5eba11))
    }
    fn reg_action2_write(&self, size: RvSize, val: MyCustomField) -> Result<(), BusError> {
        write!(self.log.w(), "reg_action2 write {size:?} 0x{:08x}; ", val.0).unwrap();
        Ok(())
    }
    fn reg_action3_read(&self, size: RvSize) -> Result<MyCustomField, BusError> {
        write!(self.log.w(), "reg_action2 read {size:?}; ").unwrap();
        Ok(MyCustomField(0xba5eba11))
    }
    fn reg_action3_write(&self, size: RvSize, val: MyCustomField) -> Result<(), BusError> {
        write!(self.log.w(), "reg_action2 write {size:?} 0x{:08x}; ", val.0).unwrap();
        Ok(())
    }
    fn reg_array_action0_read(&self, size: RvSize, index: usize) -> Result<RvData, BusError> {
        write!(
            self.log.w(),
            "reg_array_action0[{:x}] read {size:?}; ",
            index
        )
        .unwrap();
        Ok(0xf00d_0000 + index as u32)
    }
    fn reg_array_action1_write(
        &self,
        size: RvSize,
        index: usize,
        val: MyCustomField,
    ) -> Result<(), BusError> {
        write!(
            self.log.w(),
            "reg_array_action1[{index}] write {size:?} 0x{:08x}; ",
            val.0
        )
        .unwrap();
        Ok(())
    }
    fn reg_array_action2_read(&self, size: RvSize, index: usize) -> Result<RvData, BusError> {
        write!(
            self.log.w(),
            "reg_array_action2[{:x}] read {size:?}; ",
            index
        )
        .unwrap();
        Ok(0xd00d_0000 + index as u32)
    }
    fn reg_array_action2_write(
        &self,
        size: RvSize,
        index: usize,
        val: MyCustomField,
    ) -> Result<(), BusError> {
        write!(
            self.log.w(),
            "reg_array_action2[{index}] write {size:?} 0x{:08x}; ",
            val.0
        )
        .unwrap();
        Ok(())
    }

    fn poll(&self) {
        write!(self.log.w(), "poll; ").unwrap();
    }
}

#[test]
fn test_read_dispatch() {
    let mut bus = MyBus {
        rom: Ram::new(vec![0u8; 65536]),
        sram: Ram::new(vec![0u8; 65536]),
        dram: Ram::new(vec![0u8; 65536]),
        uart0: Ram::new(vec![0u8; 128]),
        uart1: Ram::new(vec![0u8; 128]),
        i2c0: Ram::new(vec![0u8; 128]),
        i2c1: Ram::new(vec![0u8; 128]),
        i2c2: Ram::new(vec![0u8; 128]),
        spi0: Ram::new(vec![0u8; 65536]),
        fake: FakeBus::new(),

        reg_u32: 0xd149_b444,
        reg_u16: 0x695c,
        reg_u8: 0xc1,

        reg_action0: 0,
        reg_action1: 0xa813_c333,

        reg_array: [
            0x1043_0000,
            0x1043_1000,
            0x1043_2000,
            0x1043_3000,
            0x1043_4000,
        ],

        reg_array_action0: [0x1001_1000, 0x1001_2000],
        reg_array_action1: [0x2001_1000, 0x2001_2000],

        _fieldless_regs: (),

        log: Log::new(),
    };
    bus.rom.write(RvSize::Word, 0x3430, 0x3828_abcd).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0x3430).unwrap(), 0x3828_abcd);

    bus.sram.write(RvSize::Word, 0x0, 0x892a_b38a).unwrap();
    assert_eq!(bus.read(RvSize::HalfWord, 0x1000_0000).unwrap(), 0xb38a);

    bus.dram.write(RvSize::Word, 0xfffc, 0x2a29_3072).unwrap();
    assert_eq!(bus.read(RvSize::Byte, 0x2000_ffff).unwrap(), 0x2a);

    bus.uart0.write(RvSize::Word, 0x20, 0x8e27_ab42).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0xaa00_0020).unwrap(), 0x8e27_ab42);

    bus.uart1.write(RvSize::Word, 0x74, 0x38b8_e201).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0xaa01_0074).unwrap(), 0x38b8_e201);

    bus.i2c0.write(RvSize::Word, 0x1c, 0xc1a4_823f).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0xaa02_001c).unwrap(), 0xc1a4_823f);

    bus.i2c0.write(RvSize::Word, 0x68, 0x0e8a_440b).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0xaa02_0068).unwrap(), 0x0e8a_440b);

    bus.i2c1.write(RvSize::Word, 0x00, 0x0e8a_440b).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0xaa02_0400).unwrap(), 0x0e8a_440b);

    bus.i2c2.write(RvSize::Word, 0x54, 0x70fa_81c9).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0xaa02_0854).unwrap(), 0x70fa_81c9);

    bus.spi0.write(RvSize::Word, 0xd87c, 0x48ba_38c1).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0xbb42_d87c).unwrap(), 0x48ba_38c1);

    assert_eq!(
        bus.read(RvSize::Word, 0x0001_0000).unwrap_err(),
        BusError::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Word, 0xf000_0000).unwrap_err(),
        BusError::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Word, 0xaa03_0000).unwrap_err(),
        BusError::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Word, 0xaa02_0900).unwrap_err(),
        BusError::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Word, 0xbb41_0000).unwrap_err(),
        BusError::LoadAccessFault
    );

    assert_eq!(bus.read(RvSize::Word, 0xcafe_f0d0).unwrap(), 0xd149_b444);
    assert_eq!(bus.read(RvSize::HalfWord, 0xcafe_f0d4).unwrap(), 0x695c);
    assert_eq!(bus.read(RvSize::Byte, 0xcafe_f0d8).unwrap(), 0xc1);

    assert_eq!(
        bus.read(RvSize::HalfWord, 0xcafe_f0d0).unwrap_err(),
        BusError::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Word, 0xcafe_f0d4).unwrap_err(),
        BusError::LoadAccessFault
    );

    assert_eq!(
        bus.read(RvSize::HalfWord, 0xcafe_f0f0).unwrap_err(),
        BusError::LoadAccessFault
    );
    assert_eq!(bus.read(RvSize::Word, 0xcafe_f0f4).unwrap(), 0x1043_0000);
    assert_eq!(bus.read(RvSize::Word, 0xcafe_f0f8).unwrap(), 0x1043_1000);
    assert_eq!(bus.read(RvSize::Word, 0xcafe_f0fc).unwrap(), 0x1043_2000);
    assert_eq!(bus.read(RvSize::Word, 0xcafe_f100).unwrap(), 0x1043_3000);
    assert_eq!(bus.read(RvSize::Word, 0xcafe_f104).unwrap(), 0x1043_4000);
    assert_eq!(
        bus.read(RvSize::Word, 0xcafe_f108).unwrap_err(),
        BusError::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::HalfWord, 0xcafe_f0f6).unwrap_err(),
        BusError::LoadAccessFault
    );

    assert_eq!(bus.read(RvSize::Word, 0xcafe_f0e0).unwrap(), 0x4de0d4f5);
    assert_eq!(bus.read(RvSize::HalfWord, 0xcafe_f0e0).unwrap(), 0x4de0d4f5);
    assert_eq!(
        bus.log.take(),
        "reg_action0 read Word; reg_action0 read HalfWord; "
    );

    assert_eq!(bus.read(RvSize::Word, 0xcafe_f0e4).unwrap(), 0xa813_c333);

    assert_eq!(bus.read(RvSize::Word, 0xcafe_f0e8).unwrap(), 0xba5e_ba11);
    assert_eq!(bus.log.take(), "reg_action2 read Word; ");

    assert_eq!(bus.read(RvSize::Word, 0xcafe_f114).unwrap(), 0xf00d_0000);
    assert_eq!(bus.log.take(), "reg_array_action0[0] read Word; ");

    assert_eq!(bus.read(RvSize::Word, 0xcafe_f118).unwrap(), 0xf00d_0001);
    assert_eq!(bus.log.take(), "reg_array_action0[1] read Word; ");

    assert_eq!(bus.read(RvSize::Word, 0xcafe_f11c).unwrap(), 0x2001_1000);
    assert_eq!(bus.log.take(), "");

    assert_eq!(bus.read(RvSize::Word, 0xcafe_f120).unwrap(), 0x2001_2000);
    assert_eq!(bus.log.take(), "");

    assert_eq!(
        bus.read(RvSize::Word, 0xcafe_f130).unwrap_err(),
        BusError::LoadAccessFault
    );
    assert_eq!(bus.read(RvSize::Word, 0xcafe_f134).unwrap(), 0xd00d_0000);
    assert_eq!(bus.log.take(), "reg_array_action2[0] read Word; ");
    assert_eq!(bus.read(RvSize::Word, 0xcafe_f138).unwrap(), 0xd00d_0001);
    assert_eq!(bus.log.take(), "reg_array_action2[1] read Word; ");
    assert_eq!(bus.read(RvSize::Word, 0xcafe_f144).unwrap(), 0xd00d_0004);
    assert_eq!(bus.log.take(), "reg_array_action2[4] read Word; ");
    assert_eq!(
        bus.read(RvSize::Word, 0xcafe_f148).unwrap_err(),
        BusError::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Byte, 0xcafe_f131).unwrap_err(),
        BusError::LoadAccessFault
    );
}

#[test]
fn test_write_dispatch() {
    let mut bus = MyBus {
        rom: Ram::new(vec![0u8; 65536]),
        sram: Ram::new(vec![0u8; 65536]),
        dram: Ram::new(vec![0u8; 65536]),
        uart0: Ram::new(vec![0u8; 128]),
        uart1: Ram::new(vec![0u8; 128]),
        i2c0: Ram::new(vec![0u8; 128]),
        i2c1: Ram::new(vec![0u8; 128]),
        i2c2: Ram::new(vec![0u8; 128]),
        spi0: Ram::new(vec![0u8; 65536]),
        fake: FakeBus::new(),

        reg_u32: 0,
        reg_u16: 0,
        reg_u8: 0,

        reg_array: [0; 5],
        reg_array_action0: [0; 2],
        reg_array_action1: [0; 2],

        reg_action0: 0,
        reg_action1: 0,

        _fieldless_regs: (),

        log: Log::new(),
    };
    bus.write(RvSize::Word, 0x3430, 0x3828_abcd).unwrap();
    assert_eq!(bus.rom.read(RvSize::Word, 0x3430).unwrap(), 0x3828_abcd);

    bus.write(RvSize::HalfWord, 0x1000_0002, 0x892a).unwrap();
    bus.write(RvSize::HalfWord, 0x1000_0000, 0xb38a).unwrap();
    assert_eq!(bus.sram.read(RvSize::Word, 0x0).unwrap(), 0x892a_b38a);

    bus.write(RvSize::Byte, 0x2000_fffc, 0x72).unwrap();
    bus.write(RvSize::Byte, 0x2000_fffd, 0x30).unwrap();
    bus.write(RvSize::Byte, 0x2000_fffe, 0x29).unwrap();
    bus.write(RvSize::Byte, 0x2000_ffff, 0x2a).unwrap();
    assert_eq!(bus.dram.read(RvSize::Word, 0xfffc).unwrap(), 0x2a29_3072);

    bus.write(RvSize::Word, 0xaa00_0020, 0x8e27_ab42).unwrap();
    assert_eq!(bus.uart0.read(RvSize::Word, 0x20).unwrap(), 0x8e27_ab42);

    bus.write(RvSize::Word, 0xaa01_0074, 0x38b8_e201).unwrap();
    assert_eq!(bus.uart1.read(RvSize::Word, 0x74).unwrap(), 0x38b8_e201);

    bus.write(RvSize::Word, 0xaa02_001c, 0xc1a4_823f).unwrap();
    assert_eq!(bus.i2c0.read(RvSize::Word, 0x1c).unwrap(), 0xc1a4_823f);

    bus.write(RvSize::Word, 0xaa02_0068, 0x0e8a_440b).unwrap();
    assert_eq!(bus.i2c0.read(RvSize::Word, 0x68).unwrap(), 0x0e8a_440b);

    bus.write(RvSize::Word, 0xaa02_0400, 0x0e8a_440b).unwrap();
    assert_eq!(bus.i2c1.read(RvSize::Word, 0x00).unwrap(), 0x0e8a_440b);

    bus.write(RvSize::Word, 0xaa02_0854, 0x70fa_81c9).unwrap();
    assert_eq!(bus.i2c2.read(RvSize::Word, 0x54).unwrap(), 0x70fa_81c9);

    bus.write(RvSize::Word, 0xbb42_d87c, 0x48ba_38c1).unwrap();
    assert_eq!(bus.spi0.read(RvSize::Word, 0xd87c).unwrap(), 0x48ba_38c1);

    assert_eq!(
        bus.write(RvSize::Word, 0x0001_0000, 0).unwrap_err(),
        BusError::StoreAccessFault
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xf000_0000, 0).unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xaa03_0000, 0).unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xaa02_0900, 0).unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xbb41_0000, 0).unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );

    bus.write(RvSize::Word, 0xcafe_f0d0, 0xd149_b445).unwrap();
    assert_eq!(bus.reg_u32, 0xd149_b445);
    bus.write(RvSize::HalfWord, 0xcafe_f0d4, 0x695c).unwrap();
    assert_eq!(bus.reg_u16, 0x695c);
    bus.write(RvSize::Byte, 0xcafe_f0d8, 0xc1).unwrap();
    assert_eq!(bus.reg_u8, 0xc1);

    assert_eq!(
        bus.write(RvSize::HalfWord, 0xcafe_f0d0, 0).unwrap_err(),
        BusError::StoreAccessFault
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xcafe_f0d4, 0).unwrap_err(),
        BusError::StoreAccessFault
    );

    bus.write(RvSize::Word, 0xcafe_f0e0, 0x82d1_aa14).unwrap();
    assert_eq!(bus.reg_action0, 0x82d1_aa14);

    assert_eq!(
        bus.write(RvSize::Word, 0xcafe_f0f0, 0xface_ff00)
            .unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );
    bus.write(RvSize::Word, 0xcafe_f0f4, 0xface_0000).unwrap();
    bus.write(RvSize::Word, 0xcafe_f0f8, 0xface_0100).unwrap();
    bus.write(RvSize::Word, 0xcafe_f0fc, 0xface_0200).unwrap();
    bus.write(RvSize::Word, 0xcafe_f100, 0xface_0300).unwrap();
    bus.write(RvSize::Word, 0xcafe_f104, 0xface_0400).unwrap();
    assert_eq!(
        bus.reg_array,
        [
            0xface_0000,
            0xface_0100,
            0xface_0200,
            0xface_0300,
            0xface_0400
        ]
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xcafe_f108, 0xface_f000)
            .unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );
    assert_eq!(
        bus.write(RvSize::HalfWord, 0xcafe_f0f6, 0xface_f000)
            .unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );

    bus.write(RvSize::Word, 0xcafe_f0e4, 0xbaf3_e991).unwrap();
    bus.write(RvSize::Word, 0xcafe_f0e4, 0x6965_617f).unwrap();
    bus.write(RvSize::HalfWord, 0xcafe_f0e4, 0xc8aa).unwrap();

    assert_eq!(bus.log.take(), "reg_action1 write Word 0xbaf3e991; reg_action1 write Word 0x6965617f; reg_action1 write HalfWord 0x0000c8aa; ");

    bus.write(RvSize::Word, 0xcafe_f0e8, 0xb01d_face).unwrap();
    assert_eq!(bus.log.take(), "reg_action2 write Word 0xb01dface; ");

    bus.write(RvSize::Word, 0xcafe_f114, 0x1255).unwrap();
    assert_eq!(bus.log.take(), "");
    bus.write(RvSize::Word, 0xcafe_f118, 0x1255).unwrap();
    assert_eq!(bus.log.take(), "");

    bus.write(RvSize::Word, 0xcafe_f11c, 0xface_b01d).unwrap();
    assert_eq!(
        bus.log.take(),
        "reg_array_action1[0] write Word 0xfaceb01d; "
    );
    bus.write(RvSize::Word, 0xcafe_f120, 0xface_b01e).unwrap();
    assert_eq!(
        bus.log.take(),
        "reg_array_action1[1] write Word 0xfaceb01e; "
    );

    assert_eq!(
        bus.write(RvSize::Word, 0xcafe_f130, 0xface_f000)
            .unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );
    bus.write(RvSize::Word, 0xcafe_f134, 0xface_b0dd).unwrap();
    assert_eq!(
        bus.log.take(),
        "reg_array_action2[0] write Word 0xfaceb0dd; "
    );
    bus.write(RvSize::Word, 0xcafe_f138, 0xface_b0de).unwrap();
    assert_eq!(
        bus.log.take(),
        "reg_array_action2[1] write Word 0xfaceb0de; "
    );
    bus.write(RvSize::Word, 0xcafe_f144, 0xface_b0df).unwrap();
    assert_eq!(
        bus.log.take(),
        "reg_array_action2[4] write Word 0xfaceb0df; "
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xcafe_f148, 0xface_f000)
            .unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );
    assert_eq!(
        bus.write(RvSize::Byte, 0xcafe_f133, 0xface_f000)
            .unwrap_err(),
        BusError::StoreAccessFaultImprecise
    );
}

#[test]
fn test_poll() {
    let mut bus = MyBus {
        rom: Ram::new(vec![0u8; 65536]),
        sram: Ram::new(vec![0u8; 65536]),
        dram: Ram::new(vec![0u8; 65536]),
        uart0: Ram::new(vec![0u8; 128]),
        uart1: Ram::new(vec![0u8; 128]),
        i2c0: Ram::new(vec![0u8; 128]),
        i2c1: Ram::new(vec![0u8; 128]),
        i2c2: Ram::new(vec![0u8; 128]),
        spi0: Ram::new(vec![0u8; 65536]),
        fake: FakeBus::new(),

        reg_u32: 0,
        reg_u16: 0,
        reg_u8: 0,

        reg_array: [0; 5],
        reg_array_action0: [0; 2],
        reg_array_action1: [0; 2],

        reg_action0: 0,
        reg_action1: 0,

        _fieldless_regs: (),

        log: Log::new(),
    };
    Bus::poll(&mut bus);
    assert_eq!(bus.log.take(), "poll; ");
    assert_eq!(bus.fake.log.take(), "poll()\n")
}
