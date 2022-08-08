use caliptra_emu_bus::{Bus, Device, Ram};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvExceptionCause, RvSize};

#[derive(Bus)]
struct MyBus {
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
}

#[test]
fn test_read_dispatch() {
    let mut bus = MyBus {
        rom: Ram::new("rom", 0, vec![0u8; 65536]),
        sram: Ram::new("sram", 0, vec![0u8; 65536]),
        dram: Ram::new("dram", 0, vec![0u8; 65536]),
        uart0: Ram::new("uart0", 0, vec![0u8; 128]),
        uart1: Ram::new("uart1", 0, vec![0u8; 128]),
        i2c0: Ram::new("i2c0", 0, vec![0u8; 128]),
        i2c1: Ram::new("i2c1", 0, vec![0u8; 128]),
        i2c2: Ram::new("i2c2", 0, vec![0u8; 128]),
        spi0: Ram::new("spi0", 0, vec![0u8; 65536]),
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
        bus.read(RvSize::Word, 0x0001_0000).unwrap_err().cause(),
        RvExceptionCause::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Word, 0xf000_0000).unwrap_err().cause(),
        RvExceptionCause::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Word, 0xaa03_0000).unwrap_err().cause(),
        RvExceptionCause::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Word, 0xaa02_0900).unwrap_err().cause(),
        RvExceptionCause::LoadAccessFault
    );
    assert_eq!(
        bus.read(RvSize::Word, 0xbb41_0000).unwrap_err().cause(),
        RvExceptionCause::LoadAccessFault
    );
}

#[test]
fn test_write_dispatch() {
    let mut bus = MyBus {
        rom: Ram::new("rom", 0, vec![0u8; 65536]),
        sram: Ram::new("sram", 0, vec![0u8; 65536]),
        dram: Ram::new("dram", 0, vec![0u8; 65536]),
        uart0: Ram::new("uart0", 0, vec![0u8; 128]),
        uart1: Ram::new("uart1", 0, vec![0u8; 128]),
        i2c0: Ram::new("i2c0", 0, vec![0u8; 128]),
        i2c1: Ram::new("i2c1", 0, vec![0u8; 128]),
        i2c2: Ram::new("i2c2", 0, vec![0u8; 128]),
        spi0: Ram::new("spi0", 0, vec![0u8; 65536]),
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
        bus.write(RvSize::Word, 0x0001_0000, 0).unwrap_err().cause(),
        RvExceptionCause::StoreAccessFault
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xf000_0000, 0).unwrap_err().cause(),
        RvExceptionCause::StoreAccessFault
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xaa03_0000, 0).unwrap_err().cause(),
        RvExceptionCause::StoreAccessFault
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xaa02_0900, 0).unwrap_err().cause(),
        RvExceptionCause::StoreAccessFault
    );
    assert_eq!(
        bus.write(RvSize::Word, 0xbb41_0000, 0).unwrap_err().cause(),
        RvExceptionCause::StoreAccessFault
    );
}
