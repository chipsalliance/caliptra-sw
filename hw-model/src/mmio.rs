// Licensed under the Apache-2.0 license

use std::cell::{Cell, RefCell};

use caliptra_emu_bus::Bus;
use caliptra_emu_types::RvSize;

use crate::rv32_builder::Rv32Builder;

const fn rvsize<T>() -> RvSize {
    match core::mem::size_of::<T>() {
        1 => RvSize::Byte,
        2 => RvSize::HalfWord,
        4 => RvSize::Word,
        _other => panic!("Unsupported RvSize"),
    }
}

unsafe fn transmute_to_u32<T>(src: &T) -> u32 {
    match std::mem::size_of::<T>() {
        1 => std::mem::transmute_copy::<T, u8>(&src).into(),
        2 => std::mem::transmute_copy::<T, u16>(&src).into(),
        4 => std::mem::transmute_copy::<T, u32>(&src).into(),
        _ => panic!("Unsupported write size"),
    }
}

/// An MMIO implementation that reads and writes to a `caliptra_emu_bus::Bus`.
pub struct BusMmio<TBus: Bus> {
    bus: RefCell<TBus>,
}
impl<TBus: Bus> BusMmio<TBus> {
    pub fn new(bus: TBus) -> Self {
        Self {
            bus: RefCell::new(bus),
        }
    }
    pub fn into_inner(self) -> TBus {
        self.bus.into_inner()
    }
}
impl<TBus: Bus> ureg::Mmio for BusMmio<TBus> {
    /// Loads from address `src` on the bus and returns the value.
    ///
    /// # Panics
    ///
    /// This function panics if the bus faults.
    ///
    /// # Safety
    ///
    /// As the pointer isn't read from, this Mmio implementation isn't actually
    /// unsafe for POD types like u8/u16/u32.
    unsafe fn read_volatile<T: Clone + Copy + Sized>(&self, src: *const T) -> T {
        let val_u32 = self
            .bus
            .borrow_mut()
            .read(rvsize::<T>(), src as usize as u32)
            .unwrap();
        match std::mem::size_of::<T>() {
            1 => std::mem::transmute_copy::<u8, T>(&(val_u32 as u8)),
            2 => std::mem::transmute_copy::<u16, T>(&(val_u32 as u16)),
            4 => std::mem::transmute_copy::<u32, T>(&val_u32),
            _ => panic!("Unsupported read size"),
        }
    }

    /// Stores `src` to address `dst` on the bus.
    ///
    /// # Panics
    ///
    /// This function panics if the bus faults.
    ///
    /// # Safety
    ///
    /// As the pointer isn't written to, this Mmio implementation isn't actually
    /// unsafe for POD types like u8/u16/u32.
    unsafe fn write_volatile<T: Clone + Copy>(&self, dst: *mut T, src: T) {
        self.bus
            .borrow_mut()
            .write(rvsize::<T>(), dst as usize as u32, transmute_to_u32(&src))
            .unwrap()
    }
}

/// An MMIO interface that generates RV32IMC store instructions.
pub struct Rv32GenMmio {
    builder: Cell<Rv32Builder>,
}
impl Rv32GenMmio {
    pub fn new() -> Self {
        Self {
            builder: Cell::new(Rv32Builder::new()),
        }
    }
    pub fn build(self) -> Vec<u8> {
        self.into_inner().build()
    }
    pub fn into_inner(self) -> Rv32Builder {
        self.builder.into_inner()
    }
}
impl ureg::Mmio for Rv32GenMmio {
    unsafe fn read_volatile<T: Clone + Copy + Sized>(&self, _src: *const T) -> T {
        panic!("Rv32GenMmio: Reads not supported; write-only");
    }

    /// Adds machine code that stores the 32-bit value `src` to destination
    /// address `dst`.
    ///
    /// # Safety
    ///
    /// As the pointer isn't written to, this Mmio implementation isn't actually
    /// unsafe for POD types like u8/u16/u32.
    unsafe fn write_volatile<T: Clone + Copy>(&self, dst: *mut T, src: T) {
        self.builder.set(
            self.builder
                .take()
                .store(dst as u32, transmute_to_u32(&src)),
        );
    }
}

#[cfg(test)]
mod tests {
    use caliptra_emu_bus::Ram;
    use ureg::Mmio;

    use super::*;

    #[test]
    fn test_bus_mmio() {
        let mmio = BusMmio::new(Ram::new(vec![0u8; 12]));
        unsafe {
            mmio.write_volatile(4 as *mut u32, 0x3abc_9321);
            mmio.write_volatile(8 as *mut u16, 0x39af);
            mmio.write_volatile(10 as *mut u8, 0xf3);

            assert_eq!(mmio.read_volatile(4 as *const u32), 0x3abc_9321);
            assert_eq!(mmio.read_volatile(8 as *const u16), 0x39af);
            assert_eq!(mmio.read_volatile(10 as *const u8), 0xf3);
        }
        assert_eq!(
            mmio.into_inner().data(),
            &[0x00, 0x00, 0x00, 0x00, 0x21, 0x93, 0xbc, 0x3a, 0xaf, 0x39, 0xf3, 0x00]
        );
    }

    #[test]
    fn test_rv32gen_mmio() {
        let mmio = Rv32GenMmio::new();
        unsafe {
            mmio.write_volatile(4 as *mut u32, 0x3abc_9321);
            mmio.write_volatile(8 as *mut u32, 0xd00f_b00d);
        }
        assert_eq!(
            &mmio.build(),
            &[
                0xb7, 0x02, 0x00, 0x00, 0x37, 0x93, 0xbc, 0x3a, 0x13, 0x03, 0x13, 0x32, 0x23, 0xa2,
                0x62, 0x00, 0xb7, 0x02, 0x00, 0x00, 0x37, 0xb3, 0x0f, 0xd0, 0x13, 0x03, 0xd3, 0x00,
                0x23, 0xa4, 0x62, 0x00, 0x13, 0x00, 0x00, 0x00,
            ]
        );
    }
}
