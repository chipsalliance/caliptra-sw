// Licensed under the Apache-2.0 license

use std::cell::Cell;

use crate::rv32_builder::Rv32Builder;

unsafe fn transmute_to_u32<T>(src: &T) -> u32 {
    match std::mem::size_of::<T>() {
        1 => std::mem::transmute_copy::<T, u8>(src).into(),
        2 => std::mem::transmute_copy::<T, u16>(src).into(),
        4 => std::mem::transmute_copy::<T, u32>(src),
        _ => panic!("Unsupported write size"),
    }
}

/// An MMIO interface that generates RV32IMC store instructions.
#[derive(Default)]
pub struct Rv32GenMmio {
    builder: Cell<Rv32Builder>,
}
impl Rv32GenMmio {
    pub fn new() -> Self {
        Self::default()
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
    use ureg::Mmio;

    use super::*;

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
