/*++

Licensed under the Apache-2.0 license.

File Name:

    array.rs

Abstract:

    File contains common array definitions used by Caliptra hardware software
    interface.

--*/

use caliptra_cfi_derive::Launder;
use core::mem::MaybeUninit;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

macro_rules! static_assert {
    ($expression:expr) => {
        const _: () = assert!($expression);
    };
}

/// The `Array4xN` type represents large arrays in the native format of the Caliptra
/// cryptographic hardware, and provides From traits for converting to/from byte arrays.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Launder, Zeroize)]
pub struct Array4xN<const W: usize, const B: usize>(pub [u32; W]);
impl<const W: usize, const B: usize> Array4xN<W, B> {
    pub const fn new(val: [u32; W]) -> Self {
        Self(val)
    }
}

impl<const W: usize, const B: usize> Default for Array4xN<W, B> {
    fn default() -> Self {
        Self([0u32; W])
    }
}

//// Ensure there is no padding in the struct
static_assert!(core::mem::size_of::<Array4xN<1, 4>>() == 4);
unsafe impl<const W: usize, const B: usize> AsBytes for Array4xN<W, B> {
    fn only_derive_is_allowed_to_implement_this_trait() {}
}

//// Ensure there is no padding in the struct
static_assert!(core::mem::size_of::<Array4xN<1, 4>>() == 4);
unsafe impl<const W: usize, const B: usize> FromBytes for Array4xN<W, B> {
    fn only_derive_is_allowed_to_implement_this_trait() {}
}

impl<const W: usize, const B: usize> Array4xN<W, B> {
    #[inline(always)]
    #[allow(unused)]
    pub fn read_from_reg<
        TReg: ureg::ReadableReg<ReadVal = u32, Raw = u32>,
        TMmio: ureg::Mmio + Copy,
    >(
        reg_array: ureg::Array<W, ureg::RegRef<TReg, TMmio>>,
    ) -> Self {
        reg_array.read().into()
    }

    #[inline(always)]
    #[allow(unused)]
    pub fn write_to_reg<
        TReg: ureg::ResettableReg + ureg::WritableReg<WriteVal = u32, Raw = u32>,
        TMmio: ureg::MmioMut + Copy,
    >(
        &self,
        reg_array: ureg::Array<W, ureg::RegRef<TReg, TMmio>>,
    ) {
        reg_array.write(&self.0);
    }
}

impl<const W: usize, const B: usize> From<[u8; B]> for Array4xN<W, B> {
    #[inline(always)]
    fn from(value: [u8; B]) -> Self {
        Self::from(&value)
    }
}

#[inline(never)]
unsafe fn u32_be_to_u8_impl<const W: usize, const B: usize>(
    dest: &mut MaybeUninit<[u8; B]>,
    src: &Array4xN<W, B>,
) {
    let ptr = dest.as_mut_ptr() as *mut [u8; 4];
    for i in 0..W {
        ptr.add(i).write(src.0[i].to_be_bytes());
    }
}

impl<const W: usize, const B: usize> From<Array4xN<W, B>> for [u8; B] {
    #[inline(always)]
    fn from(value: Array4xN<W, B>) -> Self {
        Self::from(&value)
    }
}

impl<const W: usize, const B: usize> From<&Array4xN<W, B>> for [u8; B] {
    #[inline(always)]
    fn from(value: &Array4xN<W, B>) -> Self {
        unsafe {
            let mut result = MaybeUninit::<[u8; B]>::uninit();
            u32_be_to_u8_impl(&mut result, value);
            result.assume_init()
        }
    }
}

#[inline(never)]
unsafe fn u8_to_u32_be_impl<const W: usize, const B: usize>(
    dest: &mut MaybeUninit<Array4xN<W, B>>,
    src: &[u8; B],
) {
    let dest = dest.as_mut_ptr() as *mut u32;
    for i in 0..W {
        dest.add(i)
            .write(u32::from_be_bytes(src[i * 4..][..4].try_into().unwrap()));
    }
}

impl<const W: usize, const B: usize> From<&[u8; B]> for Array4xN<W, B> {
    #[inline(always)]
    fn from(value: &[u8; B]) -> Self {
        let mut result = MaybeUninit::<Array4xN<W, B>>::uninit();
        unsafe {
            u8_to_u32_be_impl(&mut result, value);
            result.assume_init()
        }
    }
}

impl<const W: usize, const B: usize> From<&[u32; W]> for Array4xN<W, B> {
    fn from(value: &[u32; W]) -> Self {
        Self(*value)
    }
}

impl<const W: usize, const B: usize> From<[u32; W]> for Array4xN<W, B> {
    fn from(value: [u32; W]) -> Self {
        Self(value)
    }
}

impl<const W: usize, const B: usize> From<Array4xN<W, B>> for [u32; W] {
    fn from(value: Array4xN<W, B>) -> Self {
        value.0
    }
}

pub type Array4x4 = Array4xN<4, 16>;
pub type Array4x5 = Array4xN<5, 20>;
pub type Array4x8 = Array4xN<8, 32>;
pub type Array4x12 = Array4xN<12, 48>;
pub type Array4x16 = Array4xN<16, 64>;
pub type Array4x32 = Array4xN<32, 128>;
pub type Array4x648 = Array4xN<648, 2592>;
pub type Array4x1157 = Array4xN<1157, 4628>;

#[cfg(test)]
mod tests {
    use super::*;

    // To run inside the MIRI interpreter to detect undefined behavior in the
    // unsafe code, run with:
    // cargo +nightly miri test -p caliptra-drivers --lib

    #[test]
    fn test_array_4x4_from_bytes() {
        assert_eq!(
            Array4x4::from([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]),
            Array4x4::new([0x0011_2233, 0x4455_6677, 0x8899_aabb, 0xccdd_eeff])
        );
        assert_eq!(
            Array4x4::from(&[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]),
            Array4x4::new([0x0011_2233, 0x4455_6677, 0x8899_aabb, 0xccdd_eeff])
        );
    }

    #[test]
    fn test_array_4x4_to_bytes() {
        assert_eq!(
            <[u8; 16]>::from(Array4x4::new([
                0x0011_2233,
                0x4455_6677,
                0x8899_aabb,
                0xccdd_eeff
            ])),
            [
                0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff
            ]
        );
        assert_eq!(
            <[u8; 16]>::from(&Array4x4::new([
                0x0011_2233,
                0x4455_6677,
                0x8899_aabb,
                0xccdd_eeff
            ])),
            [
                0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff
            ]
        );
    }
}
