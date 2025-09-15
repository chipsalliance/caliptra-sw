/*++

Licensed under the Apache-2.0 license.

File Name:

    array.rs

Abstract:

    File contains common array definitions used by Caliptra hardware software
    interface.

--*/

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::Launder;
use core::mem::MaybeUninit;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroize;

macro_rules! static_assert {
    ($expression:expr) => {
        const _: () = assert!($expression);
    };
}

/// The `Array4xN` type represents large arrays in the native format of the Caliptra
/// cryptographic hardware, and provides From traits for converting to/from byte arrays.
#[repr(transparent)]
#[derive(
    Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq, Zeroize,
)]
#[cfg_attr(not(feature = "no-cfi"), derive(Launder))]
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

/// Conversion from big-endian Array4xN to little-endian LEArray4xN
impl<const W: usize, const B: usize> From<Array4xN<W, B>> for LEArray4xN<W, B> {
    fn from(value: Array4xN<W, B>) -> Self {
        let result: [u8; B] = value.into();
        Self::from(&result)
    }
}

/// The `LEArray4xN` type represents large arrays in little-endian format,
/// and provides From traits for converting to/from byte arrays.
#[repr(transparent)]
#[derive(
    Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq, Zeroize,
)]
#[cfg_attr(not(feature = "no-cfi"), derive(Launder))]
pub struct LEArray4xN<const W: usize, const B: usize>(pub [u32; W]);
impl<const W: usize, const B: usize> LEArray4xN<W, B> {
    pub const fn new(val: [u32; W]) -> Self {
        Self(val)
    }
}

impl<const W: usize, const B: usize> Default for LEArray4xN<W, B> {
    fn default() -> Self {
        Self([0u32; W])
    }
}

//// Ensure there is no padding in the struct
static_assert!(core::mem::size_of::<LEArray4xN<1, 4>>() == 4);

impl<const W: usize, const B: usize> LEArray4xN<W, B> {
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

impl<const W: usize, const B: usize> From<[u8; B]> for LEArray4xN<W, B> {
    #[inline(always)]
    fn from(value: [u8; B]) -> Self {
        Self::from(&value)
    }
}

#[inline(never)]
// [CAP2][TODO] does this get optimized away if host is LE?
unsafe fn u32_le_to_u8_impl<const W: usize, const B: usize>(
    dest: &mut MaybeUninit<[u8; B]>,
    src: &LEArray4xN<W, B>,
) {
    let ptr = dest.as_mut_ptr() as *mut [u8; 4];
    for i in 0..W {
        ptr.add(i).write(src.0[i].to_le_bytes());
    }
}

impl<const W: usize, const B: usize> From<LEArray4xN<W, B>> for [u8; B] {
    #[inline(always)]
    fn from(value: LEArray4xN<W, B>) -> Self {
        Self::from(&value)
    }
}

impl<const W: usize, const B: usize> From<&LEArray4xN<W, B>> for [u8; B] {
    #[inline(always)]
    fn from(value: &LEArray4xN<W, B>) -> Self {
        unsafe {
            let mut result = MaybeUninit::<[u8; B]>::uninit();
            u32_le_to_u8_impl(&mut result, value);
            result.assume_init()
        }
    }
}

#[inline(never)]
unsafe fn u8_to_u32_le_impl<const W: usize, const B: usize>(
    dest: &mut MaybeUninit<LEArray4xN<W, B>>,
    src: &[u8; B],
) {
    let dest = dest.as_mut_ptr() as *mut u32;
    for i in 0..W {
        dest.add(i)
            .write(u32::from_le_bytes(src[i * 4..][..4].try_into().unwrap()));
    }
}

impl<const W: usize, const B: usize> From<&[u8; B]> for LEArray4xN<W, B> {
    #[inline(always)]
    fn from(value: &[u8; B]) -> Self {
        let mut result = MaybeUninit::<LEArray4xN<W, B>>::uninit();
        unsafe {
            u8_to_u32_le_impl(&mut result, value);
            result.assume_init()
        }
    }
}

impl<const W: usize, const B: usize> From<&[u32; W]> for LEArray4xN<W, B> {
    fn from(value: &[u32; W]) -> Self {
        Self(*value)
    }
}

impl<const W: usize, const B: usize> From<[u32; W]> for LEArray4xN<W, B> {
    fn from(value: [u32; W]) -> Self {
        Self(value)
    }
}

impl<const W: usize, const B: usize> From<LEArray4xN<W, B>> for [u32; W] {
    fn from(value: LEArray4xN<W, B>) -> Self {
        value.0
    }
}

/// Conversion from little-endian LEArray4xN to big-endian Array4xN
impl<const W: usize, const B: usize> From<&LEArray4xN<W, B>> for Array4xN<W, B> {
    fn from(value: &LEArray4xN<W, B>) -> Self {
        let result: [u8; B] = value.into();
        Self::from(result)
    }
}

impl<const W: usize, const B: usize> From<LEArray4xN<W, B>> for Array4xN<W, B> {
    fn from(value: LEArray4xN<W, B>) -> Self {
        Self::from(&value)
    }
}

pub type LEArray4x4 = LEArray4xN<4, 16>;
pub type LEArray4x8 = LEArray4xN<8, 32>;
pub type LEArray4x16 = LEArray4xN<16, 64>;
pub type LEArray4x392 = LEArray4xN<392, 1568>;
pub type LEArray4x648 = LEArray4xN<648, 2592>;
pub type LEArray4x792 = LEArray4xN<792, 3168>;
pub type LEArray4x1157 = LEArray4xN<1157, 4628>;
pub type LEArray4x1224 = LEArray4xN<1224, 4896>;

pub type Array4x4 = Array4xN<4, 16>;
pub type Array4x5 = Array4xN<5, 20>;
pub type Array4x8 = Array4xN<8, 32>;
pub type Array4x12 = Array4xN<12, 48>;
pub type Array4x16 = Array4xN<16, 64>;
pub type Array4x32 = Array4xN<32, 128>;

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

    #[test]
    fn test_array_conversion() {
        let be_array = Array4x8::new([
            0x0011_2233,
            0x4455_6677,
            0x8899_aabb,
            0xccdd_eeff,
            0x0123_4567,
            0x89ab_cdef,
            0xfedc_ba98,
            0x7654_3210,
        ]);
        let le_array = LEArray4x8::new([
            0x3322_1100,
            0x7766_5544,
            0xbbaa_9988,
            0xffee_ddcc,
            0x6745_2301,
            0xefcd_ab89,
            0x98ba_dcfe,
            0x1032_5476,
        ]);

        // Test BE to LE conversion
        assert_eq!(LEArray4x8::from(be_array), le_array);

        // Test LE to BE conversion
        assert_eq!(Array4x8::from(le_array), be_array);

        // Test round-trip conversion
        assert_eq!(Array4x8::from(LEArray4x8::from(be_array)), be_array);
        assert_eq!(LEArray4x8::from(Array4x8::from(le_array)), le_array);
    }
}
