// Licensed under the Apache-2.0 license

use crate::{RealMmio, RealMmioMut, Uint, UintType};

#[inline(always)]
pub unsafe fn read_volatile_array<const LEN: usize, T: Uint>(dst: *mut T, src: *mut T) {
    match (T::TYPE, LEN) {
        (UintType::U32, 12) => copy_12words(dst as *mut u32, src as *const u32),
        (UintType::U32, 16) => copy_16words(dst as *mut u32, src as *const u32),
        _ => super::read_volatile_slice(&RealMmio::default(), dst, src, LEN),
    }
}

#[inline(always)]
pub unsafe fn write_volatile_array<const LEN: usize, T: Uint>(dst: *mut T, src: *const [T; LEN]) {
    match (T::TYPE, LEN) {
        (UintType::U32, 12) => copy_12words(dst as *mut u32, src as *const u32),
        (UintType::U32, 16) => copy_16words(dst as *mut u32, src as *const u32),
        _ => super::write_volatile_slice(&RealMmioMut::default(), dst, &*src),
    }
}

#[inline(never)]
unsafe fn copy_16words(dest: *mut u32, val: *const u32) {
    core::arch::asm!(
        "lw {tmp0}, 0({s})",
        "lw {tmp1}, 4({s})",
        "lw {tmp2}, 8({s})",
        "lw {tmp3}, 12({s})",
        "sw {tmp0}, 0({d})",
        "sw {tmp1}, 4({d})",
        "sw {tmp2}, 8({d})",
        "sw {tmp3}, 12({d})",
        "lw {tmp0}, 16({s})",
        "lw {tmp1}, 20({s})",
        "lw {tmp2}, 24({s})",
        "lw {tmp3}, 28({s})",
        "sw {tmp0}, 16({d})",
        "sw {tmp1}, 20({d})",
        "sw {tmp2}, 24({d})",
        "sw {tmp3}, 28({d})",
        "lw {tmp0}, 32({s})",
        "lw {tmp1}, 36({s})",
        "lw {tmp2}, 40({s})",
        "lw {tmp3}, 44({s})",
        "sw {tmp0}, 32({d})",
        "sw {tmp1}, 36({d})",
        "sw {tmp2}, 40({d})",
        "sw {tmp3}, 44({d})",
        "lw {tmp0}, 48({s})",
        "lw {tmp1}, 52({s})",
        "lw {tmp2}, 56({s})",
        "lw {tmp3}, 60({s})",
        "sw {tmp0}, 48({d})",
        "sw {tmp1}, 52({d})",
        "sw {tmp2}, 56({d})",
        "sw {tmp3}, 60({d})",

        s = in(reg) val,
        d = in(reg) dest,
        tmp0 = out(reg) _,
        tmp1 = out(reg) _,
        tmp2 = out(reg) _,
        tmp3 = out(reg) _,
    );
}

#[inline(never)]
unsafe fn copy_12words(dest: *mut u32, val: *const u32) {
    core::arch::asm!(
        "lw {tmp0}, 0({s})",
        "lw {tmp1}, 4({s})",
        "lw {tmp2}, 8({s})",
        "lw {tmp3}, 12({s})",
        "sw {tmp0}, 0({d})",
        "sw {tmp1}, 4({d})",
        "sw {tmp2}, 8({d})",
        "sw {tmp3}, 12({d})",
        "lw {tmp0}, 16({s})",
        "lw {tmp1}, 20({s})",
        "lw {tmp2}, 24({s})",
        "lw {tmp3}, 28({s})",
        "sw {tmp0}, 16({d})",
        "sw {tmp1}, 20({d})",
        "sw {tmp2}, 24({d})",
        "sw {tmp3}, 28({d})",
        "lw {tmp0}, 32({s})",
        "lw {tmp1}, 36({s})",
        "lw {tmp2}, 40({s})",
        "lw {tmp3}, 44({s})",
        "sw {tmp0}, 32({d})",
        "sw {tmp1}, 36({d})",
        "sw {tmp2}, 40({d})",
        "sw {tmp3}, 44({d})",
        s = in(reg) val,
        d = in(reg) dest,
        tmp0 = out(reg) _,
        tmp1 = out(reg) _,
        tmp2 = out(reg) _,
        tmp3 = out(reg) _,
    );
}

#[cfg(test)]
mod test {
    use super::*;

    // To test, run "cargo install cross", then "cross test --target riscv64gc-unknown-linux-gnu"

    #[test]
    fn test_read_volatile_array_12_u32() {
        let mut src: [u32; 12] = [
            0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23, 0x27fc0139,
            0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2,
        ];

        let mut dest = [0x5555_5555_u32; 14];
        unsafe {
            read_volatile_array::<12, u32>(dest.as_mut_ptr().add(1), src.as_mut_ptr() as *mut u32)
        };
        assert_eq!(
            dest,
            [
                0x55555555, 0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23,
                0x27fc0139, 0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0x55555555
            ]
        );
        assert_eq!(
            src,
            [
                0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23, 0x27fc0139,
                0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2,
            ],
        );
    }

    #[test]
    fn test_read_volatile_array_12_u8() {
        let mut src: [u8; 12] = [
            0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f,
        ];

        let mut dest = [0x55_u8; 14];
        unsafe {
            read_volatile_array::<12, u8>(dest.as_mut_ptr().add(1), src.as_mut_ptr() as *mut u8)
        };
        assert_eq!(
            dest,
            [0x55, 0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f, 0x55,]
        );
        assert_eq!(
            src,
            [0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f,]
        );
    }

    #[test]
    fn test_read_volatile_array_16_u32() {
        let mut src: [u32; 16] = [
            0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23, 0x27fc0139,
            0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4, 0x44e612a1,
            0x46690857, 0x3bfe2428,
        ];

        let mut dest = [0x5555_5555; 18];
        unsafe {
            read_volatile_array::<16, u32>(dest.as_mut_ptr().add(1), src.as_mut_ptr() as *mut u32)
        };
        assert_eq!(
            dest,
            [
                0x55555555, 0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23,
                0x27fc0139, 0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4,
                0x44e612a1, 0x46690857, 0x3bfe2428, 0x55555555
            ]
        );
        assert_eq!(
            src,
            [
                0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23, 0x27fc0139,
                0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4, 0x44e612a1,
                0x46690857, 0x3bfe2428,
            ]
        );
    }

    #[test]
    fn test_read_volatile_array_16_u8() {
        let mut src: [u8; 16] = [
            0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f, 0xc4, 0x4c,
            0x6a, 0x28,
        ];

        let mut dest = [0x55_u8; 18];
        unsafe {
            read_volatile_array::<16, u8>(dest.as_mut_ptr().add(1), src.as_mut_ptr() as *mut u8)
        };
        assert_eq!(
            dest,
            [
                0x55, 0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f, 0xc4,
                0x4c, 0x6a, 0x28, 0x55,
            ]
        );
        assert_eq!(
            src,
            [
                0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f, 0xc4, 0x4c,
                0x6a, 0x28,
            ]
        );
    }

    #[test]
    fn test_read_volatile_array_15_u32() {
        let mut src: [u32; 15] = [
            0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23, 0x27fc0139,
            0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4, 0x44e612a1,
            0x46690857,
        ];

        let mut dest = [0x5555_5555; 17];
        unsafe {
            read_volatile_array::<15, u32>(dest.as_mut_ptr().add(1), src.as_mut_ptr() as *mut u32)
        };
        assert_eq!(
            dest,
            [
                0x55555555, 0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23,
                0x27fc0139, 0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4,
                0x44e612a1, 0x46690857, 0x55555555,
            ]
        );
        assert_eq!(
            src,
            [
                0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23, 0x27fc0139,
                0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4, 0x44e612a1,
                0x46690857,
            ]
        );
    }

    #[test]
    fn test_write_volatile_array_12_u32() {
        let src: [u32; 12] = [
            0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23, 0x27fc0139,
            0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2,
        ];

        let mut dest = [0x5555_5555_u32; 14];
        unsafe { write_volatile_array::<12, u32>(dest.as_mut_ptr().add(1), &src) };
        assert_eq!(
            dest,
            [
                0x55555555, 0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23,
                0x27fc0139, 0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0x55555555
            ]
        )
    }

    #[test]
    fn test_write_volatile_array_12_u8() {
        let src: [u8; 12] = [
            0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f,
        ];

        let mut dest = [0x55_u8; 14];
        unsafe { write_volatile_array::<12, u8>(dest.as_mut_ptr().add(1), &src) };
        assert_eq!(
            dest,
            [0x55, 0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f, 0x55,]
        )
    }

    #[test]
    fn test_write_volatile_array_16_u32() {
        let src = [
            0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23, 0x27fc0139,
            0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4, 0x44e612a1,
            0x46690857, 0x3bfe2428,
        ];

        let mut dest = [0x5555_5555; 18];
        unsafe { write_volatile_array::<16, u32>(dest.as_mut_ptr().add(1), &src) };
        assert_eq!(
            dest,
            [
                0x55555555, 0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23,
                0x27fc0139, 0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4,
                0x44e612a1, 0x46690857, 0x3bfe2428, 0x55555555
            ]
        )
    }

    #[test]
    fn test_write_volatile_array_16_u8() {
        let src: [u8; 16] = [
            0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f, 0xc4, 0x4c,
            0x6a, 0x28,
        ];

        let mut dest = [0x55_u8; 18];
        unsafe { write_volatile_array::<16, u8>(dest.as_mut_ptr().add(1), &src) };
        assert_eq!(
            dest,
            [
                0x55, 0xe3, 0xc3, 0x63, 0xe7, 0x00, 0x87, 0x50, 0xdf, 0xda, 0xff, 0x76, 0x7f, 0xc4,
                0x4c, 0x6a, 0x28, 0x55,
            ]
        )
    }

    #[test]
    fn test_write_volatile_array_15_u32() {
        let src: [u32; 15] = [
            0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23, 0x27fc0139,
            0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4, 0x44e612a1,
            0x46690857,
        ];

        let mut dest = [0x5555_5555; 17];
        unsafe { write_volatile_array::<15, u32>(dest.as_mut_ptr().add(1), &src) };
        assert_eq!(
            dest,
            [
                0x55555555, 0xcf3ae93b, 0x3a5f6465, 0x0bbcb2c1, 0xad82403e, 0xdc0454aa, 0x038b0e23,
                0x27fc0139, 0x4fd1b300, 0x627ec17f, 0x9f58d0fc, 0x05f7b36c, 0x588179e2, 0xb039d6b4,
                0x44e612a1, 0x46690857, 0x55555555,
            ]
        )
    }
}
