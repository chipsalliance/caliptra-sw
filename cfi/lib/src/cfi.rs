/*++

Licensed under the Apache-2.0 license.

File Name:

    cfi.rs

Abstract:

    File contains CFI launder implementation.

References:
    https://github.com/lowRISC/opentitan/blob/7a61300cf7c409fa68fd892942c1d7b58a7cd4c0/sw/device/lib/base/hardened.h#L260

--*/

use caliptra_error::CaliptraError;

use crate::CfiCounter;
use core::cfg;
use core::cmp::{Eq, Ord, PartialEq, PartialOrd};
use core::marker::Copy;

/// CFI Panic Information
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CfiPanicInfo {
    /// CFI Counter decode error
    CounterCorrupt,

    /// CFI Counter overflow
    CounterOverflow,

    /// CFI Counter underflow
    CounterUnderflow,

    /// CFI Counter mismatch
    CounterMismatch,

    /// CFI Assert Equal failed
    AssertEqFail,

    /// CFI Assert Not Equal failed
    AssertNeFail,

    /// CFI Greater Than failed
    AssertGtFail,

    /// CFI Less Than failed
    AssertLtFail,

    /// CFI Greater Than Equal failed
    AssertGeFail,

    /// CFI Less Than Equal failed
    AssertLeFail,

    /// Random number generator error
    TrngError,

    /// An enum match statement finds an unexpected value.
    UnexpectedMatchBranch,

    /// Unknown error
    UnknownError,
}

impl From<CfiPanicInfo> for CaliptraError {
    /// Converts to this type from the input type.
    fn from(info: CfiPanicInfo) -> CaliptraError {
        match info {
            CfiPanicInfo::CounterCorrupt => CaliptraError::ROM_CFI_PANIC_COUNTER_CORRUPT,
            CfiPanicInfo::CounterOverflow => CaliptraError::ROM_CFI_PANIC_COUNTER_OVERFLOW,
            CfiPanicInfo::CounterUnderflow => CaliptraError::ROM_CFI_PANIC_COUNTER_UNDERFLOW,
            CfiPanicInfo::CounterMismatch => CaliptraError::ROM_CFI_PANIC_COUNTER_MISMATCH,
            CfiPanicInfo::AssertEqFail => CaliptraError::ROM_CFI_PANIC_ASSERT_EQ_FAILURE,
            CfiPanicInfo::AssertNeFail => CaliptraError::ROM_CFI_PANIC_ASSERT_NE_FAILURE,
            CfiPanicInfo::AssertGtFail => CaliptraError::ROM_CFI_PANIC_ASSERT_GT_FAILURE,
            CfiPanicInfo::AssertLtFail => CaliptraError::ROM_CFI_PANIC_ASSERT_LT_FAILURE,
            CfiPanicInfo::AssertGeFail => CaliptraError::ROM_CFI_PANIC_ASSERT_GE_FAILURE,
            CfiPanicInfo::AssertLeFail => CaliptraError::ROM_CFI_PANIC_ASSERT_LE_FAILURE,
            CfiPanicInfo::TrngError => CaliptraError::ROM_CFI_PANIC_TRNG_FAILURE,
            _ => CaliptraError::ROM_CFI_PANIC_UNKNOWN,
        }
    }
}

/// Launder the value to prevent compiler optimization
///
/// # Arguments
///
/// * `val` - Value to launder
///
/// # Returns
///
/// `T` - Same value
pub fn cfi_launder<T>(val: T) -> T {
    if cfg!(feature = "cfi") {
        // Note: The black box seems to be disabling more optimization
        // than necessary and results in larger binary size
        core::hint::black_box(val)
    } else {
        val
    }
}

/// Control flow integrity panic
///
/// This panic is raised when the control flow integrity error is detected
///
/// # Arguments
///
/// * `info` - Panic information
///
/// # Returns
///
/// `!` - Never returns
#[inline(never)]
pub fn cfi_panic(info: CfiPanicInfo) -> ! {
    // Prevent the compiler from optimizing the reason
    let _ = cfi_launder(info);

    #[cfg(feature = "cfi")]
    {
        #[cfg(feature = "cfi-test")]
        {
            panic!("CFI Panic = {:04x?}", info);
        }

        #[cfg(not(feature = "cfi-test"))]
        {
            extern "C" {
                fn cfi_panic_handler(code: u32) -> !;
            }
            unsafe {
                cfi_panic_handler(CaliptraError::from(info).into());
            }
        }
    }

    #[cfg(not(feature = "cfi"))]
    {
        unimplemented!()
    }
}

macro_rules! cfi_assert_macro {
    ($name: ident, $op: tt, $trait1: path, $trait2: path, $panic_info: ident) => {
        /// CFI Binary Condition Assertion
        ///
        /// # Arguments
        ///
        /// `a` - Left hand side
        /// `b` - Right hand side
        #[inline(always)]
        #[allow(unused)]
        pub fn $name<T>(lhs: T, rhs: T)
        where
            T: $trait1 + $trait2,
        {
            if cfg!(feature = "cfi") {
                CfiCounter::delay();
                if !(lhs $op rhs) {
                    cfi_panic(CfiPanicInfo::$panic_info);
                }

                // Second check for glitch protection
                CfiCounter::delay();
                if !(cfi_launder(lhs) $op cfi_launder(rhs)) {
                    cfi_panic(CfiPanicInfo::$panic_info);
                }

            } else {
                lhs $op rhs;
            }
        }
    };
}

cfi_assert_macro!(cfi_assert_eq, ==, PartialEq, PartialEq, AssertEqFail);
cfi_assert_macro!(cfi_assert_ne, !=, PartialEq, PartialEq, AssertNeFail);
cfi_assert_macro!(cfi_assert_gt, >, Ord, PartialOrd, AssertGtFail);
cfi_assert_macro!(cfi_assert_lt, <, Ord, PartialOrd, AssertLtFail);
cfi_assert_macro!(cfi_assert_ge, >=, Ord, PartialOrd, AssertGeFail);
cfi_assert_macro!(cfi_assert_le, <=, Ord, PartialOrd, AssertLeFail);

#[macro_export]
macro_rules! cfi_assert {
    ($cond: expr) => {
        cfi_assert_eq($cond, true)
    };
}

#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
pub fn cfi_assert_eq_12_words(a: &[u32; 12], b: &[u32; 12]) {
    if a != b {
        cfi_panic(CfiPanicInfo::AssertEqFail)
    }
}

/// Unrolled comparison of 12 words
///
/// Written in assembly so the trampoline is above the comparisons rather than
/// below
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[inline(always)]
pub fn cfi_assert_eq_12_words(a: &[u32; 12], b: &[u32; 12]) {
    unsafe {
        core::arch::asm!(
            "j 3f",
            "2:",
            "li a0, 0x01040055",
            "j cfi_panic_handler",
            "3:",
            "lw {tmp0}, 0(a4)",
            "lw {tmp1}, 0(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 4(a4)",
            "lw {tmp1}, 4(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 8(a4)",
            "lw {tmp1}, 8(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 12(a4)",
            "lw {tmp1}, 12(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 16(a4)",
            "lw {tmp1}, 16(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 20(a4)",
            "lw {tmp1}, 20(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 24(a4)",
            "lw {tmp1}, 24(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 28(a4)",
            "lw {tmp1}, 28(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 32(a4)",
            "lw {tmp1}, 32(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 36(a4)",
            "lw {tmp1}, 36(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 40(a4)",
            "lw {tmp1}, 40(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 44(a4)",
            "lw {tmp1}, 44(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            in("a4") a.as_ptr(),
            in("a5") b.as_ptr(),
            tmp0 = out(reg) _,
            tmp1 = out(reg) _);
    }
}

#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
pub fn cfi_assert_eq_8_words(a: &[u32; 8], b: &[u32; 8]) {
    if a != b {
        cfi_panic(CfiPanicInfo::AssertEqFail)
    }
}

/// Unrolled comparison of 8 words
///
/// Written in assembly so the trampoline is above the comparisons rather than
/// below
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[inline(always)]
pub fn cfi_assert_eq_8_words(a: &[u32; 8], b: &[u32; 8]) {
    unsafe {
        core::arch::asm!(
            "j 3f",
            "2:",
            "li a0, 0x01040055",
            "j cfi_panic_handler",
            "3:",
            "lw {tmp0}, 0(a4)",
            "lw {tmp1}, 0(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 4(a4)",
            "lw {tmp1}, 4(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 8(a4)",
            "lw {tmp1}, 8(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 12(a4)",
            "lw {tmp1}, 12(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 16(a4)",
            "lw {tmp1}, 16(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 20(a4)",
            "lw {tmp1}, 20(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 24(a4)",
            "lw {tmp1}, 24(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 28(a4)",
            "lw {tmp1}, 28(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            in("a4") a.as_ptr(),
            in("a5") b.as_ptr(),
            tmp0 = out(reg) _,
            tmp1 = out(reg) _);
    }
}

#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
pub fn cfi_assert_eq_6_words(a: &[u32; 6], b: &[u32; 6]) {
    if a != b {
        cfi_panic(CfiPanicInfo::AssertEqFail)
    }
}

/// Unrolled comparison of 6 words
///
/// Written in assembly so the trampoline is above the comparisons rather than
/// below
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[inline(always)]
pub fn cfi_assert_eq_6_words(a: &[u32; 6], b: &[u32; 6]) {
    unsafe {
        core::arch::asm!(
            "j 3f",
            "2:",
            "li a0, 0x01040055",
            "j cfi_panic_handler",
            "3:",
            "lw {tmp0}, 0(a4)",
            "lw {tmp1}, 0(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 4(a4)",
            "lw {tmp1}, 4(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 8(a4)",
            "lw {tmp1}, 8(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 12(a4)",
            "lw {tmp1}, 12(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 16(a4)",
            "lw {tmp1}, 16(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            "lw {tmp0}, 20(a4)",
            "lw {tmp1}, 20(a5)",
            "bne {tmp0}, {tmp1}, 2b",
            in("a4") a.as_ptr(),
            in("a5") b.as_ptr(),
            tmp0 = out(reg) _,
            tmp1 = out(reg) _);
    }
}
