/*++

Licensed under the Apache-2.0 license.

File Name:

    cfi_ctr.rs

Abstract:

    File contains CFI Integer and Counter implementations. The counter is based on ideas from
    Trusted Firmware-M firmware.

References:
    https://tf-m-user-guide.trustedfirmware.org/design_docs/tfm_physical_attack_mitigation.html

--*/

use crate::cfi::{cfi_panic, CfiPanicInfo};
use crate::xoshiro::{Xoshiro128, Xoshiro128Reg};
#[cfg(not(feature = "cfi-test"))]
use caliptra_common::memory_layout::{CFI_MASK_ORG, CFI_VAL_ORG};
use core::default::Default;

#[cfg(feature = "cfi-test")]
static mut CFI_VAL: u32 = 0u32;
#[cfg(feature = "cfi-test")]
static mut CFI_MASK: u32 = 0u32;

/// CFI Integer
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct CfiInt {
    /// Actual Value
    val: u32,

    /// Masked Value
    masked_val: u32,
}

impl CfiInt {
    /// Integer mask with high hamming distance
    const MASK: u32 = 0xA5A5A5A5;

    /// Create integer from raw values
    fn from_raw(val: u32, masked_val: u32) -> Self {
        Self { val, masked_val }
    }

    /// Encode the integer
    fn encode(val: u32) -> Self {
        Self {
            val,
            masked_val: val ^ Self::MASK,
        }
    }

    /// Check if the integer is valid
    fn is_valid(&self) -> bool {
        self.val == self.masked_val ^ Self::MASK
    }
}

impl Default for CfiInt {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self::encode(0)
    }
}

/// CFI counter
pub enum CfiCounter {}

impl CfiCounter {
    /// Reset counter
    #[inline(never)]
    pub fn reset() {
        Xoshiro128::new(Xoshiro128Reg);
        Self::write(CfiInt::default());
    }

    // Zero the counter
    pub fn corrupt() {
        Self::write(CfiInt {
            val: 0,
            masked_val: 0,
        });
    }

    /// Increment counter
    #[inline(never)]
    pub fn increment() -> CfiInt {
        if cfg!(all(feature = "cfi", feature = "cfi-counter")) {
            let int = Self::read();
            if !int.is_valid() {
                cfi_panic(CfiPanicInfo::CounterCorrupt);
            }

            let (new, overflow) = int.val.overflowing_add(1);
            if overflow {
                cfi_panic(CfiPanicInfo::CounterOverflow);
            }

            let new_int = CfiInt::encode(new);
            Self::write(new_int);

            int
        } else {
            CfiInt::default()
        }
    }

    /// Decrement Counter
    #[inline(never)]
    pub fn decrement() -> CfiInt {
        if cfg!(all(feature = "cfi", feature = "cfi-counter")) {
            let val = Self::read();
            if !val.is_valid() {
                cfi_panic(CfiPanicInfo::CounterCorrupt);
            }

            let (new, underflow) = val.val.overflowing_sub(1);
            if underflow {
                cfi_panic(CfiPanicInfo::CounterUnderflow);
            }

            let new_val = CfiInt::encode(new);
            Self::write(new_val);

            Self::read()
        } else {
            CfiInt::default()
        }
    }

    /// Assert the counters are equal
    #[inline(never)]
    pub fn assert_eq(val1: CfiInt, val2: CfiInt) {
        if cfg!(all(feature = "cfi", feature = "cfi-counter")) {
            if !val1.is_valid() {
                cfi_panic(CfiPanicInfo::CounterCorrupt);
            }
            if !val2.is_valid() {
                cfi_panic(CfiPanicInfo::CounterCorrupt);
            }
            if val1 != val2 {
                cfi_panic(CfiPanicInfo::CounterMismatch);
            }
        }
    }

    #[inline(never)]
    pub fn delay() {
        #[cfg(all(target_arch = "riscv32", feature = "cfi", feature = "cfi-counter"))]
        unsafe {
            let cycles = Xoshiro128::assume_init(Xoshiro128Reg).next() % 256;
            let real_cyc = 1 + cycles / 2;
            core::arch::asm!(
                "1:",
                "addi {0}, {0}, -1",
                "bne {0}, zero, 1b",
                inout(reg) real_cyc => _,
                options(nomem, nostack),
            );
        }
    }

    /// Read counter value
    fn read() -> CfiInt {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                CfiInt::from_raw(
                    core::ptr::read_volatile(&CFI_VAL as *const u32),
                    core::ptr::read_volatile(&CFI_MASK as *const u32),
                )
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                CfiInt::from_raw(
                    core::ptr::read_volatile(CFI_VAL_ORG as *const u32),
                    core::ptr::read_volatile(CFI_MASK_ORG as *const u32),
                )
            }
        }
    }

    /// Write counter value
    fn write(val: CfiInt) {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                core::ptr::write_volatile(&mut CFI_VAL as *mut u32, val.val);
                core::ptr::write_volatile(&mut CFI_MASK as *mut u32, val.masked_val);
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                core::ptr::write_volatile(CFI_VAL_ORG as *mut u32, val.val);
                core::ptr::write_volatile(CFI_MASK_ORG as *mut u32, val.masked_val);
            }
        }
    }
}
