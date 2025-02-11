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

use caliptra_error::CaliptraResult;

use crate::cfi::{cfi_panic, CfiPanicInfo};
use crate::with_cfi_state;
use core::default::Default;

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
    #[inline(always)]
    pub fn reset(entropy_gen: &mut impl FnMut() -> CaliptraResult<[u32; 12]>) {
        with_cfi_state(|cfi_state| cfi_state.prng.mix_entropy(entropy_gen));
        Self::reset_internal();
    }

    #[cfg(feature = "cfi-test")]
    pub fn reset_for_test() {
        Self::reset_internal()
    }

    fn reset_internal() {
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
        let cycles = with_cfi_state(|cfi_state| cfi_state.prng.next() % 256);
        let _real_cyc = 1 + cycles / 2;
        #[cfg(all(target_arch = "riscv32", feature = "cfi", feature = "cfi-counter"))]
        unsafe {
            core::arch::asm!(
                "1:",
                "addi {0}, {0}, -1",
                "bne {0}, zero, 1b",
                inout(reg) _real_cyc => _,
                options(nomem, nostack),
            );
        }
    }

    /// Read counter value
    pub fn read() -> CfiInt {
        with_cfi_state(|cfi_state| CfiInt::from_raw(cfi_state.val.get(), cfi_state.mask.get()))
    }

    /// Write counter value
    fn write(val: CfiInt) {
        with_cfi_state(|cfi_state| {
            cfi_state.val.set(val.val);
            cfi_state.mask.set(val.masked_val);
        });
    }
}
