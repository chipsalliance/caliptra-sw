/*++

Licensed under the Apache-2.0 license.

File Name:

    xoshiro.rs

Abstract:

    File contains implementation of RNG based on System.Random Xoshiro128** algorithm.

References:
    https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Random.Xoshiro128StarStarImpl.cs

--*/

use crate::{cfi_panic, CfiPanicInfo};
#[cfg(not(feature = "cfi-test"))]
use caliptra_common::memory_layout::{CFI_XO_S0_ORG, CFI_XO_S1_ORG, CFI_XO_S2_ORG, CFI_XO_S3_ORG};

#[cfg(feature = "cfi-test")]
static mut S0: u32 = 0u32;
#[cfg(feature = "cfi-test")]
static mut S1: u32 = 0u32;
#[cfg(feature = "cfi-test")]
static mut S2: u32 = 0u32;
#[cfg(feature = "cfi-test")]
static mut S3: u32 = 0u32;

pub struct Xoshiro128Reg;

impl Xoshiro128Reg {
    pub fn s0(&self) -> u32 {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                core::ptr::read_volatile(&S0 as *const u32)
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                core::ptr::read_volatile(CFI_XO_S0_ORG as *const u32)
            }
        }
    }

    pub fn set_s0(&self, val: u32) {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                core::ptr::write_volatile(&mut S0 as *mut u32, val);
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                core::ptr::write_volatile(CFI_XO_S0_ORG as *mut u32, val);
            }
        }
    }

    pub fn s1(&self) -> u32 {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                core::ptr::read_volatile(&S1 as *const u32)
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                core::ptr::read_volatile(CFI_XO_S1_ORG as *const u32)
            }
        }
    }

    pub fn set_s1(&self, val: u32) {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                core::ptr::write_volatile(&mut S1 as *mut u32, val);
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                core::ptr::write_volatile(CFI_XO_S1_ORG as *mut u32, val);
            }
        }
    }

    pub fn s2(&self) -> u32 {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                core::ptr::read_volatile(&S2 as *const u32)
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                core::ptr::read_volatile(CFI_XO_S2_ORG as *const u32)
            }
        }
    }

    pub fn set_s2(&self, val: u32) {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                core::ptr::write_volatile(&mut S2 as *mut u32, val);
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                core::ptr::write_volatile(CFI_XO_S2_ORG as *mut u32, val);
            }
        }
    }

    pub fn s3(&self) -> u32 {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                core::ptr::read_volatile(&S3 as *const u32)
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                core::ptr::read_volatile(CFI_XO_S3_ORG as *const u32)
            }
        }
    }

    pub fn set_s3(&self, val: u32) {
        unsafe {
            #[cfg(feature = "cfi-test")]
            {
                core::ptr::write_volatile(&mut S3 as *mut u32, val);
            }

            #[cfg(not(feature = "cfi-test"))]
            {
                core::ptr::write_volatile(CFI_XO_S3_ORG as *mut u32, val);
            }
        }
    }
}

/// Provides an implementation of the xoshiro128** algorithm. This implementation is used
/// on 32-bit when no seed is specified and an instance of the base Random class is constructed.
/// As such, we are free to implement however we see fit, without back compat concerns around
/// the sequence of numbers generated or what methods call what other methods.
pub struct Xoshiro128 {
    reg: Xoshiro128Reg,
}

impl Xoshiro128 {
    /// Create a new instance of the xoshiro128** algorithm.
    ///
    /// # Arguments
    ///
    /// * `reg` - Register to use
    ///
    /// # Returns
    ///
    /// * Instance of the xoshiro128** algorithm
    pub(crate) fn new(reg: Xoshiro128Reg) -> Self {
        if !cfg!(feature = "cfi-test") {
            let mut trng = unsafe {
                caliptra_drivers::Trng::assume_initialized(
                    caliptra_registers::csrng::CsrngReg::new(),
                    caliptra_registers::entropy_src::EntropySrcReg::new(),
                    caliptra_registers::soc_ifc_trng::SocIfcTrngReg::new(),
                    &caliptra_registers::soc_ifc::SocIfcReg::new(),
                )
            };

            loop {
                if let Ok(entropy) = trng.generate() {
                    reg.set_s0(entropy.0[0]);
                    reg.set_s1(entropy.0[1]);
                    reg.set_s2(entropy.0[2]);
                    reg.set_s3(entropy.0[3]);
                } else {
                    cfi_panic(CfiPanicInfo::TrngError)
                }

                // Atlease one value must be non-zero
                if reg.s0() | reg.s1() | reg.s2() | reg.s3() != 0 {
                    break;
                }
            }
        }

        Self { reg }
    }

    /// Create a new instance of the xoshiro128** algorithm from a register
    pub fn assume_init(reg: Xoshiro128Reg) -> Self {
        Self { reg }
    }

    /// Get the next random number
    pub fn next(&self) -> u32 {
        // next is based on the algorithm from http://prng.di.unimi.it/xoshiro128starstar.c:
        //
        //     Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)
        //
        //     To the extent possible under law, the author has dedicated all copyright
        //     and related and neighboring rights to this software to the public domain
        //     worldwide. This software is distributed without any warranty.
        //
        //     See <http://creativecommons.org/publicdomain/zero/1.0/>.
        let mut s0 = self.reg.s0();
        let mut s1 = self.reg.s1();
        let mut s2 = self.reg.s2();
        let mut s3 = self.reg.s3();

        let result = u32::wrapping_mul(u32::wrapping_mul(s1, 5).rotate_left(7), 9);
        let t = s1 << 9;

        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;

        s2 ^= t;
        s3 = s3.rotate_left(11);

        self.reg.set_s0(s0);
        self.reg.set_s1(s1);
        self.reg.set_s2(s2);
        self.reg.set_s3(s3);

        result
    }
}
