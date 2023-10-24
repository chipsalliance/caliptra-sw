/*++

Licensed under the Apache-2.0 license.

File Name:

    xoshiro.rs

Abstract:

    File contains implementation of RNG based on System.Random Xoshiro128** algorithm.

References:
    https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Random.Xoshiro128StarStarImpl.cs

--*/

use core::cell::Cell;

use crate::{cfi_panic, CfiPanicInfo};

/// Provides an implementation of the xoshiro128** algorithm. This implementation is used
/// on 32-bit when no seed is specified and an instance of the base Random class is constructed.
/// As such, we are free to implement however we see fit, without back compat concerns around
/// the sequence of numbers generated or what methods call what other methods.
#[repr(C)]
pub struct Xoshiro128 {
    // It is critical for safety that every bit-pattern of this struct
    // is valid (no padding, no enums, no references), similar to the requirements for
    // zerocopy::FromBytes.
    s0: Cell<u32>,
    s1: Cell<u32>,
    s2: Cell<u32>,
    s3: Cell<u32>,
}

impl Xoshiro128 {
    /// Create a new instance of the xoshiro128** algorithm seeded with zeroes.
    pub(crate) const fn new_unseeded() -> Self {
        Self::new_with_seed(0, 0, 0, 0)
    }

    /// Create a new instance of the xoshiro128** algorithm with a seed.
    pub const fn new_with_seed(s0: u32, s1: u32, s2: u32, s3: u32) -> Self {
        Self {
            s0: Cell::new(s0),
            s1: Cell::new(s1),
            s2: Cell::new(s2),
            s3: Cell::new(s3),
        }
    }

    /// Get a reference to a xoshiro instance backed by static memory
    ///
    /// # Safety
    ///
    /// Caller must verify that the memory locations between `addr` and
    /// `addr + size_of::<Xoshiro128>()` are valid and meet the alignment
    /// requirements of Xoshiro128, and are not used for anything else.
    pub unsafe fn from_address(addr: u32) -> &'static Self {
        &*(addr as *const Xoshiro128)
    }

    pub fn mix_entropy_from_trng(&self, trng: &mut caliptra_drivers::Trng) {
        loop {
            if let Ok(entropy) = trng.generate() {
                self.s0.set(self.s0.get() ^ entropy.0[0]);
                self.s1.set(self.s1.get() ^ entropy.0[1]);
                self.s2.set(self.s2.get() ^ entropy.0[2]);
                self.s3.set(self.s3.get() ^ entropy.0[3]);
            } else {
                cfi_panic(CfiPanicInfo::TrngError)
            }

            // Atlease one value must be non-zero
            if self.s0.get() | self.s1.get() | self.s2.get() | self.s3.get() != 0 {
                break;
            }
        }
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
        let mut s0 = self.s0.get();
        let mut s1 = self.s1.get();
        let mut s2 = self.s2.get();
        let mut s3 = self.s3.get();

        let result = u32::wrapping_mul(u32::wrapping_mul(s1, 5).rotate_left(7), 9);
        let t = s1 << 9;

        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;

        s2 ^= t;
        s3 = s3.rotate_left(11);

        self.s0.set(s0);
        self.s1.set(s1);
        self.s2.set(s2);
        self.s3.set(s3);

        result
    }
}
