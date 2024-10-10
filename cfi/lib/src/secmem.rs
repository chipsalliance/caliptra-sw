/*++

Licensed under the Apache-2.0 license.

File Name:

    secmem.rs

Abstract:

    File contains support routines and macros for secure memory operations.

--*/

use core::ptr;

//use crate::{cfi_assert_eq, cfi_assert_ne};

// Adapted from https://github.com/lowRISC/opentitan/blob/7a61300cf7c409fa68fd892942c1d7b58a7cd4c0/sw/device/lib/base/hardened_asm.h
// and https://github.com/lowRISC/opentitan/blob/7a61300cf7c409fa68fd892942c1d7b58a7cd4c0/sw/device/lib/base/hardened_memory.c
// which are:
// Copyright lowRISC contributors.

/// Values for a hardened boolean type.
///
/// The intention is that this is used instead of `<stdbool.h>`'s #bool, where a
/// higher hamming distance is required between the truthy and the falsey value.
///
/// The values below were chosen at random, with some specific restrictions. They
/// have a Hamming Distance of 8, and they are 11-bit values so they can be
/// materialized with a single instruction on RISC-V. They are also specifically
/// not the complement of each other.
// pub type HardenedBool = u32;
// pub const HARDENED_BOOL_TRUE: HardenedBool = 0x739;
// pub const HARDENED_BOOL_FALSE: HardenedBool = 0x1d4;

struct RandomOrder {
    state: u32,
    max: u32,
}

/// Context for a random traversal order.
///
/// A "random traversal order" specifies a random order to walk through some
/// buffer of length `n`, which is an important building block for
/// constant-power code. Given `n`, the random order emits integers in the
/// range `0..m`, where `m` is an implementation-defined, per-random-order
/// value greater than `n`. The order is guaranteed to visit each integer in
/// `0..n` at least once, but with some caveats:
/// - Values greater than `n` may be returned.
/// - The same value may be returned multiple times.
///
/// Users must be mindful of these constraints when using `RandomOrder`.
/// These caveats are intended to allow for implementation flexibility, such as
/// intentionally adding decoys to the sequence.
impl RandomOrder {
    /// Constructs a new, randomly-seeded traversal order,
    /// running from `0` to at least `min_len`.
    ///
    /// This function does not take a seed as input; instead, the seed is
    /// extracted, in some manner or another, from the hardware by this function.
    ///
    /// @param min_len The minimum length this traversal order must visit.
    fn new(min_len: u32) -> RandomOrder {
        RandomOrder {
            state: 0,
            max: (min_len + 1).next_power_of_two(),
        }
    }

    /// Returns the length of the sequence represented by `ctx`.
    ///
    /// This value may be greater than `min_len` specified in
    /// `random_order_init()`, but the sequence is guaranteed to contain every
    /// integer in `0..min_len`.
    ///
    /// This value represents the number of times `random_order_advance()` may be
    /// called.
    ///
    /// @param ctx The context to query.
    /// @return The length of the sequence.
    fn len(&self) -> u32 {
        self.max
    }

    /// Returns the next element in the sequence represented by `ctx`.
    ///
    /// See `random_order_len()` for discovering how many times this function can
    /// be called.
    ///
    /// @param ctx The context to advance.
    /// @return The next value in the sequence.
    fn advance(&mut self) -> u32 {
        // TODO: The current implementation is just a skeleton, and currently just
        // traverses from 0 to `min_len * 2`.
        let s = self.state ^ (self.state >> 1);
        self.state += 1;
        s
    }
}

#[inline(always)]
pub fn memeq(lhs: &[u32], rhs: &[u32]) -> bool {
    hardened_memeq(lhs, rhs) == true
}

// Performs constant-time unsigned ascending comparison.
// Returns `a < b` as a constant-time boolean.
#[inline(always)]
fn ct_slt(a: usize, b: usize) -> usize {
    ct_sltz(((a & !b) | ((a ^ !b) & (a.wrapping_sub(b)))) as isize)
}

// Performs constant-time signed comparison to zero.
// Returns whether `a < 0`, as a constant-time boolean.
// In other words, this checks if `a` is negative, i.e., its sign bit is set.
#[inline(always)]
fn ct_sltz(a: isize) -> usize {
    // Proof. `a` is negative iff its MSB is set;
    // arithmetic-right-shifting by bits(a)-1 smears the sign bit across all
    // of `a`.
    ((a as isize) >> (usize::BITS - 1)) as usize
}

// Performs a constant-time select.
// Returns `a` if `c` is true; otherwise, returns `b`.
// This function should be used with one of the comparison functions above; do
// NOT create `c` using an `if` or `?:` operation.
#[inline(always)]
fn ct_cmov(c: usize, a: usize, b: usize) -> usize {
    (launders(c) & a) | (launders(!c) & b)
}

#[inline(never)]
pub fn hardened_memeq(lhs: &[u32], rhs: &[u32]) -> bool {
    let word_len = lhs.len();
    //assert_eq!(word_len, rhs.len());
    if word_len != rhs.len() {
        return false; //HARDENED_BOOL_FALSE;
    }

    let mut order = RandomOrder::new(word_len as u32);

    let mut count: u32 = 0;
    let expected_count = order.len();
    //let expected_count = (word_len as u32).next_power_of_two();

    let lhs_addr = lhs.as_ptr() as usize;
    let rhs_addr = rhs.as_ptr() as usize;

    // `decoys` is a small stack array that is filled with values with a Hamming weight
    // of around 16, which is the most common Hamming weight among 32-bit words.
    //
    // It is scratch space for us to do "extra" operations, when the number of
    // iteration indices the chosen random order is different from `word_len`.
    //
    // These extra operations also introduce noise that an attacker must do work
    // to filter, such as by applying side-channel analysis to obtain an address
    // trace.
    const DECOYS: usize = 8;
    let decoys: [u32; DECOYS] = [0xaaaaaaaa; DECOYS];
    let decoy_addr = decoys.as_ptr() as usize;

    let mut zeros = 0;
    let mut ones = u32::MAX;

    let byte_len = word_len * core::mem::size_of::<u32>();
    while count < expected_count {
        // The order values themselves are in units of words, but we need `byte_idx`
        // to be in units of bytes.
        //
        // The value obtained from `advance()` is laundered to prevent
        // implementation details from leaking across procedures.
        let byte_idx = launder(order.advance()) as usize * core::mem::size_of::<u32>();
        //let byte_idx = ((count ^ (count >> 1)) * 4) as usize;

        // Prevent the compiler from reordering the loop; this ensures a
        // happens-before among indices consistent with `order`.
        barrier(byte_idx as u32);

        // Compute putative offsets into `src`, `dest`, and `decoys`. Some of these
        // may go off the end of `src` and `dest`, but they will not be cast to
        // pointers in that case. (Note that casting out-of-range addresses to
        // pointers is UB.)
        let ap = lhs_addr + byte_idx;
        let bp = rhs_addr + byte_idx;
        let decoy1 = decoy_addr + (byte_idx % core::mem::size_of_val(&decoys));
        let decoy2 = decoy_addr
            + ((byte_idx + core::mem::size_of_val(&decoys) / 2) % core::mem::size_of_val(&decoys));

        // Branchlessly select whether to do a "real" comparison or a decoy comparison,
        // depending on whether we've gone off the end of the array or not.
        //
        // Pretty much everything needs to be laundered: we need to launder
        // `byte_idx` for obvious reasons, and we need to launder the result of the
        // select, so that the compiler cannot delete the resulting loads and
        // stores. This is similar to having used `volatile uint32_t *`.p
        let av = ct_cmov(ct_slt(byte_idx, byte_len), ap, decoy1) as *const u32;
        let bv = ct_cmov(ct_slt(byte_idx, byte_len), bp, decoy2) as *const u32;

        let a = unsafe { ptr::read_volatile(av) };
        let b = unsafe { ptr::read_volatile(bv) };

        // Launder one of the operands so that the compiler cannot cache the result
        // of the xor for use in the next operation.
        //
        // We launder `zeroes` so that compiler cannot learn that `zeroes` has
        // strictly more bits set at the end of the loop.
        zeros = launder(zeros) | (launder(a) ^ b);

        // Same as above. The compiler can cache the value of `a[offset]` but it
        // has no chance to strength-reduce this operation.
        ones = launder(ones) & (launder(a) ^ !b);

        // We need to launder `count` so that the SW.LOOP-COMPLETION check is not
        // deleted by the compiler.
        count = launder(count) + 1;
    }

    if launder(zeros) == 0 {
        //cfi_assert_eq(ones, u32::MAX);
        if ones == u32::MAX {
            return true;
        }
    }

    //cfi_assert_ne(ones, u32::MAX);
    false
}

#[allow(asm_sub_register)] // otherwise x86 complains about the no-op asm
#[inline(always)]
fn launder(mut val: u32) -> u32 {
    unsafe {
        core::arch::asm!(
            "/* {t} */",
            t = inout(reg) val,
        );
    }
    val
}

#[allow(asm_sub_register)] // otherwise x86 complains about the no-op asm
#[inline(always)]
fn launders(mut val: usize) -> usize {
    unsafe {
        core::arch::asm!(
            "/* {t} */",
            t = inout(reg) val,
        );
    }
    val
}

#[allow(asm_sub_register)] // otherwise x86 complains about the no-op asm
#[inline(always)]
fn barrier(val: u32) {
    unsafe {
        core::arch::asm!(
            "/* {t} */",
            t = in(reg) val,
        );
    }
}
