// Licensed under the Apache-2.0 license
//
// No-assembly shim of caliptra-cfi-lib for WASM builds.
// CFI (Control Flow Integrity) is a firmware security feature for hardened
// RISC-V targets. The emulator doesn't need it, so all functions are no-ops.

#![no_std]
extern crate core;

use core::cmp::{Eq, Ord, PartialEq, PartialOrd};
use core::marker::{Copy, PhantomData};

// --- CfiPanicInfo ---

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CfiPanicInfo {
    CounterCorrupt,
    CounterOverflow,
    CounterUnderflow,
    CounterMismatch,
    AssertEqFail,
    AssertNeFail,
    AssertGtFail,
    AssertLtFail,
    AssertGeFail,
    AssertLeFail,
    TrngError,
    UnexpectedMatchBranch,
    UnknownError,
}

impl From<CfiPanicInfo> for u32 {
    fn from(val: CfiPanicInfo) -> Self {
        val as u32
    }
}

// --- Launder (no-op, no asm) ---

pub fn cfi_launder<T>(val: T) -> T
where
    Launder<T>: LaunderTrait<T>,
{
    val
}

pub trait LaunderTrait<T> {
    fn launder(&self, val: T) -> T {
        core::hint::black_box(val)
    }
}

pub struct Launder<T> {
    _val: PhantomData<T>,
}

impl LaunderTrait<u32> for Launder<u32> {
    fn launder(&self, val: u32) -> u32 {
        core::hint::black_box(val)
    }
}

impl LaunderTrait<bool> for Launder<bool> {
    fn launder(&self, val: bool) -> bool {
        core::hint::black_box(val)
    }
}

impl LaunderTrait<usize> for Launder<usize> {
    fn launder(&self, val: usize) -> usize {
        core::hint::black_box(val)
    }
}

impl<const N: usize, T> LaunderTrait<[T; N]> for Launder<[T; N]> {}
impl<'a, const N: usize, T> LaunderTrait<&'a [T; N]> for Launder<&'a [T; N]> {}
impl LaunderTrait<Option<u32>> for Launder<Option<u32>> {}
impl LaunderTrait<CfiPanicInfo> for Launder<CfiPanicInfo> {}

// --- cfi_panic ---

#[inline(never)]
pub fn cfi_panic(_info: CfiPanicInfo) -> ! {
    panic!("CFI panic (no-op shim)")
}

// --- Assertions (all no-ops) ---

#[inline(always)]
pub fn cfi_assert_eq<T>(_lhs: T, _rhs: T)
where
    T: Eq + PartialEq,
    Launder<T>: LaunderTrait<T>,
{
}

#[inline(always)]
pub fn cfi_assert_ne<T>(_lhs: T, _rhs: T)
where
    T: Eq + PartialEq,
    Launder<T>: LaunderTrait<T>,
{
}

#[inline(always)]
pub fn cfi_assert_gt<T>(_lhs: T, _rhs: T)
where
    T: Ord + PartialOrd,
    Launder<T>: LaunderTrait<T>,
{
}

#[inline(always)]
pub fn cfi_assert_lt<T>(_lhs: T, _rhs: T)
where
    T: Ord + PartialOrd,
    Launder<T>: LaunderTrait<T>,
{
}

#[inline(always)]
pub fn cfi_assert_ge<T>(_lhs: T, _rhs: T)
where
    T: Ord + PartialOrd,
    Launder<T>: LaunderTrait<T>,
{
}

#[inline(always)]
pub fn cfi_assert_le<T>(_lhs: T, _rhs: T)
where
    T: Ord + PartialOrd,
    Launder<T>: LaunderTrait<T>,
{
}

#[inline(always)]
pub fn cfi_assert_bool(_cond: bool) {}

#[macro_export]
macro_rules! cfi_assert {
    ($cond:expr) => {
        cfi_assert_bool($cond)
    };
}

pub fn cfi_assert_eq_16_words(_a: &[u32; 16], _b: &[u32; 16]) {}
pub fn cfi_assert_ne_16_words(_a: &[u32; 16], _b: &[u32; 16]) {}
pub fn cfi_assert_eq_12_words(_a: &[u32; 12], _b: &[u32; 12]) {}
pub fn cfi_assert_eq_8_words(_a: &[u32; 8], _b: &[u32; 8]) {}
pub fn cfi_assert_eq_6_words(_a: &[u32; 6], _b: &[u32; 6]) {}

// --- CfiInt / CfiCounter (no-ops) ---

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct CfiInt {
    val: u32,
    masked_val: u32,
}

impl Default for CfiInt {
    fn default() -> Self {
        Self {
            val: 0,
            masked_val: 0,
        }
    }
}

pub enum CfiCounter {}

impl CfiCounter {
    pub fn reset(_entropy_gen: &mut impl FnMut() -> CfiResult<(u32, u32, u32, u32)>) {}
    #[cfg(feature = "cfi-test")]
    pub fn reset_for_test() {}
    pub fn corrupt() {}
    pub fn increment() -> CfiInt {
        CfiInt::default()
    }
    pub fn decrement() -> CfiInt {
        CfiInt::default()
    }
    pub fn assert_eq(_val1: CfiInt, _val2: CfiInt) {}
    pub fn delay() {}
    pub fn read() -> CfiInt {
        CfiInt::default()
    }
}

// --- Error types ---

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CfiError(pub u32);

impl CfiError {
    pub const ROM_CFI_PANIC_ASSERT_EQ_FAILURE: Self = Self(0x01040055);
}

impl From<CfiError> for u32 {
    fn from(val: CfiError) -> Self {
        val.0
    }
}

pub type CfiResult<T> = core::result::Result<T, CfiError>;

// --- Xoshiro128 (minimal stub) ---

#[repr(C)]
pub struct Xoshiro128 {
    s0: u32,
    s1: u32,
    s2: u32,
    s3: u32,
}

impl Xoshiro128 {
    pub const fn new_unseeded() -> Self {
        Self::new_with_seed(0, 0, 0, 0)
    }
    pub const fn new_with_seed(s0: u32, s1: u32, s2: u32, s3: u32) -> Self {
        Self { s0, s1, s2, s3 }
    }
    pub fn mix_entropy(&self, _entropy_gen: &mut impl FnMut() -> CfiResult<(u32, u32, u32, u32)>) {
    }
    pub fn next(&self) -> u32 {
        0
    }
}

// --- CfiState (for completeness) ---

#[repr(C)]
pub struct CfiState {
    pub val: u32,
    pub mask: u32,
    pub prng: Xoshiro128,
}
