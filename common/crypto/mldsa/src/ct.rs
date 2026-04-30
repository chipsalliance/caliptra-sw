// Licensed under the Apache-2.0 license

#![allow(dead_code)]

#[inline(always)]
pub fn ct_value_barrier(x: u32) -> u32 {
    core::hint::black_box(x)
}

#[inline(always)]
pub fn ct_if(mask: u32, a: u32, b: u32) -> u32 {
    let mask = ct_value_barrier(mask);
    (mask & a) | (!mask & b)
}

#[inline(always)]
pub fn ct_lt(a: u32, b: u32) -> u32 {
    let mask = a ^ ((a ^ b) | (a.wrapping_sub(b) ^ a));
    0u32.wrapping_sub(mask >> 31)
}

#[inline(always)]
pub fn ct_ge(a: u32, b: u32) -> u32 {
    !ct_lt(a, b)
}
