/*++

Licensed under the Apache-2.0 license.

File Name:

    test_derive.rs

--*/

use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_cfi_lib::{CfiCounter, Xoshiro128, Xoshiro128Reg};

#[cfi_mod_fn]
fn test1<T>(val: T) -> T {
    test2(val)
}

#[cfi_mod_fn]
fn test2<T>(val: T) -> T {
    val
}

struct Test;

impl Test {
    #[cfi_mod_fn]
    fn test1<T>(val: T) -> T {
        test2(val)
    }

    #[cfi_mod_fn]
    #[allow(dead_code)]
    fn test2<T>(val: T) -> T {
        val
    }

    #[cfi_impl_fn]
    fn test_self1<T>(&self, val: T) -> T {
        test2(val)
    }

    #[cfi_impl_fn]
    #[allow(dead_code)]
    fn test_self2<T>(&self, val: T) -> T {
        test2(val)
    }
}

#[test]
#[cfg(feature = "cfi-counter")]
#[should_panic(expected = "CFI Panic = CounterCorrupt")]
fn test_with_not_initialized_counter() {
    CfiCounter::corrupt();
    assert_eq!(test1(10), 10);
}

#[test]
fn test_with_initialized_counter() {
    CfiCounter::reset();
    assert_eq!(test1(10), 10);

    assert_eq!(Test::test1(10), 10);

    let test = Test;
    assert_eq!(test.test_self1(10), 10);
}

#[test]
fn test_rand_seed_read_write() {
    let reg = Xoshiro128Reg;
    reg.set_s0(1);
    assert_eq!(reg.s0(), 1);

    reg.set_s1(2);
    assert_eq!(reg.s1(), 2);

    reg.set_s2(3);
    assert_eq!(reg.s2(), 3);

    reg.set_s3(4);
    assert_eq!(reg.s3(), 4);
}

#[test]
fn test_rand() {
    let reg = Xoshiro128Reg;

    // Expected random numbers generated from a modified implementation of:
    // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Random.Xoshiro128StarStarImpl.cs
    let expected_rand_num: [u32; 20] = [
        11520, 0, 5927040, 70819200, 2031721883, 1637235492, 1287239034, 3734860849, 3729100597,
        4258142804, 337829053, 2142557243, 3576906021, 2006103318, 3870238204, 1001584594,
        3804789018, 2299676403, 3571406116, 2962224741,
    ];
    reg.set_s0(1);
    reg.set_s1(2);
    reg.set_s2(3);
    reg.set_s3(4);
    for expected_rand_num in expected_rand_num.iter() {
        assert_eq!(
            Xoshiro128::assume_init(Xoshiro128Reg).next(),
            *expected_rand_num
        );
    }
}

#[test]
fn test_rand_stress() {
    let reg = Xoshiro128Reg;
    reg.set_s0(1);
    reg.set_s1(2);
    reg.set_s2(3);
    reg.set_s3(4);
    for _idx in 0..1000 {
        let _ = Xoshiro128::assume_init(Xoshiro128Reg).next();
    }
}
