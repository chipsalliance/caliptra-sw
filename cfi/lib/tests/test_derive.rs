/*++

Licensed under the Apache-2.0 license.

File Name:

    test_derive.rs

--*/

use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_cfi_lib::{CfiCounter, Xoshiro128};
use serial_test::serial;

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
#[serial]
#[cfg(feature = "cfi-counter")]
#[should_panic(expected = "CFI Panic = CounterCorrupt")]
fn test_with_not_initialized_counter() {
    CfiCounter::corrupt();
    assert_eq!(test1(10), 10);
}

#[test]
#[serial]
fn test_with_initialized_counter() {
    CfiCounter::reset_for_test();
    assert_eq!(test1(10), 10);

    assert_eq!(Test::test1(10), 10);

    let test = Test;
    assert_eq!(test.test_self1(10), 10);
}

#[test]
fn test_rand() {
    // Expected random numbers generated from a modified implementation of:
    // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Random.Xoshiro128StarStarImpl.cs
    let expected_rand_num: [u32; 20] = [
        11520, 0, 5927040, 70819200, 2031721883, 1637235492, 1287239034, 3734860849, 3729100597,
        4258142804, 337829053, 2142557243, 3576906021, 2006103318, 3870238204, 1001584594,
        3804789018, 2299676403, 3571406116, 2962224741,
    ];
    let prng = Xoshiro128::new_with_seed(1, 2, 3, 4);
    for expected_rand_num in expected_rand_num.iter() {
        assert_eq!(prng.next(), *expected_rand_num);
    }
}

#[test]
fn test_rand_stress() {
    let prng = Xoshiro128::new_with_seed(1, 2, 3, 4);
    for _idx in 0..1000 {
        prng.next();
    }
}
