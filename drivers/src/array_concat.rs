// Licensed under the Apache-2.0 license

use core::mem::MaybeUninit;

#[inline(always)]
pub fn array_concat3<
    T: Copy,
    const LEN0: usize,
    const LEN1: usize,
    const LEN2: usize,
    const TOTAL_LEN: usize,
>(
    a0: [T; LEN0],
    a1: [T; LEN1],
    a2: [T; LEN2],
) -> [T; TOTAL_LEN] {
    let expected_total_len = LEN0 + LEN1 + LEN2;
    // Unfortunately, runtime assert is the only way to detect this today.
    // Fortunately, it will be optimized out when correct (and the ROM tests
    // check to make sure panic is impossible).
    assert!(
        expected_total_len == TOTAL_LEN,
        "TOTAL_LEN should be {expected_total_len}, was {TOTAL_LEN}"
    );
    let mut result = MaybeUninit::<[T; TOTAL_LEN]>::uninit();
    let mut ptr = result.as_mut_ptr() as *mut T;
    unsafe {
        ptr.copy_from_nonoverlapping(a0.as_ptr(), LEN0);
        ptr = ptr.add(LEN0);
        ptr.copy_from_nonoverlapping(a1.as_ptr(), LEN1);
        ptr = ptr.add(LEN1);
        ptr.copy_from_nonoverlapping(a2.as_ptr(), LEN2);
        result.assume_init()
    }
}

#[cfg(test)]
mod tests {
    use crate::array_concat3;

    // To run inside the MIRI interpreter to detect undefined behavior in the
    // unsafe code, run with:
    // cargo +nightly miri test -p caliptra-drivers --lib

    #[test]
    fn test_array_concat3_u8() {
        assert_eq!(
            array_concat3([0x01u8], [0x22, 0x23], [0x34, 0x35, 0x36]),
            [0x01, 0x22, 0x23, 0x34, 0x35, 0x36]
        );
        assert_eq!(
            array_concat3([0x01u8], [], [0x34, 0x35, 0x36]),
            [0x01, 0x34, 0x35, 0x36]
        );
        assert_eq!(
            array_concat3([], [], [0x34u8, 0x35, 0x36]),
            [0x34, 0x35, 0x36]
        );
        assert_eq!(array_concat3::<u8, 0, 0, 0, 0>([], [], []), []);
    }
    #[test]
    fn test_array_concat3_u16() {
        assert_eq!(
            array_concat3([0x101u16], [0x222, 0x223], [0x334, 0x335, 0x336]),
            [0x101, 0x222, 0x223, 0x334, 0x335, 0x336]
        );
    }
    #[test]
    #[should_panic(expected = "TOTAL_LEN should be 6, was 5")]
    fn test_array_concat3_result_too_small() {
        let _: [u8; 5] = array_concat3([0x01u8], [0x22, 0x23], [0x34, 0x35, 0x36]);
    }

    #[test]
    #[should_panic(expected = "TOTAL_LEN should be 6, was 7")]
    fn test_array_concat3_result_too_large() {
        let _: [u8; 7] = array_concat3([0x01u8], [0x22, 0x23], [0x34, 0x35, 0x36]);
    }
}
