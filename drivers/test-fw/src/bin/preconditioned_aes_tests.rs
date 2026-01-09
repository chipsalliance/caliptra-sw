// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    preconditioned_aes::{preconditioned_aes_decrypt, preconditioned_aes_encrypt},
    AesKey, LEArray4x8,
};
use caliptra_drivers_test_bin::TestRegisters;
use caliptra_test_harness::test_suite;

test_suite! {
    test_preconditioned_key_aes,
}

fn test_preconditioned_key_aes() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    let key = LEArray4x8::default();

    let salt = [0xFF; 12];
    let pt = [0xAB; 32];
    let mut ct = [0; 32];
    let result = preconditioned_aes_encrypt(
        &mut regs.aes,
        &mut regs.trng,
        AesKey::Array(&key),
        b"hello world",
        b"aad",
        &salt,
        &pt,
        &mut ct,
    )
    .unwrap();

    let mut pt = [0; 32];
    let key = LEArray4x8::default();
    preconditioned_aes_decrypt(
        &mut regs.aes,
        &mut regs.trng,
        AesKey::Array(&key),
        b"hello world",
        b"aad",
        &salt,
        &ct,
        &mut pt,
        &result.iv,
        &result.tag,
    )
    .unwrap();

    assert_eq!(pt, [0xAB; 32]);
}
