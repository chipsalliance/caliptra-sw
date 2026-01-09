// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    preconditioned_aes::{preconditioned_aes_decrypt, preconditioned_aes_encrypt},
    Array4x16, HmacKey, KeyId, KeyReadArgs, KeyUsage,
};
use caliptra_drivers_test_bin::{populate_slot, TestRegisters};
use caliptra_test_harness::test_suite;

test_suite! {
    test_preconditioned_key_aes,
    test_preconditioned_key_aes_kv,
}

fn test_preconditioned_key_aes() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    let key = Array4x16::default();
    let key = HmacKey::Array4x16(&key);

    let pt = [0xAB; 32];
    let mut ct = [0; 32];
    let result = preconditioned_aes_encrypt(
        &mut regs.aes,
        &mut regs.hmac,
        &mut regs.trng,
        key,
        b"hello world",
        b"aad",
        &pt,
        &mut ct,
    )
    .unwrap();

    let mut pt = [0; 32];
    preconditioned_aes_decrypt(
        &mut regs.aes,
        &mut regs.hmac,
        &mut regs.trng,
        key,
        b"hello world",
        b"aad",
        &result.salt,
        &result.iv,
        &result.tag,
        &ct,
        &mut pt,
    )
    .unwrap();

    assert_eq!(pt, [0xAB; 32]);
}

fn test_preconditioned_key_aes_kv() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    populate_slot(
        &mut regs.hmac,
        &mut regs.trng,
        KeyId::KeyId0,
        KeyUsage::default().set_hmac_key_en(),
    )
    .unwrap();

    let key = HmacKey::Key(KeyReadArgs::new(KeyId::KeyId0));

    let pt = [0xAB; 32];
    let mut ct = [0; 32];
    let result = preconditioned_aes_encrypt(
        &mut regs.aes,
        &mut regs.hmac,
        &mut regs.trng,
        key,
        b"hello world",
        b"aad",
        &pt,
        &mut ct,
    )
    .unwrap();

    populate_slot(
        &mut regs.hmac,
        &mut regs.trng,
        KeyId::KeyId0,
        KeyUsage::default().set_hmac_key_en(),
    )
    .unwrap();

    let mut pt = [0; 32];
    preconditioned_aes_decrypt(
        &mut regs.aes,
        &mut regs.hmac,
        &mut regs.trng,
        key,
        b"hello world",
        b"aad",
        &result.salt,
        &result.iv,
        &result.tag,
        &ct,
        &mut pt,
    )
    .unwrap();

    assert_eq!(pt, [0xAB; 32]);
}
