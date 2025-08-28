/*++
Licensed under the Apache-2.0 license.

File Name:

    ocp_lock_tests.rs

Abstract:

    File contains test cases for OCP LOCK.

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    cmac_kdf, hmac_kdf, AesKey, Array4x4, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage,
    KeyWriteArgs,
};
use caliptra_drivers_test_bin::{
    hmac_kv_sequence_check, kv_release, populate_slot, TestRegisters, DOE_TEST_IV, ENCRYPTED_HEK,
};
use caliptra_test_harness::test_suite;

use itertools::Itertools;

const REGULAR_LOCK_KV_RANGE: core::ops::Range<u8> = core::ops::Range { start: 0, end: 17 };
const OCP_LOCK_KV_RANGE: core::ops::Range<u8> = core::ops::Range { start: 16, end: 24 };

// TODO(clundin): Write test to verify DOE flow works.
test_suite! {
    test_ocp_lock_enabled,
    test_hek_seed_fuse_bank,
    test_hek_seed_doe,
    test_aes_kv_release_unlocked,
    test_hmac_regular_kv_to_ocp_lock_kv_unlocked,
    // Run `test_hmac_regular_kv_to_ocp_lock_kv_unlocked` before to avoid overwriting MDK slot.
    test_populate_mdk,
    // Modifies behavior of subsequent tests.
    // Tests before should test "ROM" flows, afterwards they should test "Runtime" flows.
    test_set_ocp_lock_in_progress,
    test_decrypt_to_mek_kv_locked,
    test_kv_release, // Should be after `test_decrypt_to_mek_kv_locked`.
    test_decrypt_to_mek_kv_with_mek_secret_locked,
    test_hmac_regular_kv_to_ocp_lock_kv_locked,
    test_hmac_ocp_lock_kv_to_ocp_lock_kv_unlocked,
    test_aes_kv_release_locked,
}

fn test_ocp_lock_enabled() {
    let test_regs = TestRegisters::default();
    assert!(test_regs.soc.ocp_lock_enabled());
}

fn test_set_ocp_lock_in_progress() {
    let mut test_regs = TestRegisters::default();
    test_regs.soc.ocp_lock_set_lock_in_progress();
    assert!(test_regs.soc.ocp_lock_get_lock_in_progress());
}

fn test_hek_seed_fuse_bank() {
    let test_regs = TestRegisters::default();
    let fuse_bank = test_regs.soc.fuse_bank().ocp_heck_seed();
    // Check hard coded hek seed from test MCU ROM.
    assert_eq!(fuse_bank, [0xABDEu32; 8].into());
}

// TODO(clundin): Verify decrypted contents
// TODO(clundin): Test can't be called twice.
fn test_hek_seed_doe() {
    let mut test_regs = TestRegisters::default();
    test_regs
        .doe
        .decrypt_hek_seed(&Array4x4::from(DOE_TEST_IV), KeyId::KeyId22)
        .unwrap();
}

// AES Decrypt to KV should never work for all KVs until register OCP in progress is set.
fn test_aes_kv_release_unlocked() {
    let mut test_regs = TestRegisters::default();
    for (input_kv, output_kv) in OCP_LOCK_KV_RANGE.cartesian_product(OCP_LOCK_KV_RANGE) {
        let input = KeyId::try_from(input_kv).unwrap();
        let output = KeyId::try_from(output_kv).unwrap();
        let key = KeyReadArgs::new(input);
        let output = KeyWriteArgs::new(output, KeyUsage::default().set_dma_data_en());
        populate_slot(
            &mut test_regs.hmac,
            &mut test_regs.trng,
            input,
            KeyUsage::default().set_aes_key_en(),
        )
        .unwrap();

        assert!(test_regs
            .aes
            .aes_256_ecb_decrypt_kv_inner(AesKey::KV(key), output, &[0; 64])
            .is_err(),);
    }
}

// AES Decrypt to KV only work for KV 16 -> KV 23 when OCP in progress is set.
fn test_aes_kv_release_locked() {
    let mut test_regs = TestRegisters::default();
    for (input_kv, output_kv) in OCP_LOCK_KV_RANGE.cartesian_product(OCP_LOCK_KV_RANGE) {
        let input = KeyId::try_from(input_kv).unwrap();
        let output = KeyId::try_from(output_kv).unwrap();

        // Already exercised on the happy path.
        // Can't HMAC into KV 23, so we skip that as input.
        if (input == KeyId::KeyId16 || input == KeyId::KeyId23) || output == KeyId::KeyId23 {
            continue;
        }

        let key = KeyReadArgs::new(input);
        let output = KeyWriteArgs::new(output, KeyUsage::default().set_dma_data_en());
        populate_slot(
            &mut test_regs.hmac,
            &mut test_regs.trng,
            input,
            KeyUsage::default().set_aes_key_en(),
        )
        .unwrap();

        assert!(test_regs
            .aes
            .aes_256_ecb_decrypt_kv_inner(AesKey::KV(key), output, &[0; 64])
            .is_err(),);
    }
}

fn test_populate_mdk() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::default();

    let cdi_slot = HmacKey::Key(KeyReadArgs::new(KeyId::KeyId3));
    let mdk_slot = HmacTag::Key(KeyWriteArgs::from(KeyWriteArgs::new(
        KeyId::KeyId16,
        KeyUsage::default().set_aes_key_en(),
    )));

    populate_slot(
        &mut test_regs.hmac,
        &mut test_regs.trng,
        KeyId::KeyId3,
        KeyUsage::default().set_hmac_key_en(),
    )
    .unwrap();
    hmac_kdf(
        &mut test_regs.hmac,
        cdi_slot,
        b"OCP_LOCK_MDK", // TODO: Use real label from spec.
        None,
        &mut test_regs.trng,
        mdk_slot,
        HmacMode::Hmac512,
    )
    .unwrap();
}

// Before `ocp_lock_set_lock_in_progress` it's okay to HMAC from regular KV to OCP LOCK KV.
fn test_hmac_regular_kv_to_ocp_lock_kv_unlocked() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    hmac_kv_sequence_check(REGULAR_LOCK_KV_RANGE, OCP_LOCK_KV_RANGE, true, |res| {
        assert!(res.is_ok())
    });
}

// After `ocp_lock_set_lock_in_progress` it's not okay to HMAC from regular KV to OCP LOCK KV.
fn test_hmac_regular_kv_to_ocp_lock_kv_locked() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    hmac_kv_sequence_check(REGULAR_LOCK_KV_RANGE, OCP_LOCK_KV_RANGE, false, |res| {
        assert!(res.is_err())
    });
}

fn test_hmac_ocp_lock_kv_to_ocp_lock_kv_unlocked() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    hmac_kv_sequence_check(OCP_LOCK_KV_RANGE, OCP_LOCK_KV_RANGE, false, |res| {
        assert!(res.is_ok())
    });
}

// Checks if MEK can be decrypted to KV.
// NOTE: Must be run after `test_populate_mdk`.
fn test_decrypt_to_mek_kv_locked() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::default();

    test_regs
        .aes
        .aes_256_ecb_decrypt_kv(&ENCRYPTED_HEK)
        .unwrap();
}

// Tests MEK derive flow. Does not validate Key release contents.
fn test_decrypt_to_mek_kv_with_mek_secret_locked() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::default();

    let mek_secret_kv = KeyId::KeyId21;
    populate_slot(
        &mut test_regs.hmac,
        &mut test_regs.trng,
        mek_secret_kv,
        KeyUsage::default().set_aes_key_en(),
    )
    .unwrap();

    let mek_seed = cmac_kdf(
        &mut test_regs.aes,
        AesKey::KV(KeyReadArgs::new(mek_secret_kv)),
        b"derived_mek",
        None,
        4,
    )
    .unwrap();

    test_regs
        .aes
        .aes_256_ecb_decrypt_kv(&mek_seed.into())
        .unwrap();
}

// Must be after `test_decrypt_to_mek_kv_locked`.
// Validates the contents of the MEK DMA KV release.
fn test_kv_release() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::default();
    kv_release(&mut test_regs);
}
