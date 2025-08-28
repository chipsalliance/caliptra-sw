/*++
Licensed under the Apache-2.0 license.

File Name:

    ocp_lock_warm_reset_test.rs

Abstract:

    File contains test cases for OCP LOCK after a warm reset.

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    cprintln, hmac_kdf, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs,
    PersistentData, PersistentDataAccessor,
};
use caliptra_drivers_test_bin::{kv_release, populate_slot, TestRegisters, ENCRYPTED_HEK};
use caliptra_test_harness::test_suite;

// Marker in DCCM to signal if a warm reset has happened.
const WARM_RESET_SENTINEL: u16 = 0xAB_FE;

test_suite! {
    test_ocp_lock_warm_reset,
}

fn test_ocp_lock_warm_reset() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::default();
    let mut pdata = unsafe { PersistentDataAccessor::new() };
    let data = pdata.get_mut();

    assert!(test_regs.soc.ocp_lock_enabled());
    // Reuse `rtalias_mldsa_tbs_size` to set our sentinel.
    if data.rtalias_mldsa_tbs_size == WARM_RESET_SENTINEL {
        warm_reset_flow(&mut test_regs);
    } else {
        cold_reset_flow(&mut test_regs, data);
    }
}

fn warm_reset_flow(test_regs: &mut TestRegisters) {
    ocp_lock_flow(test_regs);
}

fn cold_reset_flow(test_regs: &mut TestRegisters, data: &mut PersistentData) {
    ocp_lock_flow(test_regs);
    data.rtalias_mldsa_tbs_size = WARM_RESET_SENTINEL;
    cprintln!("READY FOR RESET");
}

fn ocp_lock_flow(test_regs: &mut TestRegisters) {
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
        b"OCP_LOCK_MDK",
        None,
        &mut test_regs.trng,
        mdk_slot,
        HmacMode::Hmac512,
    )
    .unwrap();
    test_regs.soc.ocp_lock_set_lock_in_progress();
    assert!(test_regs.soc.ocp_lock_get_lock_in_progress());

    test_regs
        .aes
        .aes_256_ecb_decrypt_kv(&ENCRYPTED_HEK)
        .unwrap();
    kv_release(test_regs);
}
