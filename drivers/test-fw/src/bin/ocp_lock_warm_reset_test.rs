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
    hmac_kdf, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, ResetReason,
};
use caliptra_drivers_test_bin::{
    kv_release, populate_slot, TestRegisters, ENCRYPTED_MEK, OCP_LOCK_WARM_RESET_MAGIC_BOOT_STATUS,
};
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_test_harness::test_suite;

test_suite! {
    test_ocp_lock_warm_reset,
}

fn test_ocp_lock_warm_reset() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::default();
    assert!(test_regs.soc.ocp_lock_enabled());

    let reason = test_regs.soc.reset_reason();
    match reason {
        ResetReason::ColdReset => {
            cold_reset_flow(&mut test_regs);
        }
        ResetReason::WarmReset => {
            warm_reset_flow(&mut test_regs);
        }
        _ => panic!("Unexpected reset reason"),
    }
}

fn warm_reset_flow(test_regs: &mut TestRegisters) {
    assert!(test_regs.soc.ocp_lock_get_lock_in_progress());

    let fuse_bank = test_regs.soc.fuse_bank().ocp_hek_seed();
    // Check hard coded hek seed from test MCU ROM.
    assert_eq!(fuse_bank, [0xABDEu32; 8].into());

    // Write lock should be lost on warm reset
    assert!(!test_regs.kv.key_write_lock(KeyId::KeyId16));
    assert!(!test_regs.kv.key_write_lock(KeyId::KeyId22));

    // MDK & HEK should still be in KVs.
    test_regs
        .aes
        .aes_256_ecb_decrypt_kv(&ENCRYPTED_MEK)
        .unwrap();
    // Check that we still derive the same MEK
    kv_release(test_regs);
}

fn cold_reset_flow(test_regs: &mut TestRegisters) -> ! {
    ocp_lock_flow(test_regs);
    let mut soc_ifc = unsafe { SocIfcReg::new() };

    // Signal test harness we are ready for reset
    soc_ifc
        .regs_mut()
        .cptra_boot_status()
        .write(|_| OCP_LOCK_WARM_RESET_MAGIC_BOOT_STATUS);

    loop {}
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
        KeyId::KeyId3, // CDI Slot
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

    test_regs.kv.set_key_write_lock(KeyId::KeyId16);
    test_regs.kv.set_key_write_lock(KeyId::KeyId22);

    let fuse_bank = test_regs.soc.fuse_bank().ocp_hek_seed();
    assert_eq!(fuse_bank, [0xABDEu32; 8].into());

    test_regs.soc.ocp_lock_set_lock_in_progress();
    assert!(test_regs.soc.ocp_lock_get_lock_in_progress());

    test_regs
        .aes
        .aes_256_ecb_decrypt_kv(&ENCRYPTED_MEK)
        .unwrap();
    kv_release(test_regs);
}
