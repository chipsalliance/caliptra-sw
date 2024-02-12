/*++

Licensed under the Apache-2.0 license.

File Name:

    keyvault_tests.rs

Abstract:

    File contains test cases for Key-Vault API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{KeyId, KeyUsage, KeyVault};
use caliptra_registers::kv::KvReg;
use caliptra_test_harness::test_suite;

#[cfg(not(feature = "fpga_realtime"))]
const KEY_IDS: [KeyId; 32] = [
    KeyId::KeyId0,
    KeyId::KeyId1,
    KeyId::KeyId2,
    KeyId::KeyId3,
    KeyId::KeyId4,
    KeyId::KeyId5,
    KeyId::KeyId6,
    KeyId::KeyId7,
    KeyId::KeyId8,
    KeyId::KeyId9,
    KeyId::KeyId10,
    KeyId::KeyId11,
    KeyId::KeyId12,
    KeyId::KeyId13,
    KeyId::KeyId14,
    KeyId::KeyId15,
    KeyId::KeyId16,
    KeyId::KeyId17,
    KeyId::KeyId18,
    KeyId::KeyId19,
    KeyId::KeyId20,
    KeyId::KeyId21,
    KeyId::KeyId22,
    KeyId::KeyId23,
    KeyId::KeyId24,
    KeyId::KeyId25,
    KeyId::KeyId26,
    KeyId::KeyId27,
    KeyId::KeyId28,
    KeyId::KeyId29,
    KeyId::KeyId30,
    KeyId::KeyId31,
];

#[cfg(feature = "fpga_realtime")]
const KEY_IDS: [KeyId; 16] = [
    KeyId::KeyId0,
    KeyId::KeyId1,
    KeyId::KeyId2,
    KeyId::KeyId3,
    KeyId::KeyId4,
    KeyId::KeyId5,
    KeyId::KeyId6,
    KeyId::KeyId7,
    KeyId::KeyId8,
    KeyId::KeyId9,
    KeyId::KeyId10,
    KeyId::KeyId11,
    KeyId::KeyId12,
    KeyId::KeyId13,
    KeyId::KeyId14,
    KeyId::KeyId15,
];

fn test_read_write() {
    let mut kv = unsafe { KvReg::new() };

    let key = [0x25cd4f4d, 0xaee6a94d, 0xa8828dab, 0xb61de972, 0x9e02880f, 0x7e103168,
    0xef1bdd4b, 0xcb49eff8, 0xf5e8e1d9, 0xbc084c4b, 0x43f300b4, 0x4f08a7fd];

    kv.regs_mut().key_entry().at(KeyId::KeyId0.into()).write(&key);
    let read_key = kv.regs().key_entry().at(KeyId::KeyId0.into()).read();
    assert_eq!(read_key, key)
}

fn test_write_lock_and_erase_keys() {
    let mut vault = unsafe { KeyVault::new(KvReg::new()) };

    for key_id in KEY_IDS {
        assert!(vault.erase_key(key_id).is_ok());

        // Set write lock.
        assert!(!vault.key_write_lock(key_id));
        vault.set_key_write_lock(key_id);
        assert!(vault.key_write_lock(key_id));

        // Test erasing key. This should fail.
        assert!(vault.erase_key(key_id).is_err());
    }
}

fn test_erase_all_keys() {
    let mut vault = unsafe { KeyVault::new(KvReg::new()) };
    vault.erase_all_keys();
}

fn test_read_key_usage() {
    let mut vault = unsafe { KeyVault::new(KvReg::new()) };

    for key_id in KEY_IDS {
        assert_eq!(vault.key_usage(key_id), KeyUsage(0));
    }
}

fn test_use_lock() {
    let mut vault = unsafe { KeyVault::new(KvReg::new()) };

    for key_id in KEY_IDS {
        assert!(!vault.key_use_lock(key_id));
        vault.set_key_use_lock(key_id);
        assert!(vault.key_use_lock(key_id));
    }
}

fn test_write_protection_stickiness() {
    let mut vault = unsafe { KeyVault::new(KvReg::new()) };

    for key_id in KEY_IDS {
        assert!(vault.key_write_lock(key_id));
        vault.clear_key_write_lock(key_id);
        assert!(vault.key_write_lock(key_id));
    }
}

fn test_use_protection_stickiness() {
    let mut vault = unsafe { KeyVault::new(KvReg::new()) };

    for key_id in KEY_IDS {
        assert!(vault.key_use_lock(key_id));
        vault.clear_key_use_lock(key_id);
        assert!(vault.key_use_lock(key_id));
    }
}

// Maintain the order of the tests.
test_suite! {
    test_read_write,
    test_write_lock_and_erase_keys,
    test_erase_all_keys,
    test_read_key_usage,
    test_use_lock,
    test_write_protection_stickiness,
    test_use_protection_stickiness,

}
