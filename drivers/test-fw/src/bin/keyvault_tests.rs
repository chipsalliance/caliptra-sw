/*++

Licensed under the Apache-2.0 license.

File Name:

    keyvault_tests.rs

Abstract:

    File contains test cases for Key-Vault API

--*/

#![no_std]
#![no_main]

use caliptra_lib::{KeyId, KeyUsage, KeyVault};
mod harness;

const KEY_IDS: [KeyId; 8] = [
    KeyId::KeyId0,
    KeyId::KeyId1,
    KeyId::KeyId2,
    KeyId::KeyId3,
    KeyId::KeyId4,
    KeyId::KeyId5,
    KeyId::KeyId6,
    KeyId::KeyId7,
];

fn test_write_lock_and_erase_keys() {
    let mut vault = KeyVault::default();

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
    let mut vault = KeyVault::default();
    vault.erase_all_keys();
}

fn test_read_key_usage() {
    let vault = KeyVault::default();

    for key_id in KEY_IDS {
        assert_eq!(vault.key_usage(key_id), KeyUsage(0));
    }
}

fn test_use_lock() {
    let mut vault = KeyVault::default();

    for key_id in KEY_IDS {
        assert!(!vault.key_use_lock(key_id));
        vault.set_key_use_lock(key_id);
        assert!(vault.key_use_lock(key_id));
    }
}

fn test_write_protection_stickiness() {
    let mut vault = KeyVault::default();

    for key_id in KEY_IDS {
        assert!(vault.key_write_lock(key_id));
        vault.clear_key_write_lock(key_id);
        assert!(vault.key_write_lock(key_id));
    }
}

fn test_use_protection_stickiness() {
    let mut vault = KeyVault::default();

    for key_id in KEY_IDS {
        assert!(vault.key_use_lock(key_id));
        vault.clear_key_use_lock(key_id);
        assert!(vault.key_use_lock(key_id));
    }
}

// Maintain the order of the tests.
test_suite! {
    test_write_lock_and_erase_keys,
    test_erase_all_keys,
    test_read_key_usage,
    test_use_lock,
    test_write_protection_stickiness,
    test_use_protection_stickiness,

}
