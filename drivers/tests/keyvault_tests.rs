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
        assert_eq!(vault.erase_key(key_id).is_ok(), true);

        // Set write lock.
        assert_eq!(vault.key_write_lock(key_id), false);
        vault.set_key_write_lock(key_id);
        assert_eq!(vault.key_write_lock(key_id), true);

        // Test erasing key. This should fail.
        assert_eq!(vault.erase_key(key_id).is_ok(), false);
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
        assert_eq!(vault.key_use_lock(key_id), false);
        vault.set_key_use_lock(key_id);
        assert_eq!(vault.key_use_lock(key_id), true);
    }
}

fn test_write_protection_stickiness() {
    let mut vault = KeyVault::default();

    for key_id in KEY_IDS {
        assert_eq!(vault.key_write_lock(key_id), true);
        vault.clear_key_write_lock(key_id);
        assert_eq!(vault.key_write_lock(key_id), true);
    }
}

fn test_use_protection_stickiness() {
    let mut vault = KeyVault::default();

    for key_id in KEY_IDS {
        assert_eq!(vault.key_use_lock(key_id), true);
        vault.clear_key_use_lock(key_id);
        assert_eq!(vault.key_use_lock(key_id), true);
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
