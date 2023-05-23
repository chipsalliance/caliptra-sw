/*++

Licensed under the Apache-2.0 license.

File Name:

    doe_tests.rs

Abstract:

    File contains test cases for Deobfuscation Engine API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{Array4x4, DeobfuscationEngine, KeyId};

use caliptra_registers::doe::DoeReg;
use caliptra_test_harness::test_suite;

fn test_decrypt_uds() {
    let iv = [0xFF_u8; 16];
    let mut doe = unsafe { DeobfuscationEngine::new(DoeReg::new()) };
    assert_eq!(
        doe.decrypt_uds(&Array4x4::from(iv), KeyId::KeyId0).ok(),
        Some(())
    );
}

fn test_decrypt_field_entropy() {
    let iv = [0xFF_u8; 16];
    let mut doe = unsafe { DeobfuscationEngine::new(DoeReg::new()) };
    assert_eq!(
        doe.decrypt_field_entropy(&Array4x4::from(iv), KeyId::KeyId0)
            .ok(),
        Some(())
    );
}

fn test_clear_secrets() {
    let mut doe = unsafe { DeobfuscationEngine::new(DoeReg::new()) };
    assert_eq!(doe.clear_secrets().ok(), Some(()))
}

test_suite! {
    test_decrypt_uds,
    test_decrypt_field_entropy,
    test_clear_secrets,
}
