/*++

Licensed under the Apache-2.0 license.

File Name:

    doe_tests.rs

Abstract:

    File contains test cases for Deobfuscation Engine API

--*/

#![no_std]
#![no_main]

use caliptra_lib::{Doe, KeyId};

mod harness;

fn test_decrypt_uds() {
    let iv = [0xFF; 16];
    Doe::decrypt_uds(&iv, KeyId::KeyId0);
}

fn test_decrypt_field_entropy() {
    let iv = [0xFF; 16];
    Doe::decrypt_field_entropy(&iv, KeyId::KeyId1);
}

fn test_clear_secrets() {
    Doe::clear_secrets()
}

test_suite! {
    test_decrypt_uds,
    test_decrypt_field_entropy,
    test_clear_secrets,
}
