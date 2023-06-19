/*++

Licensed under the Apache-2.0 license.

File Name:

    doe_tests.rs

Abstract:

    File contains test cases for Deobfuscation Engine API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{
    Array4x12, Array4x4, DeobfuscationEngine, Hmac384, Hmac384Data, Hmac384Key, Hmac384Tag, KeyId,
    KeyReadArgs, Mailbox,
};
use caliptra_drivers_test_bin::{DoeTestResults, DOE_TEST_HMAC_KEY, DOE_TEST_IV};

use caliptra_registers::{doe::DoeReg, hmac::HmacReg, mbox::MboxCsr};
use caliptra_test_harness::test_suite;
use zerocopy::AsBytes;

fn test_decrypt() {
    let mut test_results = DoeTestResults::default();

    let mut hmac384 = Hmac384::new(unsafe { HmacReg::new() });
    let mut doe = unsafe { DeobfuscationEngine::new(DoeReg::new()) };
    assert_eq!(
        doe.decrypt_uds(&Array4x4::from(DOE_TEST_IV), KeyId::KeyId0)
            .ok(),
        Some(())
    );
    // Make sure the UDS can be used as a HMAC key
    let mut result = Array4x12::default();
    hmac384
        .hmac(
            Hmac384Key::Key(KeyReadArgs { id: KeyId::KeyId0 }),
            Hmac384Data::Slice("Hello world!".as_bytes()),
            Hmac384Tag::Array4x12(&mut result),
        )
        .unwrap();
    test_results.hmac_uds_as_key = result.0;

    // Make sure the UDS can be used as HMAC data
    let mut result = Array4x12::default();
    hmac384
        .hmac(
            Hmac384Key::Array4x12(&Array4x12::new(DOE_TEST_HMAC_KEY)),
            Hmac384Data::Key(KeyReadArgs { id: KeyId::KeyId0 }),
            Hmac384Tag::Array4x12(&mut result),
        )
        .unwrap();
    test_results.hmac_uds_as_data = result.0;

    doe.decrypt_field_entropy(&Array4x4::from(DOE_TEST_IV), KeyId::KeyId1)
        .unwrap();

    // Make sure the FE can be used as a HMAC key
    let mut result = Array4x12::default();
    hmac384
        .hmac(
            Hmac384Key::Key(KeyReadArgs { id: KeyId::KeyId1 }),
            Hmac384Data::Slice("Hello world!".as_bytes()),
            Hmac384Tag::Array4x12(&mut result),
        )
        .unwrap();
    test_results.hmac_field_entropy_as_key = result.0;

    // Make sure the FE can be used as HMAC data
    let mut result = Array4x12::default();
    hmac384
        .hmac(
            Hmac384Key::Array4x12(&Array4x12::new(DOE_TEST_HMAC_KEY)),
            Hmac384Data::Key(KeyReadArgs { id: KeyId::KeyId1 }),
            Hmac384Tag::Array4x12(&mut result),
        )
        .unwrap();
    test_results.hmac_field_entropy_as_data = result.0;

    let mut mbox = Mailbox::new(unsafe { MboxCsr::new() });
    mbox.try_start_send_txn()
        .unwrap()
        .send_request(0, test_results.as_bytes())
        .unwrap();
}

fn test_clear_secrets() {
    let mut doe = unsafe { DeobfuscationEngine::new(DoeReg::new()) };
    doe.clear_secrets().unwrap();
}

test_suite! {
    test_decrypt,
    test_clear_secrets,
}
