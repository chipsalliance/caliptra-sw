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
    Array4x12, Array4x4, DeobfuscationEngine, Ecc384, Ecc384PubKey, Hmac384, Hmac384Data,
    Hmac384Key, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, Mailbox, Trng,
};
use caliptra_drivers_test_bin::{DoeTestResults, DOE_TEST_HMAC_KEY, DOE_TEST_IV};

use caliptra_cfi_lib::CfiCounter;
use caliptra_registers::ecc::EccReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_registers::{
    csrng::CsrngReg, doe::DoeReg, entropy_src::EntropySrcReg, hmac::HmacReg, mbox::MboxCsr,
};
use caliptra_test_harness::test_suite;
use zerocopy::IntoBytes;

fn export_result_from_kv(ecc: &mut Ecc384, trng: &mut Trng, key_id: KeyId) -> Ecc384PubKey {
    ecc.key_pair(
        &KeyReadArgs::new(key_id).into(),
        &Array4x12::default(),
        trng,
        KeyWriteArgs::new(KeyId::KeyId3, KeyUsage::default().set_ecc_private_key_en()).into(),
    )
    .unwrap()
}

fn test_decrypt() {
    let mut test_results = DoeTestResults::default();

    let mut ecc = unsafe { Ecc384::new(EccReg::new()) };
    let mut hmac384 = Hmac384::new(unsafe { HmacReg::new() });
    let mut doe = unsafe { DeobfuscationEngine::new(DoeReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    // Init CFI
    let mut entropy_gen = || trng.generate().map(|a| a.0);
    CfiCounter::reset(&mut entropy_gen);

    assert_eq!(
        doe.decrypt_uds(&Array4x4::from(DOE_TEST_IV), KeyId::KeyId0)
            .ok(),
        Some(())
    );

    let key_out_id = KeyId::KeyId2;
    let key_out = KeyWriteArgs::new(key_out_id, KeyUsage::default().set_ecc_key_gen_seed_en());

    // Make sure the UDS can be used as a HMAC key
    hmac384
        .hmac(
            &KeyReadArgs::new(KeyId::KeyId0).into(),
            &Hmac384Data::Slice("Hello world!".as_bytes()),
            &mut trng,
            key_out.into(),
        )
        .unwrap();
    test_results.hmac_uds_as_key_out_pub = export_result_from_kv(&mut ecc, &mut trng, key_out_id);

    // Make sure the UDS can be used as HMAC data
    hmac384
        .hmac(
            &Hmac384Key::Array4x12(&Array4x12::new(DOE_TEST_HMAC_KEY)),
            &Hmac384Data::Key(KeyReadArgs { id: KeyId::KeyId0 }),
            &mut trng,
            key_out.into(),
        )
        .unwrap();
    test_results.hmac_uds_as_data_out_pub = export_result_from_kv(&mut ecc, &mut trng, key_out_id);

    doe.decrypt_field_entropy(&Array4x4::from(DOE_TEST_IV), KeyId::KeyId1)
        .unwrap();

    // Make sure the FE can be used as a HMAC key
    hmac384
        .hmac(
            &Hmac384Key::Key(KeyReadArgs { id: KeyId::KeyId1 }),
            &Hmac384Data::Slice("Hello world!".as_bytes()),
            &mut trng,
            key_out.into(),
        )
        .unwrap();
    test_results.hmac_field_entropy_as_key_out_pub =
        export_result_from_kv(&mut ecc, &mut trng, key_out_id);

    // Make sure the FE can be used as HMAC data
    hmac384
        .hmac(
            &Hmac384Key::Array4x12(&Array4x12::new(DOE_TEST_HMAC_KEY)),
            &Hmac384Data::Key(KeyReadArgs { id: KeyId::KeyId1 }),
            &mut trng,
            key_out.into(),
        )
        .unwrap();
    test_results.hmac_field_entropy_as_data_out_pub =
        export_result_from_kv(&mut ecc, &mut trng, key_out_id);

    let mut mbox = Mailbox::new(unsafe { MboxCsr::new() });
    let mut txn = mbox.try_start_send_txn().unwrap();
    txn.send_request(0, test_results.as_bytes()).unwrap();
    while !txn.is_response_ready() {}
}

fn test_clear_secrets() {
    let mut doe = unsafe { DeobfuscationEngine::new(DoeReg::new()) };
    doe.clear_secrets().unwrap();
}

test_suite! {
    test_decrypt,
    test_clear_secrets,
}
