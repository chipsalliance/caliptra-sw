/*++

Licensed under the Apache-2.0 license.

File Name:

    mlkem_tests.rs

Abstract:

    File contains test cases for ML-KEM-1024 API tests

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    Array4x12, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage,
    KeyWriteArgs, LEArray4x8, MlKem1024, MlKem1024Message, MlKem1024MessageSource, MlKem1024Seeds,
    MlKem1024SharedKey, MlKem1024SharedKeyOut, Trng,
};
use caliptra_registers::abr::AbrReg;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::hmac::HmacReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::test_suite;
use zerocopy::IntoBytes;

// Test vectors for ML-KEM-1024
const SEED_D: [u32; 8] = [
    0x12345678, 0x9abcdef0, 0x11223344, 0x55667788, 0xaabbccdd, 0xeeff0011, 0x22334455, 0x66778899,
];

const SEED_Z: [u32; 8] = [
    0x87654321, 0x0fedcba9, 0x44332211, 0x88776655, 0xddccbbaa, 0x1100ffee, 0x55443322, 0x99887766,
];

const MESSAGE: [u32; 8] = [
    0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0, 0x11223344, 0x55667788, 0xaabbccdd, 0xeeff0011,
];

const KEY_ID: KeyId = KeyId::KeyId2;

fn test_key_pair_generation() {
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };
    let mut entropy_gen = || trng.generate4();

    // This needs to happen in the first test
    CfiCounter::reset(&mut entropy_gen);

    let mut mlkem = unsafe { MlKem1024::new(AbrReg::new()) };

    // Test key pair generation with arrays
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, decaps_key) = mlkem.key_pair(seeds).unwrap();

    // Keys should be non-zero (basic sanity check)
    assert_ne!(encaps_key.0, [0u32; 392]);
    assert_ne!(decaps_key.0, [0u32; 792]);
}

fn test_key_pair_generation_from_kv() {
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let mut mlkem = unsafe { MlKem1024::new(AbrReg::new()) };
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };

    // Store seeds in key vault
    let key_out = KeyWriteArgs {
        id: KEY_ID,
        usage: KeyUsage::default().set_mlkem_seed_en(),
    };

    hmac.hmac(
        HmacKey::from(&Array4x12::default()),
        HmacData::from(&[]),
        &mut trng,
        HmacTag::Key(key_out),
        HmacMode::Hmac384,
    )
    .unwrap();

    // Test key pair generation from key vault
    let seeds = MlKem1024Seeds::Key(KeyReadArgs::new(KEY_ID));
    let (encaps_key, decaps_key) = mlkem.key_pair(seeds).unwrap();

    // Keys should be non-zero (basic sanity check)
    assert_ne!(encaps_key.0, [0u32; 392]);
    assert_ne!(decaps_key.0, [0u32; 792]);
}

fn test_encapsulate_and_decapsulate() {
    let mut mlkem = unsafe { MlKem1024::new(AbrReg::new()) };

    // Generate key pair
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, decaps_key) = mlkem.key_pair(seeds).unwrap();

    // Test encapsulation with array message and array output
    let message = MlKem1024Message::from(MESSAGE);
    let mut shared_key_out = MlKem1024SharedKey::default();
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Array(&message),
            MlKem1024SharedKeyOut::Array(&mut shared_key_out),
        )
        .unwrap();

    // Ciphertext should be non-zero
    assert_ne!(ciphertext.0, [0u32; 392]);
    // Shared key should be non-zero
    assert_ne!(shared_key_out.0, [0u32; 8]);

    // Test decapsulation
    let mut decaps_shared_key = MlKem1024SharedKey::default();
    mlkem
        .decapsulate(
            &decaps_key,
            &ciphertext,
            MlKem1024SharedKeyOut::Array(&mut decaps_shared_key),
        )
        .unwrap();

    // The decapsulated shared key should match the encapsulated one
    assert_eq!(shared_key_out.0, decaps_shared_key.0);
}

fn test_encapsulate_with_kv_message() {
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let mut mlkem = unsafe { MlKem1024::new(AbrReg::new()) };
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };

    // Generate key pair
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, _decaps_key) = mlkem.key_pair(seeds).unwrap();

    // Store message in key vault
    let msg_key_id = KeyId::KeyId3;
    let msg_key_out = KeyWriteArgs {
        id: msg_key_id,
        usage: KeyUsage::default().set_mlkem_msg_en(),
    };

    let message_array = LEArray4x8::from(MESSAGE);
    let message_bytes = message_array.as_bytes();
    hmac.hmac(
        HmacKey::from(&Array4x12::default()),
        HmacData::from(message_bytes),
        &mut trng,
        HmacTag::Key(msg_key_out),
        HmacMode::Hmac384,
    )
    .unwrap();

    // Test encapsulation with key vault message
    let mut shared_key_out = MlKem1024SharedKey::default();
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Key(KeyReadArgs::new(msg_key_id)),
            MlKem1024SharedKeyOut::Array(&mut shared_key_out),
        )
        .unwrap();

    // Results should be non-zero
    assert_ne!(ciphertext.0, [0u32; 392]);
    assert_ne!(shared_key_out.0, [0u32; 8]);
}

fn test_encapsulate_with_kv_output() {
    let _trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let mut mlkem = unsafe { MlKem1024::new(AbrReg::new()) };

    // Generate key pair
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, _decaps_key) = mlkem.key_pair(seeds).unwrap();

    // Test encapsulation with key vault shared key output
    let shared_key_id = KeyId::KeyId4;
    let mut shared_key_usage = KeyUsage::default();
    shared_key_usage.set_hmac_key(true);
    let shared_key_out = KeyWriteArgs {
        id: shared_key_id,
        usage: shared_key_usage,
    };

    let message = MlKem1024Message::from(MESSAGE);
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Array(&message),
            MlKem1024SharedKeyOut::Key(shared_key_out),
        )
        .unwrap();

    // Ciphertext should be non-zero
    assert_ne!(ciphertext.0, [0u32; 392]);
}

fn test_keygen_decapsulate() {
    let mut mlkem = unsafe { MlKem1024::new(AbrReg::new()) };

    // Generate key pair for encapsulation
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds_enc = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, _) = mlkem.key_pair(seeds_enc).unwrap();

    // Encapsulate with the encaps key
    let message = MlKem1024Message::from(MESSAGE);
    let mut original_shared_key = MlKem1024SharedKey::default();
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Array(&message),
            MlKem1024SharedKeyOut::Array(&mut original_shared_key),
        )
        .unwrap();

    // Test keygen + decapsulate in one operation
    let seed_d2 = LEArray4x8::from(SEED_D);
    let seed_z2 = LEArray4x8::from(SEED_Z);
    let seeds_dec = MlKem1024Seeds::Arrays(&seed_d2, &seed_z2);
    let mut keygen_decaps_shared_key = MlKem1024SharedKey::default();
    mlkem
        .keygen_decapsulate(
            seeds_dec,
            &ciphertext,
            MlKem1024SharedKeyOut::Array(&mut keygen_decaps_shared_key),
        )
        .unwrap();

    // The shared keys should match since we used the same seeds
    assert_eq!(original_shared_key.0, keygen_decaps_shared_key.0);
}

fn test_keygen_decapsulate_with_kv() {
    let mut mlkem = unsafe { MlKem1024::new(AbrReg::new()) };

    // Generate key pair for encapsulation using KV
    let seeds_kv = MlKem1024Seeds::Key(KeyReadArgs::new(KEY_ID));
    let (encaps_key, _) = mlkem.key_pair(seeds_kv).unwrap();

    // Encapsulate
    let message = MlKem1024Message::from(MESSAGE);
    let mut original_shared_key = MlKem1024SharedKey::default();
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Array(&message),
            MlKem1024SharedKeyOut::Array(&mut original_shared_key),
        )
        .unwrap();

    // Test keygen + decapsulate with KV seeds and KV output
    let shared_key_out_id = KeyId::KeyId5;
    let mut shared_key_out_usage = KeyUsage::default();
    shared_key_out_usage.set_aes_key(true);
    let shared_key_out = KeyWriteArgs {
        id: shared_key_out_id,
        usage: shared_key_out_usage,
    };

    mlkem
        .keygen_decapsulate(
            MlKem1024Seeds::Key(KeyReadArgs::new(KEY_ID)),
            &ciphertext,
            MlKem1024SharedKeyOut::Key(shared_key_out),
        )
        .unwrap();

    // If we got here without error, the operation succeeded
}

test_suite! {
    test_key_pair_generation,
    test_key_pair_generation_from_kv,
    test_encapsulate_and_decapsulate,
    test_encapsulate_with_kv_message,
    test_encapsulate_with_kv_output,
    test_keygen_decapsulate,
    test_keygen_decapsulate_with_kv,
}
