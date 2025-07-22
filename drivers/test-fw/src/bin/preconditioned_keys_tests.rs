// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::preconditioned_key::preconditioned_key_extract;
use caliptra_drivers::{
    Aes, AesKey, AesOperation, Array4x12, Array4x16, Hmac, HmacData, HmacKey, HmacMode, HmacTag,
    KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, Trng,
};
use caliptra_kat::CaliptraError;
use caliptra_registers::aes::AesReg;
use caliptra_registers::aes_clp::AesClpReg;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::hmac::HmacReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::test_suite;

const OUTPUT_KEY_ID: KeyId = KeyId::KeyId15;
const SALT_KEY_ID: KeyId = KeyId::KeyId9;
const INPUT_KEY_ID: KeyId = KeyId::KeyId13;

fn test_preconditioned_key_combo(
    key: HmacKey,
    salt: HmacKey,
    label: &[u8],
    result: &[u8],
    key_in_kv: bool,
    salt_in_kv: bool,
) {
    let mut aes = unsafe { Aes::new(AesReg::new(), AesClpReg::new()) };
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
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
    CfiCounter::reset(&mut entropy_gen);

    let input_key_arr = get_populated_kv_slot_value(&mut hmac, &mut trng, key);
    let input_key = if key_in_kv {
        let input_key = HmacKey::Key(KeyReadArgs::new(INPUT_KEY_ID));
        populate_kv_slot(&mut hmac, &mut trng, INPUT_KEY_ID, key);
        input_key
    } else {
        HmacKey::Array4x16(&input_key_arr)
    };

    let salt_key_arr = get_populated_kv_slot_value(&mut hmac, &mut trng, salt);
    let salt_key = if salt_in_kv {
        let salt_key = HmacKey::Key(KeyReadArgs::new(SALT_KEY_ID));
        populate_kv_slot(&mut hmac, &mut trng, SALT_KEY_ID, salt);
        salt_key
    } else {
        HmacKey::Array4x16(&salt_key_arr)
    };

    let output_key = HmacTag::Key(KeyWriteArgs::new(
        OUTPUT_KEY_ID,
        KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
    ));

    preconditioned_key_extract(
        input_key, output_key, label, salt_key, &mut trng, &mut hmac, &mut aes,
    )
    .unwrap();

    let fingerprint = get_kv_slot_fingerprint(&mut aes, OUTPUT_KEY_ID);
    assert_eq!(fingerprint, result);
}

fn test_preconditioned_key(key: HmacKey, salt: HmacKey, label: &[u8], result: &[u8]) {
    test_preconditioned_key_combo(key, salt, label, result, true, true);
    test_preconditioned_key_combo(key, salt, label, result, true, false);
    test_preconditioned_key_combo(key, salt, label, result, false, true);
    test_preconditioned_key_combo(key, salt, label, result, false, false);
}

fn test_preconditioned_key_384_seed() {
    // Populated by [drivers/test-fw/scripts/vector_gen/src/preconditioned_key_extract_gen.rs].
    let input_key_seed = Array4x12::from([
        0x6a, 0xf7, 0x86, 0x29, 0xa5, 0x7d, 0xb4, 0x76, 0xae, 0x6d, 0x05, 0x4e, 0x2b, 0xb9, 0xd5,
        0x97, 0x14, 0x7d, 0x2b, 0xff, 0x19, 0x35, 0xd6, 0xa0, 0x58, 0x50, 0x2b, 0xa9, 0x2a, 0x95,
        0xe0, 0x71, 0x75, 0x79, 0xfc, 0xe7, 0xd4, 0xe6, 0xbe, 0x4c, 0x35, 0x97, 0x65, 0x0d, 0xc7,
        0x08, 0x89, 0x56,
    ]);
    let salt_seed = Array4x12::from([
        0x6f, 0x60, 0x19, 0x56, 0xe0, 0x22, 0x9a, 0xaf, 0xbe, 0x5f, 0x9d, 0x07, 0xe9, 0x9d, 0xbd,
        0x0e, 0x16, 0x76, 0x74, 0x5c, 0x4c, 0x9c, 0x1e, 0xa9, 0xcd, 0xad, 0xe1, 0x4c, 0x5b, 0x7b,
        0x25, 0x59, 0x71, 0xdf, 0xc8, 0xe1, 0x12, 0xa3, 0x00, 0xff, 0x26, 0x66, 0xdb, 0x27, 0x4d,
        0x2d, 0x19, 0x5e,
    ]);
    const KDF_LABEL: &[u8] = &[
        0xcb, 0x92, 0x12, 0x26, 0x25, 0xb2, 0x69, 0x48, 0xba, 0x67, 0x6d, 0x2a, 0xeb, 0x5a, 0xcd,
        0x26, 0x9d, 0xd1, 0x32, 0xbc, 0xb5, 0x37, 0x5f, 0x73, 0xcd, 0xe9, 0xff, 0xb7, 0x2d, 0x70,
        0xef, 0x45,
    ];
    const EXPECTED_RESULT: &[u8; 16] = &[
        0x1a, 0xaa, 0x29, 0xfc, 0xb8, 0xf5, 0x80, 0xd2, 0x14, 0xbd, 0x61, 0x78, 0xb1, 0xd7, 0xd2,
        0xd8,
    ];
    test_preconditioned_key(
        HmacKey::Array4x12(&input_key_seed),
        HmacKey::Array4x12(&salt_seed),
        KDF_LABEL,
        EXPECTED_RESULT,
    );
}

fn test_preconditioned_key_512_seed() {
    // Populated by [drivers/test-fw/scripts/vector_gen/src/preconditioned_key_extract_gen.rs].
    let input_key_seed = Array4x16::from([
        0x3b, 0xf0, 0x85, 0x0f, 0x8a, 0x54, 0x4a, 0x9e, 0x09, 0x11, 0x84, 0xb1, 0x2e, 0xe4, 0x02,
        0x85, 0x2f, 0xc9, 0x3c, 0xc2, 0x1d, 0xb4, 0xd9, 0x84, 0x56, 0x9a, 0x74, 0xf9, 0x19, 0x13,
        0xf0, 0xd6, 0x44, 0x7e, 0xe7, 0x15, 0x93, 0xfc, 0xb0, 0x53, 0xf6, 0xfe, 0x70, 0x69, 0x04,
        0xd8, 0xd7, 0x2e, 0xf1, 0x41, 0x92, 0x03, 0x2c, 0xc9, 0x7d, 0x0a, 0x4d, 0x05, 0xc1, 0xd1,
        0x06, 0x69, 0x7f, 0xd0,
    ]);
    let salt_seed = Array4x16::from([
        0x21, 0xfd, 0xf1, 0xdf, 0x10, 0x72, 0xee, 0xd0, 0x3e, 0xad, 0xc8, 0xe3, 0x55, 0x8b, 0x0f,
        0x27, 0x6b, 0xa6, 0x66, 0x50, 0xef, 0x73, 0xa3, 0x51, 0x15, 0x7a, 0xfc, 0xd8, 0x64, 0xf8,
        0x7b, 0xde, 0xb8, 0x4e, 0x4c, 0xc0, 0x02, 0xa7, 0xa3, 0x20, 0xe1, 0x4b, 0xac, 0x89, 0x08,
        0x00, 0x2f, 0xc2, 0xdf, 0xd6, 0x57, 0x76, 0xf8, 0x92, 0x2c, 0xe5, 0x5a, 0xf2, 0x65, 0xd3,
        0x82, 0xd4, 0x46, 0x90,
    ]);
    const KDF_LABEL: &[u8] = &[
        0xb7, 0x38, 0x58, 0x5f, 0x26, 0xf0, 0xf1, 0x47, 0x07, 0x6d, 0x91, 0x03, 0x3b, 0x17, 0x19,
        0x48, 0xd1, 0x97, 0xa6, 0xba, 0x73, 0x9c, 0x7f, 0x19, 0xb7, 0xd6, 0x64, 0xf0, 0xd1, 0x21,
        0x1f, 0x8a,
    ];
    const EXPECTED_RESULT: &[u8; 16] = &[
        0xd4, 0x5a, 0x49, 0x3e, 0xcc, 0xb6, 0x73, 0x63, 0xde, 0x77, 0x2f, 0x31, 0xbe, 0xe8, 0xd1,
        0xcc,
    ];
    test_preconditioned_key(
        HmacKey::Array4x16(&input_key_seed),
        HmacKey::Array4x16(&salt_seed),
        KDF_LABEL,
        EXPECTED_RESULT,
    );
}

fn test_preconditioned_key_arg_invariants() {
    let mut aes = unsafe { Aes::new(AesReg::new(), AesClpReg::new()) };
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
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
    CfiCounter::reset(&mut entropy_gen);

    // HmacTag MUST be a KV slot.
    assert_eq!(
        preconditioned_key_extract(
            HmacKey::Array4x16(&Array4x16::default()),
            HmacTag::Array4x12(&mut Array4x12::default()),
            &[0],
            HmacKey::Array4x16(&Array4x16::default()),
            &mut trng,
            &mut hmac,
            &mut aes,
        ),
        Err(CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_KEY_INVALID_INPUT)
    );

    // Salt MUST be `Array4x16`.
    assert_eq!(
        preconditioned_key_extract(
            HmacKey::Array4x16(&Array4x16::default()),
            HmacTag::Key(KeyWriteArgs::new(
                OUTPUT_KEY_ID,
                KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
            )),
            &[0],
            HmacKey::Array4x12(&Array4x12::default()),
            &mut trng,
            &mut hmac,
            &mut aes,
        ),
        Err(CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_KEY_INVALID_INPUT)
    );
}

test_suite! {
    test_preconditioned_key_384_seed,
    test_preconditioned_key_512_seed,
    test_preconditioned_key_arg_invariants,
}

fn populate_kv_slot(hmac: &mut Hmac, trng: &mut Trng, key_id: KeyId, seed: HmacKey) {
    hmac.hmac(
        seed,
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(
            key_id,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
        HmacMode::Hmac512,
    )
    .unwrap();
}

fn get_populated_kv_slot_value(hmac: &mut Hmac, trng: &mut Trng, seed: HmacKey) -> Array4x16 {
    let mut tag: Array4x16 = Array4x16::default();
    hmac.hmac(
        seed,
        HmacData::from(&[0]),
        trng,
        HmacTag::Array4x16(&mut tag),
        HmacMode::Hmac512,
    )
    .unwrap();
    tag
}

fn get_kv_slot_fingerprint(aes: &mut Aes, key_id: KeyId) -> [u8; 16] {
    let mut output = [0; 16];
    aes.aes_256_ecb(
        AesKey::KV(KeyReadArgs::new(key_id)),
        AesOperation::Encrypt,
        &[0; 16],
        &mut output,
    )
    .unwrap();
    output
}
