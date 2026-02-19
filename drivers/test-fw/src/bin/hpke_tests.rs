/*++
Licensed under the Apache-2.0 license.

File Name:

    hpke_tests.rs

Abstract:

    File contains test cases for the OCP LOCK HPKE feature.

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    hpke::{
        kem::{
            EncapsulationKey, HybridEncapsulatedSecret, HybridEncapsulationKey, Kem, MlKem,
            MlKem1024P384, MlKem1024P384KemContext, MlKemContext, MlKemEncapsulatedSecret,
            MlKemEncapsulationKey, P384EncapsulatedSecret, P384KemContext, P384,
        },
        Hpke, HpkeHybridContext, HpkeHybridDrivers, HpkeMlKemContext, HpkeMlKemDrivers,
        HpkeP384Context, HpkeP384DriverContext,
    },
    Ecc384PubKey, Ecc384Scalar,
};
use caliptra_drivers_test_bin::TestRegisters;
use caliptra_kat::CaliptraError;
use caliptra_test_harness::test_suite;

use zerocopy::{FromBytes, IntoBytes};

include!(concat!(env!("OUT_DIR"), "/hpke_test_vectors.rs"));

const HYBRID_TRAD_DK: &[u8] = &[
    0x62, 0xde, 0xaa, 0x37, 0xaa, 0x5f, 0xb8, 0x30, 0xbd, 0x7, 0xa5, 0xf9, 0x1a, 0x12, 0xae, 0x80,
    0xe2, 0x8b, 0x69, 0x2, 0xbf, 0x11, 0xf6, 0xfd, 0x96, 0xb8, 0x48, 0x4, 0x70, 0x93, 0x40, 0x65,
    0x91, 0x95, 0x17, 0xc8, 0x79, 0x38, 0x6e, 0xae, 0x84, 0xff, 0x44, 0x1a, 0x7, 0xc5, 0x3, 0x87,
];
const HYBRID_TRAD_EK: &[u8] = &[
    0x4, 0xd0, 0x64, 0x3, 0xae, 0x9d, 0x14, 0x5, 0x41, 0x50, 0x5c, 0x8, 0x17, 0x27, 0xe9, 0x5c,
    0x2c, 0x79, 0x41, 0x61, 0xdf, 0x56, 0xc5, 0xaa, 0x10, 0xf4, 0xc, 0xf6, 0xb1, 0xaa, 0x47, 0x1a,
    0x9c, 0xdd, 0xc4, 0xa8, 0xbc, 0x1b, 0x98, 0x9, 0x55, 0xec, 0x74, 0x34, 0x15, 0xf3, 0x8b, 0x4f,
    0x72, 0xe2, 0xdc, 0x9f, 0xfc, 0xdf, 0x82, 0x40, 0xca, 0xd7, 0x79, 0x57, 0xbd, 0x59, 0x65, 0xc4,
    0x94, 0x43, 0x23, 0x5e, 0x6d, 0xd9, 0x7d, 0x62, 0x4d, 0x56, 0x1a, 0x6c, 0x81, 0xe3, 0x3b, 0xa,
    0xb3, 0x5b, 0xa0, 0xad, 0x9a, 0x54, 0x55, 0xf3, 0x13, 0x6b, 0x3a, 0xc5, 0x90, 0xd1, 0xcf, 0xe7,
    0xc6,
];

test_suite! {
    test_ml_kem_1024_test_vector,
    test_ml_kem_1024_self_talk,
    test_p384_self_talk,
    test_p384_test_vector,
    test_hybrid_test_vector,
    test_hybrid_self_talk,
    // Keep this test case last
    test_p384_public_key_curve_validation,
}

fn test_ml_kem_1024_test_vector() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    // SAFETY: This API is unsafe to discourage usage in firmware. It's used here to verify the
    // HPKE implementation against a known test vector.
    let hpke = unsafe { HpkeMlKemContext::from_seed(MLKEM_TEST_VECTOR.ikm_r.try_into().unwrap()) };

    let mut ctx = MlKemContext::new(&mut regs.trng, &mut regs.sha3, &mut regs.ml_kem);
    let mut kem = MlKem::derive_key_pair(&mut ctx, hpke.as_ref()).unwrap();
    let mut kem_ctx = HpkeMlKemDrivers::new(
        &mut regs.trng,
        &mut regs.sha3,
        &mut regs.hmac,
        &mut regs.ml_kem,
    );

    let mut pk_rm = [0; MlKem::NPK];
    hpke.serialize_public_key(&mut kem, &mut kem_ctx, &mut pk_rm)
        .unwrap();
    assert_eq!(pk_rm.as_ref(), MLKEM_TEST_VECTOR.pk_rm);

    let enc = MlKemEncapsulatedSecret::read_from_bytes(MLKEM_TEST_VECTOR.enc).unwrap();
    let mut reader = hpke
        .setup_base_r(&mut kem, &mut kem_ctx, &enc, &MLKEM_TEST_VECTOR.info)
        .unwrap();

    for vector in MLKEM_TEST_VECTOR.encryptions {
        assert_eq!(*vector.nonce, <[u8; 12]>::from(reader.compute_nonce()));

        let (ct, suffix) = <[u8; 58]>::ref_from_prefix(&vector.ct.as_bytes()).unwrap();
        let tag = <[u8; 16]>::ref_from_bytes(suffix).unwrap();

        let mut pt = [0; 58];
        reader
            .open(&mut regs.aes, &mut regs.trng, &vector.aad, tag, ct, &mut pt)
            .unwrap();
        assert_eq!(vector.pt, pt);
    }
}

fn test_ml_kem_1024_self_talk() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    let hpke = HpkeMlKemContext::generate(&mut regs.trng).unwrap();
    let mut ctx = MlKemContext::new(&mut regs.trng, &mut regs.sha3, &mut regs.ml_kem);
    let mut kem = MlKem::derive_key_pair(&mut ctx, hpke.as_ref()).unwrap();
    let mut kem_ctx = HpkeMlKemDrivers::new(
        &mut regs.trng,
        &mut regs.sha3,
        &mut regs.hmac,
        &mut regs.ml_kem,
    );

    let mut pk_rm = [0; MlKem::NPK];
    hpke.serialize_public_key(&mut kem, &mut kem_ctx, &mut pk_rm)
        .unwrap();

    let (enc, mut sender) = hpke
        .setup_base_s(
            &mut kem,
            &mut kem_ctx,
            &MlKemEncapsulationKey::from(pk_rm),
            &MLKEM_TEST_VECTOR.info,
        )
        .unwrap();
    let mut reader = hpke
        .setup_base_r(&mut kem, &mut kem_ctx, &enc, &MLKEM_TEST_VECTOR.info)
        .unwrap();

    for vector in MLKEM_TEST_VECTOR.encryptions {
        let mut ct = [0; 58];
        let tag = sender
            .seal(
                &mut regs.aes,
                &mut regs.trng,
                vector.aad,
                vector.pt,
                &mut ct,
            )
            .unwrap();
        let mut pt = [0; 58];
        reader
            .open(
                &mut regs.aes,
                &mut regs.trng,
                &vector.aad,
                &tag,
                &ct,
                &mut pt,
            )
            .unwrap();
        assert_eq!(vector.pt, pt);
    }
}

fn test_p384_test_vector() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    let private_key = Ecc384Scalar::from(<[u8; 48]>::try_from(P384_TEST_VECTOR.sk_rm).unwrap());
    let pub_key = Ecc384PubKey {
        x: Ecc384Scalar::from(<[u8; 48]>::try_from(&P384_TEST_VECTOR.pk_rm[1..49]).unwrap()),
        y: Ecc384Scalar::from(<[u8; 48]>::try_from(&P384_TEST_VECTOR.pk_rm[49..97]).unwrap()),
    };

    let hpke = HpkeP384Context::generate(&mut regs.trng).unwrap();

    // SAFETY: This API is unsafe to discourage usage in firmware. It's used here to verify the
    // HPKE implementation against a known test vector. The Caliptra hardware ECDSA key gen mixes
    // in a nonce, so we cannot re-create the same keys from the IKM seed.
    let mut kem = unsafe { P384::load_raw_keys(pub_key, private_key) };
    let mut kem_ctx = P384KemContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);

    let ek = kem.serialize_public_key(&mut kem_ctx).unwrap();
    assert_eq!(
        <EncapsulationKey<{ P384::NPK }> as AsRef<[u8]>>::as_ref(&ek),
        P384_TEST_VECTOR.pk_rm
    );

    let enc = P384EncapsulatedSecret::read_from_bytes(P384_TEST_VECTOR.enc).unwrap();

    let mut kem_ctx = HpkeP384DriverContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);
    let mut reader = hpke
        .setup_base_r(&mut kem, &mut kem_ctx, &enc, &P384_TEST_VECTOR.info)
        .unwrap();

    for vector in P384_TEST_VECTOR.encryptions {
        assert_eq!(*vector.nonce, <[u8; 12]>::from(reader.compute_nonce()));

        let (ct, tag) = vector.ct.split_at(vector.pt.len());

        let mut pt = [0; 32];
        let pt = &mut pt[..vector.pt.len()];
        reader
            .open(
                &mut regs.aes,
                &mut regs.trng,
                &vector.aad,
                &tag.try_into().unwrap(),
                &ct,
                pt,
            )
            .unwrap();
        assert_eq!(vector.pt, pt);
    }
}

fn test_p384_self_talk() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    let hpke = HpkeP384Context::generate(&mut regs.trng).unwrap();
    let mut kem_ctx = P384KemContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);
    let mut kem = P384::derive_key_pair(&mut kem_ctx, hpke.as_ref()).unwrap();

    let ek = kem.serialize_public_key(&mut kem_ctx).unwrap();

    let mut kem_ctx = HpkeP384DriverContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);
    let (enc, mut sender) = hpke
        .setup_base_s(&mut kem, &mut kem_ctx, &ek, &P384_TEST_VECTOR.info)
        .unwrap();
    let mut reader = hpke
        .setup_base_r(&mut kem, &mut kem_ctx, &enc, &P384_TEST_VECTOR.info)
        .unwrap();

    for vector in P384_TEST_VECTOR.encryptions {
        let mut ct = [0; 32];
        let ct = &mut ct[..vector.pt.len()];
        let tag = sender
            .seal(&mut regs.aes, &mut regs.trng, vector.aad, vector.pt, ct)
            .unwrap();
        let mut pt = [0; 32];
        let pt = &mut pt[..vector.pt.len()];
        reader
            .open(&mut regs.aes, &mut regs.trng, &vector.aad, &tag, &ct, pt)
            .unwrap();
        assert_eq!(vector.pt, pt);
    }
}

fn test_p384_public_key_curve_validation() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    let hpke = HpkeP384Context::generate(&mut regs.trng).unwrap();
    let mut kem_ctx = P384KemContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);
    let mut kem = P384::derive_key_pair(&mut kem_ctx, hpke.as_ref()).unwrap();

    // A point at infinity should result in a hardware error.
    let enc = P384EncapsulatedSecret::read_from_bytes(&[0; P384::NENC]).unwrap();

    let mut kem_ctx = HpkeP384DriverContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);
    assert_eq!(
        hpke.setup_base_r(&mut kem, &mut kem_ctx, &enc, &P384_TEST_VECTOR.info)
            .unwrap_err(),
        CaliptraError::DRIVER_ECC384_HW_ERROR,
    );

    let mut enc: [u8; P384::NENC] = P384_TEST_VECTOR.enc.try_into().unwrap();
    // Mess with the valid public key (P-384 encapsulated secrets are a public key) to take it off
    // the curve.
    enc[9] ^= enc[9];

    let enc = P384EncapsulatedSecret::read_from_bytes(&enc).unwrap();
    assert_eq!(
        hpke.setup_base_r(&mut kem, &mut kem_ctx, &enc, &P384_TEST_VECTOR.info)
            .unwrap_err(),
        CaliptraError::DRIVER_ECC384_HW_ERROR,
    );
}

fn test_hybrid_test_vector() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    let trad_priv_key = Ecc384Scalar::from(<[u8; 48]>::try_from(HYBRID_TRAD_DK).unwrap());
    let trad_pub_key = Ecc384PubKey {
        x: Ecc384Scalar::from(<[u8; 48]>::try_from(&HYBRID_TRAD_EK[1..49]).unwrap()),
        y: Ecc384Scalar::from(<[u8; 48]>::try_from(&HYBRID_TRAD_EK[49..97]).unwrap()),
    };

    // SAFETY: This API is unsafe to discourage usage in firmware. It's used here to verify the
    // HPKE implementation against a known test vector. The Caliptra hardware ECDSA key gen mixes
    // in a nonce, so we cannot re-create the same keys from the IKM seed.
    let trad = unsafe { P384::load_raw_keys(trad_pub_key, trad_priv_key) };

    let mut kem_ctx = MlKem1024P384KemContext::new(
        &mut regs.trng,
        &mut regs.sha3,
        &mut regs.ml_kem,
        &mut regs.ecc,
        &mut regs.hmac,
    );
    let ikm = <[u8; 32]>::try_from(HYBRID_TEST_VECTOR.ikm_r).unwrap();
    let mut kem = MlKem1024P384::new(ikm, trad);

    let pk_r = kem.serialize_public_key(&mut kem_ctx).unwrap();
    let pk_rm: &[u8] = pk_r.as_ref();

    assert_eq!(pk_rm, HYBRID_TEST_VECTOR.pk_rm,);

    let enc = HybridEncapsulatedSecret::read_from_bytes(HYBRID_TEST_VECTOR.enc).unwrap();
    let shared_secret = kem.decap(&mut kem_ctx, &enc).unwrap();
    assert_eq!(shared_secret.as_ref(), HYBRID_TEST_VECTOR.shared_secret);

    let hpke = HpkeHybridContext::generate(&mut regs.trng).unwrap();
    let mut drivers = HpkeHybridDrivers::new(
        &mut regs.trng,
        &mut regs.sha3,
        &mut regs.hmac,
        &mut regs.ml_kem,
        &mut regs.ecc,
    );
    let mut reader = hpke
        .setup_base_r(&mut kem, &mut drivers, &enc, &HYBRID_TEST_VECTOR.info)
        .unwrap();

    for vector in HYBRID_TEST_VECTOR.encryptions {
        assert_eq!(*vector.nonce, <[u8; 12]>::from(reader.compute_nonce()));

        let (ct, tag) = vector.ct.split_at(vector.pt.len());

        let mut pt = [0; 58];
        let pt = &mut pt[..vector.pt.len()];
        reader
            .open(
                &mut regs.aes,
                &mut regs.trng,
                &vector.aad,
                &tag.try_into().unwrap(),
                &ct,
                pt,
            )
            .unwrap();
        assert_eq!(vector.pt, pt);
    }
}

fn test_hybrid_self_talk() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    let hpke = HpkeHybridContext::generate(&mut regs.trng).unwrap();

    let mut kem_ctx = MlKem1024P384KemContext::new(
        &mut regs.trng,
        &mut regs.sha3,
        &mut regs.ml_kem,
        &mut regs.ecc,
        &mut regs.hmac,
    );
    let mut kem = MlKem1024P384::derive_key_pair(&mut kem_ctx, hpke.as_ref()).unwrap();
    let mut drivers = HpkeHybridDrivers::new(
        &mut regs.trng,
        &mut regs.sha3,
        &mut regs.hmac,
        &mut regs.ml_kem,
        &mut regs.ecc,
    );

    let mut pk_rm = [0; MlKem1024P384::NPK];
    hpke.serialize_public_key(&mut kem, &mut drivers, &mut pk_rm)
        .unwrap();

    let (enc, mut sender) = hpke
        .setup_base_s(
            &mut kem,
            &mut drivers,
            &HybridEncapsulationKey::from(&pk_rm),
            &HYBRID_TEST_VECTOR.info,
        )
        .unwrap();

    let mut reader = hpke
        .setup_base_r(&mut kem, &mut drivers, &enc, &HYBRID_TEST_VECTOR.info)
        .unwrap();

    for vector in HYBRID_TEST_VECTOR.encryptions {
        let mut ct = [0; 58];
        let ct = &mut ct[..vector.pt.len()];
        let tag = sender
            .seal(&mut regs.aes, &mut regs.trng, vector.aad, vector.pt, ct)
            .unwrap();
        let mut pt = [0; 58];
        let pt = &mut pt[..vector.pt.len()];
        reader
            .open(&mut regs.aes, &mut regs.trng, &vector.aad, &tag, &ct, pt)
            .unwrap();
        assert_eq!(vector.pt, pt);
    }
}
