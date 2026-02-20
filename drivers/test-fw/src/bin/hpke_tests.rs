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
        self,
        kem::{
            EncapsulationKey, Kem, MlKem, MlKemContext, MlKemEncapsulatedSecret,
            MlKemEncapsulationKey, P384EncapsulatedSecret, P384KemContext, P384,
        },
        Hpke, HpkeMlKemContext, HpkeP384Context,
    },
    Ecc384PubKey, Ecc384Scalar,
};
use caliptra_drivers_test_bin::TestRegisters;
use caliptra_kat::CaliptraError;
use caliptra_test_harness::test_suite;

use zerocopy::{FromBytes, IntoBytes};

include!(concat!(env!("OUT_DIR"), "/hpke_test_vectors.rs"));

test_suite! {
    test_ml_kem_1024_test_vector,
    test_ml_kem_1024_self_talk,
    test_p384_self_talk,
    test_p384_test_vector,
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
    let mut kem_ctx = hpke::HpkeMlKemDrivers::new(
        &mut regs.trng,
        &mut regs.sha3,
        &mut regs.hmac,
        &mut regs.ml_kem,
    );

    let mut pk_rm = [0; hpke::kem::MlKem::NPK];
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
        assert_eq!(*vector.pt, pt);
    }
}

fn test_ml_kem_1024_self_talk() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    let hpke = HpkeMlKemContext::generate(&mut regs.trng).unwrap();
    let mut ctx = MlKemContext::new(&mut regs.trng, &mut regs.sha3, &mut regs.ml_kem);
    let mut kem = MlKem::derive_key_pair(&mut ctx, hpke.as_ref()).unwrap();
    let mut kem_ctx = hpke::HpkeMlKemDrivers::new(
        &mut regs.trng,
        &mut regs.sha3,
        &mut regs.hmac,
        &mut regs.ml_kem,
    );

    let mut pk_rm = [0; hpke::kem::MlKem::NPK];
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
    let mut kem = unsafe { hpke::kem::P384::load_raw_keys(pub_key, private_key) };
    let mut kem_ctx = P384KemContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);

    let ek = kem.serialize_public_key(&mut kem_ctx).unwrap();
    assert_eq!(
        <EncapsulationKey<{ P384::NPK }> as AsRef<[u8]>>::as_ref(&ek),
        P384_TEST_VECTOR.pk_rm
    );

    let enc = P384EncapsulatedSecret::read_from_bytes(P384_TEST_VECTOR.enc).unwrap();

    let mut kem_ctx =
        hpke::HpkeP384DriverContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);
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

    let mut kem_ctx =
        hpke::HpkeP384DriverContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);
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

    let mut kem_ctx =
        hpke::HpkeP384DriverContext::new(&mut regs.trng, &mut regs.ecc, &mut regs.hmac);
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
