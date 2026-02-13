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
use caliptra_drivers::hpke::{
    self,
    kem::{MlKemEncapsulatedSecret, MlKemEncapsulationKey},
    Hpke, HpkeMlKemContext,
};
use caliptra_drivers_test_bin::TestRegisters;
use caliptra_test_harness::test_suite;

use zerocopy::{FromBytes, IntoBytes};

include!(concat!(env!("OUT_DIR"), "/hpke_test_vectors.rs"));

test_suite! {
    test_ml_kem_1024_test_vector,
    test_ml_kem_1024_self_talk,
}

fn test_ml_kem_1024_test_vector() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut regs = TestRegisters::default();

    // SAFETY: This API is unsafe to discourage usage in firmware. It's used here to verify the
    // HPKE implementation against a known test vector.
    let hpke = unsafe { HpkeMlKemContext::from_seed(MLKEM_TEST_VECTOR.ikm_r.try_into().unwrap()) };
    let mut ml_kem = hpke::kem::MlKem::new(&mut regs.sha3, &mut regs.ml_kem);
    let mut hkdf = hpke::kdf::Hmac384::new(&mut regs.hmac);

    let mut pk_rm = [0; hpke::kem::MlKem::NPK];
    hpke.serialize_public_key(&mut ml_kem, &mut pk_rm).unwrap();
    assert_eq!(pk_rm.as_ref(), MLKEM_TEST_VECTOR.pk_rm);

    let enc = MlKemEncapsulatedSecret::ref_from_bytes(MLKEM_TEST_VECTOR.enc).unwrap();
    let mut reader = hpke
        .setup_base_r(
            &mut ml_kem,
            &mut hkdf,
            &mut regs.trng,
            enc,
            &MLKEM_TEST_VECTOR.info,
        )
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
    let mut kem = hpke::kem::MlKem::new(&mut regs.sha3, &mut regs.ml_kem);
    let mut hkdf = hpke::kdf::Hmac384::new(&mut regs.hmac);

    let mut pk_rm = [0; hpke::kem::MlKem::NPK];
    hpke.serialize_public_key(&mut kem, &mut pk_rm).unwrap();
    let (enc, mut sender) = hpke
        .setup_base_s(
            &mut kem,
            &mut hkdf,
            &mut regs.trng,
            &MlKemEncapsulationKey::from(pk_rm),
            &MLKEM_TEST_VECTOR.info,
        )
        .unwrap();
    let mut reader = hpke
        .setup_base_r(
            &mut kem,
            &mut hkdf,
            &mut regs.trng,
            &enc,
            &MLKEM_TEST_VECTOR.info,
        )
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
        assert_eq!(*vector.pt, pt);
    }
}
