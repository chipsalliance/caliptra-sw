// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test, RuntimeTestArgs};
use aes_gcm::{aead::AeadMutInPlace, Aes256Gcm, Key, KeyInit};
use caliptra_api::{
    mailbox::{
        CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp, CmAesGcmDecryptFinalRespHeader,
        CmAesGcmDecryptInitReq, CmAesGcmDecryptInitResp, CmImportReq, CmImportResp, CmKeyUsage,
        CmMlkemDecapsulateReq, CmMlkemDecapsulateResp, CmMlkemKeyGenReq, CmMlkemKeyGenResp, Cmk,
        MailboxReq, MailboxRespHeader, MAX_CMB_DATA_SIZE,
    },
    SocManager,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;
use zerocopy::{transmute, FromBytes};

const MLKEM1024_SEED_SIZE: usize = 64;
const MLKEM1024_CIPHERTEXT_SIZE: usize = 1568;
const MLKEM_SHARED_SECRET_SIZE: usize = 32;

fn import_mlkem_seed(model: &mut DefaultHwModel, seed: &[u8]) -> Cmk {
    let mut input = [0u8; 64];
    input.copy_from_slice(seed);

    let mut req = MailboxReq::CmImport(CmImportReq {
        key_usage: CmKeyUsage::Mlkem.into(),
        input_size: seed.len() as u32,
        input,
        ..Default::default()
    });
    req.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
        .unwrap()
        .expect("CM_IMPORT should return a response");
    let resp = CmImportResp::ref_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    resp.cmk.clone()
}

fn decrypt_with_cmk(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    iv: [u8; 12],
    ciphertext: &[u8],
    tag: [u8; 16],
) -> (bool, Vec<u8>) {
    let mut req = MailboxReq::CmAesGcmDecryptInit(CmAesGcmDecryptInitReq {
        cmk: cmk.clone(),
        iv: transmute!(iv),
        ..Default::default()
    });
    req.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
        .unwrap()
        .expect("CM_AES_GCM_DECRYPT_INIT should return a response");
    let resp = CmAesGcmDecryptInitResp::ref_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let mut req = CmAesGcmDecryptFinalReq {
        context: resp.context,
        tag_len: tag.len() as u32,
        tag: transmute!(tag),
        ciphertext_size: ciphertext.len() as u32,
        ..Default::default()
    };
    req.ciphertext[..ciphertext.len()].copy_from_slice(ciphertext);
    let mut req = MailboxReq::CmAesGcmDecryptFinal(req);
    req.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
        .unwrap()
        .expect("CM_AES_GCM_DECRYPT_FINAL should return a response");

    const HEADER_SIZE: usize = core::mem::size_of::<CmAesGcmDecryptFinalRespHeader>();
    let header = CmAesGcmDecryptFinalRespHeader::read_from_bytes(&resp[..HEADER_SIZE]).unwrap();
    assert_eq!(
        header.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    let plaintext_size = header.plaintext_size as usize;
    assert!(plaintext_size <= MAX_CMB_DATA_SIZE);

    let mut final_resp = CmAesGcmDecryptFinalResp {
        hdr: header,
        ..Default::default()
    };
    final_resp.plaintext[..plaintext_size]
        .copy_from_slice(&resp[HEADER_SIZE..HEADER_SIZE + plaintext_size]);
    (
        final_resp.hdr.tag_verified == 1,
        final_resp.plaintext[..plaintext_size].to_vec(),
    )
}

#[test]
fn mlkem_cmd_run_wycheproof() {
    // This test is too slow to run as part of the verilator nightly.
    #![cfg_attr(all(not(feature = "slow_tests"), feature = "verilator"), ignore)]

    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let keygen_tests = wycheproof_mlkem::mlkem::TestSet::load(
        wycheproof_mlkem::mlkem::TestName::MlKem1024KeyGenSeed,
    )
    .unwrap();
    let mut keygen_test_count = 0;
    for group in &keygen_tests.test_groups {
        for test in &group.tests {
            keygen_test_count += 1;
            let seed = test.seed.as_ref().unwrap().as_slice();
            let expected_encaps_key = test.encaps_key.as_ref().unwrap().as_slice();
            assert_eq!(seed.len(), MLKEM1024_SEED_SIZE);

            let cmk = import_mlkem_seed(&mut model, seed);
            let mut req = MailboxReq::CmMlkemKeyGen(CmMlkemKeyGenReq {
                cmk,
                ..Default::default()
            });
            req.populate_chksum().unwrap();
            let resp = model
                .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
                .unwrap()
                .expect("CM_MLKEM_KEY_GEN should return a response");
            let resp = CmMlkemKeyGenResp::ref_from_bytes(resp.as_slice()).unwrap();
            assert_eq!(
                resp.encaps_key.as_slice(),
                expected_encaps_key,
                "Wycheproof ML-KEM-1024 keygen test {} failed: {}",
                test.tc_id,
                test.comment
            );
        }
    }
    assert_eq!(keygen_test_count, 100);

    let decaps_tests =
        wycheproof_mlkem::mlkem::TestSet::load(wycheproof_mlkem::mlkem::TestName::MlKem1024)
            .unwrap();
    let mut decaps_test_count = 0;
    for group in &decaps_tests.test_groups {
        for test in &group.tests {
            let Some(seed) = test.seed.as_ref().map(|value| value.as_slice()) else {
                continue;
            };
            let Some(ciphertext) = test.ct.as_ref().map(|value| value.as_slice()) else {
                continue;
            };
            let Some(shared_secret) = test.shared_secret.as_ref().map(|value| value.as_slice())
            else {
                continue;
            };
            if seed.len() != MLKEM1024_SEED_SIZE
                || ciphertext.len() != MLKEM1024_CIPHERTEXT_SIZE
                || shared_secret.len() != MLKEM_SHARED_SECRET_SIZE
            {
                continue;
            }

            decaps_test_count += 1;
            let cmk = import_mlkem_seed(&mut model, seed);
            let mut req = MailboxReq::CmMlkemDecapsulate(CmMlkemDecapsulateReq {
                key_usage: CmKeyUsage::Aes.into(),
                cmk,
                ciphertext: ciphertext.try_into().unwrap(),
                ..Default::default()
            });
            req.populate_chksum().unwrap();
            let resp = model
                .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
                .unwrap()
                .expect("CM_MLKEM_DECAPSULATE should return a response");
            let resp = CmMlkemDecapsulateResp::ref_from_bytes(resp.as_slice()).unwrap();

            let iv = [0x42; 12];
            let expected_plaintext = [0x5a; 32];
            let key: &Key<Aes256Gcm> = shared_secret.into();
            let mut cipher = Aes256Gcm::new(key);
            let mut ciphertext = expected_plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached((&iv).into(), &[], &mut ciphertext)
                .unwrap();
            let (verified, plaintext) =
                decrypt_with_cmk(&mut model, &resp.shared_key, iv, &ciphertext, tag.into());
            assert!(
                verified && plaintext == expected_plaintext,
                "Wycheproof ML-KEM-1024 decapsulation test {} failed: {}",
                test.tc_id,
                test.comment
            );
        }
    }
    assert_eq!(decaps_test_count, 153);
}
