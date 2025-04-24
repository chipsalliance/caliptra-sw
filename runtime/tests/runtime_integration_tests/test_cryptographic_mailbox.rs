// Licensed under the Apache-2.0 license

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};
use aes_gcm::{aead::AeadMutInPlace, Key, KeyInit};
use caliptra_api::mailbox::{
    CmAesCbcDecryptInitReq, CmAesCbcDecryptUpdateReq, CmAesCbcEncryptInitReq,
    CmAesCbcEncryptInitResp, CmAesCbcEncryptInitRespHeader, CmAesCbcEncryptUpdateReq, CmAesCbcResp,
    CmAesCbcRespHeader, CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp,
    CmAesGcmDecryptFinalRespHeader, CmAesGcmDecryptInitReq, CmAesGcmDecryptInitResp,
    CmAesGcmDecryptUpdateReq, CmAesGcmDecryptUpdateResp, CmAesGcmDecryptUpdateRespHeader,
    CmAesGcmEncryptFinalReq, CmAesGcmEncryptFinalResp, CmAesGcmEncryptFinalRespHeader,
    CmAesGcmEncryptInitReq, CmAesGcmEncryptInitResp, CmAesGcmEncryptUpdateReq,
    CmAesGcmEncryptUpdateResp, CmAesGcmEncryptUpdateRespHeader, CmEcdhFinishReq, CmEcdhFinishResp,
    CmEcdhGenerateReq, CmEcdhGenerateResp, CmImportReq, CmImportResp, CmKeyUsage,
    CmRandomGenerateReq, CmRandomGenerateResp, CmRandomStirReq, CmShaFinalReq, CmShaFinalResp,
    CmShaInitReq, CmShaInitResp, CmShaUpdateReq, CmStatusResp, Cmk, CommandId, MailboxReq,
    MailboxReqHeader, MailboxResp, MailboxRespHeader, MailboxRespHeaderVarSize,
    CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, CMK_SIZE_BYTES, MAX_CMB_DATA_SIZE,
};
use caliptra_api::SocManager;
use caliptra_drivers::AES_BLOCK_SIZE_BYTES;
use caliptra_hw_model::{DefaultHwModel, HwModel, InitParams, TrngMode};
use caliptra_runtime::RtBootStatus;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use rand::prelude::*;
use rand::rngs::StdRng;
use sha2::{Digest, Sha384, Sha512};
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_status() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CM_STATUS), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::CM_STATUS), payload.as_bytes())
        .unwrap()
        .expect("We should have received a response");

    let cm_resp = CmStatusResp::ref_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(cm_resp.used_usage_storage, 0);
    assert_eq!(cm_resp.total_usage_storage, 256);
}

#[test]
fn test_import() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // check too large of an input
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::AES.into(),
        input_size: 1000,
        input: [0xaa; 64],
    });
    assert_eq!(
        cm_import_cmd.populate_chksum().unwrap_err(),
        caliptra_drivers::CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE
    );

    // wrong size
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::AES.into(),
        input_size: 64,
        input: [0xaa; 64],
    });
    cm_import_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CM_IMPORT),
            cm_import_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE,
        resp,
    );

    // AES key import
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::AES.into(),
        input_size: 32,
        input: [0xaa; 64],
    });
    cm_import_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CM_IMPORT),
            cm_import_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let cm_import_resp = CmImportResp::ref_from_bytes(resp.as_slice()).unwrap();
    let cmk = cm_import_resp.cmk.as_bytes();
    assert_eq!(CMK_SIZE_BYTES, cmk.len());
    assert!(!cmk.iter().all(|&x| x == 0));

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CM_STATUS), &[]),
    };
    let status_resp = model
        .mailbox_execute(u32::from(CommandId::CM_STATUS), payload.as_bytes())
        .unwrap()
        .expect("We should have received a response");

    let cm_resp = CmStatusResp::ref_from_bytes(status_resp.as_slice()).unwrap();
    assert_eq!(cm_resp.used_usage_storage, 1);
    assert_eq!(cm_resp.total_usage_storage, 256);
}

#[test]
fn test_import_full() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // AES key import
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::AES.into(),
        input_size: 32,
        input: [0xaa; 64],
    });
    cm_import_cmd.populate_chksum().unwrap();

    for _ in 0..256 {
        model
            .mailbox_execute(
                u32::from(CommandId::CM_IMPORT),
                cm_import_cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("We should have received a response");
    }
    let err = model
        .mailbox_execute(
            u32::from(CommandId::CM_IMPORT),
            cm_import_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_CMB_KEY_USAGE_STORAGE_FULL,
        err,
    );

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CM_STATUS), &[]),
    };
    let status_resp = model
        .mailbox_execute(u32::from(CommandId::CM_STATUS), payload.as_bytes())
        .unwrap()
        .expect("We should have received a response");

    let cm_resp = CmStatusResp::ref_from_bytes(status_resp.as_slice()).unwrap();
    assert_eq!(cm_resp.used_usage_storage, 256);
    assert_eq!(cm_resp.total_usage_storage, 256);
}

#[ignore] // this test is very slow so we only test it manually
#[test]
fn test_import_wraparound() {
    // TODO: implement this when we have the clear and delete commands
}

#[test]
fn test_sha384_simple() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let input_data = "a".repeat(129);
    let input_data = input_data.as_bytes();

    // Simple case
    let mut req = CmShaInitReq {
        hash_algorithm: 1, // SHA384
        input_size: input_data.len() as u32,
        ..Default::default()
    };
    req.input[..input_data.len()].copy_from_slice(input_data);

    let mut init = MailboxReq::CmShaInit(req);
    init.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(u32::from(CommandId::CM_SHA_INIT), init.as_bytes().unwrap())
        .unwrap()
        .expect("Should have gotten a context");
    let resp = CmShaInitResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

    let req = CmShaFinalReq {
        context: resp.context,
        ..Default::default()
    };

    let mut fin = MailboxReq::CmShaFinal(req);
    fin.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(u32::from(CommandId::CM_SHA_FINAL), fin.as_bytes().unwrap())
        .unwrap()
        .expect("Should have gotten a context");

    let mut expected_resp = CmShaFinalResp::default();
    expected_resp.hdr.data_len = 48;

    let mut hasher = Sha384::new();
    hasher.update(input_data);
    let expected_hash = hasher.finalize();
    expected_resp.hash[..48].copy_from_slice(expected_hash.as_bytes());
    let mut expected_resp = MailboxResp::CmShaFinal(expected_resp);
    expected_resp.populate_chksum().unwrap();
    let expected_bytes = expected_resp.as_bytes().unwrap();
    assert_eq!(expected_bytes, resp_bytes);
}

#[test]
fn test_sha_many() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // check sha384 and sha512
    for sha in [1, 2] {
        // 467 is a prime so should exercise different edge cases in sizes but not take too long
        for i in (0..MAX_CMB_DATA_SIZE * 4).step_by(467) {
            let input_str = "a".repeat(i);
            let input_copy = input_str.clone();
            let original_input_data = input_copy.as_bytes();
            let mut input_data = input_str.as_bytes().to_vec();
            let mut input_data = input_data.as_mut_slice();

            let process = input_data.len().min(MAX_CMB_DATA_SIZE);

            let mut req: CmShaInitReq = CmShaInitReq {
                hash_algorithm: sha,
                input_size: process as u32,
                ..Default::default()
            };
            req.input[..process].copy_from_slice(&input_data[..process]);
            input_data = &mut input_data[process..];

            let mut init = MailboxReq::CmShaInit(req);
            init.populate_chksum().unwrap();
            let resp_bytes = model
                .mailbox_execute(u32::from(CommandId::CM_SHA_INIT), init.as_bytes().unwrap())
                .unwrap()
                .expect("Should have gotten a context");
            let mut resp = CmShaInitResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();
            let mut resp_bytes: Vec<u8>;

            while input_data.len() > MAX_CMB_DATA_SIZE {
                let mut req = CmShaUpdateReq {
                    input_size: MAX_CMB_DATA_SIZE as u32,
                    context: resp.context,
                    ..Default::default()
                };
                req.input.copy_from_slice(&input_data[..MAX_CMB_DATA_SIZE]);

                let mut update = MailboxReq::CmShaUpdate(req);
                update.populate_chksum().unwrap();
                resp_bytes = model
                    .mailbox_execute(
                        u32::from(CommandId::CM_SHA_UPDATE),
                        update.as_bytes().unwrap(),
                    )
                    .unwrap()
                    .expect("Should have gotten a context");

                resp = CmShaInitResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();
                input_data = &mut input_data[MAX_CMB_DATA_SIZE..];
            }

            let mut req = CmShaFinalReq {
                input_size: input_data.len() as u32,
                context: resp.context,
                ..Default::default()
            };
            req.input[..input_data.len()].copy_from_slice(input_data);

            let mut fin = MailboxReq::CmShaFinal(req);
            fin.populate_chksum().unwrap();
            let resp_bytes = model
                .mailbox_execute(u32::from(CommandId::CM_SHA_FINAL), fin.as_bytes().unwrap())
                .unwrap()
                .expect("Should have gotten a context");

            let mut expected_resp = CmShaFinalResp::default();
            if sha == 1 {
                let mut hasher = Sha384::new();
                hasher.update(original_input_data);
                let expected_hash = hasher.finalize();
                expected_resp.hash[..48].copy_from_slice(expected_hash.as_bytes());
                expected_resp.hdr.data_len = 48;
            } else {
                let mut hasher = Sha512::new();
                hasher.update(original_input_data);
                let expected_hash = hasher.finalize();
                expected_resp.hash.copy_from_slice(expected_hash.as_bytes());
                expected_resp.hdr.data_len = 64;
            };
            let mut expected_resp = MailboxResp::CmShaFinal(expected_resp);
            expected_resp.populate_chksum().unwrap();
            let expected_bytes = expected_resp.as_bytes().unwrap();
            assert_eq!(expected_bytes, resp_bytes);
        }
    }
}

#[test]
fn test_random_generate() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // check too large of an input
    let mut cm_random_generate = MailboxReq::CmRandomGenerate(CmRandomGenerateReq {
        hdr: MailboxReqHeader::default(),
        size: u32::MAX,
    });
    cm_random_generate.populate_chksum().unwrap();

    let err = model
        .mailbox_execute(
            u32::from(CommandId::CM_RANDOM_GENERATE),
            cm_random_generate.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        err,
    );

    // 0 bytes
    let mut cm_random_generate = MailboxReq::CmRandomGenerate(CmRandomGenerateReq {
        hdr: MailboxReqHeader::default(),
        size: 0,
    });
    cm_random_generate.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_RANDOM_GENERATE),
            cm_random_generate.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let mut resp = CmRandomGenerateResp::default();
    const VAR_HEADER_SIZE: usize = size_of::<MailboxRespHeaderVarSize>();
    resp.hdr = MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..VAR_HEADER_SIZE]).unwrap();
    assert_eq!(resp.hdr.data_len, 0);
    assert!(resp_bytes[VAR_HEADER_SIZE..].iter().all(|&x| x == 0));

    // 1 byte
    let mut cm_random_generate = MailboxReq::CmRandomGenerate(CmRandomGenerateReq {
        hdr: MailboxReqHeader::default(),
        size: 1,
    });
    cm_random_generate.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_RANDOM_GENERATE),
            cm_random_generate.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let mut resp = CmRandomGenerateResp {
        hdr: MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..VAR_HEADER_SIZE]).unwrap(),
        ..Default::default()
    };
    let len = resp.hdr.data_len as usize;
    assert_eq!(len, 1);
    resp.data[..len].copy_from_slice(&resp_bytes[VAR_HEADER_SIZE..VAR_HEADER_SIZE + len]);
    // We can't check if it is non-zero because it will randomly be 0 sometimes.

    for req_len in [47usize, 48, 1044] {
        let mut cm_random_generate = MailboxReq::CmRandomGenerate(CmRandomGenerateReq {
            hdr: MailboxReqHeader::default(),
            size: req_len as u32,
        });
        cm_random_generate.populate_chksum().unwrap();

        let resp_bytes = model
            .mailbox_execute(
                u32::from(CommandId::CM_RANDOM_GENERATE),
                cm_random_generate.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("We should have received a response");

        let mut resp = CmRandomGenerateResp {
            hdr: MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..VAR_HEADER_SIZE]).unwrap(),
            ..Default::default()
        };
        let len = resp.hdr.data_len as usize;
        assert_eq!(len, req_len);
        resp.data[..len].copy_from_slice(&resp_bytes[VAR_HEADER_SIZE..VAR_HEADER_SIZE + len]);
        assert!(
            resp.data[..len]
                .iter()
                .copied()
                .reduce(|a, b| (a | b))
                .unwrap()
                != 0
        );
    }
}

#[test]
fn test_random_stir_itrng() {
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let mut model = run_rt_test(RuntimeTestArgs {
        init_params: Some(InitParams {
            rom: &rom,
            trng_mode: Some(TrngMode::Internal),
            ..Default::default()
        }),
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // check too large of an input
    let mut cm_random_stir = MailboxReq::CmRandomStir(CmRandomStirReq {
        hdr: MailboxReqHeader::default(),
        input_size: u32::MAX,
        ..Default::default()
    });
    assert_eq!(
        cm_random_stir.populate_chksum().unwrap_err(),
        caliptra_drivers::CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE
    );

    // 0 bytes
    let mut cm_random_stir = MailboxReq::CmRandomStir(CmRandomStirReq {
        hdr: MailboxReqHeader::default(),
        input_size: 0,
        ..Default::default()
    });
    cm_random_stir.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_RANDOM_STIR),
            cm_random_stir.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    // There's nothing we can really check other than success.
    let _ =
        MailboxRespHeader::read_from_bytes(&resp_bytes[..size_of::<MailboxRespHeader>()]).unwrap();

    // 1 byte
    let mut cm_random_stir = MailboxReq::CmRandomStir(CmRandomStirReq {
        hdr: MailboxReqHeader::default(),
        input_size: 1,
        input: [0xff; MAX_CMB_DATA_SIZE],
    });
    cm_random_stir.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_RANDOM_STIR),
            cm_random_stir.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    // There's nothing we can really check other than success.
    let _ =
        MailboxRespHeader::read_from_bytes(&resp_bytes[..size_of::<MailboxRespHeader>()]).unwrap();

    for req_len in [47usize, 48, 1044] {
        let mut cm_random_stir = MailboxReq::CmRandomStir(CmRandomStirReq {
            hdr: MailboxReqHeader::default(),
            input_size: req_len as u32,
            input: [0xff; MAX_CMB_DATA_SIZE],
        });
        cm_random_stir.populate_chksum().unwrap();

        let resp_bytes = model
            .mailbox_execute(
                u32::from(CommandId::CM_RANDOM_STIR),
                cm_random_stir.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("We should have received a response");

        // There's nothing we can really check other than success.
        let _ = MailboxRespHeader::read_from_bytes(&resp_bytes[..size_of::<MailboxRespHeader>()])
            .unwrap();
    }
}

#[cfg_attr(feature = "fpga_realtime", ignore)] // FPGA always has an itrng
#[test]
fn test_random_stir_etrng_not_supported() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cm_random_stir = MailboxReq::CmRandomStir(CmRandomStirReq {
        hdr: MailboxReqHeader::default(),
        input_size: 0,
        ..Default::default()
    });
    cm_random_stir.populate_chksum().unwrap();

    let err = model
        .mailbox_execute(
            u32::from(CommandId::CM_RANDOM_STIR),
            cm_random_stir.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::DRIVER_TRNG_UPDATE_NOT_SUPPORTED,
        err,
    );
}

#[test]
fn test_aes_gcm_edge_cases() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let cmk = import_aes_key(&mut model, &[0xaa; 32]);

    // check too large of an input
    let mut cm_aes_encrypt_init = MailboxReq::CmAesGcmEncryptInit(CmAesGcmEncryptInitReq {
        hdr: MailboxReqHeader::default(),
        cmk,
        aad_size: u32::MAX,
        aad: [0; MAX_CMB_DATA_SIZE],
    });
    cm_aes_encrypt_init
        .populate_chksum()
        .expect_err("Should have failed");

    // TODO: check the rest of the edge cases
}

// Check a simle encryption with 4 bytes of data.
#[test]
fn test_aes_gcm_simple() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let key = [0xaa; 32];

    let cmk = import_aes_key(&mut model, &key);

    let mut cm_aes_encrypt_init = MailboxReq::CmAesGcmEncryptInit(CmAesGcmEncryptInitReq {
        hdr: MailboxReqHeader::default(),
        cmk,
        aad_size: 0,
        aad: [0; MAX_CMB_DATA_SIZE],
    });
    cm_aes_encrypt_init.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_ENCRYPT_INIT),
            cm_aes_encrypt_init.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    let resp = CmAesGcmEncryptInitResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

    let mut cm_aes_encrypt_final = MailboxReq::CmAesGcmEncryptFinal(CmAesGcmEncryptFinalReq {
        hdr: MailboxReqHeader::default(),
        context: resp.context,
        plaintext_size: 4,
        plaintext: [1; MAX_CMB_DATA_SIZE],
    });
    cm_aes_encrypt_final.populate_chksum().unwrap();

    let final_resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_ENCRYPT_FINAL),
            cm_aes_encrypt_final.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    const FINAL_HEADER_SIZE: usize = size_of::<CmAesGcmEncryptFinalRespHeader>();

    let mut final_resp = CmAesGcmEncryptFinalResp {
        hdr: CmAesGcmEncryptFinalRespHeader::read_from_bytes(
            &final_resp_bytes[..FINAL_HEADER_SIZE],
        )
        .unwrap(),
        ..Default::default()
    };
    let len = final_resp.hdr.ciphertext_size as usize;
    assert_eq!(len, 4);
    final_resp.ciphertext[..len]
        .copy_from_slice(&final_resp_bytes[FINAL_HEADER_SIZE..FINAL_HEADER_SIZE + len]);
    let ciphertext = &final_resp.ciphertext[..final_resp.hdr.ciphertext_size as usize];

    let iv = &resp.iv;
    let aad = &[];
    let plaintext = &[1, 1, 1, 1];
    let key: &Key<aes_gcm::Aes256Gcm> = (&key).into();
    let mut cipher = aes_gcm::Aes256Gcm::new(key);
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place_detached(iv.into(), aad, &mut buffer)
        .expect("Encryption failed");

    assert_eq!(ciphertext, &buffer);
}

// Random encrypt and decrypt GCM stress test.
#[test]
fn test_aes_gcm_random_encrypt_decrypt() {
    let seed_bytes = [1u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed_bytes);

    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    const KEYS: usize = 16;
    let mut keys = vec![];
    let mut cmks = vec![];
    for _ in 0..KEYS {
        let mut key = [0u8; 32];
        seeded_rng.fill_bytes(&mut key);
        keys.push(key);
        cmks.push(import_aes_key(&mut model, &key));
    }

    for _ in 0..100 {
        let key_idx = seeded_rng.gen_range(0..KEYS);
        let len = seeded_rng.gen_range(0..MAX_CMB_DATA_SIZE * 3);
        let mut plaintext = vec![0u8; len];
        seeded_rng.fill_bytes(&mut plaintext);

        let aad_len = seeded_rng.gen_range(0..MAX_CMB_DATA_SIZE);
        let mut aad = vec![0u8; aad_len];
        seeded_rng.fill_bytes(&mut aad);

        let (iv, tag, ciphertext) = mailbox_gcm_encrypt(
            &mut model,
            &cmks[key_idx],
            &aad,
            &plaintext,
            MAX_CMB_DATA_SIZE,
        );
        let (rtag, rciphertext) = rustcrypto_gcm_encrypt(&keys[key_idx], &iv, &aad, &plaintext);
        assert_eq!(ciphertext, rciphertext);
        assert_eq!(tag, rtag);
        let (dtag, dplaintext) = mailbox_gcm_decrypt(
            &mut model,
            &cmks[key_idx],
            &iv,
            &aad,
            &ciphertext,
            &tag,
            MAX_CMB_DATA_SIZE,
        );
        assert_eq!(dplaintext, plaintext);
        assert_eq!(dtag, tag);
    }
}

// Check encrypting and decrypting a single byte at a time.
// This checks the internal buffering is working correctly.
#[test]
fn test_aes_gcm_random_encrypt_decrypt_1() {
    let seed_bytes = [1u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed_bytes);

    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    const KEYS: usize = 16;
    let mut keys = vec![];
    let mut cmks = vec![];
    for _ in 0..KEYS {
        let mut key = [0u8; 32];
        seeded_rng.fill_bytes(&mut key);
        keys.push(key);
        cmks.push(import_aes_key(&mut model, &key));
    }

    for _ in 0..10 {
        let key_idx = seeded_rng.gen_range(0..KEYS);
        let len = seeded_rng.gen_range(0..100);
        let mut plaintext = vec![0u8; len];
        seeded_rng.fill_bytes(&mut plaintext);

        let aad_len = seeded_rng.gen_range(0..MAX_CMB_DATA_SIZE);
        let mut aad = vec![0u8; aad_len];
        seeded_rng.fill_bytes(&mut aad);

        let (iv, tag, ciphertext) =
            mailbox_gcm_encrypt(&mut model, &cmks[key_idx], &aad, &plaintext, 1);
        let (rtag, rciphertext) = rustcrypto_gcm_encrypt(&keys[key_idx], &iv, &aad, &plaintext);
        assert_eq!(ciphertext, rciphertext);
        assert_eq!(tag, rtag);
        let (dtag, dplaintext) =
            mailbox_gcm_decrypt(&mut model, &cmks[key_idx], &iv, &aad, &ciphertext, &tag, 1);
        assert_eq!(dplaintext, plaintext);
        assert_eq!(dtag, tag);
    }
}

// Random encrypt and decrypt CBC stress test.
#[test]
fn test_aes_cbc_random_encrypt_decrypt() {
    let seed_bytes = [1u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed_bytes);

    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    const KEYS: usize = 16;
    let mut keys = vec![];
    let mut cmks = vec![];
    for _ in 0..KEYS {
        let mut key = [0u8; 32];
        seeded_rng.fill_bytes(&mut key);
        keys.push(key);
        cmks.push(import_aes_key(&mut model, &key));
    }

    for _ in 0..100 {
        let key_idx = seeded_rng.gen_range(0..KEYS);
        let len = seeded_rng
            .gen_range(0..MAX_CMB_DATA_SIZE * 3)
            .next_multiple_of(AES_BLOCK_SIZE_BYTES);
        let mut plaintext = vec![0u8; len];
        seeded_rng.fill_bytes(&mut plaintext);

        let (iv, ciphertext) =
            mailbox_cbc_encrypt(&mut model, &cmks[key_idx], &plaintext, MAX_CMB_DATA_SIZE);
        let rciphertext = rustcrypto_cbc_encrypt(&keys[key_idx], &iv, &plaintext);
        assert_eq!(ciphertext, rciphertext);
        let dplaintext = mailbox_cbc_decrypt(
            &mut model,
            &cmks[key_idx],
            &iv,
            &ciphertext,
            MAX_CMB_DATA_SIZE,
        );
        assert_eq!(dplaintext, plaintext);
    }
}

fn rustcrypto_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> ([u8; 16], Vec<u8>) {
    let key: &Key<aes_gcm::Aes256Gcm> = key.into();
    let mut cipher = aes_gcm::Aes256Gcm::new(key);
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(iv.into(), aad, &mut buffer)
        .expect("Encryption failed");
    (tag.into(), buffer)
}

fn rustcrypto_cbc_encrypt(key: &[u8], iv: &[u8], mut plaintext: &[u8]) -> Vec<u8> {
    let mut encryptor = cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into());

    let mut output = vec![];
    while !plaintext.is_empty() {
        let block = plaintext[..AES_BLOCK_SIZE_BYTES].into();
        let mut out_block = [0u8; AES_BLOCK_SIZE_BYTES].into();
        encryptor.encrypt_block_b2b_mut(block, &mut out_block);
        output.extend_from_slice(&out_block);
        plaintext = &plaintext[AES_BLOCK_SIZE_BYTES..];
    }
    output
}

fn mailbox_gcm_encrypt(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    aad: &[u8],
    mut plaintext: &[u8],
    split: usize,
) -> ([u8; 12], [u8; 16], Vec<u8>) {
    let mut cm_aes_encrypt_init = CmAesGcmEncryptInitReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        aad_size: aad.len() as u32,
        aad: [0; MAX_CMB_DATA_SIZE],
    };
    cm_aes_encrypt_init.aad[..aad.len()].copy_from_slice(aad);
    let mut cm_aes_encrypt_init = MailboxReq::CmAesGcmEncryptInit(cm_aes_encrypt_init);
    cm_aes_encrypt_init.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_ENCRYPT_INIT),
            cm_aes_encrypt_init.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    let resp = CmAesGcmEncryptInitResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

    let mut ciphertext = vec![];

    let mut context = resp.context;

    while plaintext.len() > split {
        let mut cm_aes_encrypt_update = CmAesGcmEncryptUpdateReq {
            hdr: MailboxReqHeader::default(),
            context,
            plaintext_size: split as u32,
            plaintext: [0; MAX_CMB_DATA_SIZE],
        };
        cm_aes_encrypt_update.plaintext[..split].copy_from_slice(&plaintext[..split]);
        let mut cm_aes_encrypt_update = MailboxReq::CmAesGcmEncryptUpdate(cm_aes_encrypt_update);
        plaintext = &plaintext[split..];
        cm_aes_encrypt_update.populate_chksum().unwrap();

        let update_resp_bytes = model
            .mailbox_execute(
                u32::from(CommandId::CM_AES_GCM_ENCRYPT_UPDATE),
                cm_aes_encrypt_update.as_bytes().unwrap(),
            )
            .expect("Should have succeeded")
            .unwrap();

        const UPDATE_HEADER_SIZE: usize = size_of::<CmAesGcmEncryptUpdateRespHeader>();

        let mut update_resp = CmAesGcmEncryptUpdateResp {
            hdr: CmAesGcmEncryptUpdateRespHeader::read_from_bytes(
                &update_resp_bytes[..UPDATE_HEADER_SIZE],
            )
            .unwrap(),
            ..Default::default()
        };
        let len = update_resp.hdr.ciphertext_size as usize;
        assert!(len < split + AES_BLOCK_SIZE_BYTES);
        assert!(len as isize >= split as isize - AES_BLOCK_SIZE_BYTES as isize);
        update_resp.ciphertext[..len]
            .copy_from_slice(&update_resp_bytes[UPDATE_HEADER_SIZE..UPDATE_HEADER_SIZE + len]);
        ciphertext
            .extend_from_slice(&update_resp.ciphertext[..update_resp.hdr.ciphertext_size as usize]);
        context = update_resp.hdr.context;
    }

    let mut cm_aes_encrypt_final = CmAesGcmEncryptFinalReq {
        hdr: MailboxReqHeader::default(),
        context,
        plaintext_size: plaintext.len() as u32,
        plaintext: [0; MAX_CMB_DATA_SIZE],
    };
    cm_aes_encrypt_final.plaintext[..plaintext.len()].copy_from_slice(plaintext);
    let mut cm_aes_encrypt_final = MailboxReq::CmAesGcmEncryptFinal(cm_aes_encrypt_final);
    cm_aes_encrypt_final.populate_chksum().unwrap();

    let final_resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_ENCRYPT_FINAL),
            cm_aes_encrypt_final.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    const FINAL_HEADER_SIZE: usize = size_of::<CmAesGcmEncryptFinalRespHeader>();

    let mut final_resp = CmAesGcmEncryptFinalResp {
        hdr: CmAesGcmEncryptFinalRespHeader::read_from_bytes(
            &final_resp_bytes[..FINAL_HEADER_SIZE],
        )
        .unwrap(),
        ..Default::default()
    };
    let len = final_resp.hdr.ciphertext_size as usize;
    assert!(len <= split + AES_BLOCK_SIZE_BYTES);
    final_resp.ciphertext[..len]
        .copy_from_slice(&final_resp_bytes[FINAL_HEADER_SIZE..FINAL_HEADER_SIZE + len]);
    ciphertext.extend_from_slice(&final_resp.ciphertext[..final_resp.hdr.ciphertext_size as usize]);

    (resp.iv, final_resp.hdr.tag, ciphertext)
}

fn mailbox_gcm_decrypt(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    iv: &[u8; 12],
    aad: &[u8],
    mut ciphertext: &[u8],
    tag: &[u8; 16],
    split: usize,
) -> ([u8; 16], Vec<u8>) {
    let mut cm_aes_decrypt_init = CmAesGcmDecryptInitReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        iv: *iv,
        aad_size: aad.len() as u32,
        aad: [0; MAX_CMB_DATA_SIZE],
    };
    cm_aes_decrypt_init.aad[..aad.len()].copy_from_slice(aad);
    let mut cm_aes_encrypt_init = MailboxReq::CmAesGcmDecryptInit(cm_aes_decrypt_init);
    cm_aes_encrypt_init.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_DECRYPT_INIT),
            cm_aes_encrypt_init.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    let resp = CmAesGcmDecryptInitResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

    let mut plaintext = vec![];

    let mut context = resp.context;

    while ciphertext.len() > split {
        let mut cm_aes_decrypt_update = CmAesGcmDecryptUpdateReq {
            hdr: MailboxReqHeader::default(),
            context,
            ciphertext_size: split as u32,
            ciphertext: [0; MAX_CMB_DATA_SIZE],
        };
        cm_aes_decrypt_update.ciphertext[..split].copy_from_slice(&ciphertext[..split]);
        let mut cm_aes_decrypt_update = MailboxReq::CmAesGcmDecryptUpdate(cm_aes_decrypt_update);
        ciphertext = &ciphertext[split..];
        cm_aes_decrypt_update.populate_chksum().unwrap();

        let update_resp_bytes = model
            .mailbox_execute(
                u32::from(CommandId::CM_AES_GCM_DECRYPT_UPDATE),
                cm_aes_decrypt_update.as_bytes().unwrap(),
            )
            .expect("Should have succeeded")
            .unwrap();

        const UPDATE_HEADER_SIZE: usize = size_of::<CmAesGcmDecryptUpdateRespHeader>();

        let mut update_resp = CmAesGcmDecryptUpdateResp {
            hdr: CmAesGcmDecryptUpdateRespHeader::read_from_bytes(
                &update_resp_bytes[..UPDATE_HEADER_SIZE],
            )
            .unwrap(),
            ..Default::default()
        };
        let len = update_resp.hdr.plaintext_size as usize;
        assert!(len < split + AES_BLOCK_SIZE_BYTES);
        assert!(len as isize >= split as isize - AES_BLOCK_SIZE_BYTES as isize);
        update_resp.plaintext[..len]
            .copy_from_slice(&update_resp_bytes[UPDATE_HEADER_SIZE..UPDATE_HEADER_SIZE + len]);
        plaintext
            .extend_from_slice(&update_resp.plaintext[..update_resp.hdr.plaintext_size as usize]);
        context = update_resp.hdr.context;
    }

    let mut cm_aes_decrypt_final = CmAesGcmDecryptFinalReq {
        hdr: MailboxReqHeader::default(),
        context,
        tag_len: tag.len() as u32,
        tag: *tag,
        ciphertext_size: ciphertext.len() as u32,
        ciphertext: [0; MAX_CMB_DATA_SIZE],
    };
    cm_aes_decrypt_final.ciphertext[..ciphertext.len()].copy_from_slice(ciphertext);
    let mut cm_aes_decrypt_final = MailboxReq::CmAesGcmDecryptFinal(cm_aes_decrypt_final);
    cm_aes_decrypt_final.populate_chksum().unwrap();

    let final_resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_DECRYPT_FINAL),
            cm_aes_decrypt_final.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    const FINAL_HEADER_SIZE: usize = size_of::<CmAesGcmDecryptFinalRespHeader>();

    let mut final_resp = CmAesGcmDecryptFinalResp {
        hdr: CmAesGcmDecryptFinalRespHeader::read_from_bytes(
            &final_resp_bytes[..FINAL_HEADER_SIZE],
        )
        .unwrap(),
        ..Default::default()
    };
    let len = final_resp.hdr.plaintext_size as usize;
    assert!(len <= split + AES_BLOCK_SIZE_BYTES);
    final_resp.plaintext[..len]
        .copy_from_slice(&final_resp_bytes[FINAL_HEADER_SIZE..FINAL_HEADER_SIZE + len]);
    plaintext.extend_from_slice(&final_resp.plaintext[..final_resp.hdr.plaintext_size as usize]);

    (final_resp.hdr.tag, plaintext)
}

fn mailbox_cbc_encrypt(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    mut plaintext: &[u8],
    split: usize,
) -> ([u8; 16], Vec<u8>) {
    let init_len = plaintext.len().min(split);
    let mut cm_aes_encrypt_init = CmAesCbcEncryptInitReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        plaintext_size: init_len as u32,
        plaintext: [0; MAX_CMB_DATA_SIZE],
    };
    cm_aes_encrypt_init.plaintext[..init_len].copy_from_slice(&plaintext[..init_len]);
    plaintext = &plaintext[init_len..];
    let mut cm_aes_encrypt_init = MailboxReq::CmAesCbcEncryptInit(cm_aes_encrypt_init);
    cm_aes_encrypt_init.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_CBC_ENCRYPT_INIT),
            cm_aes_encrypt_init.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    const INIT_HEADER_SIZE: usize = size_of::<CmAesCbcEncryptInitRespHeader>();
    let mut resp = CmAesCbcEncryptInitResp {
        hdr: CmAesCbcEncryptInitRespHeader::read_from_bytes(&resp_bytes[..INIT_HEADER_SIZE])
            .unwrap(),
        ..Default::default()
    };
    let len = resp.hdr.ciphertext_size as usize;
    assert_eq!(len, init_len);
    resp.ciphertext[..len].copy_from_slice(&resp_bytes[INIT_HEADER_SIZE..INIT_HEADER_SIZE + len]);

    let mut ciphertext = vec![];
    ciphertext.extend_from_slice(&resp.ciphertext[..resp.hdr.ciphertext_size as usize]);

    let mut context = resp.hdr.context;

    while !plaintext.is_empty() {
        let len = plaintext.len().min(split);
        let mut cm_aes_encrypt_update = CmAesCbcEncryptUpdateReq {
            hdr: MailboxReqHeader::default(),
            context,
            plaintext_size: len as u32,
            plaintext: [0; MAX_CMB_DATA_SIZE],
        };
        cm_aes_encrypt_update.plaintext[..len].copy_from_slice(&plaintext[..len]);
        let mut cm_aes_encrypt_update: MailboxReq =
            MailboxReq::CmAesCbcEncryptUpdate(cm_aes_encrypt_update);
        plaintext = &plaintext[len..];
        cm_aes_encrypt_update.populate_chksum().unwrap();

        let update_resp_bytes = model
            .mailbox_execute(
                u32::from(CommandId::CM_AES_CBC_ENCRYPT_UPDATE),
                cm_aes_encrypt_update.as_bytes().unwrap(),
            )
            .expect("Should have succeeded")
            .unwrap();

        const UPDATE_HEADER_SIZE: usize = size_of::<CmAesCbcRespHeader>();

        let mut update_resp = CmAesCbcResp {
            hdr: CmAesCbcRespHeader::read_from_bytes(&update_resp_bytes[..UPDATE_HEADER_SIZE])
                .unwrap(),
            ..Default::default()
        };
        let update_len = update_resp.hdr.output_size as usize;
        assert_eq!(len, update_len);
        update_resp.output[..len]
            .copy_from_slice(&update_resp_bytes[UPDATE_HEADER_SIZE..UPDATE_HEADER_SIZE + len]);
        ciphertext.extend_from_slice(&update_resp.output[..len]);
        context = update_resp.hdr.context;
    }

    (resp.hdr.iv, ciphertext)
}

fn mailbox_cbc_decrypt(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    iv: &[u8; 16],
    mut ciphertext: &[u8],
    split: usize,
) -> Vec<u8> {
    let init_len = ciphertext.len().min(split);
    let mut cm_aes_decrypt_init = CmAesCbcDecryptInitReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        iv: *iv,
        ciphertext_size: init_len as u32,
        ciphertext: [0; MAX_CMB_DATA_SIZE],
    };
    cm_aes_decrypt_init.ciphertext[..init_len].copy_from_slice(&ciphertext[..init_len]);
    ciphertext = &ciphertext[init_len..];
    let mut cm_aes_encrypt_init = MailboxReq::CmAesCbcDecryptInit(cm_aes_decrypt_init);
    cm_aes_encrypt_init.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_CBC_DECRYPT_INIT),
            cm_aes_encrypt_init.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    const RESP_HEADER_SIZE: usize = size_of::<CmAesCbcRespHeader>();

    let mut resp = CmAesCbcResp {
        hdr: CmAesCbcRespHeader::read_from_bytes(&resp_bytes[..RESP_HEADER_SIZE]).unwrap(),
        ..Default::default()
    };
    let len = resp.hdr.output_size as usize;
    assert_eq!(len, init_len);
    resp.output[..len].copy_from_slice(&resp_bytes[RESP_HEADER_SIZE..RESP_HEADER_SIZE + len]);
    let mut plaintext = vec![];
    plaintext.extend_from_slice(&resp.output[..resp.hdr.output_size as usize]);
    let mut context = resp.hdr.context;

    while !ciphertext.is_empty() {
        let len = split.min(ciphertext.len());
        let mut cm_aes_decrypt_update = CmAesCbcDecryptUpdateReq {
            hdr: MailboxReqHeader::default(),
            context,
            ciphertext_size: len as u32,
            ciphertext: [0; MAX_CMB_DATA_SIZE],
        };
        cm_aes_decrypt_update.ciphertext[..len].copy_from_slice(&ciphertext[..len]);
        let mut cm_aes_decrypt_update = MailboxReq::CmAesCbcDecryptUpdate(cm_aes_decrypt_update);
        ciphertext = &ciphertext[len..];
        cm_aes_decrypt_update.populate_chksum().unwrap();

        let update_resp_bytes = model
            .mailbox_execute(
                u32::from(CommandId::CM_AES_CBC_DECRYPT_UPDATE),
                cm_aes_decrypt_update.as_bytes().unwrap(),
            )
            .expect("Should have succeeded")
            .unwrap();

        let mut update_resp = CmAesCbcResp {
            hdr: CmAesCbcRespHeader::read_from_bytes(&update_resp_bytes[..RESP_HEADER_SIZE])
                .unwrap(),
            ..Default::default()
        };
        let update_len = update_resp.hdr.output_size as usize;
        assert_eq!(len, update_len);
        update_resp.output[..len]
            .copy_from_slice(&update_resp_bytes[RESP_HEADER_SIZE..RESP_HEADER_SIZE + len]);
        plaintext.extend_from_slice(&update_resp.output[..update_resp.hdr.output_size as usize]);
        context = update_resp.hdr.context;
    }
    plaintext
}

fn import_aes_key(model: &mut DefaultHwModel, key: &[u8]) -> Cmk {
    let mut input = [0u8; 64];
    input[..key.len()].copy_from_slice(key);

    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::AES.into(),
        input_size: key.len() as u32,
        input,
    });
    cm_import_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CM_IMPORT),
            cm_import_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let cm_import_resp = CmImportResp::ref_from_bytes(resp.as_slice()).unwrap();
    cm_import_resp.cmk.clone()
}

#[test]
fn test_ecdh() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut req = MailboxReq::CmEcdhGenerate(CmEcdhGenerateReq::default());
    req.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
        .unwrap()
        .expect("Should have gotten a response");
    let resp = CmEcdhGenerateResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

    // Calculate our side of the exchange and the shared secret.
    // Based on the flow in https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman.
    let mut bn_ctx = openssl::bn::BigNumContext::new().unwrap();
    let curve = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
    let mut a_exchange_data = vec![4];
    a_exchange_data.extend_from_slice(&resp.exchange_data);
    let a_public_point =
        openssl::ec::EcPoint::from_bytes(&curve, &a_exchange_data, &mut bn_ctx).unwrap();
    let a_key = openssl::ec::EcKey::from_public_key(&curve, &a_public_point).unwrap();

    let b_key = openssl::ec::EcKey::generate(&curve).unwrap();
    let b_exchange_data = &b_key
        .public_key()
        .to_bytes(
            &curve,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )
        .unwrap()[1..];
    let a_pkey = openssl::pkey::PKey::from_ec_key(a_key).unwrap();
    let b_pkey = openssl::pkey::PKey::from_ec_key(b_key).unwrap();
    let mut deriver = openssl::derive::Deriver::new(&b_pkey).unwrap();
    deriver.set_peer(&a_pkey).unwrap();
    let shared_secret = deriver.derive_to_vec().unwrap();

    // calculate the shared secret using the cryptographic mailbox
    let mut send_exchange_data = [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE];
    send_exchange_data[..b_exchange_data.len()].copy_from_slice(b_exchange_data);
    let req = CmEcdhFinishReq {
        context: resp.context,
        key_usage: CmKeyUsage::AES.into(),
        incoming_exchange_data: send_exchange_data,
        ..Default::default()
    };
    let mut fin = MailboxReq::CmEcdhFinish(req);
    fin.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(fin.cmd_code().into(), fin.as_bytes().unwrap())
        .unwrap()
        .expect("Should have gotten a response");

    let resp = CmEcdhFinishResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();
    let cmk = Cmk::ref_from_bytes(resp.output_cmk.as_slice()).unwrap();

    // use the CMK shared secret to AES encrypt a known plaintext.
    let plaintext = [0u8; 16];
    let (iv, tag, ciphertext) =
        mailbox_gcm_encrypt(&mut model, cmk, &[], &plaintext, MAX_CMB_DATA_SIZE);
    // encrypt with RustCrypto and check if everything matches
    let (rtag, rciphertext) = rustcrypto_gcm_encrypt(&shared_secret[..32], &iv, &[], &plaintext);

    // check that ciphertext and tags match, meaning the shared secret is the same on both sides
    assert_eq!(ciphertext, rciphertext);
    assert_eq!(tag, rtag);
}
