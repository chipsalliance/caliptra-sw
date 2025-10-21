// Licensed under the Apache-2.0 license

use std::collections::VecDeque;

use crate::common::{assert_error, run_rt_test, start_rt_test_pqc_model, RuntimeTestArgs};
use aes::Aes256;
use aes_gcm::{aead::AeadMutInPlace, Key};
use caliptra_api::mailbox::{
    populate_checksum, CmAesDecryptInitReq, CmAesDecryptUpdateReq, CmAesEncryptInitReq,
    CmAesEncryptInitResp, CmAesEncryptInitRespHeader, CmAesEncryptUpdateReq,
    CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp, CmAesGcmDecryptFinalRespHeader,
    CmAesGcmDecryptInitReq, CmAesGcmDecryptInitResp, CmAesGcmDecryptUpdateReq,
    CmAesGcmDecryptUpdateResp, CmAesGcmDecryptUpdateRespHeader, CmAesGcmEncryptFinalReq,
    CmAesGcmEncryptFinalResp, CmAesGcmEncryptFinalRespHeader, CmAesGcmEncryptInitReq,
    CmAesGcmEncryptInitResp, CmAesGcmEncryptUpdateReq, CmAesGcmEncryptUpdateResp,
    CmAesGcmEncryptUpdateRespHeader, CmAesGcmSpdmDecryptInitReq, CmAesGcmSpdmDecryptInitResp,
    CmAesGcmSpdmEncryptInitReq, CmAesGcmSpdmEncryptInitResp, CmAesMode, CmAesResp, CmAesRespHeader,
    CmDeleteReq, CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmEcdhFinishReq, CmEcdhFinishResp,
    CmEcdhGenerateReq, CmEcdhGenerateResp, CmEcdsaPublicKeyReq, CmEcdsaPublicKeyResp,
    CmEcdsaSignReq, CmEcdsaSignResp, CmEcdsaVerifyReq, CmHashAlgorithm, CmHkdfExpandReq,
    CmHkdfExpandResp, CmHkdfExtractReq, CmHkdfExtractResp, CmHmacKdfCounterReq,
    CmHmacKdfCounterResp, CmHmacReq, CmHmacResp, CmImportReq, CmImportResp, CmKeyUsage,
    CmMldsaPublicKeyReq, CmMldsaPublicKeyResp, CmMldsaSignReq, CmMldsaSignResp, CmMldsaVerifyReq,
    CmRandomGenerateReq, CmRandomGenerateResp, CmRandomStirReq, CmShaFinalReq, CmShaFinalResp,
    CmShaInitReq, CmShaInitResp, CmShaUpdateReq, CmStableKeyType, CmStatusResp, Cmk, CommandId,
    MailboxReq, MailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize, ResponseVarSize,
    CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, CMK_SIZE_BYTES, MAX_CMB_DATA_SIZE,
};
use caliptra_api::SocManager;
use caliptra_drivers::AES_BLOCK_SIZE_BYTES;
use caliptra_hw_model::{DefaultHwModel, Fuses, HwModel, InitParams, TrngMode};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_runtime::RtBootStatus;
use cbc::cipher::BlockEncryptMut;
use cipher::{KeyIvInit, StreamCipherCore};
use fips204::ml_dsa_87;
use fips204::traits::Signer;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::{Signature, SigningKey};
use rand::prelude::*;
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore};
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
        key_usage: CmKeyUsage::Aes.into(),
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
        key_usage: CmKeyUsage::Aes.into(),
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
        key_usage: CmKeyUsage::Aes.into(),
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
        key_usage: CmKeyUsage::Aes.into(),
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

    let cm_resp = status(&mut model);
    assert_eq!(cm_resp.used_usage_storage, 256);
    assert_eq!(cm_resp.total_usage_storage, 256);
}

// this test is very slow so we only test it manually (on an FPGA, preferably)
#[ignore]
// Test that we can import more than 2^24 keys as long as we delete them occasionally.
#[test]
fn test_import_wraparound() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let raw_key = [0xaa; 32];
    let mut keys = VecDeque::new();
    for _ in 0..((1 << 24) + 1000) {
        let cmk = import_key(&mut model, &raw_key, CmKeyUsage::Aes);
        keys.push_back(cmk);
        if keys.len() >= 256 {
            delete_key(&mut model, &keys.pop_front().unwrap());
        }
    }
}

fn status(model: &mut DefaultHwModel) -> CmStatusResp {
    let mut req = MailboxReq::CmStatus(MailboxReqHeader::default());
    req.populate_chksum().unwrap();
    let req = req.as_bytes().unwrap();
    let status_resp = model
        .mailbox_execute(u32::from(CommandId::CM_STATUS), req)
        .unwrap()
        .expect("We should have received a response");
    CmStatusResp::read_from_bytes(status_resp.as_slice()).unwrap()
}

fn delete_key(model: &mut DefaultHwModel, cmk: &Cmk) {
    let mut req = MailboxReq::CmDelete(CmDeleteReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
    });
    req.populate_chksum().unwrap();
    let req = req.as_bytes().unwrap();
    model
        .mailbox_execute(u32::from(CommandId::CM_DELETE), req)
        .unwrap()
        .expect("We should have received a response");
}

#[test]
fn test_delete() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let cmk = import_key(&mut model, &[0xaa; 32], CmKeyUsage::Aes);
    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 1);
    assert_eq!(status_resp.total_usage_storage, 256);

    delete_key(&mut model, &cmk);

    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 0);
    assert_eq!(status_resp.total_usage_storage, 256);
}

#[test]
fn test_clear() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut req = MailboxReq::CmClear(MailboxReqHeader::default());
    req.populate_chksum().unwrap();
    let req = req.as_bytes().unwrap();

    let raw_key = [0xaa; 32];
    let mut keys = VecDeque::new();
    for _ in 0..256 {
        let cmk = import_key(&mut model, &raw_key, CmKeyUsage::Aes);
        keys.push_back(cmk);
    }

    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 256);
    assert_eq!(status_resp.total_usage_storage, 256);

    model
        .mailbox_execute(u32::from(CommandId::CM_CLEAR), req)
        .unwrap()
        .expect("We should have received a response");

    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 0);
    assert_eq!(status_resp.total_usage_storage, 256);
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
    populate_checksum(expected_resp.as_bytes_partial_mut().unwrap());
    let expected_bytes = expected_resp.as_bytes_partial().unwrap();
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
            populate_checksum(expected_resp.as_bytes_partial_mut().unwrap());
            let expected_bytes = expected_resp.as_bytes_partial().unwrap();
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

#[cfg_attr(any(feature = "fpga_realtime", feature = "fpga_subsystem"), ignore)] // FPGA always has an itrng
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

    let cmk = import_key(&mut model, &[0xaa; 32], CmKeyUsage::Aes);

    // check too large of an input
    let mut cm_aes_encrypt_init = MailboxReq::CmAesGcmEncryptInit(CmAesGcmEncryptInitReq {
        hdr: MailboxReqHeader::default(),
        flags: 0,
        cmk,
        aad_size: u32::MAX,
        aad: [0; MAX_CMB_DATA_SIZE],
    });
    cm_aes_encrypt_init
        .populate_chksum()
        .expect_err("Should have failed");

    // check tag too large or small
    let mut cm_aes_decrypt_final = MailboxReq::CmAesGcmDecryptFinal(CmAesGcmDecryptFinalReq {
        tag_len: 7,
        ..Default::default()
    });
    cm_aes_decrypt_final.populate_chksum().unwrap();
    let err = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_DECRYPT_FINAL),
            cm_aes_decrypt_final.as_bytes().unwrap(),
        )
        .expect_err("Should have failed");
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        err,
    );

    let mut cm_aes_decrypt_final = MailboxReq::CmAesGcmDecryptFinal(CmAesGcmDecryptFinalReq {
        tag_len: 17,
        ..Default::default()
    });
    cm_aes_decrypt_final.populate_chksum().unwrap();
    let err = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_DECRYPT_FINAL),
            cm_aes_decrypt_final.as_bytes().unwrap(),
        )
        .expect_err("Should have failed");
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        err,
    );

    // TODO: check the rest of the edge cases
}

// Check a simple encryption with 4 bytes of data.
#[test]
fn test_aes_gcm_simple() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let key = [0xaa; 32];

    let cmk = import_key(&mut model, &key, CmKeyUsage::Aes);

    let mut cm_aes_encrypt_init = MailboxReq::CmAesGcmEncryptInit(CmAesGcmEncryptInitReq {
        hdr: MailboxReqHeader::default(),
        flags: 0,
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
    let (rtag, rciphertext) = rustcrypto_gcm_encrypt(&key, iv, aad, plaintext);

    assert_eq!(ciphertext, &rciphertext);
    assert_eq!(final_resp.hdr.tag, rtag);
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
        cmks.push(import_key(&mut model, &key, CmKeyUsage::Aes));
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
        assert!(dtag);
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
        cmks.push(import_key(&mut model, &key, CmKeyUsage::Aes));
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
        assert!(dtag);
    }
}

#[test]
fn test_aes_gcm_spdm_mode() {
    // output from libspdm debug unit test (libspdm_test_responder_key_exchange_case1, modified to use SHA384, P384):
    // response_handshake_secret (0x30) - ed c0 61 97 77 0f 53 8c b2 50 85 b0 bc 98 c0 49 54 db 9c a6 4b 2c 78 28 50 f2 ca 5a d3 37 16 2f
    //  2f 24 42 85 70 2a b0 74 9b 6e 1b 43 c3 0a db c4
    // bin_str5 (0xd):
    // 0000: 20 00 73 70 64 6d 31 2e 31 20 6b 65 79
    // key (0x20) - 23 82 fc 62 b2 e8 2a d4 d6 29 6e 3f c7 38 8f 48 4e f7 fd 27 d5 c7 66 4c 6f 38 84 97 bb 9f cb 53
    // bin_str6 (0xc):
    // 0000: 0c 00 73 70 64 6d 31 2e 31 20 69 76
    // iv (0xc) - 86 2b 00 c9 58 44 5f 37 e8 86 a4 a0
    //
    // the little endian IV counter XOR will look like:
    // generate_iv counter (0x1)
    // generate_iv endian (0x0)
    // generate_iv (0xc) - 01 00 00 00 00 00 00 00 00 00 00 00

    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let major_secret = [
        0xed, 0xc0, 0x61, 0x97, 0x77, 0x0f, 0x53, 0x8c, 0xb2, 0x50, 0x85, 0xb0, 0xbc, 0x98, 0xc0,
        0x49, 0x54, 0xdb, 0x9c, 0xa6, 0x4b, 0x2c, 0x78, 0x28, 0x50, 0xf2, 0xca, 0x5a, 0xd3, 0x37,
        0x16, 0x2f, 0x2f, 0x24, 0x42, 0x85, 0x70, 0x2a, 0xb0, 0x74, 0x9b, 0x6e, 0x1b, 0x43, 0xc3,
        0x0a, 0xdb, 0xc4,
    ];

    let major_secret_cmk = import_key(&mut model, &major_secret, CmKeyUsage::Hmac);
    let plaintext = [1, 2, 3, 4, 5, 6, 7, 8];

    // test with little endian counter (the standard)

    let (tag, ciphertext) = mailbox_spdm_gcm_encrypt(
        &mut model,
        &major_secret_cmk,
        &[],
        &plaintext,
        0x11,
        1,
        false,
    );

    let iv = [
        0x87, 0x2b, 0x00, 0xc9, 0x58, 0x44, 0x5f, 0x37, 0xe8, 0x86, 0xa4, 0xa0,
    ];
    let expected_key = [
        0x23, 0x82, 0xfc, 0x62, 0xb2, 0xe8, 0x2a, 0xd4, 0xd6, 0x29, 0x6e, 0x3f, 0xc7, 0x38, 0x8f,
        0x48, 0x4e, 0xf7, 0xfd, 0x27, 0xd5, 0xc7, 0x66, 0x4c, 0x6f, 0x38, 0x84, 0x97, 0xbb, 0x9f,
        0xcb, 0x53,
    ];

    let (rtag, rciphertext) = rustcrypto_gcm_encrypt(&expected_key, &iv, &[], &plaintext);

    assert_eq!(ciphertext, rciphertext);
    assert_eq!(tag, rtag);

    let (ok, check_plaintext) = mailbox_spdm_gcm_decrypt(
        &mut model,
        &major_secret_cmk,
        &[],
        &ciphertext,
        &rtag,
        0x11,
        1,
        false,
    );
    assert!(ok);
    assert_eq!(check_plaintext, plaintext);

    // test with big endian counter (not in the standard but libspdm supports it)

    let (tag, ciphertext) = mailbox_spdm_gcm_encrypt(
        &mut model,
        &major_secret_cmk,
        &[],
        &plaintext,
        0x11,
        1,
        true,
    );

    let iv = [
        0x86, 0x2b, 0x00, 0xc9, 0x58, 0x44, 0x5f, 0x37, 0xe8, 0x86, 0xa4, 0xa1,
    ];
    let expected_key = [
        0x23, 0x82, 0xfc, 0x62, 0xb2, 0xe8, 0x2a, 0xd4, 0xd6, 0x29, 0x6e, 0x3f, 0xc7, 0x38, 0x8f,
        0x48, 0x4e, 0xf7, 0xfd, 0x27, 0xd5, 0xc7, 0x66, 0x4c, 0x6f, 0x38, 0x84, 0x97, 0xbb, 0x9f,
        0xcb, 0x53,
    ];

    let (rtag, rciphertext) = rustcrypto_gcm_encrypt(&expected_key, &iv, &[], &plaintext);

    assert_eq!(ciphertext, rciphertext);
    assert_eq!(tag, rtag);

    let (ok, check_plaintext) = mailbox_spdm_gcm_decrypt(
        &mut model,
        &major_secret_cmk,
        &[],
        &ciphertext,
        &rtag,
        0x11,
        1,
        true,
    );
    assert!(ok);
    assert_eq!(check_plaintext, plaintext);
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
        cmks.push(import_key(&mut model, &key, CmKeyUsage::Aes));
    }

    for _ in 0..100 {
        let key_idx = seeded_rng.gen_range(0..KEYS);
        let len = seeded_rng
            .gen_range(0..MAX_CMB_DATA_SIZE * 3)
            .next_multiple_of(AES_BLOCK_SIZE_BYTES);
        let mut plaintext = vec![0u8; len];
        seeded_rng.fill_bytes(&mut plaintext);

        let (iv, ciphertext) = mailbox_aes_encrypt(
            &mut model,
            &cmks[key_idx],
            &plaintext,
            MAX_CMB_DATA_SIZE,
            CmAesMode::Cbc,
        );
        let rciphertext = rustcrypto_cbc_encrypt(&keys[key_idx], &iv, &plaintext);
        assert_eq!(ciphertext, rciphertext);
        let dplaintext = mailbox_aes_decrypt(
            &mut model,
            &cmks[key_idx],
            &iv,
            &ciphertext,
            MAX_CMB_DATA_SIZE,
            CmAesMode::Cbc,
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
    use aes_gcm::KeyInit;
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

// Check crypting a single byte at a time.
// This checks that counter incrementing is working properly.
#[test]
fn test_aes_ctr_crypt_1() {
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
        cmks.push(import_key(&mut model, &key, CmKeyUsage::Aes));
    }

    for _ in 0..10 {
        let key_idx = seeded_rng.gen_range(0..KEYS);
        let len = seeded_rng.gen_range(0..100);
        let mut plaintext = vec![0u8; len];
        seeded_rng.fill_bytes(&mut plaintext);
        let cmk = &cmks[key_idx];

        let (iv, ciphertext) = mailbox_aes_encrypt(&mut model, cmk, &plaintext, 1, CmAesMode::Ctr);
        let rciphertext = rustcrypto_ctr_crypt(&keys[key_idx], &iv, &plaintext);
        assert_eq!(ciphertext, rciphertext);
        let dplaintext = mailbox_aes_decrypt(
            &mut model,
            &cmks[key_idx],
            &iv,
            &ciphertext,
            1,
            CmAesMode::Ctr,
        );
        assert_eq!(dplaintext, plaintext);
    }
}

// Random encrypt and decrypt CTR stress test.
#[test]
fn test_aes_ctr_random_encrypt_decrypt() {
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
        cmks.push(import_key(&mut model, &key, CmKeyUsage::Aes));
    }

    for _ in 0..50 {
        let key_idx = seeded_rng.gen_range(0..KEYS);
        let len = seeded_rng
            .gen_range(0..MAX_CMB_DATA_SIZE * 3)
            .next_multiple_of(AES_BLOCK_SIZE_BYTES);
        let split = seeded_rng.gen_range(MAX_CMB_DATA_SIZE / 2..MAX_CMB_DATA_SIZE);
        let mut plaintext = vec![0u8; len];
        seeded_rng.fill_bytes(&mut plaintext);

        let (iv, ciphertext) = mailbox_aes_encrypt(
            &mut model,
            &cmks[key_idx],
            &plaintext,
            split,
            CmAesMode::Ctr,
        );
        let rciphertext = rustcrypto_ctr_crypt(&keys[key_idx], &iv, &plaintext);
        assert_eq!(ciphertext, rciphertext);
        let dplaintext = mailbox_aes_decrypt(
            &mut model,
            &cmks[key_idx],
            &iv,
            &ciphertext,
            split,
            CmAesMode::Ctr,
        );
        assert_eq!(dplaintext, plaintext);
    }
}

type Ctr = ctr::CtrCore<Aes256, ctr::flavors::Ctr128BE>;

fn rustcrypto_ctr_crypt(key: &[u8], iv: &[u8], input: &[u8]) -> Vec<u8> {
    let ctr = Ctr::new(key.into(), iv.into());
    let mut output = input.to_vec();
    ctr.apply_keystream_partial(output.as_mut_slice().into());
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
        cmk: cmk.clone(),
        aad_size: aad.len() as u32,
        ..Default::default()
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

fn mailbox_spdm_gcm_encrypt(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    aad: &[u8],
    mut plaintext: &[u8],
    version: u8,
    counter: u64,
    big_endian_counter_xor: bool,
) -> ([u8; 16], Vec<u8>) {
    let split = MAX_CMB_DATA_SIZE;
    let mut cm_aes_encrypt_init = CmAesGcmSpdmEncryptInitReq {
        spdm_flags: (version as u32) | (if big_endian_counter_xor { 1 << 8 } else { 0 }),
        spdm_counter: counter.to_le_bytes(),
        cmk: cmk.clone(),
        aad_size: aad.len() as u32,
        ..Default::default()
    };
    cm_aes_encrypt_init.aad[..aad.len()].copy_from_slice(aad);
    let mut cm_aes_encrypt_init = MailboxReq::CmAesGcmSpdmEncryptInit(cm_aes_encrypt_init);
    cm_aes_encrypt_init.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_SPDM_ENCRYPT_INIT),
            cm_aes_encrypt_init.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    let resp = CmAesGcmSpdmEncryptInitResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

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

    (final_resp.hdr.tag, ciphertext)
}

#[allow(clippy::too_many_arguments)]
fn mailbox_gcm_decrypt(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    iv: &[u8; 12],
    aad: &[u8],
    mut ciphertext: &[u8],
    tag: &[u8; 16],
    split: usize,
) -> (bool, Vec<u8>) {
    let mut cm_aes_decrypt_init = CmAesGcmDecryptInitReq {
        cmk: cmk.clone(),
        iv: *iv,
        aad_size: aad.len() as u32,
        ..Default::default()
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
    (final_resp.hdr.tag_verified == 1, plaintext)
}

#[allow(clippy::too_many_arguments)]
fn mailbox_spdm_gcm_decrypt(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    aad: &[u8],
    mut ciphertext: &[u8],
    tag: &[u8; 16],
    version: u8,
    counter: u64,
    big_endian_counter_xor: bool,
) -> (bool, Vec<u8>) {
    let split = MAX_CMB_DATA_SIZE;
    let mut cm_aes_decrypt_init = CmAesGcmSpdmDecryptInitReq {
        hdr: MailboxReqHeader::default(),
        spdm_flags: (version as u32) | (if big_endian_counter_xor { 1 << 8 } else { 0 }),
        spdm_counter: counter.to_le_bytes(),
        cmk: cmk.clone(),
        aad_size: aad.len() as u32,
        aad: [0; MAX_CMB_DATA_SIZE],
    };
    cm_aes_decrypt_init.aad[..aad.len()].copy_from_slice(aad);
    let mut cm_aes_encrypt_init = MailboxReq::CmAesGcmSpdmDecryptInit(cm_aes_decrypt_init);
    cm_aes_encrypt_init.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_SPDM_DECRYPT_INIT),
            cm_aes_encrypt_init.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    let resp = CmAesGcmSpdmDecryptInitResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

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
    (final_resp.hdr.tag_verified == 1, plaintext)
}

fn mailbox_aes_encrypt(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    mut plaintext: &[u8],
    split: usize,
    mode: CmAesMode,
) -> ([u8; 16], Vec<u8>) {
    let init_len = plaintext.len().min(split);
    let mut cm_aes_encrypt_init = CmAesEncryptInitReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        mode: mode as u32,
        plaintext_size: init_len as u32,
        plaintext: [0; MAX_CMB_DATA_SIZE],
    };
    cm_aes_encrypt_init.plaintext[..init_len].copy_from_slice(&plaintext[..init_len]);
    plaintext = &plaintext[init_len..];
    let mut cm_aes_encrypt_init = MailboxReq::CmAesEncryptInit(cm_aes_encrypt_init);
    cm_aes_encrypt_init.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_ENCRYPT_INIT),
            cm_aes_encrypt_init.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    const INIT_HEADER_SIZE: usize = size_of::<CmAesEncryptInitRespHeader>();
    let mut resp = CmAesEncryptInitResp {
        hdr: CmAesEncryptInitRespHeader::read_from_bytes(&resp_bytes[..INIT_HEADER_SIZE]).unwrap(),
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
        let mut cm_aes_encrypt_update = CmAesEncryptUpdateReq {
            hdr: MailboxReqHeader::default(),
            context,
            plaintext_size: len as u32,
            plaintext: [0; MAX_CMB_DATA_SIZE],
        };
        cm_aes_encrypt_update.plaintext[..len].copy_from_slice(&plaintext[..len]);
        let mut cm_aes_encrypt_update: MailboxReq =
            MailboxReq::CmAesEncryptUpdate(cm_aes_encrypt_update);
        plaintext = &plaintext[len..];
        cm_aes_encrypt_update.populate_chksum().unwrap();

        let update_resp_bytes = model
            .mailbox_execute(
                u32::from(CommandId::CM_AES_ENCRYPT_UPDATE),
                cm_aes_encrypt_update.as_bytes().unwrap(),
            )
            .expect("Should have succeeded")
            .unwrap();

        const UPDATE_HEADER_SIZE: usize = size_of::<CmAesRespHeader>();

        let mut update_resp = CmAesResp {
            hdr: CmAesRespHeader::read_from_bytes(&update_resp_bytes[..UPDATE_HEADER_SIZE])
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

fn mailbox_aes_decrypt(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    iv: &[u8; 16],
    mut ciphertext: &[u8],
    split: usize,
    mode: CmAesMode,
) -> Vec<u8> {
    let init_len = ciphertext.len().min(split);
    let mut cm_aes_decrypt_init = CmAesDecryptInitReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        mode: mode as u32,
        iv: *iv,
        ciphertext_size: init_len as u32,
        ciphertext: [0; MAX_CMB_DATA_SIZE],
    };
    cm_aes_decrypt_init.ciphertext[..init_len].copy_from_slice(&ciphertext[..init_len]);
    ciphertext = &ciphertext[init_len..];
    let mut cm_aes_encrypt_init = MailboxReq::CmAesDecryptInit(cm_aes_decrypt_init);
    cm_aes_encrypt_init.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_DECRYPT_INIT),
            cm_aes_encrypt_init.as_bytes().unwrap(),
        )
        .expect("Should have succeeded")
        .unwrap();

    const RESP_HEADER_SIZE: usize = size_of::<CmAesRespHeader>();

    let mut resp = CmAesResp {
        hdr: CmAesRespHeader::read_from_bytes(&resp_bytes[..RESP_HEADER_SIZE]).unwrap(),
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
        let mut cm_aes_decrypt_update = CmAesDecryptUpdateReq {
            hdr: MailboxReqHeader::default(),
            context,
            ciphertext_size: len as u32,
            ciphertext: [0; MAX_CMB_DATA_SIZE],
        };
        cm_aes_decrypt_update.ciphertext[..len].copy_from_slice(&ciphertext[..len]);
        let mut cm_aes_decrypt_update = MailboxReq::CmAesDecryptUpdate(cm_aes_decrypt_update);
        ciphertext = &ciphertext[len..];
        cm_aes_decrypt_update.populate_chksum().unwrap();

        let update_resp_bytes = model
            .mailbox_execute(
                u32::from(CommandId::CM_AES_DECRYPT_UPDATE),
                cm_aes_decrypt_update.as_bytes().unwrap(),
            )
            .expect("Should have succeeded")
            .unwrap();

        let mut update_resp = CmAesResp {
            hdr: CmAesRespHeader::read_from_bytes(&update_resp_bytes[..RESP_HEADER_SIZE]).unwrap(),
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

fn import_key(model: &mut DefaultHwModel, key: &[u8], key_usage: CmKeyUsage) -> Cmk {
    let mut input = [0u8; 64];
    input[..key.len()].copy_from_slice(key);

    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: key_usage.into(),
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
        key_usage: CmKeyUsage::Aes.into(),
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
    let cmk = &resp.output;

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

// We can't do HMAC-SHA-512 on a 384-bit key in HW.
#[test]
fn test_hmac_cant_use_sha512_on_384_key() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let cmk = import_key(&mut model, &[0u8; 48], CmKeyUsage::Hmac);

    let cm_hmac = CmHmacReq {
        cmk: cmk.clone(),
        hash_algorithm: CmHashAlgorithm::Sha512.into(),
        ..Default::default()
    };
    let mut cm_hmac = MailboxReq::CmHmac(cm_hmac);
    cm_hmac.populate_chksum().unwrap();

    let err = model
        .mailbox_execute(u32::from(CommandId::CM_HMAC), cm_hmac.as_bytes().unwrap())
        .expect_err("Should have failed");
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::CMB_HMAC_INVALID_KEY_USAGE_AND_SIZE,
        err,
    );
}

type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

#[test]
fn test_hmac_random() {
    let seed_bytes = [1u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed_bytes);

    for size in [48, 64] {
        let hash_algorithm = if size == 48 {
            CmHashAlgorithm::Sha384
        } else {
            CmHashAlgorithm::Sha512
        };
        let mut model = run_rt_test(RuntimeTestArgs::default());
        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });
        const KEYS: usize = 16;
        let mut keys = vec![];
        let mut cmks = vec![];
        for _ in 0..KEYS {
            let mut key = vec![0u8; size];
            seeded_rng.fill_bytes(&mut key);
            cmks.push(import_key(&mut model, &key, CmKeyUsage::Hmac));
            keys.push(key);
        }

        for _ in 0..100 {
            let key_idx = seeded_rng.gen_range(0..KEYS);
            let len = seeded_rng.gen_range(0..MAX_CMB_DATA_SIZE);
            let mut data = vec![0u8; len];
            seeded_rng.fill_bytes(&mut data);

            let mut cm_hmac = CmHmacReq {
                cmk: cmks[key_idx].clone(),
                hash_algorithm: hash_algorithm.into(),
                data_size: len as u32,
                ..Default::default()
            };
            cm_hmac.data[..len].copy_from_slice(&data);
            let mut cm_hmac = MailboxReq::CmHmac(cm_hmac);
            cm_hmac.populate_chksum().unwrap();

            let resp_bytes = model
                .mailbox_execute(u32::from(CommandId::CM_HMAC), cm_hmac.as_bytes().unwrap())
                .expect("Should have succeeded")
                .unwrap();
            const HMAC_HEADER_SIZE: usize = size_of::<MailboxRespHeaderVarSize>();
            let mut resp = CmHmacResp {
                hdr: MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..HMAC_HEADER_SIZE])
                    .unwrap(),
                ..Default::default()
            };
            let len = resp.hdr.data_len as usize;
            assert!(len < MAX_CMB_DATA_SIZE);
            resp.mac[..len].copy_from_slice(&resp_bytes[HMAC_HEADER_SIZE..HMAC_HEADER_SIZE + len]);

            assert_eq!(len, resp.hdr.data_len as usize);
            let expected_hmac = rustcrypto_hmac(hash_algorithm, &keys[key_idx], &data);
            assert_eq!(resp.mac[..len], expected_hmac);
        }
    }
}

#[test]
fn test_hmac_kdf_counter_random() {
    let seed_bytes = [1u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed_bytes);

    for size in [48, 64] {
        let hash_algorithm = if size == 48 {
            CmHashAlgorithm::Sha384
        } else {
            CmHashAlgorithm::Sha512
        };
        let mut model = run_rt_test(RuntimeTestArgs::default());
        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });
        const KEYS: usize = 16;
        let mut keys = vec![];
        let mut cmks = vec![];
        for _ in 0..KEYS {
            let mut key = vec![0u8; size];
            seeded_rng.fill_bytes(&mut key);
            cmks.push(import_key(&mut model, &key, CmKeyUsage::Hmac));
            keys.push(key);
        }

        for _ in 0..100 {
            let key_idx = seeded_rng.gen_range(0..KEYS);
            let len = seeded_rng.gen_range(0..MAX_CMB_DATA_SIZE);
            let mut data = vec![0u8; len];
            seeded_rng.fill_bytes(&mut data);

            let mut cm_hmac_kdf = CmHmacKdfCounterReq {
                kin: cmks[key_idx].clone(),
                hash_algorithm: hash_algorithm.into(),
                key_usage: CmKeyUsage::Aes.into(),
                key_size: 32,
                label_size: len as u32,
                ..Default::default()
            };
            cm_hmac_kdf.label[..len].copy_from_slice(&data);
            let mut cm_hmac_kdf = MailboxReq::CmHmacKdfCounter(cm_hmac_kdf);
            cm_hmac_kdf.populate_chksum().unwrap();

            let resp_bytes = model
                .mailbox_execute(
                    u32::from(CommandId::CM_HMAC_KDF_COUNTER),
                    cm_hmac_kdf.as_bytes().unwrap(),
                )
                .expect("Should have succeeded")
                .unwrap();
            let resp = CmHmacKdfCounterResp::ref_from_bytes(resp_bytes.as_slice())
                .expect("Response should be correct size");

            let cmk = &resp.kout;

            let key = rustcrypto_hmac_hkdf_counter(hash_algorithm, &keys[key_idx], &data);

            // use the CMK shared secret to AES encrypt a known plaintext.
            let plaintext = [0u8; 16];
            let (iv, tag, ciphertext) =
                mailbox_gcm_encrypt(&mut model, cmk, &[], &plaintext, MAX_CMB_DATA_SIZE);
            // encrypt with RustCrypto and check if everything matches
            let (rtag, rciphertext) = rustcrypto_gcm_encrypt(&key[..32], &iv, &[], &plaintext);

            // check that ciphertext and tags match, meaning the shared secret is the same on both sides
            assert_eq!(ciphertext, rciphertext);
            assert_eq!(tag, rtag);
        }
    }
}

fn rustcrypto_hmac_hkdf_counter(
    hash_algorithm: CmHashAlgorithm,
    key: &[u8],
    label: &[u8],
) -> Vec<u8> {
    let mut data = vec![];
    data.extend(1u32.to_be_bytes().as_slice());
    data.extend(label);
    rustcrypto_hmac(hash_algorithm, key, &data)
}

fn rustcrypto_hmac(hash_algorithm: CmHashAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    match hash_algorithm {
        CmHashAlgorithm::Sha384 => {
            let mut mac = HmacSha384::new_from_slice(key).unwrap();
            mac.update(data);
            let result = mac.finalize();
            let x: [u8; 48] = result.into_bytes().into();
            x.into()
        }
        CmHashAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(key).unwrap();
            mac.update(data);
            let result = mac.finalize();
            let x: [u8; 64] = result.into_bytes().into();
            x.into()
        }
        _ => panic!("Invalid hash algorithm"),
    }
}

type Hkdf384 = Hkdf<Sha384>;
type Hkdf512 = Hkdf<Sha512>;

fn rustcrypto_hkdf(
    hash_algorithm: CmHashAlgorithm,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Vec<u8> {
    match hash_algorithm {
        CmHashAlgorithm::Sha384 => {
            let hk = Hkdf384::new(Some(salt), ikm);
            let mut okm = [0u8; 48];
            hk.expand(info, &mut okm).unwrap();
            Vec::from(&okm)
        }
        CmHashAlgorithm::Sha512 => {
            let hk = Hkdf512::new(Some(salt), ikm);
            let mut okm = [0u8; 64];
            hk.expand(info, &mut okm).unwrap();
            Vec::from(&okm)
        }
        _ => panic!("Invalid hash algorithm"),
    }
}

#[test]
fn test_hkdf_random() {
    let seed_bytes = [1u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed_bytes);

    for size in [48, 64] {
        let hash_algorithm = if size == 48 {
            CmHashAlgorithm::Sha384
        } else {
            CmHashAlgorithm::Sha512
        };
        let mut model = run_rt_test(RuntimeTestArgs::default());
        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });
        const KEYS: usize = 16;
        let mut keys = vec![];
        let mut cmks = vec![];
        for _ in 0..KEYS {
            let mut key = vec![0u8; size];
            seeded_rng.fill_bytes(&mut key);
            cmks.push(import_key(&mut model, &key, CmKeyUsage::Hmac));
            keys.push(key);
        }

        for _ in 0..25 {
            let key_idx = seeded_rng.gen_range(0..KEYS);
            let salt_len = seeded_rng.gen_range(0..size);
            let mut salt = [0u8; 64];
            seeded_rng.fill_bytes(&mut salt[..salt_len]);

            let salt_cmk = import_key(&mut model, &salt[..size], CmKeyUsage::Hmac);

            let mut cm_hkdf_extract = MailboxReq::CmHkdfExtract(CmHkdfExtractReq {
                ikm: cmks[key_idx].clone(),
                hash_algorithm: hash_algorithm.into(),
                salt: salt_cmk,
                ..Default::default()
            });
            cm_hkdf_extract.populate_chksum().unwrap();

            let resp_bytes = model
                .mailbox_execute(
                    u32::from(CommandId::CM_HKDF_EXTRACT),
                    cm_hkdf_extract.as_bytes().unwrap(),
                )
                .expect("Should have succeeded")
                .unwrap();
            let resp = CmHkdfExtractResp::ref_from_bytes(resp_bytes.as_slice())
                .expect("Response should be correct size");

            let len = seeded_rng.gen_range(0..MAX_CMB_DATA_SIZE);
            let mut info = vec![0u8; len];
            seeded_rng.fill_bytes(&mut info);

            let mut cm_hkdf_expand = CmHkdfExpandReq {
                prk: resp.prk.clone(),
                hash_algorithm: hash_algorithm.into(),
                key_usage: CmKeyUsage::Aes.into(),
                key_size: 32,
                info_size: len as u32,
                ..Default::default()
            };
            cm_hkdf_expand.info[..len].copy_from_slice(&info);
            let mut cm_hkdf_expand = MailboxReq::CmHkdfExpand(cm_hkdf_expand);
            cm_hkdf_expand.populate_chksum().unwrap();

            let resp_bytes = model
                .mailbox_execute(
                    u32::from(CommandId::CM_HKDF_EXPAND),
                    cm_hkdf_expand.as_bytes().unwrap(),
                )
                .expect("Should have succeeded")
                .unwrap();
            let resp = CmHkdfExpandResp::ref_from_bytes(resp_bytes.as_slice())
                .expect("Response should be correct size");

            let cmk = &resp.okm;
            let key = rustcrypto_hkdf(hash_algorithm, &keys[key_idx], &salt[..salt_len], &info);

            // use the CMK shared secret to AES encrypt a known plaintext.
            let plaintext = [0u8; 16];
            let (iv, tag, ciphertext) =
                mailbox_gcm_encrypt(&mut model, cmk, &[], &plaintext, MAX_CMB_DATA_SIZE);
            // encrypt with RustCrypto and check if everything matches
            let (rtag, rciphertext) = rustcrypto_gcm_encrypt(&key[..32], &iv, &[], &plaintext);

            // check that ciphertext and tags match, meaning the shared secret is the same on both sides
            assert_eq!(ciphertext, rciphertext);
            assert_eq!(tag, rtag);
        }
    }
}

#[test]
fn test_mldsa_public_key() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let seed_bytes: [u8; 32] = [
        0x63, 0x1a, 0xfc, 0x2a, 0x36, 0xa5, 0x7e, 0x1d, 0x09, 0x0d, 0xad, 0xc2, 0x79, 0x1d, 0x48,
        0x6d, 0x72, 0xc6, 0x9a, 0x9a, 0xab, 0xf9, 0x79, 0x90, 0xc5, 0x73, 0x21, 0x48, 0x46, 0xfe,
        0x5b, 0x64,
    ];
    let cmk = import_key(&mut model, &seed_bytes, CmKeyUsage::Mldsa);

    let mut req = MailboxReq::CmMldsaPublicKey(CmMldsaPublicKeyReq {
        cmk: cmk.clone(),
        ..Default::default()
    });
    req.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
        .unwrap()
        .expect("Should have gotten a response");
    let resp = CmMldsaPublicKeyResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

    let expected_public_key: [u8; 2592] = [
        0x57, 0x34, 0x49, 0xae, 0x17, 0x72, 0x43, 0x0d, 0xb9, 0x58, 0xdd, 0x78, 0x74, 0x7f, 0x0a,
        0xef, 0xc0, 0x3f, 0x6d, 0xde, 0xdc, 0xe5, 0x92, 0xd5, 0xf4, 0xb5, 0x17, 0xb3, 0x8b, 0xcf,
        0xcb, 0x90, 0xe6, 0xc1, 0xdf, 0x44, 0xce, 0x2c, 0xe4, 0xd3, 0xc6, 0xa5, 0x68, 0x2d, 0x05,
        0x7d, 0xbd, 0xcf, 0xce, 0xd3, 0xea, 0x58, 0xea, 0x12, 0x54, 0x37, 0xf6, 0xb8, 0x96, 0xa4,
        0x73, 0xce, 0x48, 0x80, 0xff, 0xbb, 0x97, 0xc2, 0xc0, 0x75, 0x0d, 0x41, 0xd1, 0xb7, 0xc0,
        0x0e, 0x21, 0x06, 0x13, 0x7d, 0xae, 0x49, 0x60, 0x9d, 0xd6, 0x30, 0xa2, 0x3d, 0x5d, 0x49,
        0x8d, 0x54, 0x66, 0x25, 0xf8, 0x0e, 0x29, 0xa6, 0xb1, 0x8b, 0x01, 0xde, 0x39, 0x9f, 0xaf,
        0xc9, 0x11, 0xee, 0xac, 0x4a, 0x97, 0x76, 0x1e, 0xc0, 0x19, 0x73, 0x59, 0xa1, 0xe4, 0xb3,
        0x93, 0x0d, 0xb1, 0x7a, 0x61, 0x44, 0xbd, 0x7b, 0x2b, 0x3c, 0x93, 0xdd, 0x1f, 0x21, 0xa0,
        0x56, 0x2c, 0xe6, 0xc6, 0xd1, 0x12, 0x8f, 0x65, 0x89, 0x49, 0x8e, 0x61, 0x33, 0xf9, 0x81,
        0x64, 0xd5, 0x44, 0xc8, 0x88, 0xa1, 0xda, 0x5a, 0x5e, 0x26, 0x6e, 0x7d, 0x18, 0x64, 0xfa,
        0xb2, 0x57, 0x08, 0xce, 0x6b, 0x60, 0x7c, 0x11, 0xd5, 0x2b, 0x0f, 0x58, 0x2f, 0x63, 0x68,
        0xbf, 0xd7, 0x33, 0x25, 0x92, 0x75, 0xb0, 0x99, 0xbc, 0xb5, 0x00, 0xfa, 0x62, 0xb5, 0xe3,
        0x66, 0xce, 0x20, 0x93, 0xe8, 0x9c, 0xd3, 0xef, 0xfe, 0x8d, 0xd3, 0xcf, 0x2c, 0xd0, 0x1a,
        0xc8, 0x17, 0x6b, 0xa2, 0x35, 0x23, 0x33, 0xfb, 0xe0, 0x44, 0xcf, 0x5f, 0xe0, 0x95, 0x53,
        0xa3, 0x18, 0xf0, 0x5f, 0x05, 0x5b, 0x83, 0xc7, 0x23, 0x9d, 0xaf, 0x26, 0x8c, 0x27, 0xfc,
        0x85, 0xf6, 0xa4, 0x1e, 0xb5, 0x80, 0x57, 0x0b, 0xa6, 0xc5, 0x98, 0xa6, 0x4c, 0x3f, 0x09,
        0x56, 0xac, 0x91, 0xee, 0x58, 0x81, 0x4e, 0x3e, 0xe0, 0x9f, 0x69, 0x71, 0x8c, 0xae, 0xcf,
        0xe8, 0xc0, 0xbf, 0xa6, 0xcd, 0xec, 0xe7, 0x33, 0xb6, 0x56, 0xd5, 0xee, 0xd9, 0xf3, 0x9f,
        0xd7, 0xab, 0x9f, 0x07, 0x90, 0x96, 0x4d, 0x7f, 0xc0, 0xe6, 0xfb, 0xf2, 0xa9, 0x78, 0x15,
        0x39, 0x87, 0x51, 0x79, 0xad, 0xa3, 0xa8, 0x77, 0x12, 0x88, 0xc9, 0x57, 0xd4, 0x78, 0xaa,
        0x47, 0xe8, 0x00, 0x76, 0x87, 0x43, 0xb2, 0xce, 0xe8, 0xbd, 0x22, 0x8d, 0xab, 0x02, 0xe0,
        0x49, 0xec, 0x64, 0x32, 0xb9, 0xa2, 0xd2, 0x1a, 0xb7, 0x7f, 0xa3, 0x13, 0x21, 0x3e, 0xbd,
        0x9c, 0x59, 0xe8, 0x59, 0x1a, 0x48, 0x0e, 0x7e, 0xb5, 0x1b, 0x22, 0x37, 0xeb, 0x71, 0x7f,
        0x7b, 0x1d, 0xe6, 0x84, 0xe6, 0xfb, 0xb8, 0xad, 0x78, 0xaf, 0x5f, 0x03, 0x2d, 0x75, 0x2c,
        0xc2, 0x8b, 0x4b, 0x03, 0xa5, 0x37, 0x15, 0x6c, 0xad, 0x9d, 0x07, 0x3b, 0x4f, 0x50, 0xad,
        0x8c, 0x86, 0x9d, 0xb0, 0xba, 0xdc, 0x7d, 0xba, 0xfd, 0xec, 0x5d, 0x92, 0xeb, 0xfb, 0x00,
        0xe2, 0xba, 0x9c, 0x85, 0x32, 0x79, 0x88, 0xd0, 0x9c, 0xa9, 0x0c, 0x2f, 0xdb, 0xb2, 0x19,
        0xe5, 0xa7, 0x5f, 0x85, 0x78, 0xd7, 0xd4, 0xa2, 0xad, 0x53, 0xa0, 0xe0, 0x4b, 0x7d, 0x90,
        0x4f, 0x4c, 0x69, 0x39, 0xaa, 0x16, 0x43, 0x5d, 0x14, 0xd6, 0x13, 0x96, 0xd4, 0x7c, 0xdb,
        0x5f, 0x27, 0x8f, 0xb8, 0x78, 0x39, 0xb1, 0xec, 0x85, 0x7c, 0x9d, 0x81, 0x8b, 0x91, 0x7a,
        0xce, 0x3d, 0x34, 0x50, 0xbe, 0xe9, 0xd0, 0xe5, 0x1d, 0xeb, 0xdc, 0x64, 0xde, 0x38, 0xde,
        0x70, 0x42, 0x9b, 0xf7, 0xdf, 0xc0, 0x88, 0x08, 0x17, 0xba, 0x20, 0x28, 0x40, 0xa3, 0xcb,
        0x83, 0x8d, 0x45, 0x37, 0x3f, 0x55, 0x3c, 0x5c, 0xd3, 0x0c, 0xd1, 0x36, 0xc2, 0xd3, 0xf3,
        0x83, 0x7f, 0xf9, 0x11, 0x40, 0x22, 0xa2, 0xda, 0x73, 0x04, 0x8c, 0xa5, 0x37, 0x99, 0x59,
        0x4f, 0x35, 0x3c, 0xe5, 0x32, 0x0f, 0x2e, 0x92, 0x1b, 0x92, 0x76, 0x27, 0xd7, 0xf6, 0x74,
        0x1b, 0xc9, 0x5b, 0x03, 0x65, 0x77, 0x53, 0xb6, 0x4a, 0x95, 0x13, 0x32, 0x8f, 0xe9, 0x49,
        0xcf, 0x19, 0xa0, 0x98, 0x6a, 0x89, 0xbb, 0xee, 0xf4, 0x09, 0xe9, 0xac, 0xdb, 0x73, 0xde,
        0x81, 0xfe, 0xa6, 0x48, 0x2d, 0x31, 0xc0, 0x5e, 0xed, 0xe5, 0x01, 0x14, 0x63, 0xf4, 0x8b,
        0x17, 0x75, 0x34, 0xe0, 0x35, 0x08, 0x9f, 0xc9, 0x8a, 0xfb, 0x92, 0x89, 0x89, 0x25, 0x0c,
        0x55, 0x21, 0xbd, 0x9b, 0xd8, 0x77, 0xee, 0x80, 0xf1, 0xe8, 0xa7, 0x07, 0x76, 0xf9, 0x51,
        0xdd, 0xd2, 0x9e, 0xd9, 0x68, 0x51, 0xf1, 0x4f, 0x87, 0x3a, 0x54, 0x61, 0x99, 0x58, 0xdc,
        0xc3, 0x57, 0x42, 0xf8, 0xbc, 0x27, 0xda, 0x8f, 0xce, 0x7f, 0x2b, 0xa4, 0xfc, 0xf2, 0xc1,
        0xb7, 0xbd, 0xe0, 0x1d, 0xaa, 0xfd, 0xe2, 0x0b, 0x91, 0xc9, 0xc2, 0x55, 0xd2, 0xaf, 0xdc,
        0x5d, 0x4e, 0x69, 0x2c, 0xa9, 0x25, 0x49, 0xc5, 0x97, 0xe7, 0x6d, 0x44, 0x07, 0xb2, 0xa0,
        0x2b, 0xcc, 0x96, 0x83, 0xf7, 0xe0, 0xa3, 0xed, 0xec, 0xbd, 0xfe, 0x4a, 0xa4, 0x00, 0xcd,
        0xaa, 0x92, 0xfc, 0xb1, 0x09, 0x37, 0xac, 0x44, 0x41, 0x11, 0x6e, 0x67, 0xd0, 0xc7, 0xd7,
        0x34, 0xba, 0xcc, 0xed, 0x4d, 0xf8, 0xf4, 0x99, 0x93, 0x5d, 0x84, 0xbd, 0x57, 0xf9, 0x40,
        0xfb, 0xe6, 0x92, 0x29, 0xb0, 0xe1, 0x69, 0xb5, 0x0e, 0x30, 0xb4, 0x07, 0x92, 0x64, 0x5a,
        0xd9, 0xa1, 0xa7, 0xb0, 0xe3, 0x2a, 0xe4, 0xd2, 0x95, 0xc7, 0xc6, 0x03, 0x7e, 0x9a, 0xbc,
        0xd0, 0xd3, 0x49, 0x42, 0xee, 0x11, 0x6b, 0xe7, 0x5a, 0xca, 0x4d, 0x1e, 0x34, 0xac, 0x92,
        0x89, 0x6f, 0x3f, 0x34, 0xbd, 0x9e, 0x74, 0x00, 0x78, 0x7e, 0xae, 0x0d, 0xa6, 0x90, 0xb6,
        0x70, 0xe0, 0x5a, 0xa3, 0x35, 0x68, 0xcd, 0x9c, 0x34, 0x80, 0x83, 0xff, 0xfe, 0xba, 0x87,
        0x2d, 0x85, 0x50, 0x28, 0xe2, 0x0e, 0x2b, 0x08, 0x77, 0xdf, 0x4c, 0x83, 0x11, 0xb1, 0x66,
        0x7f, 0x34, 0x0e, 0x67, 0x58, 0x0a, 0x68, 0x04, 0x89, 0xd4, 0xa0, 0x64, 0xd8, 0x18, 0xd3,
        0x86, 0xf1, 0x13, 0xbf, 0x51, 0x5f, 0x0a, 0x9c, 0x95, 0x3d, 0x37, 0x08, 0xd9, 0x0b, 0xd3,
        0x59, 0x30, 0xfc, 0x6d, 0x86, 0x9f, 0xfb, 0xc4, 0x3c, 0xc0, 0xf2, 0xef, 0x8e, 0xd4, 0xef,
        0xfb, 0xa7, 0x78, 0xdb, 0x0e, 0x92, 0x60, 0x60, 0xcb, 0xb2, 0x3e, 0xd4, 0xa3, 0x7a, 0x1a,
        0x25, 0x30, 0x65, 0xa2, 0xdc, 0x3d, 0x06, 0xea, 0x53, 0xae, 0x2a, 0xb4, 0x22, 0x88, 0xc2,
        0x72, 0xab, 0xed, 0x84, 0x94, 0x19, 0xcf, 0x18, 0x45, 0xdc, 0x3a, 0x54, 0x10, 0xda, 0x5f,
        0x62, 0x4e, 0x72, 0x29, 0x76, 0x61, 0x0e, 0x3f, 0x8f, 0x48, 0x39, 0x20, 0xc4, 0x6a, 0x41,
        0xf1, 0xfe, 0x64, 0x83, 0xa6, 0xea, 0x28, 0x0c, 0x7c, 0xfb, 0xe4, 0x1a, 0xcf, 0x16, 0x12,
        0x03, 0x9c, 0xf1, 0x48, 0xef, 0xc8, 0x21, 0xc4, 0x3d, 0x0d, 0x34, 0x75, 0x3b, 0x8b, 0x5e,
        0xc5, 0x0f, 0xdd, 0x18, 0x4b, 0x07, 0xc4, 0xbc, 0x9f, 0x49, 0xd1, 0xfa, 0xc1, 0x97, 0x85,
        0x55, 0x58, 0xd3, 0x45, 0x17, 0x2a, 0xf5, 0x4c, 0x38, 0x2d, 0x21, 0x9f, 0x36, 0x8e, 0x46,
        0xeb, 0xfa, 0x8e, 0x3a, 0xb1, 0x81, 0x62, 0xe7, 0x08, 0xf1, 0x86, 0x63, 0x5e, 0xc4, 0x45,
        0xbb, 0xcf, 0x1f, 0x4f, 0x6c, 0x83, 0xef, 0x65, 0x11, 0xf9, 0x40, 0xbc, 0x21, 0x50, 0x65,
        0x1c, 0x5f, 0xa9, 0x5a, 0xc1, 0xf5, 0xda, 0x4a, 0xb9, 0x6d, 0x33, 0x10, 0x01, 0xbd, 0x9e,
        0x0a, 0x1f, 0x41, 0xd4, 0x79, 0x16, 0xa7, 0xe2, 0x06, 0xae, 0x8c, 0x14, 0x06, 0x50, 0xda,
        0x2a, 0x91, 0xbb, 0x70, 0x43, 0xed, 0xf2, 0x94, 0x29, 0x23, 0x94, 0x63, 0x52, 0xaf, 0x35,
        0xdd, 0x72, 0x67, 0x55, 0x0f, 0x4c, 0xc7, 0x8e, 0xb6, 0xeb, 0xfd, 0x79, 0xda, 0x14, 0x26,
        0x32, 0x6a, 0xbc, 0x10, 0x25, 0x57, 0xdb, 0xc4, 0x0c, 0x00, 0x4b, 0xd8, 0xee, 0xde, 0xb5,
        0x43, 0xfa, 0x97, 0x83, 0xe0, 0x20, 0x48, 0x68, 0x16, 0x63, 0x31, 0x85, 0x9a, 0xa9, 0x50,
        0x8c, 0x1f, 0x4e, 0x83, 0xfa, 0xe9, 0xd7, 0xe0, 0x2b, 0x30, 0x5a, 0xc9, 0xc5, 0x29, 0x21,
        0x7d, 0xe1, 0x24, 0xe5, 0x9c, 0xf9, 0xd0, 0x07, 0xe5, 0xa4, 0x59, 0xa1, 0x7a, 0x6f, 0x1e,
        0x19, 0xb2, 0x15, 0x56, 0x0d, 0x49, 0xb2, 0x6a, 0x17, 0x1a, 0x2e, 0xc0, 0x82, 0xc2, 0x20,
        0xbf, 0x40, 0x7b, 0xdb, 0x75, 0xca, 0x96, 0x23, 0x21, 0xb7, 0x86, 0x5d, 0x73, 0xe8, 0xea,
        0x70, 0x70, 0xb7, 0x3f, 0x93, 0xed, 0x69, 0xa1, 0x4d, 0x3c, 0xf3, 0x5b, 0x11, 0x15, 0x10,
        0xef, 0x60, 0x98, 0xa0, 0x8a, 0x97, 0x45, 0xea, 0x79, 0x80, 0xd9, 0x9a, 0x44, 0xb4, 0xcb,
        0xe1, 0x0b, 0x12, 0x6c, 0xa5, 0xc6, 0x1f, 0x1c, 0xd0, 0xb4, 0xdd, 0x2c, 0xd3, 0xd5, 0x1c,
        0xb7, 0x2a, 0x9c, 0xc3, 0x4b, 0xc6, 0x1d, 0x31, 0x8e, 0x3c, 0xcc, 0x7d, 0x1c, 0x04, 0x51,
        0x1d, 0xfe, 0x86, 0x5c, 0x59, 0x0c, 0xd9, 0x52, 0xe0, 0x7d, 0x26, 0xbd, 0x91, 0x62, 0x79,
        0x5a, 0xb5, 0xd5, 0xd4, 0x4f, 0x59, 0xa3, 0x88, 0xf9, 0xcf, 0x71, 0xab, 0xa8, 0x5a, 0xc2,
        0x4c, 0xb6, 0xeb, 0xe5, 0x70, 0xbd, 0x7d, 0xee, 0x2f, 0x16, 0x21, 0xdc, 0x50, 0x9c, 0x4a,
        0x26, 0x9e, 0x6b, 0x4a, 0x9e, 0x66, 0x06, 0x8d, 0x45, 0xe9, 0x5a, 0x7e, 0xf9, 0xa3, 0x94,
        0xcc, 0xee, 0x13, 0xac, 0xf8, 0x93, 0xa5, 0xad, 0xcf, 0x81, 0x12, 0xda, 0x07, 0x7e, 0x3d,
        0xea, 0xda, 0xbc, 0x6b, 0x8a, 0xcf, 0xbf, 0x59, 0x8d, 0xb0, 0x49, 0x6d, 0x2a, 0x3d, 0x6c,
        0x58, 0x72, 0x3a, 0xea, 0x49, 0xb8, 0x26, 0x7d, 0x16, 0x56, 0xd9, 0x44, 0x37, 0xa0, 0x83,
        0x0e, 0x22, 0xe5, 0x09, 0xb8, 0x15, 0x9b, 0x11, 0x16, 0xc5, 0xad, 0xe2, 0xd1, 0xeb, 0x26,
        0x01, 0xcb, 0x13, 0x99, 0xb3, 0xc6, 0xae, 0x97, 0xa1, 0x5f, 0x93, 0x2f, 0x75, 0x38, 0xa7,
        0x4e, 0x00, 0x50, 0xec, 0xc6, 0x15, 0xb0, 0xf4, 0xba, 0xbb, 0x82, 0xf5, 0x83, 0x4a, 0xe6,
        0x43, 0xa5, 0xf4, 0x83, 0x46, 0x79, 0xc6, 0x5e, 0x0c, 0x96, 0x74, 0xee, 0x56, 0x85, 0x53,
        0x62, 0x5e, 0xc7, 0x9b, 0xce, 0xd3, 0x30, 0x65, 0xc1, 0x1d, 0x33, 0xd3, 0x49, 0x28, 0xa6,
        0x04, 0xc0, 0x61, 0x67, 0x7d, 0x07, 0xbb, 0xf6, 0x84, 0x57, 0xd0, 0x78, 0x92, 0xc4, 0x6c,
        0x88, 0x5a, 0xb7, 0xcc, 0xd2, 0xe5, 0x2b, 0x8c, 0x51, 0x89, 0xc7, 0x3f, 0x55, 0x67, 0xd2,
        0x12, 0x6a, 0x1b, 0x91, 0x0e, 0xc9, 0x3b, 0x4f, 0x15, 0x99, 0xca, 0x1a, 0x4a, 0xda, 0xe3,
        0xc7, 0x84, 0x67, 0x38, 0x10, 0x6e, 0x2b, 0xbe, 0xe5, 0xfa, 0x94, 0xff, 0x46, 0xde, 0x34,
        0x2f, 0x8f, 0x02, 0x9b, 0x4e, 0xff, 0xd4, 0x06, 0x5d, 0x52, 0x2d, 0xcc, 0x2c, 0xf6, 0x20,
        0x5c, 0x05, 0x3b, 0x33, 0xbd, 0x6f, 0x4f, 0x9a, 0x78, 0x64, 0xfb, 0x7f, 0xdf, 0x52, 0x84,
        0x33, 0x5f, 0x5e, 0x42, 0x99, 0xdf, 0xb1, 0x81, 0xf9, 0xe5, 0x72, 0x57, 0x5f, 0x45, 0x9b,
        0xd1, 0xb2, 0x8f, 0xe4, 0xe3, 0x55, 0x58, 0x0d, 0xd8, 0xd5, 0x55, 0xa4, 0x51, 0x1c, 0x5c,
        0x35, 0xf9, 0x60, 0x25, 0xbc, 0x93, 0x51, 0x95, 0xec, 0x7f, 0x6a, 0x5e, 0x03, 0x39, 0xf8,
        0x2b, 0x32, 0x50, 0x98, 0xa2, 0x44, 0xb9, 0x3f, 0xde, 0x10, 0xcc, 0xc7, 0x8a, 0x6d, 0xd1,
        0x02, 0x34, 0x16, 0x71, 0x50, 0x81, 0x94, 0x19, 0x99, 0xd6, 0x13, 0xa5, 0xc9, 0xf9, 0x29,
        0x7c, 0xe8, 0xcc, 0x9a, 0xbb, 0xfa, 0x2d, 0xf6, 0x9f, 0x35, 0x3a, 0xd3, 0xe4, 0x3b, 0xa5,
        0x24, 0x18, 0x77, 0xbe, 0x25, 0xcd, 0x32, 0x82, 0x4a, 0x12, 0x1c, 0x50, 0x4e, 0x86, 0x07,
        0xc7, 0x89, 0x7e, 0x5c, 0xcc, 0xa0, 0xd9, 0xae, 0xfe, 0x68, 0x27, 0x29, 0xcf, 0x4c, 0xaa,
        0x79, 0x07, 0x86, 0x9c, 0xba, 0xf2, 0x40, 0xcb, 0xe2, 0x8b, 0x38, 0x95, 0x60, 0x8a, 0xf0,
        0x17, 0x76, 0xb6, 0xdf, 0x1c, 0x3f, 0xa2, 0x8f, 0xdc, 0x54, 0xf8, 0xe0, 0xe6, 0x31, 0x76,
        0x6f, 0x6a, 0x13, 0x27, 0x4f, 0xcf, 0x16, 0x7e, 0xa1, 0xa5, 0x08, 0x11, 0xbb, 0x14, 0x85,
        0xd8, 0xd0, 0xfd, 0x73, 0x16, 0xec, 0x2a, 0x02, 0xd5, 0x25, 0xca, 0x6c, 0xb9, 0x38, 0x89,
        0x43, 0x9b, 0x9a, 0x19, 0xb9, 0x77, 0xb3, 0x10, 0x05, 0x4a, 0x87, 0x2e, 0x0a, 0xe6, 0xed,
        0x0c, 0x45, 0x57, 0xa4, 0xba, 0x2d, 0xaf, 0xb6, 0xd6, 0x8c, 0xc8, 0x05, 0x7a, 0x44, 0x7c,
        0x38, 0xf8, 0x8e, 0xcc, 0xc5, 0x3b, 0x81, 0xda, 0xe5, 0xe3, 0xd9, 0x16, 0x24, 0x23, 0x36,
        0xaf, 0x7b, 0xd3, 0xff, 0x74, 0x50, 0xca, 0x3d, 0x19, 0x37, 0xe1, 0xe7, 0xd2, 0x24, 0x74,
        0x67, 0xeb, 0xd5, 0x30, 0xcc, 0x42, 0x4f, 0xfd, 0xba, 0x44, 0x56, 0x93, 0x78, 0x14, 0x95,
        0xbc, 0xd8, 0x99, 0x47, 0x50, 0x54, 0x2b, 0x94, 0x0e, 0x3f, 0x2b, 0xfe, 0xfb, 0xd3, 0xe5,
        0xfd, 0x63, 0x4b, 0xe1, 0x4f, 0x90, 0x17, 0x86, 0x13, 0x84, 0xbd, 0x96, 0xb9, 0xd0, 0xf9,
        0xba, 0xac, 0x99, 0xf6, 0xa6, 0x11, 0xfb, 0x35, 0x16, 0x7a, 0xe4, 0xf6, 0x4b, 0x4e, 0x4c,
        0x13, 0x3f, 0x02, 0xaf, 0x3a, 0x12, 0x10, 0x23, 0xd6, 0x30, 0x5a, 0x95, 0x47, 0x5a, 0x04,
        0xf1, 0x02, 0xb0, 0x57, 0xeb, 0xd7, 0xad, 0xdc, 0xf8, 0xd0, 0x6d, 0x0a, 0xfc, 0x45, 0x2a,
        0xf2, 0x0d, 0x80, 0x85, 0x33, 0xf4, 0x1a, 0xe4, 0xbb, 0x0f, 0x05, 0xff, 0x7d, 0x71, 0x32,
        0x97, 0x22, 0x38, 0xf0, 0x71, 0xbb, 0x69, 0xf6, 0xe6, 0xaf, 0x2c, 0x99, 0x35, 0xb8, 0x8f,
        0xed, 0xde, 0x5d, 0x53, 0xd7, 0xc7, 0x4d, 0x7b, 0xc1, 0x7b, 0x75, 0x6f, 0x65, 0x96, 0x4f,
        0x64, 0x7e, 0xcb, 0x4a, 0x3b, 0xc7, 0xe8, 0xbb, 0xdb, 0x60, 0xb1, 0x27, 0x89, 0xe9, 0x38,
        0x47, 0xe5, 0x4d, 0x43, 0x31, 0x70, 0xe2, 0xcc, 0xa3, 0x25, 0x19, 0x46, 0xa5, 0x70, 0xa6,
        0x2c, 0xd0, 0x35, 0x8e, 0x53, 0xef, 0x51, 0xdb, 0x25, 0x6e, 0x1e, 0x2c, 0x99, 0x7e, 0x0c,
        0xd6, 0x7b, 0x5e, 0xb6, 0x8a, 0x1b, 0x62, 0x85, 0xcc, 0x1e, 0x23, 0x38, 0x8d, 0x62, 0xc6,
        0x7d, 0x41, 0x49, 0xb5, 0xc1, 0xad, 0x48, 0x5f, 0x4c, 0xb0, 0xdf, 0x47, 0x04, 0xa6, 0x5a,
        0x04, 0xe2, 0xb2, 0xf6, 0xcd, 0x49, 0x40, 0x13, 0xcd, 0x27, 0xf0, 0xaa, 0xd4, 0x10, 0xa0,
        0x21, 0x1d, 0x46, 0x5c, 0x22, 0x39, 0x2f, 0x39, 0xc4, 0xfd, 0x38, 0xb6, 0x20, 0xb4, 0xb4,
        0x0f, 0xf2, 0x32, 0x34, 0x08, 0x4a, 0xfb, 0x9a, 0x54, 0xf8, 0x50, 0x97, 0xa5, 0x1e, 0x44,
        0x73, 0x36, 0xa5, 0x7a, 0x29, 0xf2, 0x16, 0xd1, 0x5d, 0x61, 0xf3, 0x4b, 0x7e, 0xc1, 0x41,
        0x08, 0x94, 0x9c, 0xde, 0x42, 0x49, 0xe3, 0xc0, 0xc3, 0x9d, 0xe8, 0xa2, 0xc6, 0x48, 0x41,
        0xf8, 0xc4, 0x50, 0xa9, 0x13, 0x3a, 0x7a, 0xc7, 0x3f, 0xc7, 0x2c, 0x78, 0x63, 0xd2, 0x51,
        0x86, 0x69, 0x9c, 0x1a, 0xb6, 0x31, 0x03, 0x84, 0x87, 0x22, 0xc2, 0x58, 0x20, 0x03, 0x98,
        0xea, 0xe4, 0x68, 0x52, 0x2c, 0x3b, 0xa2, 0xe4, 0xb2, 0x3b, 0x03, 0x26, 0x09, 0x4a, 0x09,
        0x77, 0x63, 0x3a, 0x87, 0x09, 0xdb, 0x1c, 0x57, 0x2a, 0x04, 0x1d, 0x1e, 0xba, 0x98, 0x7c,
        0x84, 0x22, 0xb0, 0xe2, 0xbb, 0x96, 0xa5, 0x1e, 0x4d, 0xbf, 0xff, 0x7c, 0x30, 0x8e, 0x4a,
        0x4a, 0xac, 0x65, 0xb8, 0x71, 0xfc, 0xca, 0x6c, 0xd7, 0xa4, 0xfb, 0xd2, 0x73, 0xab, 0xf1,
        0x31, 0x2c, 0xd6, 0xc2, 0xa8, 0xc1, 0x75, 0x79, 0xc2, 0x28, 0x6c, 0x89, 0xab, 0xa3, 0x6a,
        0x0a, 0x7c, 0xa9, 0xfc, 0xa6, 0x0e, 0x86, 0x87, 0xec, 0xb1, 0xa4, 0xb8, 0x2e, 0xc4, 0x1e,
        0x35, 0xf7, 0xf5, 0x5c, 0x58, 0x97, 0xe2, 0x38, 0x1d, 0x73, 0xe5, 0xd5, 0x01, 0xf9, 0xc0,
        0xdb, 0xa7, 0x7e, 0xa1, 0xc5, 0xd0, 0xb4, 0xce, 0xef, 0xcd, 0xcc, 0x32, 0x1e, 0xe2, 0xa3,
        0xda, 0xcc, 0x01, 0x98, 0xe1, 0xfc, 0x32, 0x88, 0x7d, 0xf2, 0xee, 0x11, 0x7d, 0xb6, 0xa4,
        0x5a, 0xf2, 0xc4, 0xd2, 0x65, 0xef, 0x05, 0xf9, 0x0b, 0xdb, 0x4f, 0x83, 0xfc, 0x79, 0x70,
        0x18, 0xd8, 0xb7, 0x6b, 0x21, 0xc7, 0xa7, 0xfb, 0xaf, 0x33, 0xea, 0x0d, 0x5d, 0x9c, 0xa0,
        0x46, 0xeb, 0x8d, 0xcf, 0x9c, 0x0b, 0x70, 0x90, 0xc9, 0xcf, 0xbf, 0x53, 0xb9, 0x38, 0xda,
        0x83, 0x31, 0x8f, 0x8d, 0x73, 0xea, 0xe8, 0x32, 0x3a, 0xdd, 0x40, 0x4b, 0x0b, 0xb5, 0x19,
        0x07, 0xe1, 0xfa, 0xb6, 0x1a, 0xdc, 0x7e, 0x33, 0x07, 0x17, 0xf4, 0x83, 0xb8, 0x33, 0xdb,
        0x69, 0x32, 0xaf, 0xbb, 0x1e, 0xe4, 0x9c, 0x33, 0x3b, 0x69, 0x49, 0x9f, 0xaa, 0x6f, 0xe3,
        0x80, 0x51, 0xce, 0xf1, 0x45, 0x51, 0x4c, 0x5b, 0xfe, 0xbd, 0x79, 0xa3, 0x97, 0xf0, 0x78,
        0x17, 0x46, 0xac, 0xf1, 0x20, 0xda, 0xac, 0xe3, 0x71, 0x4d, 0xcf, 0x67, 0xb0, 0x97, 0x83,
        0xe7, 0x03, 0x47, 0xa2, 0x23, 0x02, 0x95, 0x3b, 0x77, 0xad, 0xba, 0x1c, 0xb6, 0x4e, 0x06,
        0xe6, 0x40, 0xed, 0xb3, 0x24, 0x3b, 0xf6, 0xd2, 0xb9, 0x78, 0x7b, 0x5f, 0x9d, 0x26, 0x58,
        0xf6, 0x3f, 0x36, 0x81, 0xea, 0x98, 0x76, 0x65, 0x8e, 0xee, 0x10, 0x7f, 0xbf, 0xbd, 0x2d,
        0x70, 0xa7, 0x0f, 0x3c, 0x9a, 0x59, 0x7e, 0x95, 0x90, 0x0d, 0x0d, 0xcb, 0x89, 0xf9, 0xf7,
        0x59, 0x6d, 0x0e, 0x52, 0x3f, 0x0d, 0x90, 0x4b, 0xd2, 0x7a, 0x72, 0x75, 0x61, 0xe4, 0xe8,
        0x99, 0x44, 0x1d, 0xaa, 0x86, 0xa7, 0x23, 0xbf, 0x40, 0x3f, 0xd1, 0x5e, 0x87, 0x33, 0x7d,
        0x0d, 0x03, 0x2d, 0x20, 0xd5, 0xb4, 0x9a, 0xb9, 0x6a, 0x39, 0xd5, 0xee, 0xc7, 0x5c, 0xf4,
        0x5a, 0xf7, 0xd3, 0x96, 0xf0, 0x9f, 0x5c, 0xd2, 0x51, 0x86, 0x25, 0x9b, 0xff, 0x1b, 0x67,
        0xdc, 0xc3, 0x3d, 0x8e, 0x05, 0x6c, 0x95, 0x95, 0x7b, 0x33, 0xcb, 0x03, 0x31, 0x88, 0x75,
        0x0e, 0x28, 0x31, 0x2b, 0x60, 0x41, 0xad, 0x17, 0x43, 0xea, 0xf8, 0x23, 0xde, 0x56, 0x57,
        0x43, 0x19, 0x71, 0x32, 0xab, 0x92, 0x59, 0x87, 0xfd, 0x4d, 0xb1, 0x42, 0x25, 0x53, 0x7f,
        0xef, 0x2d, 0x39, 0xef, 0xbb, 0xa9, 0xd8, 0xab, 0x6b, 0x52, 0x89, 0xca, 0xc6, 0xbc, 0x2a,
        0x90, 0x6c, 0x2f, 0xcf, 0x66, 0xf7, 0xbf, 0x3c, 0x71, 0xbe, 0xae, 0x2b, 0xdc, 0xee, 0xbb,
        0x27, 0x91, 0xfd, 0x43, 0x02, 0xfa, 0xc5, 0x66, 0x30, 0xa2, 0x35, 0x24, 0x3d, 0xa8, 0xf8,
        0x8c, 0xe7, 0x7b, 0x88, 0xbe, 0xc1, 0xac, 0x37, 0xb9, 0x3a, 0x71, 0x62, 0x3d, 0x58, 0xdf,
        0x8c, 0x20, 0x74, 0xd7, 0xb2, 0xf6, 0x87, 0x89, 0xda, 0xfa, 0xa7, 0x14, 0xf5, 0xf8, 0x96,
        0x86, 0x42, 0xa1, 0xb5, 0x8f, 0xb0, 0x2c, 0x99, 0xb0, 0x1f, 0x11, 0x65, 0x0d, 0x80, 0x7c,
        0x1a, 0x6e, 0x39, 0xbb, 0xe7, 0xcf, 0x22, 0xb7, 0x64, 0x05, 0x05, 0xa9, 0xb9, 0x7a, 0x25,
        0x3c, 0x7a, 0x32, 0xfb, 0xfd, 0x2c, 0x1a, 0x6a, 0x60, 0x00, 0x68, 0xcf, 0xa2, 0xb3, 0xab,
        0x7e, 0x9f, 0x31, 0x20, 0xd6, 0x53, 0x33, 0x44, 0xc1, 0x9c, 0xad, 0x82,
    ];

    assert_eq!(expected_public_key, resp.public_key)
}

// RNG that only allows a single call, which returns the fixed seed.
// This is needed to test with the fips204 crate.
struct SeedOnlyRng {
    seed: [u8; 32],
    called: bool,
}

impl SeedOnlyRng {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            called: false,
        }
    }
}

impl RngCore for SeedOnlyRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        if self.called {
            panic!("Can only call fill_bytes once");
        }
        assert_eq!(out.len(), 32);
        out.copy_from_slice(&self.seed[..32]);
        self.called = true;
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}

impl CryptoRng for SeedOnlyRng {}

#[test]
fn test_mldsa_sign_verify() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let seed_bytes: [u8; 32] = [
        0x63, 0x1a, 0xfc, 0x2a, 0x36, 0xa5, 0x7e, 0x1d, 0x09, 0x0d, 0xad, 0xc2, 0x79, 0x1d, 0x48,
        0x6d, 0x72, 0xc6, 0x9a, 0x9a, 0xab, 0xf9, 0x79, 0x90, 0xc5, 0x73, 0x21, 0x48, 0x46, 0xfe,
        0x5b, 0x64,
    ];
    let mut rng = SeedOnlyRng::new(seed_bytes);
    let (_, privkey) = ml_dsa_87::try_keygen_with_rng(&mut rng).unwrap();
    let cmk = import_key(&mut model, &seed_bytes, CmKeyUsage::Mldsa);

    let seed_rng_bytes = [1u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed_rng_bytes);

    for _ in 0..25 {
        let len = seeded_rng.gen_range(0..MAX_CMB_DATA_SIZE);
        let mut data = vec![0u8; len];
        seeded_rng.fill_bytes(&mut data);

        let mut req = CmMldsaSignReq {
            cmk: cmk.clone(),
            message_size: len as u32,
            ..Default::default()
        };
        req.message[..data.len()].copy_from_slice(&data);
        let mut req = MailboxReq::CmMldsaSign(req);
        req.populate_chksum().unwrap();
        let resp_bytes = model
            .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
            .unwrap()
            .expect("Should have gotten a response");
        let resp = CmMldsaSignResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

        let sign_seed = [0u8; 32];
        let signature = privkey.try_sign_with_seed(&sign_seed, &data, &[]).unwrap();

        assert_eq!(&resp.signature[..signature.len()], &signature);

        let mut req = CmMldsaVerifyReq {
            cmk: cmk.clone(),
            signature: resp.signature,
            message_size: len as u32,
            ..Default::default()
        };
        req.message[..data.len()].copy_from_slice(&data);
        // modify the message to test failure
        req.message[seeded_rng.gen_range(0..len)] ^= seeded_rng.gen_range(1..255);
        let mut req = MailboxReq::CmMldsaVerify(req);
        req.populate_chksum().unwrap();
        let err = model
            .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
            .expect_err("Should have failed");
        assert_error(
            &mut model,
            caliptra_drivers::CaliptraError::RUNTIME_MAILBOX_SIGNATURE_MISMATCH,
            err,
        );

        // now check with the correct message
        let mut req = CmMldsaVerifyReq {
            cmk: cmk.clone(),
            signature: resp.signature,
            message_size: len as u32,
            ..Default::default()
        };
        req.message[..data.len()].copy_from_slice(&data);
        let mut req = MailboxReq::CmMldsaVerify(req);
        req.populate_chksum().unwrap();
        model
            .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
            .expect("Should have succeeded")
            .unwrap();
    }
}

#[test]
fn test_ecdsa_public_key() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let seed_bytes = [0u8; 48];
    let cmk = import_key(&mut model, &seed_bytes, CmKeyUsage::Ecdsa);

    let mut req = MailboxReq::CmEcdsaPublicKey(CmEcdsaPublicKeyReq {
        cmk: cmk.clone(),
        ..Default::default()
    });
    req.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
        .unwrap()
        .expect("Should have gotten a response");
    let resp = CmEcdsaPublicKeyResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

    let expected_pub_key_x: [u8; 48] = [
        0xd7, 0xdd, 0x94, 0xe0, 0xbf, 0xfc, 0x4c, 0xad, 0xe9, 0x90, 0x2b, 0x7f, 0xdb, 0x15, 0x42,
        0x60, 0xd5, 0xec, 0x5d, 0xfd, 0x57, 0x95, 0xe, 0x83, 0x59, 0x1, 0x5a, 0x30, 0x2c, 0x8b,
        0xf7, 0xbb, 0xa7, 0xe5, 0xf6, 0xdf, 0xfc, 0x16, 0x85, 0x16, 0x2b, 0xdd, 0x35, 0xf9, 0xf5,
        0xc1, 0xb0, 0xff,
    ];

    let expected_pub_key_y: [u8; 48] = [
        0xbb, 0x9c, 0x3a, 0x2f, 0x6, 0x1e, 0x8d, 0x70, 0x14, 0x27, 0x8d, 0xd5, 0x1e, 0x66, 0xa9,
        0x18, 0xa6, 0xb6, 0xf9, 0xf1, 0xc1, 0x93, 0x73, 0x12, 0xd4, 0xe7, 0xa9, 0x21, 0xb1, 0x8e,
        0xf0, 0xf4, 0x1f, 0xdd, 0x40, 0x1d, 0x9e, 0x77, 0x18, 0x50, 0x9f, 0x87, 0x31, 0xe9, 0xee,
        0xc9, 0xc3, 0x1d,
    ];

    assert_eq!(expected_pub_key_x, resp.public_key_x);
    assert_eq!(expected_pub_key_y, resp.public_key_y);
}

fn rustcrypto_ecdsa_sign(priv_key: &[u8; 48], hash: &[u8; 48]) -> ([u8; 48], [u8; 48]) {
    let signing_key = SigningKey::from_slice(priv_key).unwrap();
    let ecc_sig: Signature = signing_key.sign_prehash(hash).unwrap();
    let ecc_sig = ecc_sig.to_vec();
    let r = ecc_sig[..48].try_into().unwrap();
    let s = ecc_sig[48..].try_into().unwrap();
    (r, s)
}

#[test]
fn test_ecdsa_sign_verify() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let seed_bytes = [0u8; 48];
    let cmk = import_key(&mut model, &seed_bytes, CmKeyUsage::Ecdsa);

    let seed_rng_bytes = [1u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed_rng_bytes);

    let privkey: [u8; 48] = [
        0xfe, 0xee, 0xf5, 0x54, 0x4a, 0x76, 0x56, 0x49, 0x90, 0x12, 0x8a, 0xd1, 0x89, 0xe8, 0x73,
        0xf2, 0x1f, 0xd, 0xfd, 0x5a, 0xd7, 0xe2, 0xfa, 0x86, 0x11, 0x27, 0xee, 0x6e, 0x39, 0x4c,
        0xa7, 0x84, 0x87, 0x1c, 0x1a, 0xec, 0x3, 0x2c, 0x7a, 0x8b, 0x10, 0xb9, 0x3e, 0xe, 0xab,
        0x89, 0x46, 0xd6,
    ];

    for _ in 0..25 {
        let len = seeded_rng.gen_range(0..MAX_CMB_DATA_SIZE);
        let mut data = vec![0u8; len];
        seeded_rng.fill_bytes(&mut data);

        let mut req = CmEcdsaSignReq {
            cmk: cmk.clone(),
            message_size: len as u32,
            ..Default::default()
        };
        req.message[..data.len()].copy_from_slice(&data);
        let mut req = MailboxReq::CmEcdsaSign(req);
        req.populate_chksum().unwrap();
        let resp_bytes = model
            .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
            .unwrap()
            .expect("Should have gotten a response");
        let resp = CmEcdsaSignResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();

        let mut hasher = Sha384::new();
        hasher.update(&data);
        let hash = hasher.finalize();

        let signature = rustcrypto_ecdsa_sign(&privkey, &hash.into());

        assert_eq!(resp.signature_r, signature.0);
        assert_eq!(resp.signature_s, signature.1);

        let mut req = CmEcdsaVerifyReq {
            cmk: cmk.clone(),
            signature_r: resp.signature_r,
            signature_s: resp.signature_s,
            message_size: len as u32,
            ..Default::default()
        };
        req.message[..data.len()].copy_from_slice(&data);
        // modify the message to test failure
        req.message[seeded_rng.gen_range(0..len)] ^= seeded_rng.gen_range(1..255);
        let mut req = MailboxReq::CmEcdsaVerify(req);
        req.populate_chksum().unwrap();
        let err = model
            .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
            .expect_err("Should have failed");
        assert_error(
            &mut model,
            caliptra_drivers::CaliptraError::RUNTIME_MAILBOX_SIGNATURE_MISMATCH,
            err,
        );

        // now check with the correct message
        let mut req = CmEcdsaVerifyReq {
            cmk: cmk.clone(),
            signature_r: resp.signature_r,
            signature_s: resp.signature_s,
            message_size: len as u32,
            ..Default::default()
        };
        req.message[..data.len()].copy_from_slice(&data);
        let mut req = MailboxReq::CmEcdsaVerify(req);
        req.populate_chksum().unwrap();
        model
            .mailbox_execute(req.cmd_code().into(), req.as_bytes().unwrap())
            .expect("Should have succeeded")
            .unwrap();
    }
}

#[test]
fn test_derive_stable_key() {
    const HMAC_HEADER_SIZE: usize = size_of::<MailboxRespHeaderVarSize>();

    // derive a stable key from ROM
    let (mut model, fw_image) = start_rt_test_pqc_model(
        RuntimeTestArgs {
            stop_at_rom: true,
            ..Default::default()
        },
        FwVerificationPqcKeyType::LMS,
    );
    model.step_until(|m| m.ready_for_fw());

    let mut derive_request = MailboxReq::CmDeriveStableKey(CmDeriveStableKeyReq {
        key_type: CmStableKeyType::IDevId.into(),
        ..Default::default()
    });

    derive_request.populate_chksum().unwrap();
    let response = model
        .mailbox_execute(
            CommandId::CM_DERIVE_STABLE_KEY.into(),
            derive_request.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let resp = CmDeriveStableKeyResp::ref_from_bytes(response.as_bytes()).unwrap();
    let rom_stable_cmk = resp.cmk.clone();

    let mut hmac_request = CmHmacReq {
        cmk: rom_stable_cmk.clone(),
        hash_algorithm: CmHashAlgorithm::Sha384.into(),
        data_size: 9,
        ..Default::default()
    };
    hmac_request.data[..9].copy_from_slice(b"test data");
    let mut request = MailboxReq::CmHmac(hmac_request);
    request.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(CommandId::CM_HMAC.into(), request.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    let mut resp = CmHmacResp {
        hdr: MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..HMAC_HEADER_SIZE]).unwrap(),
        ..Default::default()
    };
    let len = resp.hdr.data_len as usize;
    assert!(len < MAX_CMB_DATA_SIZE);
    resp.mac[..len].copy_from_slice(&resp_bytes[HMAC_HEADER_SIZE..HMAC_HEADER_SIZE + len]);

    let rom_hmac: [u8; 48] = resp.mac[..resp.hdr.data_len as usize].try_into().unwrap();

    // now step until runtime
    model.upload_firmware(&fw_image).unwrap();
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // use the ROM key to compute the HMAC and make sure it matches the ROM HMAC
    let resp_bytes = model
        .mailbox_execute(CommandId::CM_HMAC.into(), request.as_bytes().unwrap())
        .unwrap()
        .unwrap();
    let mut resp = CmHmacResp {
        hdr: MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..HMAC_HEADER_SIZE]).unwrap(),
        ..Default::default()
    };
    let len = resp.hdr.data_len as usize;
    assert!(len < MAX_CMB_DATA_SIZE);
    resp.mac[..len].copy_from_slice(&resp_bytes[HMAC_HEADER_SIZE..HMAC_HEADER_SIZE + len]);

    let fw_hmac_rom_cmk: [u8; 48] = resp.mac[..resp.hdr.data_len as usize].try_into().unwrap();
    assert_eq!(rom_hmac, fw_hmac_rom_cmk);

    // re-derive the same stable key in runtime
    let mut derive_request = MailboxReq::CmDeriveStableKey(CmDeriveStableKeyReq {
        key_type: CmStableKeyType::IDevId.into(),
        ..Default::default()
    });

    derive_request.populate_chksum().unwrap();
    let response = model
        .mailbox_execute(
            CommandId::CM_DERIVE_STABLE_KEY.into(),
            derive_request.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let resp = CmDeriveStableKeyResp::ref_from_bytes(response.as_bytes()).unwrap();
    let fw_stable_cmk = resp.cmk.clone();

    // compute the HMAC with the runtime derived key and make sure it matches the ROM HMAC
    let mut hmac_request = CmHmacReq {
        cmk: fw_stable_cmk,
        hash_algorithm: CmHashAlgorithm::Sha384.into(),
        data_size: 9,
        ..Default::default()
    };
    hmac_request.data[..9].copy_from_slice(b"test data");
    let mut request = MailboxReq::CmHmac(hmac_request);
    request.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(CommandId::CM_HMAC.into(), request.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    let mut resp = CmHmacResp {
        hdr: MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..HMAC_HEADER_SIZE]).unwrap(),
        ..Default::default()
    };
    let len = resp.hdr.data_len as usize;
    assert!(len < MAX_CMB_DATA_SIZE);
    resp.mac[..len].copy_from_slice(&resp_bytes[HMAC_HEADER_SIZE..HMAC_HEADER_SIZE + len]);

    let fw_hmac_fw_cmk: [u8; 48] = resp.mac[..resp.hdr.data_len as usize].try_into().unwrap();

    assert_eq!(rom_hmac, fw_hmac_fw_cmk);
}

#[test]
fn test_import_warm_reset() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // check too large of an input
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::Aes.into(),
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
        key_usage: CmKeyUsage::Aes.into(),
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
        key_usage: CmKeyUsage::Aes.into(),
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

    // Perform warm reset
    model.warm_reset_flow(&Fuses::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // AES key import
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::Aes.into(),
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
fn test_delete_warm_reset() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let cmk = import_key(&mut model, &[0xaa; 32], CmKeyUsage::Aes);
    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 1);
    assert_eq!(status_resp.total_usage_storage, 256);

    delete_key(&mut model, &cmk);

    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 0);
    assert_eq!(status_resp.total_usage_storage, 256);

    // Perform warm reset
    model.warm_reset_flow(&Fuses::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let cmk = import_key(&mut model, &[0xaa; 32], CmKeyUsage::Aes);
    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 1);
    assert_eq!(status_resp.total_usage_storage, 256);

    delete_key(&mut model, &cmk);

    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 0);
    assert_eq!(status_resp.total_usage_storage, 256);
}

#[test]
fn test_clear_warm_reset() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut req = MailboxReq::CmClear(MailboxReqHeader::default());
    req.populate_chksum().unwrap();
    let req = req.as_bytes().unwrap();

    let raw_key = [0xaa; 32];
    let mut keys = VecDeque::new();
    for _ in 0..256 {
        let cmk = import_key(&mut model, &raw_key, CmKeyUsage::Aes);
        keys.push_back(cmk);
    }

    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 256);
    assert_eq!(status_resp.total_usage_storage, 256);

    model
        .mailbox_execute(u32::from(CommandId::CM_CLEAR), req)
        .unwrap()
        .expect("We should have received a response");

    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 0);
    assert_eq!(status_resp.total_usage_storage, 256);

    // Perform warm reset
    model.warm_reset_flow(&Fuses::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let raw_key = [0xaa; 32];
    let mut keys = VecDeque::new();
    for _ in 0..256 {
        let cmk = import_key(&mut model, &raw_key, CmKeyUsage::Aes);
        keys.push_back(cmk);
    }

    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 256);
    assert_eq!(status_resp.total_usage_storage, 256);

    model
        .mailbox_execute(u32::from(CommandId::CM_CLEAR), req)
        .unwrap()
        .expect("We should have received a response");

    let status_resp = status(&mut model);
    assert_eq!(status_resp.used_usage_storage, 0);
    assert_eq!(status_resp.total_usage_storage, 256);
}

#[test]
fn test_status_warm_reset() {
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

    // Perform warm reset
    model.warm_reset_flow(&Fuses::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let resp = model
        .mailbox_execute(u32::from(CommandId::CM_STATUS), payload.as_bytes())
        .unwrap()
        .expect("We should have received a response");

    let cm_resp = CmStatusResp::ref_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(cm_resp.used_usage_storage, 0);
    assert_eq!(cm_resp.total_usage_storage, 256);
}

#[test]
fn test_sha384_simple_warm_reset() {
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
    populate_checksum(expected_resp.as_bytes_partial_mut().unwrap());
    let expected_bytes = expected_resp.as_bytes_partial().unwrap();
    assert_eq!(expected_bytes, resp_bytes);

    // Perform warm reset
    model.warm_reset_flow(&Fuses::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

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
    populate_checksum(expected_resp.as_bytes_partial_mut().unwrap());
    let expected_bytes = expected_resp.as_bytes_partial().unwrap();
    assert_eq!(expected_bytes, resp_bytes);
}

#[test]
fn test_sha_many_warm_reset() {
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
            populate_checksum(expected_resp.as_bytes_partial_mut().unwrap());
            let expected_bytes = expected_resp.as_bytes_partial().unwrap();
            assert_eq!(expected_bytes, resp_bytes);
        }
    }

    // Perform warm reset
    model.warm_reset_flow(&Fuses::default());

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
            populate_checksum(expected_resp.as_bytes_partial_mut().unwrap());
            let expected_bytes = expected_resp.as_bytes_partial().unwrap();
            assert_eq!(expected_bytes, resp_bytes);
        }
    }
}
