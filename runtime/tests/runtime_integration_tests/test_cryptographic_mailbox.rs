// Licensed under the Apache-2.0 license

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};
use caliptra_api::mailbox::{
    CmImportReq, CmImportResp, CmKeyUsage, CmRandomGenerateReq, CmRandomGenerateResp,
    CmRandomStirReq, CmShaFinalReq, CmShaFinalResp, CmShaInitReq, CmShaInitResp, CmShaUpdateReq,
    CmStatusResp, CommandId, MailboxReq, MailboxReqHeader, MailboxResp, MailboxRespHeader,
    MailboxRespHeaderVarSize, CMK_SIZE_BYTES, MAX_CMB_DATA_SIZE,
};
use caliptra_api::SocManager;
use caliptra_hw_model::{HwModel, InitParams, TrngMode};
use caliptra_runtime::RtBootStatus;
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
            println!("Checking size {}", input_str.len());

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
