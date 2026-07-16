// Licensed under the Apache-2.0 license

use crate::common::run_pqc_rt_test;
use crate::common::{execute_dpe_cmd, DpeResult, TEST_DIGEST_MLDSA, TEST_LABEL};
use caliptra_api::{
    mailbox::{FwInfoResp, ReallocateDpeContextLimitsReq},
    SocManager,
};
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::checksum::calc_checksum;
use caliptra_common::mailbox_api::{
    CommandId, GetPqCsrResp, InvokeDpeMldsa87Req, MailboxReq, MailboxReqHeader, PopulatePqCertReq,
    SetPqSeedReq, SET_PQ_SEED_SEED_SIZE,
};
use caliptra_drivers::Mldsa87Signature;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use caliptra_runtime::{CaliptraDpeProfile, RtBootStatus, DPE_SUPPORT, VENDOR_ID, VENDOR_SKU};
use caliptra_x509::MlDsa87CertBuilder;
use cms::{
    cert::x509::der::{Decode, Encode},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{SignedData, SignerIdentifier},
};
use crypto::ml_dsa::MldsaAlgorithm;
use dpe::{
    commands::{
        CertifyKeyCommand, CertifyKeyFlags, CertifyKeyMldsa87Cmd, Command, DeriveContextCmd,
        DeriveContextFlags, GetCertificateChainCmd, GetProfileCmd, InitCtxCmd, RotateCtxCmd,
        RotateCtxFlags, SignFlags, SignMldsa87Cmd,
    },
    context::ContextHandle,
    error::DpeErrorCode,
    response::{CertifyKeyResp, Response, SignResp},
    tci::TciMeasurement,
    TCI_SIZE,
};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant};
use openssl::signature::Signature;
use openssl::x509::X509Req;
use x509_parser::{nom::Parser, prelude::*};
use zerocopy::{FromBytes, IntoBytes};

const PROFILE: CaliptraDpeProfile = CaliptraDpeProfile::Mldsa;

// Invoke SET_PQ_SEED to set the PQ seed and thus enable PQC mode.
fn set_pq_seed(model: &mut DefaultHwModel) {
    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .unwrap();
}

// Build a cert out of a test TBS and invoke POPULATE_PQ_CERT to initialize the PQ cert.
fn populate_pq_cert(model: &mut DefaultHwModel) {
    // Generate an ML-DSA87 key pair
    let pk_builder = PKeyMlDsaBuilder::<Private>::from_seed(Variant::MlDsa87, &[0u8; 32]).unwrap();
    let priv_key = pk_builder.build().unwrap();

    // Sign the TBS with ML-DSA87
    let tbs: &[u8] = b"this is going to be the TBS";
    let mut sig_bytes = vec![];
    let mut ctx = PkeyCtx::new(&priv_key).unwrap();
    let mut algo = Signature::for_ml_dsa(Variant::MlDsa87).unwrap();
    ctx.sign_message_init(&mut algo).unwrap();
    ctx.sign_to_vec(tbs, &mut sig_bytes).unwrap();
    let sig = Mldsa87Signature::new(sig_bytes.try_into().unwrap());
    let builder = MlDsa87CertBuilder::new(tbs, &sig).unwrap();
    let mut cert = [0u8; PopulatePqCertReq::MAX_CERT_SIZE];
    let cert_size = builder.build(&mut cert).unwrap() as u32;

    // Build the request
    let mut cmd = MailboxReq::PopulatePqCert(PopulatePqCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cert_size,
        cert,
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(
            u32::from(CommandId::POPULATE_PQ_CERT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap();
}

#[test]
fn test_invoke_dpe_get_profile_cmd() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);

    let mut cmd: Command<'_> = Command::GetProfile(&GetProfileCmd);
    let resp = execute_dpe_cmd(PROFILE, &mut model, &mut cmd, DpeResult::Success);
    let Some(Response::GetProfile(profile)) = resp else {
        panic!("Wrong response type!");
    };
    assert_eq!(profile.resp_hdr.profile, PROFILE.into());
    assert_eq!(profile.vendor_id, VENDOR_ID);
    assert_eq!(profile.vendor_sku, VENDOR_SKU);
    assert_eq!(profile.flags, DPE_SUPPORT.bits());
    assert_eq!(profile.max_tci_nodes, 32);
}

#[test]
fn test_invoke_dpe_size_too_big() {
    // Test with data_size too big.
    let mut cmd = MailboxReq::InvokeDpeMldsa87Command(InvokeDpeMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        data_size: InvokeDpeMldsa87Req::DATA_MAX_SIZE as u32 + 1,
        data: [0u8; InvokeDpeMldsa87Req::DATA_MAX_SIZE],
    });
    assert_eq!(
        cmd.populate_chksum(),
        Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)
    );
}

#[test]
fn test_invoke_dpe_get_certificate_chain_cmd() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let get_cert_chain_cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::GetCertificateChain(&get_cert_chain_cmd),
        DpeResult::Success,
    );
    let Some(Response::GetCertificateChain(cert_chain)) = resp else {
        panic!("Wrong response type!");
    };

    assert_eq!(cert_chain.certificate_size, 2048);
    assert_ne!([0u8; 2048], cert_chain.certificate_chain);
}

#[test]
fn test_invoke_dpe_sign_and_certify_key_cmds() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let sign_cmd = SignMldsa87Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST_MLDSA,
    };
    let sign_resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::from(&sign_cmd),
        DpeResult::Success,
    )
    .unwrap();

    let certify_key_cmd = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
    };
    let certify_key_resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::from(&certify_key_cmd),
        DpeResult::Success,
    )
    .unwrap();

    match (sign_resp, certify_key_resp) {
        (
            Response::Sign(SignResp::Mldsa87(sign_resp)),
            Response::CertifyKey(CertifyKeyResp::Mldsa87(certify_key_resp)),
        ) => {
            assert_eq!(
                caliptra_mldsa::Mldsa87::verify_mu(
                    &certify_key_resp.header.pubkey,
                    &sign_resp.sig,
                    &TEST_DIGEST_MLDSA,
                ),
                caliptra_mldsa::Mldsa87Result::Success
            );
        }
        _ => panic!("Wrong response type!"),
    }
}

#[test]
fn test_invoke_dpe_asymmetric_sign() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let sign_cmd = SignMldsa87Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST_MLDSA,
    };
    let resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::from(&sign_cmd),
        DpeResult::Success,
    );
    match resp {
        Some(Response::Sign(SignResp::Mldsa87(sign_resp))) => {
            assert_ne!(
                sign_resp.sig,
                [0u8; MldsaAlgorithm::Mldsa87.signature_size()]
            );
        }
        _ => panic!("Wrong response type!"),
    }
}

#[test]
fn test_dpe_header_error_code() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);

    // cannot initialize non-simulation contexts so expect DPE cmd to fail
    let init_ctx_cmd = InitCtxCmd::new_use_default();
    let resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::InitCtx(&init_ctx_cmd),
        DpeResult::DpeCmdFailure,
    );
    let Some(Response::Error(hdr)) = resp else {
        panic!("Wrong response type!");
    };
    assert_eq!(
        hdr.status,
        DpeErrorCode::ArgumentNotSupported.get_error_code()
    );
}

#[test]
fn test_invoke_dpe_certify_key_csr() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let certify_key_cmd = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_CSR,
    };
    let resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::from(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(certify_key_resp)) = resp else {
        panic!("Wrong response type!");
    };

    // Retrieve the PQ.DevID CSR to obtain the public key that signs the DPE CSR.
    let pq_csr_payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::GET_PQ_CSR), &[]),
    };
    let pq_csr_bytes = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_CSR), pq_csr_payload.as_bytes())
        .unwrap()
        .unwrap();
    let pq_csr_resp = GetPqCsrResp::ref_from_bytes(pq_csr_bytes.as_bytes()).unwrap();
    let pq_devid_csr =
        X509Req::from_der(&pq_csr_resp.data[..pq_csr_resp.data_size as usize]).unwrap();
    let pq_devid_key = pq_devid_csr.public_key().unwrap();

    let content_info = ContentInfo::from_der(certify_key_resp.cert().unwrap()).unwrap();
    let mut signed_data = SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();
    assert_eq!(signed_data.version, CmsVersion::V3);

    // Validate signer infos.
    let signer_infos = signed_data.signer_infos.0;
    assert_eq!(signer_infos.len(), 1);
    let signer_info = signer_infos.get(0).unwrap();
    assert_eq!(signer_info.version, CmsVersion::V3);

    // Validate signer identifier, which was computed as SHA-256(raw PQ.DevID pubkey)[..20].
    let sid = &signer_info.sid;
    match sid {
        SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) => {
            // Skip first two bytes — 0x04 DER octet-string tag and length byte
            let cert_ski = &subject_key_identifier.0.as_bytes()[2..];
            let params = PKeyMlDsaParams::<Public>::from_pkey(&pq_devid_key).unwrap();
            let raw_pub_key = params.public_key().unwrap();
            let digest = hash(MessageDigest::sha256(), raw_pub_key).unwrap();
            assert_eq!(cert_ski, &digest[..20]);
        }
        _ => panic!("Error: Signer Identifier is not SubjectKeyIdentifier!"),
    };

    // Parse encapsulated content info.
    let econtent_info = &mut signed_data.encap_content_info;
    // Skip first 4 explicit encoding bytes.
    let econtent = &econtent_info.econtent.as_mut().unwrap().to_der().unwrap()[4..];

    // Validate CSR signature with the PQ.DevID alias key.
    let mut ctx = PkeyCtx::new(&pq_devid_key).unwrap();
    let mut algo = Signature::for_ml_dsa(Variant::MlDsa87).unwrap();
    ctx.verify_message_init(&mut algo).unwrap();
    assert!(ctx
        .verify(econtent, signer_info.signature.as_bytes())
        .unwrap());
}

#[test]
fn test_invoke_dpe_rotate_context() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);

    let rotate_ctx_cmd = RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
    };

    let resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::RotateCtx(&rotate_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::RotateCtx(rotate_ctx_resp)) = resp else {
        panic!("Wrong response type!");
    };

    assert!(!rotate_ctx_resp.handle.is_default());

    let rotate_ctx_cmd = RotateCtxCmd {
        handle: rotate_ctx_resp.handle,
        flags: RotateCtxFlags::TARGET_IS_DEFAULT,
    };

    let resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::RotateCtx(&rotate_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::RotateCtx(rotate_ctx_resp)) = resp else {
        panic!("Wrong response type!");
    };

    assert!(rotate_ctx_resp.handle.is_default());
}

fn check_dice_extension_criticality(cert: &[u8], expected_criticality: bool) {
    let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
    let Ok((_, cert)) = parser.parse(cert) else {
        panic!("Could not parse x509 certificate from CertifyKey!");
    };
    for extension in cert.iter_extensions() {
        // Unknown extensions are DICE extensions, and they should match the
        // criticality set by the DPE instance.
        if extension.parsed_extension().unsupported() {
            assert_eq!(extension.critical, expected_criticality);
        }
    }
}

#[test]
fn test_invoke_dpe_certify_key_with_non_critical_dice_extensions() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let certify_key_cmd = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::from(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(resp)) = resp else {
        panic!("Wrong response type!");
    };
    check_dice_extension_criticality(resp.cert().unwrap(), false);
}

#[test]
fn test_invoke_dpe_export_cdi_with_non_critical_dice_extensions() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let derive_ctx_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0; TCI_SIZE]),
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 0,
        target_locality: 0,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let Some(Response::DeriveContextExportedCdi(resp)) = resp else {
        panic!("expected derive context resp!");
    };
    check_dice_extension_criticality(
        &resp.new_certificate[..resp.header.certificate_size.try_into().unwrap()],
        false,
    );
}

#[test]
fn test_export_cdi_attestation_not_disabled_after_update_reset() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let derive_ctx_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0; TCI_SIZE]),
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        tci_type: 0,
        target_locality: 0,
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    // trigger update reset to same firmware
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    // check attestation is not disabled via FW_INFO
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    let info = FwInfoResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(info.attestation_disabled, 0);
}

#[test]
fn test_export_cdi_destroyed_root_context() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    // You probably want to retain the parent context, otherwise the whole DPE chain _may be
    // destroyed.
    //
    // This test case exercises that runtime cannot find the root context if the chain is
    // destroyed.
    let derive_ctx_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0; TCI_SIZE]),
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 0,
        target_locality: 0,
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    // trigger update reset to same firmware
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap_err();
    assert_eq!(
        resp,
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_UNABLE_TO_FIND_DPE_ROOT_CONTEXT.into())
    );
}

#[test]
fn test_certify_key_with_max_contexts() {
    let mut model = run_pqc_rt_test();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    // Set the limit to 32 so we don't have to deal with the PL1 locality
    model
        .mailbox_execute_req(ReallocateDpeContextLimitsReq {
            pl0_context_limit: 32,
            ..Default::default()
        })
        .unwrap();

    let base_derive_context_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
        ..Default::default()
    };

    // Fill PL0 contexts
    let max_after_init_contexts = 32 - 2;
    for i in 0..max_after_init_contexts {
        let cmd = DeriveContextCmd {
            tci_type: i + 1,
            ..base_derive_context_cmd
        };
        let _ = execute_dpe_cmd(
            PROFILE,
            &mut model,
            &mut Command::DeriveContext(&cmd),
            DpeResult::Success,
        );
    }

    // Trigger failure by trying to derive one more context to PL0
    let _ = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::DeriveContext(&base_derive_context_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED),
    );

    // Make sure we can get certificates and CSRs
    let formats = [
        CertifyKeyCommand::FORMAT_X509,
        CertifyKeyCommand::FORMAT_CSR,
    ];
    for format in formats {
        let certify_key_cmd = CertifyKeyMldsa87Cmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: CertifyKeyFlags::empty(),
            format,
        };

        let _ = execute_dpe_cmd(
            PROFILE,
            &mut model,
            &mut Command::from(&certify_key_cmd),
            DpeResult::Success,
        );
    }
}
