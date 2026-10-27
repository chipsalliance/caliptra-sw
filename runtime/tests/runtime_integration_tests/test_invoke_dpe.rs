// Licensed under the Apache-2.0 license.

use crate::common::{
    certify_key, check_dpe_status, execute_dpe_cmd, execute_dpe_cmd_raw, get_rt_alias_ecc384_cert,
    run_rt_test, verify_sign_and_certify_key, CertifyKeyCommandNoRef, CreateCertifyKeyCmdArgs,
    CreateSignCmdArgs, DpeResult, RuntimeTestArgs, SignCommandNoRef, TEST_DIGEST, TEST_LABEL,
    TEST_SD_SHA384,
};
use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{
    CommandId, FwInfoResp, InvokeDpeMldsa87Req, InvokeDpeReq, MailboxReq, MailboxReqHeader,
};
use caliptra_dpe::{
    commands::{
        CertifyKeyCommand, Command, DeriveContextCmd, DeriveContextFlags, GetCertificateChainCmd,
        GetProfileCmd, InitCtxCmd, RotateCtxCmd, RotateCtxFlags, SignFlags, SignMldsa87RawCmd,
        SignP384Cmd as SignCmd,
    },
    context::ContextHandle,
    error::DpeErrorCode,
    response::{CertifyKeyResp, Response, SignResp},
    DpeProfile,
};
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, SecurityState};
use caliptra_runtime::{CaliptraDpeProfile, RtBootStatus, DPE_SUPPORT, VENDOR_ID, VENDOR_SKU};
use cms::{
    cert::x509::der::{Decode, Encode},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{SignedData, SignerIdentifier},
};
use openssl::{ecdsa::EcdsaSig, x509::X509};
use sha2::{Digest, Sha384};
use x509_parser::{nom::Parser, prelude::*};
use zerocopy::{FromBytes, IntoBytes};

#[derive(asn1::Asn1Read)]
struct Fwid<'a> {
    pub(crate) _hash_alg: asn1::ObjectIdentifier,
    pub(crate) _digest: &'a [u8],
}

#[derive(asn1::Asn1Read)]
struct IntegrityRegister<'a> {
    #[implicit(0)]
    _register_name: Option<asn1::IA5String<'a>>,
    #[implicit(1)]
    _register_num: Option<u64>,
    #[implicit(2)]
    _register_digests: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
}

#[derive(asn1::Asn1Read)]
struct TcbInfo<'a> {
    #[implicit(0)]
    _vendor: Option<asn1::Utf8String<'a>>,
    #[implicit(1)]
    _model: Option<asn1::Utf8String<'a>>,
    #[implicit(2)]
    _version: Option<asn1::Utf8String<'a>>,
    #[implicit(3)]
    _svn: Option<u64>,
    #[implicit(4)]
    _layer: Option<u64>,
    #[implicit(5)]
    _index: Option<u64>,
    #[implicit(6)]
    _fwids: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
    #[implicit(7)]
    _flags: Option<asn1::BitString<'a>>,
    #[implicit(8)]
    _vendor_info: Option<&'a [u8]>,
    #[implicit(9)]
    pub tci_type: Option<&'a [u8]>,
    #[implicit(10)]
    _operational_flags_mask: Option<asn1::BitString<'a>>,
    #[implicit(11)]
    _integrity_registers: Option<asn1::SequenceOf<'a, IntegrityRegister<'a>>>,
}

#[test]
fn test_invoke_dpe_get_profile_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until_ready_for_runtime();

    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::GetProfile(&GetProfileCmd),
        DpeResult::Success,
    );
    let Some(Response::GetProfile(profile)) = resp else {
        panic!("Wrong response type!");
    };
    assert_eq!(profile.resp_hdr.profile, DpeProfile::P384Sha384);
    assert_eq!(profile.vendor_id, VENDOR_ID);
    assert_eq!(profile.vendor_sku, VENDOR_SKU);
    assert_eq!(profile.flags, DPE_SUPPORT.bits());
    assert_eq!(profile.max_tci_nodes, caliptra_dpe::MAX_HANDLES as u32);
}

#[test]
fn test_invoke_dpe_size_too_big() {
    // Test with data_size too big.
    let mut cmd = MailboxReq::InvokeDpeEcc384Command(InvokeDpeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        data_size: InvokeDpeReq::DATA_MAX_SIZE as u32 + 1,
        data: [0u8; InvokeDpeReq::DATA_MAX_SIZE],
    });
    assert_eq!(
        cmd.populate_chksum(),
        Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)
    );
}

#[test]
fn test_invoke_dpe_mldsa87_size_too_big() {
    let mut cmd = MailboxReq::InvokeDpeMldsa87Command(InvokeDpeMldsa87Req {
        data_size: InvokeDpeMldsa87Req::DATA_MAX_SIZE as u32 + 1,
        ..Default::default()
    });
    assert_eq!(
        cmd.populate_chksum(),
        Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)
    );
}

#[test]
fn test_invoke_dpe_mldsa87_raw_sign() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until_ready_for_runtime();

    let message = [0x5au8; 148];
    let mut raw_data = [0u8; 1024];
    raw_data[..message.len()].copy_from_slice(&message);
    let sign_cmd = SignMldsa87RawCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::IS_RAW,
        size: message.len() as u32,
        raw_data,
    };
    let mut cmd = Command::from(&sign_cmd);
    let resp = execute_dpe_cmd_raw(&mut model, CaliptraDpeProfile::Mldsa87, &mut cmd).unwrap();
    let resp_data = &resp.data[..resp.data_size as usize];

    check_dpe_status(resp_data, DpeErrorCode::NoError);
    assert!(matches!(
        Response::try_read_from_bytes(&cmd, resp_data).unwrap(),
        Response::Sign(SignResp::Mldsa87(_))
    ));
}

#[test]
fn test_invoke_dpe_mldsa87_raw_sign_with_context() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until_ready_for_runtime();

    let certify_key_resp = certify_key(
        &mut model,
        &mut CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
            profile: CaliptraDpeProfile::Mldsa87,
            label: TEST_LABEL,
            format: CertifyKeyCommand::FORMAT_X509,
            ..Default::default()
        }),
    )
    .unwrap();
    let CertifyKeyResp::Mldsa87(certify_key_resp) = certify_key_resp else {
        panic!("Wrong response type!");
    };

    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, VerifyingKey};

    let encoded_key =
        EncodedVerifyingKey::<MlDsa87>::try_from(certify_key_resp.header.pubkey.as_slice())
            .unwrap();
    let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_key);

    let message = [0x5au8; 148];
    let max_context = [0xa5; 255];
    for context in [
        b"responder-challenge_auth signing".as_slice(),
        max_context.as_slice(),
        &[],
    ] {
        let mut raw_data = [0u8; 1024];
        raw_data[0] = context.len() as u8;
        raw_data[1..1 + context.len()].copy_from_slice(context);
        raw_data[1 + context.len()..1 + context.len() + message.len()].copy_from_slice(&message);
        let sign_cmd = SignMldsa87RawCmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: SignFlags::IS_RAW | SignFlags::HAS_CONTEXT,
            size: (1 + context.len() + message.len()) as u32,
            raw_data,
        };
        let mut cmd = Command::from(&sign_cmd);
        let resp = execute_dpe_cmd_raw(&mut model, CaliptraDpeProfile::Mldsa87, &mut cmd).unwrap();
        let resp_data = &resp.data[..resp.data_size as usize];

        check_dpe_status(resp_data, DpeErrorCode::NoError);
        let Response::Sign(SignResp::Mldsa87(sign_resp)) =
            Response::try_read_from_bytes(&cmd, resp_data).unwrap()
        else {
            panic!("Wrong response type!");
        };

        let encoded_sig = EncodedSignature::<MlDsa87>::try_from(sign_resp.sig.as_slice()).unwrap();
        let signature = ml_dsa::Signature::decode(&encoded_sig).unwrap();
        assert!(
            verifying_key.verify_with_context(&message, context, &signature),
            "Signature verification failed for {}-byte context",
            context.len()
        );
        assert!(!verifying_key.verify_with_context(&message, b"wrong context", &signature));
    }
}

#[test]
fn test_invoke_dpe_get_certificate_chain_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until_ready_for_runtime();

    let get_cert_chain_cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let resp = execute_dpe_cmd(
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

fn sign_and_certify_key_test_helper(model: &mut DefaultHwModel) {
    // MLDSA87 Sign is not implemented on caliptra-2.0 (CryptoError::NotImplemented),
    // so only test sign+certify+verify with ECC384.
    let profile = CaliptraDpeProfile::Ecc384;
    let data = TEST_SD_SHA384;
    let sign_cmd = SignCommandNoRef::new(CreateSignCmdArgs {
        profile,
        data: data.clone(),
        ..Default::default()
    });
    let mut cmd = Command::from(&sign_cmd);
    let resp = execute_dpe_cmd_raw(model, profile, &mut cmd).unwrap();
    let resp_data = resp.data[..resp.data_size as usize].to_vec();
    check_dpe_status(&resp_data, DpeErrorCode::NoError);
    let sign_resp = Response::try_read_from_bytes(&cmd, &resp_data).unwrap();

    let certify_key_cmd = &mut CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
        profile,
        format: CertifyKeyCommand::FORMAT_X509,
        ..Default::default()
    });

    let certify_key_resp = certify_key(model, certify_key_cmd).unwrap();

    verify_sign_and_certify_key(
        model,
        profile,
        &sign_resp,
        &certify_key_resp,
        data.as_slice(),
    );
}

#[test]
fn test_invoke_dpe_sign_and_certify_key_cmds() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    sign_and_certify_key_test_helper(&mut model);

    // Make sure both profiles can get certificates and CSRs
    for profile in [CaliptraDpeProfile::Ecc384, CaliptraDpeProfile::Mldsa87] {
        let formats = [
            CertifyKeyCommand::FORMAT_X509,
            CertifyKeyCommand::FORMAT_CSR,
        ];
        for format in formats {
            let certify_key_cmd = &mut CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
                profile,
                format,
                ..Default::default()
            });

            let _ = certify_key(&mut model, certify_key_cmd).unwrap();
        }
    }
}

#[test]
fn test_invoke_dpe_asymmetric_sign() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until_ready_for_runtime();

    let sign_cmd = SignCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&sign_cmd),
        DpeResult::Success,
    );
    let Some(Response::Sign(SignResp::P384(sign_resp))) = resp else {
        panic!("Wrong response type!");
    };

    assert_ne!(sign_resp.sig_r, [0u8; 48]);
    assert_ne!(sign_resp.sig_s, [0u8; 48]);
}

#[test]
fn test_dpe_header_error_code() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until_ready_for_runtime();

    // cannot initialize non-simulation contexts so expect DPE cmd to fail
    let init_ctx_cmd = InitCtxCmd::new_use_default();
    let resp = execute_dpe_cmd(
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
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until_ready_for_runtime();

    for profile in [CaliptraDpeProfile::Ecc384, CaliptraDpeProfile::Mldsa87] {
        let certify_key_cmd = &mut CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
            profile,
            format: CertifyKeyCommand::FORMAT_CSR,
            ..Default::default()
        });
        let _ = certify_key(&mut model, certify_key_cmd).unwrap();
    }

    // Detailed CSR parsing for ECC384
    let certify_key_cmd = &mut CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
        profile: CaliptraDpeProfile::Ecc384,
        format: CertifyKeyCommand::FORMAT_CSR,
        ..Default::default()
    });
    let certify_key_resp = certify_key(&mut model, certify_key_cmd).unwrap();
    let cert_bytes = certify_key_resp.cert().unwrap();

    let rt_resp = get_rt_alias_ecc384_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    // parse CMS ContentInfo
    let content_info = ContentInfo::from_der(cert_bytes).unwrap();
    // parse SignedData
    let mut signed_data = SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();
    assert_eq!(signed_data.version, CmsVersion::V3);

    // validate signer infos
    let signer_infos = signed_data.signer_infos.0;
    // ensure there is only 1 signer info
    assert_eq!(signer_infos.len(), 1);
    let signer_info = signer_infos.get(0).unwrap();
    assert_eq!(signer_info.version, CmsVersion::V3);

    // validate signer identifier
    let sid = &signer_info.sid;
    match sid {
        SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) => {
            // skip first two bytes - first byte is 0x4 der encoding byte and second byte is size byte
            let cert_ski = &subject_key_identifier.0.as_bytes()[2..];
            let ski = rt_cert.subject_key_id().unwrap().as_slice();
            assert_eq!(cert_ski, ski);
        }
        _ => panic!("Error: Signer Identifier is not SubjectKeyIdentifier!"),
    };

    // parse encapsulated content info
    let econtent_info = &mut signed_data.encap_content_info;
    // skip first 4 explicit encoding bytes
    let econtent = &econtent_info.econtent.as_mut().unwrap().to_der().unwrap()[4..];

    // validate csr signature with the alias key
    let mut hasher = Sha384::new();
    hasher.update(econtent);
    let csr_digest = hasher.finalize();
    let alias_key = rt_cert.public_key().unwrap().ec_key().unwrap();
    let csr_sig = EcdsaSig::from_der(signer_info.signature.as_bytes()).unwrap();
    assert!(csr_sig.verify(&csr_digest, &alias_key).unwrap());
}

#[test]
fn test_invoke_dpe_rotate_context() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until_ready_for_runtime();

    let rotate_ctx_cmd = RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
    };

    let resp = execute_dpe_cmd(
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
    let mut model = run_rt_test(RuntimeTestArgs::default());

    for profile in [CaliptraDpeProfile::Ecc384, CaliptraDpeProfile::Mldsa87] {
        let certify_key_cmd = &mut CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
            profile,
            format: CertifyKeyCommand::FORMAT_X509,
            ..Default::default()
        });

        let resp = certify_key(&mut model, certify_key_cmd).unwrap();
        check_dice_extension_criticality(resp.cert().unwrap(), false);
    }
}

#[test]
fn test_invoke_dpe_export_cdi_with_non_critical_dice_extensions() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until_ready_for_runtime();

    let derive_ctx_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&derive_ctx_cmd),
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
    let mut model = run_rt_test(RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default()
                .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Production)
                .set_debug_locked(true),
        ),
        ..Default::default()
    });

    let derive_ctx_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&derive_ctx_cmd),
        DpeResult::Success,
    );

    // Wait for the runtime to be ready for the next command (ensure runtime_cmd_active is cleared)
    for _ in 0..1000 {
        model.step();
    }

    model.warm_reset_flow().unwrap();

    // Wait for mailbox to be ready after warm reset (this is set after warm reset checks complete)
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

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
    let mut model = run_rt_test(RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default()
                .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Production)
                .set_debug_locked(true),
        ),
        ..Default::default()
    });
    // You probably want to retain the parent context, otherwise the whole DPE chain _may be
    // destroyed.
    //
    // This test case exercises that runtime cannot find the root context if the chain is
    // destroyed.
    let derive_ctx_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&derive_ctx_cmd),
        DpeResult::Success,
    );

    // Triggering a warm reset while a command is being processed will disable attestation.
    for _ in 0..100 {
        model.step();
    }

    model.warm_reset_flow().unwrap();

    model.step_until_fatal_error(
        CaliptraError::RUNTIME_UNABLE_TO_FIND_DPE_ROOT_CONTEXT.into(),
        30_000_000,
    );
}

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_subsystem_leaf_cert_contains_caliptra_managed_tci_types() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let certify_key_cmd = &mut CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
        format: CertifyKeyCommand::FORMAT_X509,
        ..Default::default()
    });
    let certify_key_resp = certify_key(&mut model, certify_key_cmd).unwrap();
    let cert_bytes = certify_key_resp.cert().unwrap();

    let (_, cert) = X509CertificateParser::new()
        .with_deep_parse_extensions(true)
        .parse(cert_bytes)
        .unwrap();

    let multi_tcb_info_oid = x509_parser::oid_registry::asn1_rs::oid!(2.23.133 .5 .4 .5);
    let ext = cert
        .get_extension_unique(&multi_tcb_info_oid)
        .unwrap()
        .expect("MultiTcbInfo extension missing");

    let parsed_tcb_infos = asn1::parse_single::<asn1::SequenceOf<TcbInfo>>(ext.value).unwrap();

    let tcb_infos: Vec<TcbInfo> = parsed_tcb_infos.collect();
    for expected_tci_type in [b"RTMR", b"CCIV", b"SOMV", b"SOMO", b"MCFW"] {
        assert_eq!(
            tcb_infos
                .iter()
                .filter(|tcb_info| tcb_info.tci_type == Some(expected_tci_type.as_slice()))
                .count(),
            1
        );
    }
}
