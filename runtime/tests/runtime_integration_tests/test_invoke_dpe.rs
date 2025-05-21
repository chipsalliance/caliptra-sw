// Licensed under the Apache-2.0 license.

use crate::common::{
    execute_dpe_cmd, get_rt_alias_cert, run_rt_test, DpeResult, RuntimeTestArgs, TEST_DIGEST,
    TEST_LABEL,
};
use caliptra_api::{
    mailbox::{CommandId, FwInfoResp},
    SocManager,
};
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{InvokeDpeReq, MailboxReq, MailboxReqHeader};
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_runtime::{RtBootStatus, DPE_SUPPORT, VENDOR_ID, VENDOR_SKU};
use cms::{
    cert::x509::der::{Decode, Encode},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{SignedData, SignerIdentifier},
};
use dpe::{
    commands::{
        CertifyKeyCmd, CertifyKeyFlags, Command, DeriveContextCmd, DeriveContextFlags,
        GetCertificateChainCmd, InitCtxCmd, RotateCtxCmd, RotateCtxFlags, SignCmd, SignFlags,
    },
    context::ContextHandle,
    response::{DpeErrorCode, Response},
    DPE_PROFILE,
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    x509::X509,
};
use sha2::{Digest, Sha384};
use x509_parser::{nom::Parser, prelude::*};
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_invoke_dpe_get_profile_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let resp = execute_dpe_cmd(&mut model, &mut Command::GetProfile, DpeResult::Success);
    let Some(Response::GetProfile(profile)) = resp else {
        panic!("Wrong response type!");
    };
    assert_eq!(profile.resp_hdr.profile, DPE_PROFILE as u32);
    assert_eq!(profile.vendor_id, VENDOR_ID);
    assert_eq!(profile.vendor_sku, VENDOR_SKU);
    assert_eq!(profile.flags, DPE_SUPPORT.bits());
}

#[test]
fn test_invoke_dpe_size_too_big() {
    // Test with data_size too big.
    let mut cmd = MailboxReq::InvokeDpeCommand(InvokeDpeReq {
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
fn test_invoke_dpe_get_certificate_chain_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

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

#[test]
fn test_invoke_dpe_sign_and_certify_key_cmds() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let sign_cmd = SignCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::Sign(&sign_cmd),
        DpeResult::Success,
    );
    let Some(Response::Sign(sign_resp)) = resp else {
        panic!("Wrong response type!");
    };

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::CertifyKey(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(certify_key_resp)) = resp else {
        panic!("Wrong response type!");
    };

    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&sign_resp.sig_r).unwrap(),
        BigNum::from_slice(&sign_resp.sig_s).unwrap(),
    )
    .unwrap();

    let ecc_pub_key = EcKey::from_public_key_affine_coordinates(
        &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
        &BigNum::from_slice(&certify_key_resp.derived_pubkey_x).unwrap(),
        &BigNum::from_slice(&certify_key_resp.derived_pubkey_y).unwrap(),
    )
    .unwrap();
    assert!(sig.verify(&TEST_DIGEST, &ecc_pub_key).unwrap());
}

#[test]
fn test_invoke_dpe_asymmetric_sign() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let sign_cmd = SignCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::Sign(&sign_cmd),
        DpeResult::Success,
    );
    let Some(Response::Sign(sign_resp)) = resp else {
        panic!("Wrong response type!");
    };

    assert_ne!(sign_resp.sig_r, [0u8; 48]);
    assert_ne!(sign_resp.sig_s, [0u8; 48]);
}

#[test]
fn test_dpe_header_error_code() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

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

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_CSR,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::CertifyKey(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(certify_key_resp)) = resp else {
        panic!("Wrong response type!");
    };

    let rt_resp = get_rt_alias_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    // parse CMS ContentInfo
    let content_info = ContentInfo::from_der(
        &certify_key_resp.cert[..certify_key_resp.cert_size.try_into().unwrap()],
    )
    .unwrap();
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

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

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
    let Ok((_, cert)) = parser
            .parse(cert) else {
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

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::CertifyKey(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(resp)) = resp else {
            panic!("Wrong response type!");
        };
    check_dice_extension_criticality(&resp.cert[..resp.cert_size.try_into().unwrap()], false);
}

#[test]
fn test_invoke_dpe_export_cdi_with_non_critical_dice_extensions() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let derive_ctx_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: [0; DPE_PROFILE.get_tci_size()],
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 0,
        target_locality: 0,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let Some(Response::DeriveContextExportedCdi(resp)) = resp else {
        panic!("expected derive context resp!");
    };
    check_dice_extension_criticality(
        &resp.new_certificate[..resp.certificate_size.try_into().unwrap()],
        false,
    );
}

#[test]
fn test_export_cdi_attestation_not_disabled_after_update_reset() {
    for derive_flags in [
        DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
    ] {
        let mut model = run_rt_test(RuntimeTestArgs::default());

        let derive_ctx_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: derive_flags,
            tci_type: 0,
            target_locality: 0,
        };

        let _ = execute_dpe_cmd(
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
}
