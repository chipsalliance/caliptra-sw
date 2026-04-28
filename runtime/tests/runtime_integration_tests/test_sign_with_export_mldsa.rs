// Licensed under the Apache-2.0 license

use crate::common::{assert_error, execute_dpe_cmd, run_rt_test, DpeResult, RuntimeTestArgs};
use caliptra_api::{
    mailbox::{MailboxRespHeader, RevokeExportedCdiHandleReq},
    SocManager,
};
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, MldsaSignType, SignWithExportedMldsaReq,
    SignWithExportedMldsaResp,
};
use caliptra_dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    response::{DeriveContextExportedCdiResp, NewHandleResp, Response},
};
use caliptra_dpe_crypto::MAX_EXPORTED_CDI_SIZE;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_runtime::{CaliptraDpeProfile, RtBootStatus, TciMeasurement};
use ml_dsa_01::{
    signature::Verifier, EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey,
};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::*;
use zerocopy::{FromBytes, IntoBytes};

fn verify_mldsa_signature(
    sig: &[u8; 4627],
    exported_cdi_resp: &DeriveContextExportedCdiResp,
    sign_type: MldsaSignType,
    data: &[u8],
) -> bool {
    let (_, cert_parsed) = X509Certificate::from_der(
        &exported_cdi_resp.new_certificate
            [..exported_cdi_resp.certificate_size.try_into().unwrap()],
    )
    .unwrap();
    let raw_pubkey = cert_parsed
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data;
    let raw_pubkey: [u8; 2592] = raw_pubkey.as_ref().try_into().unwrap();
    let encoded_vk = EncodedVerifyingKey::<ml_dsa_01::MlDsa87>::from(raw_pubkey);
    let vk = VerifyingKey::<ml_dsa_01::MlDsa87>::decode(&encoded_vk);

    let encoded_sig = EncodedSignature::<ml_dsa_01::MlDsa87>::from(*sig);
    let sig = Signature::decode(&encoded_sig).unwrap();

    match sign_type {
        MldsaSignType::Mu => vk.verify_mu(&<[u8; 64]>::try_from(data).unwrap().into(), &sig),
        MldsaSignType::Raw => vk.verify(data, &sig).is_ok(),
    }
}

#[test]
fn test_sign_with_exported_cdi_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let derive_ctx_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &derive_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));
}

#[test]
fn test_sign_with_exported_incorrect_cdi_handle_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let get_cert_chain_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&get_cert_chain_cmd),
        DpeResult::Success,
    );

    match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0xFF; MAX_EXPORTED_CDI_SIZE],
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        result.unwrap_err(),
        ModelError::MailboxCmdFailed(
            caliptra_drivers::CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_KEY_DERIVIATION_FAILED.into(),
        )
    );
}

#[test]
fn test_sign_with_exported_never_derived_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0xFF; MAX_EXPORTED_CDI_SIZE],
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        result.unwrap_err(),
        ModelError::MailboxCmdFailed(
            caliptra_drivers::CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_KEY_DERIVIATION_FAILED.into(),
        )
    );
}

#[test]
fn test_sign_with_exported_cdi_measurement_update_duplicate_cdi_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT
            | DeriveContextFlags::ALLOW_RECURSIVE,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(original_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &original_cdi_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));

    let measurement_cmd = DeriveContextCmd {
        data: TciMeasurement([0xa; caliptra_dpe::TCI_SIZE]),
        flags: DeriveContextFlags::RECURSIVE,
        tci_type: if model.subsystem_mode() {
            u32::from_be_bytes(*b"MCFW")
        } else {
            u32::from_be_bytes(*b"CCIV")
        },
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&measurement_cmd),
        DpeResult::Success,
    );

    let Some(Response::Error(e)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::DpeCmdFailure,
    ) else {
        panic!("Expected the second export cdi command to fail.")
    };
    assert_eq!(
        e.status,
        caliptra_dpe::response::DpeErrorCode::Crypto(
            caliptra_dpe_crypto::CryptoError::ExportedCdiHandleDuplicateCdi
        )
        .get_error_code()
    );

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &original_cdi_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));
}

#[test]
fn test_sign_with_exported_cdi_measurement_update_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT
            | DeriveContextFlags::ALLOW_RECURSIVE,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(original_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let measurement_cmd = DeriveContextCmd {
        data: TciMeasurement([0xa; caliptra_dpe::TCI_SIZE]),
        flags: DeriveContextFlags::RECURSIVE,
        tci_type: if model.subsystem_mode() {
            u32::from_be_bytes(*b"MCFW")
        } else {
            u32::from_be_bytes(*b"CCIV")
        },
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&measurement_cmd),
        DpeResult::Success,
    );

    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.exported_cdi,
    });
    cmd.populate_chksum().unwrap();

    match model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    ) {
        Ok(_) => (),
        Err(e) => panic!("REVOKE_EXPORTED_CDI_HANDLE failed with {:?}", e),
    }

    let Some(Response::DeriveContextExportedCdi(updated_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: updated_cdi_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(response.as_bytes()).unwrap();

    // The original CDI was revoked.
    assert!(!verify_mldsa_signature(
        &sign_resp.signature,
        &original_cdi_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &updated_cdi_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));
    assert_ne!(original_cdi_resp, updated_cdi_resp);
    assert_ne!(
        original_cdi_resp.exported_cdi,
        updated_cdi_resp.exported_cdi
    );
    assert_ne!(
        original_cdi_resp.new_certificate,
        updated_cdi_resp.new_certificate
    );
}

#[test]
fn test_sign_with_revoked_exported_cdi_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut sign_cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: cdi_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    sign_cmd.populate_chksum().unwrap();

    let result = model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .expect("SIGN_WITH_EXPORTED_MLDSA should not fail until the handle is revoked")
        .unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(result.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &cdi_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));

    let mut revoke_cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: cdi_resp.exported_cdi,
    });
    revoke_cmd.populate_chksum().unwrap();

    match model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        revoke_cmd.as_bytes().unwrap(),
    ) {
        Ok(_) => (),
        Err(e) => panic!("REVOKE_EXPORTED_CDI_HANDLE failed with {:?}", e),
    }

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        sign_cmd.as_bytes().unwrap(),
    );

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_KEY_DERIVIATION_FAILED,
        result.err().unwrap(),
    );
}

#[test]
fn test_sign_with_disabled_attestation_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut sign_cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: cdi_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    sign_cmd.populate_chksum().unwrap();

    let result = model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(result.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &cdi_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_bytes()).unwrap();
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let result = model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(result.as_bytes()).unwrap();
    // Signature is still valid in terms of structure, but we can't verify it against the old cert.
    // We just check that it completes successfully.
    assert!(!verify_mldsa_signature(
        &sign_resp.signature,
        &cdi_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));
}

#[test]
fn test_sign_with_exported_cdi_warm_reset_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs {
        security_state: Some(
            *caliptra_hw_model::SecurityState::default()
                .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Production)
                .set_debug_locked(true),
        ),
        ..Default::default()
    });

    let derive_ctx_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &derive_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));

    // Wait for command to finish
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    // Triggering a warm reset while a command is being processed will disable attestation.
    for _ in 0..1000 {
        model.step();
    }

    model.warm_reset_flow().unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &derive_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));
}

#[test]
fn test_sign_with_exported_cdi_warm_reset_parent_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs {
        security_state: Some(
            *caliptra_hw_model::SecurityState::default()
                .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Production)
                .set_debug_locked(true),
        ),
        ..Default::default()
    });

    // Rotate out the default handle so we can make multiple descendants.
    let rotate_ctx_cmd = caliptra_dpe::commands::RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: caliptra_dpe::commands::RotateCtxFlags::empty(),
    };

    let Some(Response::RotateCtx(NewHandleResp { handle, .. })) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::RotateCtx(&rotate_ctx_cmd),
        DpeResult::Success,
    ) else {
        panic!("Failed to rotate context!");
    };

    // Derive a new context and retain the parent.
    // We will export the parent. We expect that the child prevents the dpe context chain from being destroyed.
    let derive_ctx_cmd = DeriveContextCmd {
        handle,
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        tci_type: 1,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let Some(Response::DeriveContext(caliptra_dpe::response::DeriveContextResp {
        parent_handle,
        ..
    })) = resp
    else {
        panic!("expected derive context resp!");
    };

    // Export the parent context from the last derive command.
    let derive_ctx_cmd = DeriveContextCmd {
        handle: parent_handle,
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 2,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &derive_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));

    // Wait for command to finish
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    // Triggering a warm reset while a command is being processed will disable attestation.
    for _ in 0..1000 {
        model.step();
    }

    model.warm_reset_flow().unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        sign_type: MldsaSignType::Mu.into(),
        tbs_size: 64,
        tbs: [0u8; 1024],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &derive_resp,
        MldsaSignType::Mu,
        &[0u8; 64]
    ));
}

#[test]
fn test_sign_with_exported_cdi_mldsa_raw() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let derive_ctx_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedMldsa(SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        sign_type: MldsaSignType::Raw.into(),
        tbs_size: 100,
        tbs: {
            let mut tbs = [0u8; 1024];
            tbs[..100].copy_from_slice(&[0xa; 100]);
            tbs
        },
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedMldsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(verify_mldsa_signature(
        &sign_resp.signature,
        &derive_resp,
        MldsaSignType::Raw,
        &[0xa; 100]
    ));
}
