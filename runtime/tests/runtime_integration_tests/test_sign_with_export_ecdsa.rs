// Licensed under the Apache-2.0 license

use caliptra_api::{
    mailbox::{MailboxRespHeader, RevokeExportedCdiHandleReq},
    SocManager,
};
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, SignWithExportedEcdsaReq, SignWithExportedEcdsaResp,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError, SecurityState};
use caliptra_runtime::{RtBootStatus, TciMeasurement};
use crypto::{CryptoError, MAX_EXPORTED_CDI_SIZE};
use dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags, RotateCtxCmd, RotateCtxFlags},
    context::ContextHandle,
    response::{
        DeriveContextExportedCdiResp, DeriveContextResp, DpeErrorCode, NewHandleResp, Response,
    },
    TCI_SIZE,
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    x509::X509,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{
    assert_error, execute_dpe_cmd, run_rt_test, DpeResult, RuntimeTestArgs, TEST_DIGEST,
};

fn check_certificate_signature(
    sign_resp: &SignWithExportedEcdsaResp,
    exported_cdi_resp: &DeriveContextExportedCdiResp,
) -> bool {
    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&sign_resp.signature_r).unwrap(),
        BigNum::from_slice(&sign_resp.signature_s).unwrap(),
    )
    .unwrap();

    // Verify that the certificate from DeriveContext can verify the signature.
    let x509 = X509::from_der(
        &exported_cdi_resp.new_certificate
            [..exported_cdi_resp.certificate_size.try_into().unwrap()],
    )
    .unwrap();
    let ec_pub_key = x509.public_key().unwrap().ec_key().unwrap();
    if !sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap() {
        return false;
    }

    // Let's also check that the returned public key can verify the signature.
    let x = BigNum::from_slice(&sign_resp.derived_pubkey_x).unwrap();
    let y = BigNum::from_slice(&sign_resp.derived_pubkey_y).unwrap();
    let ec_pub_key = EcKey::from_public_key_affine_coordinates(
        &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
        &x,
        &y,
    )
    .unwrap();
    sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap()
}

#[test]
fn test_sign_with_exported_cdi() {
    // Exports a CDI and then signs a well known hash.
    // Verifies the signature using the CA certificate paired with the export-cdi, as well as the
    // public key returned by SIGN_WITH_EXPORTED_ECDSA.
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
        &mut Command::from(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));
}

#[test]
fn test_sign_with_exported_incorrect_cdi_handle() {
    // Verifies that an invalid CDI handle cannot derive an exported ECDSA key.
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
        &mut Command::from(&get_cert_chain_cmd),
        DpeResult::Success,
    );

    match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0xFF; MAX_EXPORTED_CDI_SIZE],
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        result.unwrap_err(),
        ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED.into(),
        )
    );
}

#[test]
fn test_sign_with_exported_never_derived() {
    // Verifies that an exported ECDSA key cannot be derived without first exporting a CDI.
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0xFF; MAX_EXPORTED_CDI_SIZE],
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        result.unwrap_err(),
        ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED.into(),
        )
    );
}

#[test]
fn test_sign_with_exported_cdi_measurement_update_duplicate_cdi() {
    // Tests the following sequence:
    // 1. Export a CDI.
    //   - This CDI is know as the "original_cdi".
    // 2. Verify signing of `SIGN_WITH_EXPORTED_ECDSA` with the CA signed by the "original_cdi".
    // 3. Add a new measurement using the `DeriveContextFlags::RECURSIVE` flag.
    // 4. Try to export a new CDI, verify that it failes with
    //    `DpeErrorCode::Crypto(CryptoError::ExportedCdiHandleDuplicateCdi))`.
    // 5. Verify signing of `SIGN_WITH_EXPORTED_ECDSA` with the CA signed by the "original_cdi".
    //    This ensures that the failure in step 4 did not overwrite the "original_cdi".
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

    let Some(Response::DeriveContextExportedCdi(original_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &original_cdi_resp));

    let measurement_cmd = DeriveContextCmd {
        data: TciMeasurement([0xa; TCI_SIZE]),
        flags: DeriveContextFlags::RECURSIVE,
        tci_type: u32::from_be_bytes(*b"MBVP"),
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&measurement_cmd),
        DpeResult::Success,
    );

    let Some(Response::Error(e)) = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::DpeCmdFailure,
    ) else {
        panic!("Expected the second export cdi command to fail.")
    };
    assert_eq!(
        e.status,
        DpeErrorCode::Crypto(CryptoError::ExportedCdiHandleDuplicateCdi).get_error_code()
    );

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &original_cdi_resp));
}

#[test]
fn test_sign_with_exported_cdi_measurement_update() {
    // Tests the following sequence:
    // 1. Export a CDI.
    //   - This CDI is know as the "original_cdi".
    // 2. Add a new measurement using the `DeriveContextFlags::RECURSIVE` flag.
    // 3. Revoke the "original_cdi".
    // 3. Export a new CDI known as the "updated_cdi".
    // 4. Verify that the signature from `SIGN_WITH_EXPORTED_ECDSA` cannot be verified by the CA
    //    cert paired with the "original_cdi".
    // 5. Verify signing of `SIGN_WITH_EXPORTED_ECDSA` with the CA cert signed by the "updated_cdi"
    //    to make sure that we can create valid signatures that map with the "update_cdi" CA cert.
    // 6. Double check that the certificate and export_cdi have changed between "original_cdi" and
    //    "update_cdi".
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

    let Some(Response::DeriveContextExportedCdi(original_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let measurement_cmd = DeriveContextCmd {
        data: TciMeasurement([0xa; TCI_SIZE]),
        flags: DeriveContextFlags::RECURSIVE,
        tci_type: u32::from_be_bytes(*b"MBVP"),
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        &mut model,
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
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: updated_cdi_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();

    // The original CDI was revoked.
    assert!(!check_certificate_signature(sign_resp, &original_cdi_resp));
    assert!(check_certificate_signature(sign_resp, &updated_cdi_resp));
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
fn test_sign_with_revoked_exported_cdi() {
    // This tests the following sequence:
    // 1. Create an exported-cdi
    // 2. Check that we can create a valid signature with it.
    // 3. Revoke the exported-cdi.
    // 4. Verify that we can no longer sign with the exported-cdi and that `SIGN_WITH_EXPORTED_ECDSA`
    // returns `CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED`.
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
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut sign_cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: cdi_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    sign_cmd.populate_chksum().unwrap();

    let result = model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .expect("SIGN_WITH_EXPORTED_ECDSA should not fail until the handle is revoked")
        .unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(result.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &cdi_resp));

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
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        sign_cmd.as_bytes().unwrap(),
    );

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED,
        result.err().unwrap(),
    );
}

#[test]
fn test_sign_with_disabled_attestation() {
    // This tests the following sequence:
    // 1. Create an exported-cdi
    // 2. Check that we can create a valid signature with it.
    // 3. Disable attestation
    // 4. Verify that the signature is no longer valid.
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
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut sign_cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: cdi_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    sign_cmd.populate_chksum().unwrap();

    let result = model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(result.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &cdi_resp));

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
            CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(result.as_bytes()).unwrap();
    assert!(!check_certificate_signature(sign_resp, &cdi_resp));
}

#[test]
fn test_sign_with_exported_cdi_warm_reset() {
    // 1. Exports a CDI and then signs a well known hash.
    // 2. Verifies the signature using the CA certificate paired with the export-cdi, as well as the
    // public key returned by SIGN_WITH_EXPORTED_ECDSA.
    // 3. Performs a warm reset
    // 4. Checks that we can still create a valid signature.

    let mut model = run_rt_test(RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default()
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
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));

    // Wait for command to finish
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    // Triggering a warm reset while a command is being processed will disable attestation.
    for _ in 0..1000 {
        model.step();
    }

    model.warm_reset_flow().unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));
}

#[test]
fn test_sign_with_exported_cdi_warm_reset_parent() {
    // 1. Exports a CDI that has children and then signs a well known hash.
    // 2. Verifies the signature using the CA certificate paired with the export-cdi, as well as the
    // public key returned by SIGN_WITH_EXPORTED_ECDSA.
    // 3. Performs a warm reset
    // 4. Checks that we can still create a valid signature. This implicitly checks that the root
    //    context was not destroyed, since we can still find it in the runtime.

    let mut model = run_rt_test(RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default()
                .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Production)
                .set_debug_locked(true),
        ),
        ..Default::default()
    });

    // Rotate out the default handle so we can make multiple descendants.
    let rotate_ctx_cmd = RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
    };

    let Some(Response::RotateCtx(NewHandleResp { handle, .. })) = execute_dpe_cmd(
        &mut model,
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
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let Some(Response::DeriveContext(DeriveContextResp { parent_handle, .. })) = resp else {
        panic!("expected derive context resp!");
    };

    // Export the parent context from the last derive command.
    let derive_ctx_cmd = DeriveContextCmd {
        handle: parent_handle,
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));

    // Wait for command to finish
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    // Triggering a warm reset while a command is being processed will disable attestation.
    for _ in 0..1000 {
        model.step();
    }

    model.warm_reset_flow().unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));
}
