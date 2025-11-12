use crate::common::{
    assert_error, build_model_ready, execute_dpe_cmd, wait_runtime_ready, DpeResult, TEST_DIGEST,
};

use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, RevokeExportedCdiHandleReq, SignWithExportedEcdsaReq,
    SignWithExportedEcdsaResp,
};

use caliptra_drivers::CaliptraError;

use caliptra_hw_model::{DefaultHwModel, HwModel};

use dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    response::{DeriveContextExportedCdiResp, Response},
    DPE_PROFILE,
};

use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    x509::X509,
};

use zerocopy::{FromBytes, IntoBytes};

fn check_certificate_signature(
    sign_resp: &SignWithExportedEcdsaResp,
    exported_cdi_resp: &DeriveContextExportedCdiResp,
) -> bool {
    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&sign_resp.signature_r).unwrap(),
        BigNum::from_slice(&sign_resp.signature_s).unwrap(),
    )
    .unwrap();

    // verify sig with certificate from DeriveContext
    let x509 = X509::from_der(
        &exported_cdi_resp.new_certificate
            [..exported_cdi_resp.certificate_size.try_into().unwrap()],
    )
    .unwrap();
    let ec_pub_key = x509.public_key().unwrap().ec_key().unwrap();
    if !sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap() {
        return false;
    }

    // verify sig with  the returned public key
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

/// Returns e response payload for exported_cdi command.
fn derive_exported_cdi(model: &mut DefaultHwModel) -> DeriveContextExportedCdiResp {
    let derive_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: [0; DPE_PROFILE.get_tci_size()],
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT,

        tci_type: 0,
        target_locality: 0,
    };

    let resp = execute_dpe_cmd(
        model,
        &mut Command::DeriveContext(&derive_cmd),
        DpeResult::Success,
    );

    match resp {
        Some(Response::DeriveContextExportedCdi(r)) => r,
        _ => panic!("expected DeriveContextExportedCdi response"),
    }
}

/// Issue SIGN_WITH_EXPORTED_ECDSA and return the raw bytes (avoids lifetime issues from ref_from_bytes).
fn sign_with_exported_bytes<T: HwModel>(model: &mut T, exported_cdi_handle: [u8; 32]) -> Vec<u8> {
    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("mailbox_execute failed")
        .expect("empty response from SIGN_WITH_EXPORTED_ECDSA")
        .as_bytes()
        .to_vec()
}

#[test]
fn test_sign_exported_ecdsa_handle_after_warm_reset() {
    // Boot to RT ready
    let mut model = build_model_ready();
    wait_runtime_ready(&mut model);

    let derive_resp = derive_exported_cdi(&mut model);
    let old_handle = derive_resp.exported_cdi;

    model.warm_reset();
    wait_runtime_ready(&mut model);

    // use the pre-reset handle; should fail.
    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: old_handle,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let res = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    // Handle should be invalid after warm reset
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED,
        res.unwrap_err(),
    );
}

/// Re-derive after warm reset
#[test]
fn test_sign_exported_ecdsa_rederive_after_warm_reset() {
    // Boot to RT ready
    let mut model = build_model_ready();
    wait_runtime_ready(&mut model);

    // Pre-reset derive + sign + verify
    let derive_pre = derive_exported_cdi(&mut model);
    let bytes_pre = sign_with_exported_bytes(&mut model, derive_pre.exported_cdi);
    let sign_pre = SignWithExportedEcdsaResp::ref_from_bytes(&bytes_pre)
        .expect("parse pre-reset SignWithExportedEcdsaResp");
    assert!(
        check_certificate_signature(sign_pre, &derive_pre),
        "pre-reset signature failed CA verification"
    );

    // Warm reset
    model.warm_reset();
    wait_runtime_ready(&mut model);

    let derive_post = derive_exported_cdi(&mut model);
    let bytes_post = sign_with_exported_bytes(&mut model, derive_post.exported_cdi);
    let sign_post = SignWithExportedEcdsaResp::ref_from_bytes(&bytes_post)
        .expect("parse post-reset SignWithExportedEcdsaResp");
    assert!(
        check_certificate_signature(sign_post, &derive_post),
        "post-reset signature failed CA verification"
    );

    // Handles should differ across reset (fresh context)
    assert_ne!(
        derive_pre.exported_cdi, derive_post.exported_cdi,
        "expected a new exported CDI handle after warm reset"
    );
}

fn make_sign_cmd(handle: [u8; 32]) -> MailboxReq {
    let mut sign_cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: handle,
        tbs: crate::common::TEST_DIGEST,
    });
    sign_cmd.populate_chksum().unwrap();
    sign_cmd
}

fn make_revoke_cmd(handle: [u8; 32]) -> MailboxReq {
    let mut revoke_cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: handle,
    });
    revoke_cmd.populate_chksum().unwrap();
    revoke_cmd
}

/// Revoke before warm reset; verify signing fails before and after warm reset.
/// also try a second revoke after reset
#[test]
fn test_revoke_exported_cdi_handle_after_warm_reset() {
    // Boot to RT ready
    let mut model = build_model_ready();
    wait_runtime_ready(&mut model);

    // Export CDI and verify signing works.
    let cdi_resp = derive_exported_cdi(&mut model);
    let sign_cmd = make_sign_cmd(cdi_resp.exported_cdi);

    let sign_ok = model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .expect("SIGN_WITH_EXPORTED_ECDSA should succeed before revoke")
        .unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(sign_ok.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &cdi_resp));

    // Revoke the handle.
    let revoke_cmd = make_revoke_cmd(cdi_resp.exported_cdi);
    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            revoke_cmd.as_bytes().unwrap(),
        )
        .unwrap_or_else(|e| panic!("REVOKE_EXPORTED_CDI_HANDLE failed unexpectedly: {:?}", e));

    // Signing must now fail.
    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        sign_cmd.as_bytes().unwrap(),
    );
    crate::common::assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED,
        result.err().expect("expected signing to fail after revoke"),
    );

    // Warm reset; signing must still fail with the same stale handle.
    model.warm_reset();
    wait_runtime_ready(&mut model);

    let result_after_reset = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        sign_cmd.as_bytes().unwrap(),
    );
    crate::common::assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED,
        result_after_reset
            .err()
            .expect("expected signing to fail after warm reset"),
    );

    // Revoking again post-reset
    let revoke_again = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        make_revoke_cmd(cdi_resp.exported_cdi).as_bytes().unwrap(),
    );

    crate::common::assert_error(
        &mut model,
        CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
        revoke_again
            .err()
            .expect("expected signing to fail after revok again after reset"),
    );
}
