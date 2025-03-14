// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, SignWithExportedEcdsaReq, SignWithExportedEcdsaResp,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_runtime::RtBootStatus;
use crypto::MAX_EXPORTED_CDI_SIZE;
use dpe::{
    DPE_PROFILE,
    commands::{Command, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    response::Response,
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    x509::X509,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{DpeResult, RuntimeTestArgs, TEST_DIGEST, execute_dpe_cmd, run_rt_test};

#[test]
fn test_sign_with_exported_cdi() {
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

    let resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: resp.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let response = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&response.signature_r).unwrap(),
        BigNum::from_slice(&response.signature_s).unwrap(),
    )
    .unwrap();

    // Verify that the certificate from DeriveContext can verify the signature.
    let x509 =
        X509::from_der(&resp.new_certificate[..resp.certificate_size.try_into().unwrap()]).unwrap();
    let ec_pub_key = x509.public_key().unwrap().ec_key().unwrap();
    assert!(sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap());

    // Let's also check that the returned public key can verify the signature.
    let x = BigNum::from_slice(&response.derived_pubkey_x).unwrap();
    let y = BigNum::from_slice(&response.derived_pubkey_y).unwrap();
    let ec_pub_key = EcKey::from_public_key_affine_coordinates(
        &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
        &x,
        &y,
    )
    .unwrap();
    assert!(sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap());
}

#[test]
fn test_sign_with_exported_incorrect_cdi_handle() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let get_cert_chain_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: [0; DPE_PROFILE.get_tci_size()],
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 0,
        target_locality: 0,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&get_cert_chain_cmd),
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
