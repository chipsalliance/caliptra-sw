// Licensed under the Apache-2.0 license

//! Integration tests for the SIGN_WITH_EXPORTED_MLDSA mailbox command.
//!
//! An exported ML-DSA CDI slot is produced by INVOKE_DPE_MLDSA87 carrying a DPE
//! `DeriveContext{EXPORT_CDI | CREATE_CERTIFICATE}` (see `export_cdi` below), so
//! the successful-sign lineage is exercised here alongside the
//! request-validation paths (privilege, malformed request, handle-not-found)
//! that run before the CDI lookup.

use caliptra_api::SocManager;
use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;
use caliptra_common::checksum::calc_checksum;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, PopulatePqCertReq, RevokeExportedCdiHandleReq,
    SetPqSeedReq, SignWithExportedMldsaReq, SignWithExportedMldsaResp, SET_PQ_SEED_SEED_SIZE,
};
use caliptra_drivers::{Mldsa87Signature, MLDSA87_MU_BYTES};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use caliptra_runtime::{CaliptraDpeProfile, RtBootStatus};
use caliptra_x509::MlDsa87CertBuilder;
use dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    response::Response,
    tci::TciMeasurement,
    TCI_SIZE,
};
use openssl::pkey::Private;
use openssl::pkey_ctx::PkeyCtx;
use openssl::pkey_ml_dsa::{PKeyMlDsaBuilder, Variant};
use openssl::signature::Signature;
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{
    assert_error, execute_dpe_cmd, run_pqc_rt_test, run_rt_test, DpeResult, RuntimeTestArgs,
};

/// Issue SIGN_WITH_EXPORTED_MLDSA and return the raw response bytes.
fn sign(
    model: &mut caliptra_hw_model::DefaultHwModel,
    handle: [u8; 32],
    sign_mode: u32,
    message: &[u8],
) -> Result<Vec<u8>, ModelError> {
    let mut req = SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: handle,
        sign_mode,
        message_size: message.len() as u32,
        message: [0u8; SignWithExportedMldsaReq::MAX_DATA_SIZE],
    };
    req.message[..message.len()].copy_from_slice(message);

    let mut cmd = MailboxReq::SignWithExportedMldsa(req);
    cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
            cmd.as_bytes().unwrap(),
        )
        .map(|resp| resp.expect("expected a SIGN_WITH_EXPORTED_MLDSA response"))
}

/// Issue SIGN_WITH_EXPORTED_MLDSA encoded as the full fixed-size struct (rather
/// than the `message_size`-trimmed form). This lets a `message_size` larger than
/// the request buffer be sent, which the checksum-aware `MailboxReq` encoder
/// would otherwise reject client-side.
fn sign_full(
    model: &mut caliptra_hw_model::DefaultHwModel,
    sign_mode: u32,
    message_size: u32,
) -> Result<Vec<u8>, ModelError> {
    let mut req = SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0u8; 32],
        sign_mode,
        message_size,
        message: [0u8; SignWithExportedMldsaReq::MAX_DATA_SIZE],
    };
    let cmd_id = u32::from(CommandId::SIGN_WITH_EXPORTED_MLDSA);
    // Checksum covers the request payload after the chksum field itself.
    req.hdr.chksum = calc_checksum(cmd_id, &req.as_bytes()[4..]);

    model
        .mailbox_execute(cmd_id, req.as_bytes())
        .map(|resp| resp.expect("expected a SIGN_WITH_EXPORTED_MLDSA response"))
}

/// Provision the PQ.DevID CDI via SET_PQ_SEED, enabling PQC mode. Signing with an
/// exported CDI requires this to have run first.
fn set_pq_seed(model: &mut DefaultHwModel) {
    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .expect("SET_PQ_SEED failed");
}

/// Populate the ML-DSA PQ certificate. Exporting a CDI with a certificate
/// requires the PQ cert to have been populated first.
fn populate_pq_cert(model: &mut DefaultHwModel) {
    // Generate an ML-DSA-87 key pair and self-sign a placeholder TBS.
    let pk_builder = PKeyMlDsaBuilder::<Private>::from_seed(Variant::MlDsa87, &[0u8; 32]).unwrap();
    let priv_key = pk_builder.build().unwrap();
    let tbs: &[u8] = b"this is going to be the TBS";
    let mut sig_bytes = vec![];
    let mut ctx = PkeyCtx::new(&priv_key).unwrap();
    let mut algo = Signature::for_ml_dsa(Variant::MlDsa87).unwrap();
    ctx.sign_message_init(&mut algo).unwrap();
    ctx.sign_to_vec(tbs, &mut sig_bytes).unwrap();
    let sig = Mldsa87Signature::new(sig_bytes.try_into().unwrap());
    let builder = MlDsa87CertBuilder::new(tbs, &sig).unwrap();
    let mut cert = [0u8; PopulatePqCertReq::MAX_CERT_SIZE];
    let cert_size = builder.build(&mut cert).unwrap();

    let mut cmd = MailboxReq::PopulatePqCert(PopulatePqCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cert_size: cert_size as u32,
        cert,
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(
            u32::from(CommandId::POPULATE_PQ_CERT),
            cmd.as_bytes().unwrap(),
        )
        .expect("POPULATE_PQ_CERT failed");
}

/// Export an ML-DSA CDI via INVOKE_DPE_MLDSA87 + `DeriveContext{EXPORT_CDI}` and
/// return the exported-CDI handle that SIGN/REVOKE consume. Requires SET_PQ_SEED
/// and POPULATE_PQ_CERT to have run first.
fn export_cdi(model: &mut DefaultHwModel) -> [u8; 32] {
    let derive_ctx_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0; TCI_SIZE]),
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 0,
        target_locality: 0,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        CaliptraDpeProfile::Mldsa,
        model,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::DeriveContextExportedCdi(resp)) = resp else {
        panic!("expected derive context exported cdi resp!");
    };
    resp.header.exported_cdi
}

/// Issue REVOKE_EXPORTED_CDI_HANDLE for `handle`, expecting success.
fn revoke_cdi(model: &mut DefaultHwModel, handle: [u8; 32]) {
    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: handle,
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("REVOKE_EXPORTED_CDI_HANDLE failed");
}

#[test]
fn test_sign_with_exported_mldsa_success_sign_data() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_cdi(&mut model);

    // Data mode: the firmware signs the raw message directly.
    let message = b"caliptra exported ml-dsa sign-data test message";
    let resp = sign(
        &mut model,
        handle,
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        message,
    )
    .expect("SIGN_WITH_EXPORTED_MLDSA (data mode) should succeed");

    let (sign_resp, _) = SignWithExportedMldsaResp::ref_from_prefix(resp.as_bytes()).unwrap();
    assert_eq!(
        caliptra_mldsa::Mldsa87::verify(&sign_resp.derived_pubkey, &sign_resp.signature, message,),
        caliptra_mldsa::Mldsa87Result::Success,
        "returned signature must verify under the returned public key"
    );
}

#[test]
fn test_sign_with_exported_mldsa_success_sign_external_mu() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_cdi(&mut model);

    // External-mu mode: the caller supplies the 64-byte mu and the firmware signs
    // it directly.
    let mu = [0x42u8; MLDSA87_MU_BYTES];
    let resp = sign(
        &mut model,
        handle,
        SignWithExportedMldsaReq::SIGN_MODE_EXTERNAL_MU,
        &mu,
    )
    .expect("SIGN_WITH_EXPORTED_MLDSA (external-mu mode) should succeed");

    let (sign_resp, _) = SignWithExportedMldsaResp::ref_from_prefix(resp.as_bytes()).unwrap();
    assert_eq!(
        caliptra_mldsa::Mldsa87::verify_mu(&sign_resp.derived_pubkey, &sign_resp.signature, &mu),
        caliptra_mldsa::Mldsa87Result::Success,
        "returned signature must verify under the returned public key"
    );
}

#[test]
fn test_sign_with_exported_mldsa_wrong_handle_after_export() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    // A CDI is exported, but a handle that does not match the active slot must
    // still be rejected as not found.
    let _handle = export_cdi(&mut model);

    let result = sign(
        &mut model,
        [0xFFu8; 32],
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_FOUND,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_sign_after_revoke() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_cdi(&mut model);

    // Signing succeeds while the exported-CDI slot is active.
    sign(
        &mut model,
        handle,
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    )
    .expect("sign before revoke should succeed");

    revoke_cdi(&mut model, handle);

    // Revoking zeroizes the slot (active = false), so the same handle no longer
    // matches and signing is rejected as not found.
    let result = sign(
        &mut model,
        handle,
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_FOUND,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_sign_after_disable_attestation() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_cdi(&mut model);

    // Signing succeeds before attestation is disabled.
    sign(
        &mut model,
        handle,
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    )
    .expect("sign before disable-attestation should succeed");

    // DISABLE_ATTESTATION zeroizes the exported ML-DSA CDI slot. Unlike ECDSA
    // (which still returns a now-invalid signature), the ML-DSA slot goes
    // inactive, so signing fails outright as not found.
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::DISABLE_ATTESTATION), &[]),
    };
    model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload.as_bytes(),
        )
        .expect("DISABLE_ATTESTATION failed");

    let result = sign(
        &mut model,
        handle,
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_FOUND,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_invalid_sign_mode() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);

    // sign_mode is neither SIGN_MODE_DATA nor SIGN_MODE_EXTERNAL_MU.
    let result = sign(&mut model, [0u8; 32], 0xDEAD_BEEF, b"message");
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_PARAMS,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_external_mu_wrong_size() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);

    // External-mu mode requires exactly MLDSA87_MU_BYTES (64) of message; any
    // other length is rejected before the CDI lookup.
    for len in [0usize, 32, 63, 65] {
        let msg = vec![0u8; len];
        let result = sign(
            &mut model,
            [0u8; 32],
            SignWithExportedMldsaReq::SIGN_MODE_EXTERNAL_MU,
            &msg,
        );
        assert_error(
            &mut model,
            CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_PARAMS,
            result.unwrap_err(),
        );
    }
}

#[test]
fn test_sign_with_exported_mldsa_message_too_large() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);

    // A message_size larger than the buffer must be rejected as invalid params
    // (and must not be used to index the message buffer).
    let result = sign_full(
        &mut model,
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        SignWithExportedMldsaReq::MAX_DATA_SIZE as u32 + 1,
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_PARAMS,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_handle_not_found() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);

    // No CDI has been exported, so any handle must be rejected as not found.
    let result = sign(
        &mut model,
        [0xFFu8; 32],
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_FOUND,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_before_set_pq_seed() {
    let mut model = run_pqc_rt_test();

    // SET_PQ_SEED has not run, so PQC mode is not initialized. A well-formed
    // request that reaches the CDI derivation must be rejected before signing.
    let result = sign(
        &mut model,
        [0u8; 32],
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_PQC_NOT_INITIALIZED,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_pl1_rejected() {
    use caliptra_builder::ImageOptions;

    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        test_image_options: Some(image_opts),
        ..Default::default()
    });
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // The privilege check runs before the CDI lookup, so this is rejected
    // regardless of whether a CDI has been exported.
    let result = sign(
        &mut model,
        [0u8; 32],
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        result.unwrap_err(),
    );
}
