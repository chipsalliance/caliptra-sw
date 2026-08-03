// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, PopulatePqCertReq, RevokeExportedCdiHandleReq,
    SetPqSeedReq, SET_PQ_SEED_SEED_SIZE,
};
use caliptra_drivers::Mldsa87Signature;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel};
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

use crate::common::{
    assert_error, execute_dpe_cmd, run_pqc_rt_test, run_rt_test, DpeResult, RuntimeTestArgs,
};

/// Provision the PQ.DevID CDI (as PL0), enabling PQC mode.
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

/// Populate the ML-DSA PQ certificate (a prerequisite for exporting a CDI).
fn populate_pq_cert(model: &mut DefaultHwModel) {
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
/// return the exported-CDI handle. RETAIN_PARENT_CONTEXT keeps the root context
/// valid so a second export can run in the same boot (used by the re-export
/// test). Requires SET_PQ_SEED and POPULATE_PQ_CERT first.
fn export_cdi_with_profile(model: &mut DefaultHwModel, profile: CaliptraDpeProfile) -> [u8; 32] {
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
    let resp = execute_dpe_cmd(
        profile,
        model,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::DeriveContextExportedCdi(resp)) = resp else {
        panic!("expected derive context exported cdi resp!");
    };
    resp.header.exported_cdi
}

/// Export an ML-DSA CDI (the PQ.DevID identity) and return its handle.
fn export_cdi(model: &mut DefaultHwModel) -> [u8; 32] {
    export_cdi_with_profile(model, CaliptraDpeProfile::Mldsa)
}

/// Export an ECDSA CDI (the RT-alias identity) and return its handle. Shares the
/// DPE context tree with the ML-DSA export but lands in the separate key-vault
/// exported-CDI slot.
fn export_ecdsa_cdi(model: &mut DefaultHwModel) -> [u8; 32] {
    export_cdi_with_profile(model, CaliptraDpeProfile::Ecc384)
}

/// Build a REVOKE_EXPORTED_CDI_HANDLE request for `handle`.
fn revoke_req(handle: [u8; 32]) -> MailboxReq {
    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: handle,
    });
    cmd.populate_chksum().unwrap();
    cmd
}

#[test]
fn test_revoke_exported_cdi_handle_mldsa_not_found() {
    // Exercises the unified REVOKE_EXPORTED_CDI_HANDLE command on the ML-DSA
    // attestation build, where it also checks the ML-DSA exported-CDI slot.
    let mut model = run_pqc_rt_test();

    // Revoking a non-existent handle should return NOT_FOUND.
    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0xFFu8; RevokeExportedCdiHandleReq::EXPORTED_CDI_MAX_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
        result.unwrap_err(),
    );

    // Zero handle should also return NOT_FOUND.
    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0u8; RevokeExportedCdiHandleReq::EXPORTED_CDI_MAX_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
        result.unwrap_err(),
    );
}

#[test]
fn test_revoke_exported_cdi_handle_mldsa_pl1_rejected() {
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

    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0u8; RevokeExportedCdiHandleReq::EXPORTED_CDI_MAX_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        result.unwrap_err(),
    );
}

#[test]
fn test_revoke_exported_cdi_handle_mldsa_success() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_cdi(&mut model);

    // Revoking the handle of an active exported-CDI slot succeeds.
    let cmd = revoke_req(handle);
    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("REVOKE_EXPORTED_CDI_HANDLE should succeed for an active handle");
}

#[test]
fn test_revoke_exported_cdi_handle_mldsa_double_revoke() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_cdi(&mut model);

    let cmd = revoke_req(handle);
    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("first revoke should succeed");

    // The slot is now inactive, so revoking the same handle again returns
    // NOT_FOUND.
    let result = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
        result.unwrap_err(),
    );
}

#[test]
fn test_revoke_exported_cdi_handle_mldsa_reexport_after_revoke() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_cdi(&mut model);

    // Revoking frees the single ML-DSA exported-CDI slot.
    let cmd = revoke_req(handle);
    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("revoke should succeed");

    // With the slot freed, a fresh export succeeds instead of hitting the
    // single-slot limit.
    let _new_handle = export_cdi(&mut model);
}

// Export both an ECDSA (RT-alias) and an ML-DSA (PQ.DevID) CDI, then revoke each
// in turn and confirm the command matches the right slot: revoking one handle
// must not disturb the other, and each handle must still be found afterwards.

#[test]
fn test_revoke_exported_cdi_handle_both_populated_revoke_ecdsa_first() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let ecdsa_handle = export_ecdsa_cdi(&mut model);
    let mldsa_handle = export_cdi(&mut model);
    assert_ne!(
        ecdsa_handle, mldsa_handle,
        "the ECDSA and ML-DSA handles must differ for this test to be meaningful"
    );

    // Revoke the ECDSA handle: it is found (in the key-vault slots) and removed.
    let cmd = revoke_req(ecdsa_handle);
    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("revoking the ECDSA handle should succeed");
    let result = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
        result.unwrap_err(),
    );

    // The ML-DSA slot was left intact, so its handle is still revocable.
    let cmd = revoke_req(mldsa_handle);
    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("the ML-DSA handle must still be revocable after revoking ECDSA");
}

#[test]
fn test_revoke_exported_cdi_handle_both_populated_revoke_mldsa_first() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let ecdsa_handle = export_ecdsa_cdi(&mut model);
    let mldsa_handle = export_cdi(&mut model);
    assert_ne!(
        ecdsa_handle, mldsa_handle,
        "the ECDSA and ML-DSA handles must differ for this test to be meaningful"
    );

    // Revoke the ML-DSA handle: it is found (in the ML-DSA slot) and removed.
    let cmd = revoke_req(mldsa_handle);
    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("revoking the ML-DSA handle should succeed");
    let result = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
        result.unwrap_err(),
    );

    // The ECDSA slot was left intact, so its handle is still revocable.
    let cmd = revoke_req(ecdsa_handle);
    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("the ECDSA handle must still be revocable after revoking ML-DSA");
}
