// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, RevokeExportedCdiHandleReq,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;

use crate::common::{
    assert_error, export_ecdsa_cdi, export_mldsa_cdi, populate_pq_cert, provision_pq_seed,
    run_pqc_rt_test, run_rt_test, RuntimeTestArgs,
};

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
    provision_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_mldsa_cdi(&mut model);

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
    provision_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_mldsa_cdi(&mut model);

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
    provision_pq_seed(&mut model);
    populate_pq_cert(&mut model);
    let handle = export_mldsa_cdi(&mut model);

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
    let _new_handle = export_mldsa_cdi(&mut model);
}

// Export both an ECDSA (RT-alias) and an ML-DSA (PQ.DevID) CDI, then revoke each
// in turn and confirm the command matches the right slot: revoking one handle
// must not disturb the other, and each handle must still be found afterwards.

#[test]
fn test_revoke_exported_cdi_handle_both_populated_revoke_ecdsa_first() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let ecdsa_handle = export_ecdsa_cdi(&mut model);
    let mldsa_handle = export_mldsa_cdi(&mut model);
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
    provision_pq_seed(&mut model);
    populate_pq_cert(&mut model);

    let ecdsa_handle = export_ecdsa_cdi(&mut model);
    let mldsa_handle = export_mldsa_cdi(&mut model);
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
