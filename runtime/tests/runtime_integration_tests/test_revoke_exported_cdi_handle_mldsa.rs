// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, RevokeExportedCdiHandleReq,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;

use crate::common::{assert_error, run_pqc_rt_test, run_rt_test, RuntimeTestArgs};

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
