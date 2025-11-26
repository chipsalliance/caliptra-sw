// Licensed under the Apache-2.0 license

use caliptra_api::{mailbox::RevokeExportedCdiHandleReq, SocManager};
use caliptra_common::mailbox_api::{CommandId, MailboxReq, MailboxReqHeader};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags},
    response::Response,
};

use crate::common::{assert_error, execute_dpe_cmd, run_rt_test, DpeResult, RuntimeTestArgs};

#[test]
fn test_revoke_exported_cdi_handle() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(original_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.exported_cdi,
    });
    cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("Expected REVOKE_EXPORTED_CDI_HANDLE to pass");
}

#[test]
fn test_revoke_already_revoked_exported_cdi_handle() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(original_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.exported_cdi,
    });
    cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("Expected REVOKE_EXPORTED_CDI_HANDLE to pass");

    let result = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    );

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
        result.err().unwrap(),
    );
}

#[test]
fn test_revoke_non_existant_exported_cdi_handle() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0xFF; RevokeExportedCdiHandleReq::EXPORTED_CDI_MAX_SIZE],
    });

    cmd.populate_chksum().unwrap();
    let result = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    );

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
        result.err().unwrap(),
    );

    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq::default());

    cmd.populate_chksum().unwrap();
    let result = model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    );

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
        result.err().unwrap(),
    );
}

#[test]
fn test_export_cdi_after_revoke() {
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

    let Some(Response::DeriveContextExportedCdi(resp)) = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: resp.exported_cdi,
    });
    cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
            cmd.as_bytes().unwrap(),
        )
        .expect("Expected REVOKE_EXPORTED_CDI_HANDLE to pass");

    let Some(Response::DeriveContextExportedCdi(_)) = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };
}
