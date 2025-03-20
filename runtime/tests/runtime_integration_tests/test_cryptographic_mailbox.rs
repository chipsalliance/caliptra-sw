// Licensed under the Apache-2.0 license

use crate::common::{RuntimeTestArgs, assert_error, run_rt_test};
use caliptra_api::SocManager;
use caliptra_api::mailbox::{
    CMK_SIZE_BYTES, CmImportReq, CmImportResp, CmKeyUsage, CmStatusResp, MailboxReq,
};
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_status() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CM_STATUS), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::CM_STATUS), payload.as_bytes())
        .unwrap()
        .expect("We should have received a response");

    let cm_resp = CmStatusResp::ref_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(cm_resp.used_usage_storage, 0);
    assert_eq!(cm_resp.total_usage_storage, 256);
}

#[test]
fn test_import() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // check too large of an input
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::AES.into(),
        input_size: 1000,
        input: [0xaa; 64],
    });
    assert_eq!(
        cm_import_cmd.populate_chksum().unwrap_err(),
        caliptra_drivers::CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE
    );

    // wrong size
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::AES.into(),
        input_size: 64,
        input: [0xaa; 64],
    });
    cm_import_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CM_IMPORT),
            cm_import_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE,
        resp,
    );

    // AES key import
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::AES.into(),
        input_size: 32,
        input: [0xaa; 64],
    });
    cm_import_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CM_IMPORT),
            cm_import_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let cm_import_resp = CmImportResp::ref_from_bytes(resp.as_slice()).unwrap();
    let cmk = cm_import_resp.cmk.as_bytes();
    assert_eq!(CMK_SIZE_BYTES, cmk.len());
    assert!(!cmk.iter().all(|&x| x == 0));

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CM_STATUS), &[]),
    };
    let status_resp = model
        .mailbox_execute(u32::from(CommandId::CM_STATUS), payload.as_bytes())
        .unwrap()
        .expect("We should have received a response");

    let cm_resp = CmStatusResp::ref_from_bytes(status_resp.as_slice()).unwrap();
    assert_eq!(cm_resp.used_usage_storage, 1);
    assert_eq!(cm_resp.total_usage_storage, 256);
}

#[test]
fn test_import_full() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // AES key import
    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::AES.into(),
        input_size: 32,
        input: [0xaa; 64],
    });
    cm_import_cmd.populate_chksum().unwrap();

    for _ in 0..256 {
        model
            .mailbox_execute(
                u32::from(CommandId::CM_IMPORT),
                cm_import_cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("We should have received a response");
    }
    let err = model
        .mailbox_execute(
            u32::from(CommandId::CM_IMPORT),
            cm_import_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_CMB_KEY_USAGE_STORAGE_FULL,
        err,
    );

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CM_STATUS), &[]),
    };
    let status_resp = model
        .mailbox_execute(u32::from(CommandId::CM_STATUS), payload.as_bytes())
        .unwrap()
        .expect("We should have received a response");

    let cm_resp = CmStatusResp::ref_from_bytes(status_resp.as_slice()).unwrap();
    assert_eq!(cm_resp.used_usage_storage, 256);
    assert_eq!(cm_resp.total_usage_storage, 256);
}

#[ignore] // this test is very slow so we only test it manually
#[test]
fn test_import_wraparound() {
    // TODO: implement this when we have the clear and delete commands
}
