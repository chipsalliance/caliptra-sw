// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{
    AddSubjectAltNameReq, CertifyKeyExtendedFlags, CertifyKeyExtendedReq, CertifyKeyExtendedResp,
    CommandId, MailboxReq, MailboxReqHeader,
};
use caliptra_hw_model::HwModel;
use caliptra_runtime::{AddSubjectAltNameCmd, RtBootStatus};
use dpe::{
    commands::{CertifyKeyCmd, CertifyKeyFlags},
    context::ContextHandle,
    response::CertifyKeyResp,
};
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, oid_registry::asn1_rs::FromDer,
};
use zerocopy::{AsBytes, FromBytes};

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs, TEST_LABEL};

#[test]
fn test_dmtf_other_name_validation_fail() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let dmtf_device_info_utf8 = "abc:def:ghi:";
    let dmtf_device_info_bytes = dmtf_device_info_utf8.as_bytes();
    let mut dmtf_device_info = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
    dmtf_device_info[..dmtf_device_info_bytes.len()].copy_from_slice(dmtf_device_info_bytes);
    let mut cmd = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
        hdr: MailboxReqHeader { chksum: 0 },
        dmtf_device_info_size: dmtf_device_info_bytes.len() as u32,
        dmtf_device_info,
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_DMTF_DEVICE_INFO_VALIDATION_FAILED,
        resp,
    );
}

#[test]
fn test_dmtf_other_name_extension_present() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let dmtf_device_info_utf8 = "ChipsAlliance:Caliptra:0123456789";
    let dmtf_device_info_bytes = dmtf_device_info_utf8.as_bytes();
    let mut dmtf_device_info = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
    dmtf_device_info[..dmtf_device_info_bytes.len()].copy_from_slice(dmtf_device_info_bytes);
    let mut cmd = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
        hdr: MailboxReqHeader { chksum: 0 },
        dmtf_device_info_size: dmtf_device_info_bytes.len() as u32,
        dmtf_device_info,
    });
    cmd.populate_chksum().unwrap();

    let _ = model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let mut cmd = MailboxReq::CertifyKeyExtended(CertifyKeyExtendedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
        flags: CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
    let certify_key_extended_resp = CertifyKeyExtendedResp::read_from(resp.as_slice()).unwrap();
    let certify_key_resp =
        CertifyKeyResp::read_from(&certify_key_extended_resp.certify_key_resp[..]).unwrap();

    let (_, cert) =
        X509Certificate::from_der(&certify_key_resp.cert[..certify_key_resp.cert_size as usize])
            .unwrap();
    let ext = cert.subject_alternative_name().unwrap().unwrap();
    assert!(!ext.critical);
    let san = ext.value;
    assert_eq!(san.general_names.len(), 1);
    let general_name = san.general_names.get(0).unwrap();
    match general_name {
        GeneralName::OtherName(oid, other_name_value) => {
            assert_eq!(oid.as_bytes(), AddSubjectAltNameCmd::DMTF_OID);
            // skip first 4 der encoding bytes
            assert_eq!(&other_name_value[4..], dmtf_device_info_bytes);
        }
        _ => panic!("Wrong SubjectAlternativeName"),
    };
}

#[test]
fn test_dmtf_other_name_extension_not_present() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };

    // Check that otherName extension is not present if not provided by ADD_SUBJECT_ALT_NAME
    let mut cmd = MailboxReq::CertifyKeyExtended(CertifyKeyExtendedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
        flags: CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
    let certify_key_extended_resp = CertifyKeyExtendedResp::read_from(resp.as_slice()).unwrap();
    let certify_key_resp =
        CertifyKeyResp::read_from(&certify_key_extended_resp.certify_key_resp[..]).unwrap();
    let (_, cert) =
        X509Certificate::from_der(&certify_key_resp.cert[..certify_key_resp.cert_size as usize])
            .unwrap();
    assert!(cert.subject_alternative_name().unwrap().is_none());

    // populate DMTF otherName
    let dmtf_device_info_utf8 = "ChipsAlliance:Caliptra:0123456789";
    let dmtf_device_info_bytes = dmtf_device_info_utf8.as_bytes();
    let mut dmtf_device_info = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
    dmtf_device_info[..dmtf_device_info_bytes.len()].copy_from_slice(dmtf_device_info_bytes);
    let mut cmd = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
        hdr: MailboxReqHeader { chksum: 0 },
        dmtf_device_info_size: dmtf_device_info_bytes.len() as u32,
        dmtf_device_info,
    });
    cmd.populate_chksum().unwrap();

    let _ = model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    // Check that otherName extension is not present if not requested in input flags
    let mut cmd = MailboxReq::CertifyKeyExtended(CertifyKeyExtendedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
        flags: CertifyKeyExtendedFlags::empty(),
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
    let certify_key_extended_resp = CertifyKeyExtendedResp::read_from(resp.as_slice()).unwrap();
    let certify_key_resp =
        CertifyKeyResp::read_from(&certify_key_extended_resp.certify_key_resp[..]).unwrap();
    let (_, cert) =
        X509Certificate::from_der(&certify_key_resp.cert[..certify_key_resp.cert_size as usize])
            .unwrap();
    assert!(cert.subject_alternative_name().unwrap().is_none());
}
