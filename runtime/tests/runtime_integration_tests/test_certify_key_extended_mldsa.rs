// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{
    AddSubjectAltNameReq, CertifyKeyExtendedFlags, CertifyKeyExtendedMldsa87Req,
    CertifyKeyExtendedMldsa87Resp, CommandId, MailboxReq, MailboxReqHeader, SetPqSeedReq,
    SET_PQ_SEED_SEED_SIZE,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::{AddSubjectAltNameCmd, RtBootStatus};
use cms::{
    cert::x509::der::{Decode, Encode},
    content_info::{CmsVersion, ContentInfo},
    signed_data::SignedData,
};
use dpe::{
    commands::{CertifyKeyCommand, CertifyKeyFlags, CertifyKeyMldsa87Cmd, Command},
    context::ContextHandle,
    response::{CertifyKeyResp, Response},
};
use x509_parser::{certificate::X509Certificate, extensions::GeneralName, prelude::FromDer};
use zerocopy::{FromZeros, IntoBytes};

use crate::common::{
    assert_error, run_pqc_rt_test, run_pqc_rt_test_wdt, run_rt_test, RuntimeTestArgs, TEST_LABEL,
};

/// Provision the PQ.DevID seed (as PL0) so PQC mode is enabled.
fn provision_pq_seed(model: &mut DefaultHwModel) {
    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .unwrap();
}

/// Without SET_PQ_SEED there is no PQ.DevID identity, so the command must reject.
#[test]
fn test_certify_key_extended_mldsa87_not_initialized() {
    let mut model = run_pqc_rt_test();

    let mut cmd = MailboxReq::CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        flags: CertifyKeyExtendedFlags::empty(),
        certify_key_req: [0u8; CertifyKeyExtendedMldsa87Req::CERTIFY_KEY_REQ_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED_MLDSA87),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_PQC_NOT_INITIALIZED, resp);
}

#[test]
fn test_certify_key_extended_mldsa87() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let certify_key_cmd = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
        label: TEST_LABEL,
    };
    let mut cmd = MailboxReq::CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        flags: CertifyKeyExtendedFlags::empty(),
        certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED_MLDSA87),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("expected a response");

    // The full response is large (~25 KB); box it to keep it off the stack.
    let mut certify_key_extended_resp = Box::new(CertifyKeyExtendedMldsa87Resp::new_zeroed());
    certify_key_extended_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    let dpe_resp = Response::try_read_from_bytes(
        &Command::from(&CertifyKeyCommand::Mldsa87(&certify_key_cmd)),
        &certify_key_extended_resp.certify_key_resp,
    )
    .unwrap();
    let Response::CertifyKey(CertifyKeyResp::Mldsa87(certify_key_resp)) = dpe_resp else {
        panic!("Wrong response type!");
    };

    let cert_bytes = &certify_key_resp.cert[..certify_key_resp.header.cert_size as usize];
    // An ML-DSA-87 leaf cert (2,592-byte key + 4,627-byte signature) is large;
    // a value this size confirms it is the ML-DSA identity, not ECDSA.
    assert!(
        cert_bytes.len() > 7000,
        "unexpectedly small ML-DSA-87 cert: {} bytes",
        cert_bytes.len()
    );
    // Must be a well-formed DER certificate.
    X509Certificate::from_der(cert_bytes).unwrap();
}

#[test]
fn test_certify_key_extended_mldsa87_within_wdt() {
    let mut model = run_pqc_rt_test_wdt();
    provision_pq_seed(&mut model);

    let certify_key_cmd = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
        label: TEST_LABEL,
    };
    let mut cmd = MailboxReq::CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        flags: CertifyKeyExtendedFlags::empty(),
        certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
    });
    cmd.populate_chksum().unwrap();

    // Must complete (within the WDT budget) and return a response.
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED_MLDSA87),
            cmd.as_bytes().unwrap(),
        )
        .expect("CERTIFY_KEY_EXTENDED_MLDSA87 tripped the watchdog (over budget)")
        .expect("expected a response");

    // No fatal error should have been recorded.
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);

    let mut certify_key_extended_resp = Box::new(CertifyKeyExtendedMldsa87Resp::new_zeroed());
    certify_key_extended_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    let dpe_resp = Response::try_read_from_bytes(
        &Command::from(&CertifyKeyCommand::Mldsa87(&certify_key_cmd)),
        &certify_key_extended_resp.certify_key_resp,
    )
    .unwrap();
    let Response::CertifyKey(CertifyKeyResp::Mldsa87(certify_key_resp)) = dpe_resp else {
        panic!("Wrong response type!");
    };

    let cert_bytes = &certify_key_resp.cert[..certify_key_resp.header.cert_size as usize];
    X509Certificate::from_der(cert_bytes).unwrap();
}

// Helper: execute CERTIFY_KEY_EXTENDED_MLDSA87 and return the boxed outer
// response.  Boxes the response to keep the large ML-DSA cert off the stack.
fn run_certify_key_mldsa87(
    model: &mut DefaultHwModel,
    certify_key_cmd: &CertifyKeyMldsa87Cmd,
    flags: CertifyKeyExtendedFlags,
) -> Box<CertifyKeyExtendedMldsa87Resp> {
    let mut cmd = MailboxReq::CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        flags,
        certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED_MLDSA87),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("expected a response");
    let mut out = Box::new(CertifyKeyExtendedMldsa87Resp::new_zeroed());
    out.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    out
}

// Helper: parse the DPE certify-key bytes out of the boxed outer response.
fn parse_mldsa87_dpe_resp<'a>(
    certify_key_cmd: &'a CertifyKeyMldsa87Cmd,
    outer: &'a CertifyKeyExtendedMldsa87Resp,
) -> dpe::response::CertifyKeyMldsa87Resp {
    let dpe_resp = Response::try_read_from_bytes(
        &Command::from(&CertifyKeyCommand::Mldsa87(certify_key_cmd)),
        &outer.certify_key_resp,
    )
    .unwrap();
    let Response::CertifyKey(CertifyKeyResp::Mldsa87(inner)) = dpe_resp else {
        panic!("wrong response type");
    };
    inner
}

#[test]
fn test_certify_key_extended_mldsa87_dmtf_other_name_present() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

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
    model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("ADD_SUBJECT_ALT_NAME should succeed");

    let certify_key_cmd = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
        label: TEST_LABEL,
    };
    let outer = run_certify_key_mldsa87(
        &mut model,
        &certify_key_cmd,
        CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
    );
    let inner = parse_mldsa87_dpe_resp(&certify_key_cmd, &outer);

    let cert_bytes = &inner.cert[..inner.header.cert_size as usize];
    let (_, cert) = X509Certificate::from_der(cert_bytes).unwrap();

    let ext = cert.subject_alternative_name().unwrap().unwrap();
    assert!(!ext.critical);
    let san = ext.value;
    assert_eq!(san.general_names.len(), 1);
    let GeneralName::OtherName(oid, other_name_value) = san.general_names.first().unwrap() else {
        panic!("wrong SubjectAlternativeName type");
    };
    assert_eq!(oid.as_bytes(), AddSubjectAltNameCmd::DMTF_OID);
    // Skip the 4-byte DER encoding prefix (same convention as ECDSA variant test).
    assert_eq!(&other_name_value[4..], dmtf_device_info_bytes);
}

#[test]
fn test_certify_key_extended_mldsa87_dmtf_other_name_not_present() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let certify_key_cmd = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
        label: TEST_LABEL,
    };

    // Case 1: flag set but ADD_SUBJECT_ALT_NAME not yet called → no SAN extension.
    let outer = run_certify_key_mldsa87(
        &mut model,
        &certify_key_cmd,
        CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
    );
    let inner = parse_mldsa87_dpe_resp(&certify_key_cmd, &outer);
    let cert_bytes = &inner.cert[..inner.header.cert_size as usize];
    let (_, cert) = X509Certificate::from_der(cert_bytes).unwrap();
    assert!(cert.subject_alternative_name().unwrap().is_none());

    // Populate DMTF device info.
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
    model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("ADD_SUBJECT_ALT_NAME should succeed");

    // Case 2: ADD_SUBJECT_ALT_NAME called but flag not set → no SAN extension.
    let outer = run_certify_key_mldsa87(
        &mut model,
        &certify_key_cmd,
        CertifyKeyExtendedFlags::empty(),
    );
    let inner = parse_mldsa87_dpe_resp(&certify_key_cmd, &outer);
    let cert_bytes = &inner.cert[..inner.header.cert_size as usize];
    let (_, cert) = X509Certificate::from_der(cert_bytes).unwrap();
    assert!(cert.subject_alternative_name().unwrap().is_none());
}

#[test]
fn test_certify_key_extended_mldsa87_cannot_be_called_from_pl1() {
    use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;

    // Designate pauser 0x2 as PL0 so we can provision the PQ seed (which is
    // also PL0-only) before switching to pauser 0x1 (PL1) for the actual test.
    // The PL1 check is inside certify_key_extended.rs::certify_key(), which is
    // only reached after the PQC-initialized guard passes.
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = Some(0x2);

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        test_image_options: Some(image_opts),
        ..Default::default()
    });
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Provision PQ seed from PL0 (pauser 0x2).
    model.set_apb_pauser(0x2);
    provision_pq_seed(&mut model);

    // Switch to PL1 (pauser 0x1); the PQC guard now passes and the PL1 gate fires.
    model.set_apb_pauser(0x1);
    let mut cmd = MailboxReq::CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        flags: CertifyKeyExtendedFlags::empty(),
        certify_key_req: [0u8; CertifyKeyExtendedMldsa87Req::CERTIFY_KEY_REQ_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED_MLDSA87),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        resp,
    );
}

#[test]
fn test_certify_key_extended_mldsa87_csr_format() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let certify_key_cmd = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_CSR,
        label: TEST_LABEL,
    };
    let outer = run_certify_key_mldsa87(
        &mut model,
        &certify_key_cmd,
        CertifyKeyExtendedFlags::empty(),
    );
    let inner = parse_mldsa87_dpe_resp(&certify_key_cmd, &outer);

    let csr_bytes = &inner.cert[..inner.header.cert_size as usize];
    assert!(!csr_bytes.is_empty(), "CSR output must be non-empty");

    // DPE FORMAT_CSR output is a CMS SignedData (ContentInfo wrapper), not a
    // PKCS#10 CSR.  Verify the envelope parses and has the expected structure.
    let content_info =
        ContentInfo::from_der(csr_bytes).expect("CSR output must be a DER ContentInfo");
    let signed_data = SignedData::from_der(&content_info.content.to_der().unwrap())
        .expect("ContentInfo must contain SignedData");
    assert_eq!(signed_data.version, CmsVersion::V3);
}

#[test]
fn test_certify_key_extended_mldsa87_different_labels_produce_different_keys() {
    const OTHER_LABEL: [u8; 48] = [0xab; 48];

    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let cmd_a = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
        label: TEST_LABEL,
    };
    let outer_a = run_certify_key_mldsa87(&mut model, &cmd_a, CertifyKeyExtendedFlags::empty());
    let inner_a = parse_mldsa87_dpe_resp(&cmd_a, &outer_a);
    let pubkey_a = inner_a.header.pubkey;

    let cmd_b = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
        label: OTHER_LABEL,
    };
    let outer_b = run_certify_key_mldsa87(&mut model, &cmd_b, CertifyKeyExtendedFlags::empty());
    let inner_b = parse_mldsa87_dpe_resp(&cmd_b, &outer_b);
    let pubkey_b = inner_b.header.pubkey;

    assert_ne!(
        pubkey_a, pubkey_b,
        "different labels must produce different derived ML-DSA-87 public keys"
    );
}
