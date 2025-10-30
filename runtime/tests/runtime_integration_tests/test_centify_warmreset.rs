use crate::common::{build_model_ready, wait_runtime_ready, TEST_LABEL};

use caliptra_common::{
    checksum::verify_checksum,
    mailbox_api::{
        AddSubjectAltNameReq, CertifyKeyExtendedFlags, CertifyKeyExtendedReq,
        CertifyKeyExtendedResp, CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader,
    },
};
use zerocopy::{FromBytes, IntoBytes};

use caliptra_hw_model::{DefaultHwModel, HwModel};

use dpe::{
    commands::{CertifyKeyCmd, CertifyKeyFlags},
    context::ContextHandle,
    response::CertifyKeyResp,
};

use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, oid_registry::asn1_rs::FromDer,
    oid_registry::OID_X509_COMMON_NAME, x509::AlgorithmIdentifier,
};

use caliptra_runtime::AddSubjectAltNameCmd;

/// Send CERTIFY_KEY_EXTENDED (X.509 + DMTF_OTHER_NAME), verify checksum & FIPS
pub fn certify_and_get_san_and_raw(model: &mut DefaultHwModel) -> (Vec<u8>, Option<Vec<u8>>) {
    // Build request
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

    // Execute
    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("CERTIFY_KEY_EXTENDED should respond");

    // --- Parse the typed response (includes the response header) ---
    let ckx = CertifyKeyExtendedResp::read_from_bytes(resp_bytes.as_slice()).unwrap();

    assert!(
        verify_checksum(
            ckx.hdr.chksum,
            0x0,
            &ckx.as_bytes()[core::mem::size_of_val(&ckx.hdr.chksum)..],
        ),
        "CAPABILITIES response checksum invalid"
    );
    assert_eq!(
        ckx.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CAPABILITIES FIPS not APPROVED"
    );

    // --- Extract cert -> SAN -> DMTF OtherName payload bytes (skip 4 DER bytes) ---
    let ck = CertifyKeyResp::read_from_bytes(&ckx.certify_key_resp[..]).unwrap();
    let (_, cert) = X509Certificate::from_der(&ck.cert[..ck.cert_size as usize]).unwrap();

    let dmtf_payload_opt = cert
        .subject_alternative_name() // Result<Option<SAN>>
        .ok() // Option<Option<SAN>>
        .flatten() // Option<SAN>
        .and_then(|san| {
            san.value.general_names.iter().find_map(|gn| {
                if let GeneralName::OtherName(oid, other_name_value) = gn {
                    if oid.as_bytes() == AddSubjectAltNameCmd::DMTF_OID {
                        // skip first 4 DER bytes
                        return Some(other_name_value[4..].to_vec());
                    }
                }
                None
            })
        });

    (resp_bytes.to_vec(), dmtf_payload_opt)
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_add_subject_alt_name_persists_across_warm_reset() {
    // Boot to RT ready
    let mut model = build_model_ready();
    wait_runtime_ready(&mut model);

    // Program DMTF device info via ADD_SUBJECT_ALT_NAME
    let dmtf_str_before = "ChipsAlliance:Caliptra:0123456789";
    let dmtf_bytes_before = dmtf_str_before.as_bytes();
    let mut dmtf_buf = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
    dmtf_buf[..dmtf_bytes_before.len()].copy_from_slice(dmtf_bytes_before);

    let mut add_cmd = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
        hdr: MailboxReqHeader { chksum: 0 },
        dmtf_device_info_size: dmtf_bytes_before.len() as u32,
        dmtf_device_info: dmtf_buf,
    });
    add_cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            add_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("ADD_SUBJECT_ALT_NAME should respond");

    // BEFORE warm reset: capture raw and SAN payload
    let (raw_before, san_payload_before) = certify_and_get_san_and_raw(&mut model);

    assert_eq!(
        san_payload_before.as_deref(),
        Some(dmtf_bytes_before),
        "SAN payload mismatch before warm reset"
    );

    // Warm reset & wait ready
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // AFTER warm reset: capture raw and SAN payload (no reprogramming)
    let (raw_after, san_payload_after) = certify_and_get_san_and_raw(&mut model);

    // Compare both SAN payload and raw response bytes
    assert_eq!(
        san_payload_after, san_payload_before,
        "SAN payload changed across warm reset"
    );
    assert_eq!(
        raw_after, raw_before,
        "Raw response bytes changed across warm reset"
    );
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_add_subject_alt_name_after_warm_reset() {
    // Boot to RT ready
    let mut model = build_model_ready();
    wait_runtime_ready(&mut model);

    // Program initial value
    let first_str = "ChipsAlliance:Caliptra:FirstValue";
    let first_bytes = first_str.as_bytes();
    let mut dmtf_buf1 = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
    dmtf_buf1[..first_bytes.len()].copy_from_slice(first_bytes);

    let mut add_cmd1 = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
        hdr: MailboxReqHeader { chksum: 0 },
        dmtf_device_info_size: first_bytes.len() as u32,
        dmtf_device_info: dmtf_buf1,
    });
    add_cmd1.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            add_cmd1.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("ADD_SUBJECT_ALT_NAME (first) should respond");

    // BEFORE warm reset: snapshot raw + SAN
    let (raw_before, san_payload_before) = certify_and_get_san_and_raw(&mut model);

    assert_eq!(
        san_payload_before.as_deref(), // Option<&[u8]>
        Some(first_bytes),             // Option<&[u8]>
        "Initial SAN payload mismatch"
    );

    // Warm reset & wait ready
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // Reprogram with a new value
    let second_str = "ChipsAlliance:Caliptra:SecondValue";
    let second_bytes = second_str.as_bytes();
    let mut dmtf_buf2 = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
    dmtf_buf2[..second_bytes.len()].copy_from_slice(second_bytes);

    let mut add_cmd2 = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
        hdr: MailboxReqHeader { chksum: 0 },
        dmtf_device_info_size: second_bytes.len() as u32,
        dmtf_device_info: dmtf_buf2,
    });
    add_cmd2.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            add_cmd2.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("ADD_SUBJECT_ALT_NAME (second) should respond");

    // AFTER warm reset reprogram: snapshot raw + SAN
    let (raw_after, san_payload_after) = certify_and_get_san_and_raw(&mut model);

    // Both should change and the SAN should match the new value
    assert_ne!(
        san_payload_after, san_payload_before,
        "SAN payload did not change after reprogramming"
    );

    assert_eq!(
        san_payload_after.as_deref(), // Option<&[u8]>
        Some(second_bytes),           // Option<&[u8]>
        "SAN payload mismatch after reprogramming"
    );
    assert_ne!(
        raw_after, raw_before,
        "Raw response bytes did not change after reprogramming"
    );
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_certify_key_extended_after_warm_reset() {
    // Boot to RT ready
    let mut model = build_model_ready();
    wait_runtime_ready(&mut model);

    // BEFORE warm reset
    let (raw_before, _san_before) = certify_and_get_san_and_raw(&mut model);

    // Warm reset & wait ready
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // AFTER warm reset
    let (raw_after, _san_after) = certify_and_get_san_and_raw(&mut model);

    // Compare raw response bytes only
    assert_eq!(
        raw_after, raw_before,
        "Raw CERTIFY_KEY_EXTENDED response changed across warm reset"
    );
}

fn extract_stable_cert_fields(resp_raw: &[u8]) -> (String, String, Vec<u8>, usize) {
    let ckx = CertifyKeyExtendedResp::read_from_bytes(resp_raw).unwrap();
    let ck = CertifyKeyResp::read_from_bytes(&ckx.certify_key_resp[..]).unwrap();
    let cert_der = &ck.cert[..ck.cert_size as usize];
    let (_, cert) = X509Certificate::from_der(cert_der).unwrap();

    // Issuer CN (ignore issuer serialNumber)
    let issuer_cn = cert
        .tbs_certificate
        .issuer
        .iter_attributes()
        .find(|a| *(a.attr_type()) == OID_X509_COMMON_NAME)
        .and_then(|a| a.as_str().ok())
        .unwrap_or_default()
        .to_string();

    // Subject CN (ignore subject serialNumber)
    let subject_cn = cert
        .tbs_certificate
        .subject
        .iter_attributes()
        .find(|a| *(a.attr_type()) == OID_X509_COMMON_NAME)
        .and_then(|a| a.as_str().ok())
        .unwrap_or_default()
        .to_string();

    // SPKI algorithm must be EC; extract curve OID from parameters
    let alg: &AlgorithmIdentifier = &cert.tbs_certificate.subject_pki.algorithm;

    let curve_oid = alg
        .parameters
        .as_ref()
        .and_then(|any| any.as_oid().ok())
        .expect("Missing EC curve parameters OID")
        .as_bytes()
        .to_vec();

    // Only the SPKI bitstring length is compared (key bytes change per boot)
    let spki_len = cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .len();

    (issuer_cn, subject_cn, curve_oid, spki_len)
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_certify_key_extended_after_warm_reset_stable_fields() {
    let mut model = build_model_ready();
    wait_runtime_ready(&mut model);

    let (raw_before, san_before_opt) = certify_and_get_san_and_raw(&mut model);
    let (issuer_b, subject_b, curve_b, spki_len_b) = extract_stable_cert_fields(&raw_before);

    model.warm_reset();
    wait_runtime_ready(&mut model);

    let (raw_after, san_after_opt) = certify_and_get_san_and_raw(&mut model);
    let (issuer_a, subject_a, curve_a, spki_len_a) = extract_stable_cert_fields(&raw_after);

    assert_eq!(issuer_a, issuer_b, "Issuer changed across warm reset");
    assert_eq!(subject_a, subject_b, "Subject changed across warm reset");
    assert_eq!(curve_a, curve_b, "Curve OID changed across warm reset");
    assert_eq!(spki_len_a, spki_len_b, "SPKI bitstring length changed");

    assert_eq!(
        san_after_opt.as_deref(),
        san_before_opt.as_deref(),
        "SAN presence/value changed across warm reset without ADD_SUBJECT_ALT_NAME"
    );
}
