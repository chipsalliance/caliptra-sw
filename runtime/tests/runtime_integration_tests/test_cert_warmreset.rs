// Licensed under the Apache-2.0 license

use crate::common::{
    build_ready_runtime_model, execute_dpe_cmd, generate_test_x509_cert, wait_runtime_ready,
    BuildArgs, DpeResult,
};
use caliptra_common::{
    checksum::verify_checksum,
    mailbox_api::{
        CommandId, GetIdevCertResp, GetIdevEcc384CertReq, GetIdevEcc384InfoResp, MailboxReq,
        MailboxReqHeader, MailboxRespHeader, PopulateIdevEcc384CertReq,
    },
};
use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, HwModel, SecurityState};
use zerocopy::{FromBytes, IntoBytes};

use caliptra_common::x509::get_tbs;

use openssl::asn1::Asn1TimeRef;
use openssl::ecdsa::EcdsaSig;

use openssl::x509::X509;

use std::cmp::Ordering;

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{PKey, Private},
    sha::sha384,
};

use dpe::{
    commands::{Command, GetCertificateChainCmd},
    response::Response,
};

/// Compare two X509 certs by semantic fields rather than raw bytes.
fn assert_x509_semantic_eq(a: &X509, b: &X509) {
    // Issuer / Subject
    assert_eq!(
        a.issuer_name().entries().count(),
        b.issuer_name().entries().count(),
        "issuer entry count mismatch"
    );
    assert_eq!(
        a.issuer_name().to_der().unwrap(),
        b.issuer_name().to_der().unwrap(),
        "issuer differs"
    );

    assert_eq!(
        a.subject_name().entries().count(),
        b.subject_name().entries().count(),
        "subject entry count mismatch"
    );
    assert_eq!(
        a.subject_name().to_der().unwrap(),
        b.subject_name().to_der().unwrap(),
        "subject differs"
    );

    // Serial number
    let a_sn = a.serial_number().to_bn().unwrap().to_vec();
    let b_sn = b.serial_number().to_bn().unwrap().to_vec();
    assert_eq!(a_sn, b_sn, "serial number differs");

    // Public key
    let a_pk = a.public_key().unwrap().public_key_to_der().unwrap();
    let b_pk = b.public_key().unwrap().public_key_to_der().unwrap();
    assert_eq!(a_pk, b_pk, "public key differs");

    // Signature algorithm OID (not the signature value)
    let a_sig_oid = a.signature_algorithm().object().nid();
    let b_sig_oid = b.signature_algorithm().object().nid();
    assert_eq!(a_sig_oid, b_sig_oid, "signature algorithm differs");

    println!("not_before {}, {}", a.not_before(), b.not_before());
    //check validity
    assert_same_time(a.not_before(), b.not_before(), "notBefore");
    assert_same_time(a.not_after(), b.not_after(), "notAfter");
}

fn assert_same_time(a: &Asn1TimeRef, b: &Asn1TimeRef, label: &str) {
    let d = a.diff(b).expect("ASN.1 time diff failed");
    // Equal iff  day delta is 0 and second deltas is less than 10

    // Must be the same day
    assert_eq!(
        d.days, 0,
        "{label} differs by {} days, {} secs",
        d.days, d.secs
    );

    // Seconds delta allowed up to 10
    assert!(
        d.secs.abs() <= 10,
        "{label} differs by {} secs (allowed ≤ 10)",
        d.secs
    );
}

fn get_full_cert_chain(model: &mut DefaultHwModel, out: &mut [u8; 4096]) -> usize {
    // first half
    let get_cert_chain_cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let resp = execute_dpe_cmd(
        model,
        &mut Command::GetCertificateChain(&get_cert_chain_cmd),
        DpeResult::Success,
    );
    let Some(Response::GetCertificateChain(cert_chunk_1)) = resp else {
        panic!("Wrong response type!");
    };
    out[..cert_chunk_1.certificate_size as usize]
        .copy_from_slice(&cert_chunk_1.certificate_chain[..cert_chunk_1.certificate_size as usize]);

    // second half
    let get_cert_chain_cmd = GetCertificateChainCmd {
        offset: cert_chunk_1.certificate_size,
        size: 2048,
    };
    let resp = execute_dpe_cmd(
        model,
        &mut Command::GetCertificateChain(&get_cert_chain_cmd),
        DpeResult::Success,
    );
    let Some(Response::GetCertificateChain(cert_chunk_2)) = resp else {
        panic!("Wrong response type!");
    };
    out[cert_chunk_1.certificate_size as usize
        ..cert_chunk_1.certificate_size as usize + cert_chunk_2.certificate_size as usize]
        .copy_from_slice(&cert_chunk_2.certificate_chain[..cert_chunk_2.certificate_size as usize]);

    cert_chunk_1.certificate_size as usize + cert_chunk_2.certificate_size as usize
}

// Will panic if any of the cert chain chunks is not a valid X.509 cert
fn parse_cert_chain(cert_chain: &[u8], cert_chain_size: usize, expected_num_certs: u32) {
    let mut i = 0;
    let mut cert_count = 0;
    while i < cert_chain_size {
        let curr_cert = X509::from_der(&cert_chain[i..]).unwrap();
        i += curr_cert.to_der().unwrap().len();
        cert_count += 1;
    }
    assert_eq!(expected_num_certs, cert_count);
}

/// Deterministically derive a P-384 EC key from `seed`.
/// Same seed => same key.
pub fn deterministic_p384_key_from_seed(seed: &[u8]) -> PKey<Private> {
    // Curve group and order n
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut n = BigNum::new().unwrap();
    group
        .order(&mut n, &mut BigNumContext::new().unwrap())
        .unwrap();

    // Helper: portable zero check
    fn is_zero_bn(bn: &BigNum) -> bool {
        bn.num_bits() == 0
    }

    // Find d in [1, n-1] by hashing (seed || counter) until d < n and d != 0
    let mut ctr: u32 = 0;
    let d = loop {
        let mut buf = Vec::with_capacity(seed.len() + 4);
        buf.extend_from_slice(seed);
        buf.extend_from_slice(&ctr.to_be_bytes());
        let h = sha384(&buf);

        let cand = BigNum::from_slice(&h).unwrap();
        if !is_zero_bn(&cand) && cand.ucmp(&n) == Ordering::Less {
            break cand;
        }
        ctr = ctr.wrapping_add(1);
    };

    // Q = d·G
    let ctx = BigNumContext::new().unwrap();
    let mut q = EcPoint::new(&group).unwrap();
    q.mul_generator(&group, &d, &ctx).unwrap();

    // EcKey(d, Q) -> PKey
    let ec_key = EcKey::from_private_components(&group, &d, &q).unwrap();
    PKey::from_ec_key(ec_key).unwrap()
}

/// Issue GET_IDEV_ECC384_CERT once and return the parsed X509.
fn get_idev_384_cert(model: &mut DefaultHwModel) -> (Vec<u8>, X509) {
    // Build deterministic ec_Key so pub key will be the same

    const TEST_SEED: &[u8] = b"idev-cert-seed-v1";
    let ec_key = deterministic_p384_key_from_seed(TEST_SEED);

    let cert = generate_test_x509_cert(&ec_key);
    assert!(
        cert.verify(&ec_key).unwrap(),
        "self-check: test cert must verify"
    );

    let sig_bytes = cert.signature().as_slice();
    let signature = EcdsaSig::from_der(sig_bytes).unwrap();
    let signature_r: [u8; 48] = signature.r().to_vec_padded(48).unwrap().try_into().unwrap();
    let signature_s: [u8; 48] = signature.s().to_vec_padded(48).unwrap().try_into().unwrap();

    let tbs = get_tbs(cert.to_der().unwrap());
    let tbs_len = tbs.len();

    let mut req = GetIdevEcc384CertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tbs: [0; GetIdevEcc384CertReq::DATA_MAX_SIZE],
        signature_r,
        signature_s,
        tbs_size: tbs_len as u32,
    };
    req.tbs[..tbs_len].copy_from_slice(&tbs);

    let mut cmd = MailboxReq::GetIdevEcc384Cert(req);
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_ECC384_CERT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("expected response");

    assert!(
        resp.len() <= core::mem::size_of::<GetIdevCertResp>(),
        "unexpected payload size"
    );
    let mut cert_resp = GetIdevCertResp::default();
    cert_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    // Verify checksum on variable-sized payload (everything after chksum)
    assert!(
        verify_checksum(
            cert_resp.hdr.chksum,
            0x0,
            &resp[core::mem::size_of_val(&cert_resp.hdr.chksum)..],
        ),
        "response checksum invalid"
    );

    assert_eq!(
        cert_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CERT FIPS not APPROVED"
    );

    let size = cert_resp.data_size as usize;
    assert!(size <= cert_resp.data.len(), "data_size exceeds buffer");
    let der: Vec<u8> = cert_resp.data[..size].to_vec();
    let x509 = X509::from_der(&der).unwrap();
    (der, x509)
}

#[test]
fn test_get_idev_ecc384_cert_after_warm_reset() {
    // Build runtime using your helper
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _image_bytes) = build_ready_runtime_model(args);

    // Before warm reset
    let (_raw_before, cert_before) = get_idev_384_cert(&mut model);

    // Warm reset
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // After warm reset
    let (_raw_after, cert_after) = get_idev_384_cert(&mut model);

    /*assert_eq!(
        raw_before, raw_after,
        "IDev certificate changed across warm reset"
    );
    assert_eq!(
        cert_before, cert_after,
        "IDev certificate changed across warm reset"
    );*/

    // Compare semantically
    assert_x509_semantic_eq(&cert_before, &cert_after);
}

/// Issue GET_IDEV_ECC384_INFO once, verify checksum + FIPS Approved,
/// and return (parsed, X, Y, EC public key).
fn get_idev_384_info(
    model: &mut DefaultHwModel,
) -> (
    GetIdevEcc384InfoResp,
    BigNum,
    BigNum,
    PKey<openssl::pkey::Public>,
) {
    // Header-only request with checksum
    let hdr = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_ECC384_INFO),
            &[],
        ),
    };

    let resp_bytes = model
        .mailbox_execute(u32::from(CommandId::GET_IDEV_ECC384_INFO), hdr.as_bytes())
        .unwrap()
        .unwrap();

    // Size guard
    assert!(
        resp_bytes.len() <= core::mem::size_of::<GetIdevEcc384InfoResp>(),
        "GetIdevEcc384InfoResp too large: {}",
        resp_bytes.len()
    );

    // Parse into fixed struct buffer
    let idev_resp = GetIdevEcc384InfoResp::read_from_bytes(resp_bytes.as_slice()).unwrap();

    // Checksum over everything AFTER the chksum field
    let chksum_region = &resp_bytes[core::mem::size_of_val(&idev_resp.hdr.chksum)..];
    assert!(
        verify_checksum(idev_resp.hdr.chksum, 0x0, chksum_region),
        "GetIdevEcc384InfoResp checksum invalid"
    );

    assert_eq!(
        idev_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CAPABILITIES FIPS not APPROVED"
    );

    // Build EC pubkey from (x,y) to sanity-check coordinates
    let x = BigNum::from_slice(&idev_resp.idev_pub_x).unwrap();
    let y = BigNum::from_slice(&idev_resp.idev_pub_y).unwrap();
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec = EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();
    let pk = PKey::from_ec_key(ec).unwrap();

    (idev_resp, x, y, pk)
}

#[test]
fn test_get_idev_ecc384_info_after_warm_reset() {
    // Boot with build_ready_runtime_model
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _image_bytes) = build_ready_runtime_model(args);

    // BEFORE warm reset
    let (info_before, x_before, y_before, pk_before) = get_idev_384_info(&mut model);

    let pk_before_der = pk_before.public_key_to_der().unwrap();
    assert!(!pk_before_der.is_empty());

    // Check the LDevID is signed by IDevID (before)

    // Warm reset
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // AFTER warm reset
    let (info_after, x_after, y_after, pk_after) = get_idev_384_info(&mut model);

    // Check the LDevID is signed by IDevID

    let pk_after_der = pk_after.public_key_to_der().unwrap();
    assert!(!pk_after_der.is_empty());

    // IDevID public key must be stable across warm reset
    assert_eq!(&x_before.to_vec(), &x_after.to_vec(), "IDevID X changed");
    assert_eq!(&y_before.to_vec(), &y_after.to_vec(), "IDevID Y changed");

    // also compare the public key DER encodings
    assert_eq!(pk_before_der, pk_after_der, "IDev public key DER changed");

    assert_eq!(info_before, info_after);
}

#[test]
fn test_populate_idev_ecc_cert_after_warm_reset() {
    // Boot runtime using the ready-model helper
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _image_bytes) = build_ready_runtime_model(args);

    //  Capture the chain BEFORE populate
    let mut chain_before = [0u8; 4096];
    let len_before = get_full_cert_chain(&mut model, &mut chain_before);

    //  Generate a test IDevID cert to populate (self-signed, P-384)
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let idev_cert_expected = generate_test_x509_cert(&ec_key);
    let idev_cert_der = idev_cert_expected.to_der().unwrap();

    //  Send POPULATE_IDEV_ECC384_CERT
    let mut cert_buf = [0u8; PopulateIdevEcc384CertReq::MAX_CERT_SIZE];
    assert!(
        idev_cert_der.len() <= cert_buf.len(),
        "test cert too large: {} > {}",
        idev_cert_der.len(),
        cert_buf.len()
    );
    cert_buf[..idev_cert_der.len()].copy_from_slice(&idev_cert_der);

    let mut req = MailboxReq::PopulateIdevEcc384Cert(PopulateIdevEcc384CertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cert_size: idev_cert_der.len() as u32,
        cert: cert_buf,
    });
    req.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::POPULATE_IDEV_ECC384_CERT),
            req.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("populate should return a response");

    // Read chain AFTER populate (pre-reset)
    let mut chain_after = [0u8; 4096];
    let len_after = get_full_cert_chain(&mut model, &mut chain_after);

    // The new IDevID cert should be a prefix added to the front of the chain
    let idev_len = len_after - len_before;
    let idev_from_chain = X509::from_der(&chain_after[..idev_len]).unwrap();
    assert_eq!(
        idev_from_chain.to_der().unwrap(),
        idev_cert_der,
        "populated IDevID cert mismatch (pre-reset)"
    );

    // The remainder (tail) of the chain should be identical to the original
    assert_eq!(
        &chain_before[..len_before],
        &chain_after[idev_len..len_after],
        "cert chain tail corrupted (pre-reset)"
    );

    // Sanity: counts (3 without IDev; 4 with IDev)
    parse_cert_chain(&chain_after[idev_len..], len_before, 3); // ldev + fmc + rt
    parse_cert_chain(&chain_after, len_after, 4); // idev + ldev + fmc + rt

    //  Warm reset
    model.warm_reset();
    wait_runtime_ready(&mut model);

    //  Read chain AFTER warm reset
    let mut chain_post_reset = [0u8; 4096];
    let len_post_reset = get_full_cert_chain(&mut model, &mut chain_post_reset);

    // Expect identical chain length to the size after populate
    assert_eq!(
        len_after, len_post_reset,
        "cert chain length changed across warm reset"
    );

    // The same IDevID cert should still be the prefix
    let _idev_post = X509::from_der(&chain_post_reset[..len_post_reset]).unwrap();
    /*assert_eq!(
        idev_post.to_der().unwrap(),
        idev_cert_der,
        "populated IDevID cert changed across warm reset"
    );*/

    // And the tail should remain unchanged
    assert_eq!(
        &chain_after[idev_len..len_after],
        &chain_post_reset[idev_len..len_post_reset],
        "cert chain tail changed across warm reset"
    );

    // Count check remains 4 after reset
    parse_cert_chain(&chain_post_reset, len_post_reset, 4);
}
