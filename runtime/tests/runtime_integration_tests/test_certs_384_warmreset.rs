// Licensed under the Apache-2.0 license

use crate::common::{
    assert_x509_semantic_eq, execute_dpe_cmd, generate_test_x509_cert, get_ecc_fmc_alias_cert,
    get_rt_alias_ecc384_cert, run_rt_test_pqc, DpeResult, RuntimeTestArgs,
};
use caliptra_common::{
    checksum::verify_checksum,
    mailbox_api::{
        CommandId, GetIdevCertResp, GetIdevEcc384CertReq, GetIdevEcc384InfoResp, GetLdevCertResp,
        MailboxReq, MailboxReqHeader, MailboxRespHeader, PopulateIdevEcc384CertReq,
    },
    x509::get_tbs,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use dpe::{
    commands::{Command, GetCertificateChainCmd},
    response::Response,
};

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private},
    x509::X509,
};

use zerocopy::{FromBytes, IntoBytes};

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
pub fn deterministic_p384_key_from_seed() -> PKey<Private> {
    // Curve group and order n
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut n = BigNum::new().unwrap();
    group
        .order(&mut n, &mut BigNumContext::new().unwrap())
        .unwrap();

    let d = BigNum::from_hex_str(
        "3A1F4C9B2D7E11A0C4B85566778899AABBCCDDEEFF00112233445566778899AABBCCDDEE",
    )
    .unwrap();
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

    let ec_key = deterministic_p384_key_from_seed();

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
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_get_idev_ecc384_cert_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    // Before warm reset
    let (_raw_before, cert_before) = get_idev_384_cert(&mut model);

    // Warm reset
    model.warm_reset();

    // After warm reset
    let (_raw_after, cert_after) = get_idev_384_cert(&mut model);

    /*assert_eq!(
        _raw_before, _raw_after,
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
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_get_idev_ecc384_info_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    // BEFORE warm reset
    let (info_before, x_before, y_before, pk_before) = get_idev_384_info(&mut model);

    let pk_before_der = pk_before.public_key_to_der().unwrap();
    assert!(!pk_before_der.is_empty());

    // Check the LDevID is signed by IDevID (before)

    // Warm reset
    model.warm_reset();

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
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_populate_idev_ecc_cert_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

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

    //  Read chain AFTER warm reset
    let mut chain_post_reset = [0u8; 4096];
    let len_post_reset = get_full_cert_chain(&mut model, &mut chain_post_reset);

    // Expect identical chain length to the size after populate
    assert_eq!(
        len_after,
        len_post_reset + idev_len,
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
        &chain_post_reset[0..len_post_reset],
        "cert chain tail changed across warm reset"
    );

    // Count check remains 4 after reset
    parse_cert_chain(&chain_post_reset, len_post_reset, 3);
}

fn get_ldev_ecc384_cert(model: &mut DefaultHwModel) -> (Vec<u8>, X509) {
    let hdr = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_LDEV_ECC384_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_LDEV_ECC384_CERT), hdr.as_bytes())
        .unwrap()
        .unwrap();

    assert!(resp.len() <= std::mem::size_of::<GetLdevCertResp>());
    let mut ldev_resp = GetLdevCertResp::default();
    ldev_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    // checksum (over everything after the chksum field)
    assert!(verify_checksum(
        ldev_resp.hdr.chksum,
        0x0,
        &resp[core::mem::size_of_val(&ldev_resp.hdr.chksum)..],
    ));

    // FIPS Approved (bitmask)
    assert_eq!(
        ldev_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CERT FIPS not APPROVED"
    );

    let size = ldev_resp.data_size as usize;
    assert!(size <= ldev_resp.data.len());
    let der = ldev_resp.data[..size].to_vec();
    let x509 = X509::from_der(&der).unwrap();
    (der, x509)
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_get_ldev_ecc384_cert_after_warm_reset() {
    let mut model = run_rt_test_pqc(Default::default(), Default::default());

    // BEFORE warm reset: fetch LDev cert and IDev pubkey
    let (ldev_der_before, ldev_cert_before) = get_ldev_ecc384_cert(&mut model);
    let (_, _x_before, _y_before, idev_pk_before) = get_idev_384_info(&mut model);

    //  verify under IDev pubkey (before)
    assert!(ldev_cert_before.verify(&idev_pk_before).unwrap());

    // Warm reset and wait ready
    model.warm_reset();

    // AFTER warm reset: fetch again
    let (ldev_der_after, ldev_cert_after) = get_ldev_ecc384_cert(&mut model);
    let (_, _x_after, _y_after, idev_pk_after) = get_idev_384_info(&mut model);

    // verify under post-reset IDev pubkey too
    assert!(ldev_cert_after.verify(&idev_pk_after).unwrap());

    // LDev DER should be identical across warm reset
    assert_eq!(ldev_der_before, ldev_der_after, "LDev cert DER changed");
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_get_rt_alias_ecc384_cert_after_warm_reset() {
    // Boot runtime
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    // --- BEFORE warm reset ---
    let fmc_before = {
        let r = get_ecc_fmc_alias_cert(&mut model);
        X509::from_der(&r.data[..r.data_size as usize]).unwrap()
    };

    let (rt_der_before, rt_before) = {
        let r = get_rt_alias_ecc384_cert(&mut model);
        let der = r.data[..r.data_size as usize].to_vec();
        let x = X509::from_der(&der).unwrap();
        (der, x)
    };

    // RT must be signed by FMC and issuer/subject must match (before)
    assert!(rt_before.verify(&fmc_before.public_key().unwrap()).unwrap());
    assert_eq!(
        rt_before
            .issuer_name()
            .try_cmp(fmc_before.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );

    // --- Warm reset ---
    model.warm_reset();

    // --- AFTER warm reset ---
    let fmc_after = {
        let r = get_ecc_fmc_alias_cert(&mut model);
        X509::from_der(&r.data[..r.data_size as usize]).unwrap()
    };

    let (rt_der_after, rt_after) = {
        let r = get_rt_alias_ecc384_cert(&mut model);
        let der = r.data[..r.data_size as usize].to_vec();
        let x = X509::from_der(&der).unwrap();
        (der, x)
    };

    // Re-verify chain (after)
    assert!(rt_after.verify(&fmc_after.public_key().unwrap()).unwrap());
    assert_eq!(
        rt_after
            .issuer_name()
            .try_cmp(fmc_after.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );

    // RT alias DER should be stable across warm reset
    assert_eq!(
        rt_der_before, rt_der_after,
        "RT alias cert DER changed across warm reset"
    );
}
