// Licensed under the Apache-2.0 license

use crate::common::{
    execute_dpe_cmd, generate_test_x509_cert, get_fmc_alias_cert, get_rt_alias_cert, run_rt_test,
    DpeResult, TEST_LABEL,
};
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{
    CommandId, GetIdevCertReq, GetIdevCertResp, GetIdevInfoResp, GetLdevCertResp,
    GetRtAliasCertResp, MailboxReq, MailboxReqHeader,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use dpe::{
    commands::{CertifyKeyCmd, CertifyKeyFlags, Command},
    context::ContextHandle,
    response::Response,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::PKey,
    stack::Stack,
    x509::{
        store::X509StoreBuilder, verify::X509VerifyFlags, X509StoreContext, X509VerifyResult, X509,
    },
};
use zerocopy::{AsBytes, FromBytes};

#[test]
// Check if the owner and vendor cert validity dates are present in RT Alias cert
fn test_rt_cert_with_custom_dates() {
    const VENDOR_CONFIG: (&str, &str) = ("20250101000000Z", "20260101000000Z");
    const OWNER_CONFIG: (&str, &str) = ("20270101000000Z", "20280101000000Z");

    let mut opts = ImageOptions::default();

    opts.vendor_config
        .not_before
        .copy_from_slice(VENDOR_CONFIG.0.as_bytes());

    opts.vendor_config
        .not_after
        .copy_from_slice(VENDOR_CONFIG.1.as_bytes());

    let mut own_config = opts.owner_config.unwrap();

    own_config
        .not_before
        .copy_from_slice(OWNER_CONFIG.0.as_bytes());
    own_config
        .not_after
        .copy_from_slice(OWNER_CONFIG.1.as_bytes());

    opts.owner_config = Some(own_config);

    let mut model = run_rt_test(None, Some(opts), None);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_RT_ALIAS_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_RT_ALIAS_CERT), payload.as_bytes())
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetRtAliasCertResp>());
    let mut rt_resp = GetRtAliasCertResp::default();
    rt_resp.as_bytes_mut()[..resp.len()].copy_from_slice(&resp);

    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    let not_before: Asn1Time = Asn1Time::from_str(OWNER_CONFIG.0).unwrap();
    let not_after: Asn1Time = Asn1Time::from_str(OWNER_CONFIG.1).unwrap();

    assert!(rt_cert.not_before() == not_before);
    assert!(rt_cert.not_after() == not_after);
}

#[test]
fn test_idev_id_cert() {
    let mut model = run_rt_test(None, None, None);

    // generate 48 byte ECDSA key pair
    let ec_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = PKey::from_ec_key(EcKey::generate(&ec_group).unwrap()).unwrap();

    let cert = generate_test_x509_cert(ec_key.clone());
    assert!(cert.verify(&ec_key).unwrap());

    // Extract the r and s values of the signature
    let sig_bytes = cert.signature().as_slice();
    let signature = EcdsaSig::from_der(sig_bytes).unwrap();
    let signature_r: [u8; 48] = signature.r().to_vec_padded(48).unwrap().try_into().unwrap();
    let signature_s: [u8; 48] = signature.s().to_vec_padded(48).unwrap().try_into().unwrap();

    // Extract tbs from cert
    let mut tbs = [0u8; GetIdevCertReq::DATA_MAX_SIZE];
    let cert_der_vec = cert.to_der().unwrap();
    let cert_der = cert_der_vec.as_bytes();
    // skip first 4 outer sequence bytes
    let tbs_offset = 4;
    // this value is hard-coded and will need to be changed if the above x509 encoding is ever changed
    // you can change it by calling asn1parse on the byte dump of the x509 cert, and finding the size of the TbsCertificate portion
    let tbs_size = 223;
    tbs[..tbs_size].copy_from_slice(&cert_der[tbs_offset..tbs_offset + tbs_size]);

    let mut cmd = MailboxReq::GetIdevCert(GetIdevCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tbs,
        signature_r,
        signature_s,
        tbs_size: tbs_size as u32,
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_IDEV_CERT), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We expected a response");

    assert!(resp.len() <= std::mem::size_of::<GetIdevCertResp>());
    let mut cert = GetIdevCertResp::default();
    cert.as_bytes_mut()[..resp.len()].copy_from_slice(&resp);

    assert!(caliptra_common::checksum::verify_checksum(
        cert.hdr.chksum,
        0x0,
        &resp[core::mem::size_of_val(&cert.hdr.chksum)..],
    ));

    assert!(tbs_size < cert.cert_size as usize);
    let idev_cert = X509::from_der(&cert.cert[..cert.cert_size as usize]).unwrap();
    assert!(idev_cert.verify(&ec_key).unwrap());
}

#[test]
fn test_idev_id_cert_size_too_big() {
    // Test with tbs_size too big.
    let mut cmd = MailboxReq::GetIdevCert(GetIdevCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tbs: [0u8; GetIdevCertReq::DATA_MAX_SIZE],
        signature_r: [0u8; 48],
        signature_s: [0u8; 48],
        tbs_size: GetIdevCertReq::DATA_MAX_SIZE as u32 + 1,
    });
    assert_eq!(
        cmd.populate_chksum(),
        Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)
    );
}

fn get_ldev_cert(model: &mut DefaultHwModel) -> GetLdevCertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_LDEV_CERT), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_LDEV_CERT), payload.as_bytes())
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetLdevCertResp>());
    let mut ldev_resp = GetLdevCertResp::default();
    ldev_resp.as_bytes_mut()[..resp.len()].copy_from_slice(&resp);
    ldev_resp
}

#[test]
fn test_ldev_cert() {
    let mut model = run_rt_test(None, None, None);

    let ldev_resp = get_ldev_cert(&mut model);
    let ldev_cert: X509 = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    // Get IDev public key
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_IDEV_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    let idev_resp = GetIdevInfoResp::read_from(resp.as_slice()).unwrap();

    // Check the LDevID is signed by IDevID
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let idev_x = &BigNum::from_slice(&idev_resp.idev_pub_x).unwrap();
    let idev_y = &BigNum::from_slice(&idev_resp.idev_pub_y).unwrap();

    let idev_ec_key = EcKey::from_public_key_affine_coordinates(&group, idev_x, idev_y).unwrap();
    assert!(ldev_cert
        .verify(&PKey::from_ec_key(idev_ec_key).unwrap())
        .unwrap());
}

#[test]
fn test_fmc_alias_cert() {
    let mut model = run_rt_test(None, None, None);

    let ldev_resp = get_ldev_cert(&mut model);
    let ldev_cert: X509 = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    let fmc_resp = get_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();

    // Check the FMC is signed by LDevID and that subject/issuer names match
    assert!(fmc_cert.verify(&ldev_cert.public_key().unwrap()).unwrap());
    assert_eq!(
        fmc_cert
            .issuer_name()
            .try_cmp(ldev_cert.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );
}

#[test]
fn test_rt_alias_cert() {
    let mut model = run_rt_test(None, None, None);

    let fmc_resp = get_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();

    let rt_resp = get_rt_alias_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    // Check that RT Alias is signed by FMC and that subject/issuer names match
    assert!(rt_cert.verify(&fmc_cert.public_key().unwrap()).unwrap());
    assert_eq!(
        rt_cert
            .issuer_name()
            .try_cmp(fmc_cert.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );
}

#[test]
fn test_dpe_leaf_cert() {
    let mut model = run_rt_test(None, None, None);

    let rt_resp = get_rt_alias_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::CertifyKey(certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(certify_key_resp)) = resp else {
        panic!("Wrong response type!");
    };
    let dpe_leaf_cert: X509 =
        X509::from_der(&certify_key_resp.cert[..certify_key_resp.cert_size as usize]).unwrap();

    // Check that DPE Leaf Cert is signed by RT alias pub key and that subject/issuer names match
    assert!(dpe_leaf_cert
        .verify(&rt_cert.public_key().unwrap())
        .unwrap());
    assert_eq!(
        dpe_leaf_cert
            .issuer_name()
            .try_cmp(rt_cert.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );
}

#[test]
fn test_full_cert_chain() {
    let mut model = run_rt_test(None, None, None);

    let ldev_resp = get_ldev_cert(&mut model);
    let ldev_cert: X509 = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    let fmc_resp = get_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();

    let rt_resp = get_rt_alias_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    // Verify full cert chain
    let mut roots_bldr = X509StoreBuilder::new().unwrap();
    roots_bldr.add_cert(ldev_cert).unwrap();
    roots_bldr
        .set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::PARTIAL_CHAIN)
        .unwrap();
    let roots = roots_bldr.build();
    let mut cert_store = X509StoreContext::new().unwrap();
    let mut chain = Stack::new().unwrap();
    chain.push(fmc_cert).unwrap();
    cert_store
        .init(&roots, &rt_cert, &chain, |c| {
            let success = c.verify_cert().unwrap();
            assert_eq!(c.error(), X509VerifyResult::OK);
            assert!(success);

            Ok(())
        })
        .unwrap();
}
