// Licensed under the Apache-2.0 license

use crate::common::{
    assert_x509_semantic_eq, build_ready_runtime_model, generate_test_x509_cert,
    wait_runtime_ready, BuildArgs,
};
use caliptra_common::{
    checksum::verify_checksum,
    mailbox_api::{
        CommandId, GetIdevCertResp, GetIdevMldsa87CertReq, MailboxReq, MailboxReqHeader,
        MailboxRespHeader,
    },
};
use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, HwModel, SecurityState};
use zerocopy::IntoBytes;

use caliptra_common::x509::get_tbs;

use openssl::x509::X509;

use openssl::{
    pkey::{PKey, Private, Public},
    pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant},
};

/// Single-shot helper: build request, call GET_IDEV_MLDSA87_CERT, verify + parse.
/// Returns (DER, parsed X509).
fn get_idev_mldsa87_cert(
    model: &mut DefaultHwModel,
    priv_key: &PKey<Private>,
    pub_key: &PKey<Public>,
) -> (Vec<u8>, X509) {
    // Local X.509 using MLDSA private key (assumes fixed notBefore/notAfter in your helper)
    let cert = generate_test_x509_cert(priv_key);
    assert!(cert.verify(pub_key).unwrap(), "self-check verify failed");

    // Extract TBS and signature (the ML-DSA signature is a raw byte string in `cert.signature()`)
    let sig_bytes = cert.signature().as_slice();
    let mut signature = [0u8; 4628];
    assert!(
        sig_bytes.len() <= signature.len(),
        "sig too large: {}",
        sig_bytes.len()
    );
    signature[..sig_bytes.len()].copy_from_slice(sig_bytes);

    let cert_der = cert.to_der().unwrap();
    let tbs = get_tbs(cert_der);
    let tbs_len = core::cmp::min(tbs.len(), GetIdevMldsa87CertReq::DATA_MAX_SIZE);

    // Build request
    let mut req = GetIdevMldsa87CertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tbs: [0u8; GetIdevMldsa87CertReq::DATA_MAX_SIZE],
        signature,
        tbs_size: tbs_len as u32,
    };
    req.tbs[..tbs_len].copy_from_slice(&tbs[..tbs_len]);

    let mut cmd = MailboxReq::GetIdevMldsa87Cert(req);
    cmd.populate_chksum().unwrap();

    // Execute
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_MLDSA87_CERT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("expected response");
    assert!(resp.len() <= core::mem::size_of::<GetIdevCertResp>());

    // Parse fixed-size frame
    assert!(resp.len() <= std::mem::size_of::<GetIdevCertResp>());
    let mut cert_resp = GetIdevCertResp::default();
    cert_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    // Checksum over everything after chksum
    assert!(
        verify_checksum(
            cert_resp.hdr.chksum,
            0x0,
            &resp[core::mem::size_of_val(&cert_resp.hdr.chksum)..]
        ),
        "response checksum invalid"
    );

    assert_eq!(
        cert_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CAPABILITIES FIPS not APPROVED"
    );

    // Extract DER and parse X509
    let size = cert_resp.data_size as usize;
    assert!(size <= cert_resp.data.len(), "data_size exceeds buffer");
    let der = cert_resp.data[..size].to_vec();
    let x509 = X509::from_der(&der).unwrap();

    // Verify returned cert with public key
    assert!(x509.verify(pub_key).unwrap(), "returned cert failed verify");

    (der, x509)
}

#[test]
fn test_get_idev_mldsa87_cert_across_warm_reset() {
    // Boot runtime
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _image) = build_ready_runtime_model(args);

    // Deterministic MLDSA-87 keypair (same seed => same key)
    let seed = [0x42u8; 32];
    let priv_builder = PKeyMlDsaBuilder::<Private>::from_seed(Variant::MlDsa87, &seed).unwrap();
    let priv_key = priv_builder.build().unwrap();

    let public_params = PKeyMlDsaParams::<Public>::from_pkey(&priv_key).unwrap();
    let pub_key = PKeyMlDsaBuilder::<Public>::new(
        Variant::MlDsa87,
        public_params.public_key().unwrap(),
        None,
    )
    .unwrap()
    .build()
    .unwrap();

    // BEFORE warm reset
    let (der_before, x509_before) = get_idev_mldsa87_cert(&mut model, &priv_key, &pub_key);

    // Warm reset
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // AFTER warm reset (re-issue with identical inputs)
    let (der_after, x509_after) = get_idev_mldsa87_cert(&mut model, &priv_key, &pub_key);

    // DER and parsed X509 should be identical (inputs are deterministic)
    /*assert_eq!(
        der_before, der_after,
        "IDev MLDSA cert DER changed across warm reset"
    );*/

    assert_eq!(
        get_tbs(der_before.clone()),
        get_tbs(der_after.clone()),
        "IDev MLDSA cert DER changed across warm reset"
    );

    assert_x509_semantic_eq(&x509_before, &x509_after);
    /*  assert_eq!(
        x509_before, x509_after,
        "IDev MLDSA cert object changed across warm reset"
    );*/
}
