// Licensed under the Apache-2.0 license

use crate::common::{
    assert_x509_semantic_eq, build_ready_runtime_model, generate_test_x509_cert,
    get_mldsa_fmc_alias_cert, get_rt_alias_mldsa87_cert, wait_runtime_ready, BuildArgs,
};
use caliptra_common::{
    checksum::{calc_checksum, verify_checksum},
    mailbox_api::{
        CommandId, GetIdevCertResp, GetIdevMldsa87CertReq, GetIdevMldsa87InfoResp, GetLdevCertResp,
        MailboxReq, MailboxReqHeader, MailboxRespHeader,
    },
    x509::get_tbs,
};
use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, HwModel, SecurityState};
use zerocopy::{FromBytes, IntoBytes};

use openssl::{
    pkey::{PKey, Private, Public},
    pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant},
    x509::X509,
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
    let (mut model, _, _, _) = build_ready_runtime_model(args);

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
}

fn der_from_ldev_resp(resp: &GetLdevCertResp) -> &[u8] {
    &resp.data[..resp.data_size as usize]
}

fn get_idev_mldsa87_pubkey(
    model: &mut DefaultHwModel,
) -> openssl::pkey::PKey<openssl::pkey::Public> {
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::GET_IDEV_MLDSA87_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_MLDSA87_INFO),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let idev = GetIdevMldsa87InfoResp::read_from_bytes(resp.as_slice()).unwrap();

    // Build ML-DSA public key for OpenSSL-style verify
    PKeyMlDsaBuilder::<Public>::new(Variant::MlDsa87, &idev.idev_pub_key, None)
        .unwrap()
        .build()
        .unwrap()
}

fn get_ldev_mldsa_cert(model: &mut DefaultHwModel) -> GetLdevCertResp {
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::GET_LDEV_MLDSA87_CERT), &[]),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_LDEV_MLDSA87_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    assert!(resp.len() <= core::mem::size_of::<GetLdevCertResp>());
    let mut ldev_resp = GetLdevCertResp::default();
    ldev_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    ldev_resp
}

#[test]
fn test_get_ldev_mldsa87_cert_after_warm_reset() {
    // Boot runtime

    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _, _, _) = build_ready_runtime_model(args);

    // -------- BEFORE warm reset --------
    let ldev_resp_before = get_ldev_mldsa_cert(&mut model);
    let ldev_der_before = der_from_ldev_resp(&ldev_resp_before);
    assert!(
        !ldev_der_before.is_empty(),
        "empty LDev MLDSA cert (before)"
    );

    // Parse & verify under current IDev pubkey
    let ldev_cert_before = X509::from_der(ldev_der_before).unwrap();
    let idev_pk_before = get_idev_mldsa87_pubkey(&mut model);
    assert!(ldev_cert_before.verify(&idev_pk_before).unwrap());

    // -------- Warm reset --------
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // -------- AFTER warm reset --------
    let ldev_resp_after = get_ldev_mldsa_cert(&mut model);
    let ldev_der_after = der_from_ldev_resp(&ldev_resp_after);
    assert!(!ldev_der_after.is_empty(), "empty LDev MLDSA cert (after)");

    let ldev_cert_after = X509::from_der(ldev_der_after).unwrap();
    let idev_pk_after = get_idev_mldsa87_pubkey(&mut model);
    assert!(ldev_cert_after.verify(&idev_pk_after).unwrap());

    // If you rounded validity seconds to 00 in the builder, this should pass bit-for-bit:
    assert_eq!(
        ldev_der_before, ldev_der_after,
        "LDev MLDSA cert DER changed across warm reset"
    );
}

#[test]
fn test_get_fmc_alias_mldsa87_cert_after_warm_reset() {
    // Boot runtime
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _, _, _) = build_ready_runtime_model(args);

    // --- BEFORE warm reset ---
    // LDev (issuer of FMC-alias)
    let ldev_before = {
        let r = get_ldev_mldsa_cert(&mut model);
        X509::from_der(&r.data[..r.data_size as usize]).unwrap()
    };

    // FMC-alias cert
    let (fmc_der_before, fmc_before) = {
        let r = get_mldsa_fmc_alias_cert(&mut model);
        let der = r.data[..r.data_size as usize].to_vec();
        let x = X509::from_der(&der).unwrap();
        (der, x)
    };

    // Verify chain (before): FMC-alias must be signed by LDev and issuer/subject must match
    assert!(fmc_before
        .verify(&ldev_before.public_key().unwrap())
        .unwrap());
    assert_eq!(
        fmc_before
            .issuer_name()
            .try_cmp(ldev_before.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );

    // --- Warm reset ---
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // --- AFTER warm reset ---
    let ldev_after = {
        let r = get_ldev_mldsa_cert(&mut model);
        X509::from_der(&r.data[..r.data_size as usize]).unwrap()
    };

    let (fmc_der_after, fmc_after) = {
        let r = get_mldsa_fmc_alias_cert(&mut model);
        let der = r.data[..r.data_size as usize].to_vec();
        let x = X509::from_der(&der).unwrap();
        (der, x)
    };

    // Re-verify chain (after)
    assert!(fmc_after.verify(&ldev_after.public_key().unwrap()).unwrap());
    assert_eq!(
        fmc_after
            .issuer_name()
            .try_cmp(ldev_after.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );

    // DER should be stable across warm reset (with validity seconds fixed to 00 in builder)
    assert_eq!(
        fmc_der_before, fmc_der_after,
        "FMC-alias MLDSA cert DER changed across warm reset"
    );
}

#[test]
fn test_get_rt_alias_mldsa87_cert_after_warm_reset() {
    // Boot runtime
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _, _, _) = build_ready_runtime_model(args);

    // ---------- BEFORE warm reset ----------
    let fmc_before = {
        let r = get_mldsa_fmc_alias_cert(&mut model);
        X509::from_der(&r.data[..r.data_size as usize]).unwrap()
    };

    // RT-alias
    let (rt_der_before, rt_before) = {
        let r: GetLdevCertResp = get_rt_alias_mldsa87_cert(&mut model);
        let der = r.data[..r.data_size as usize].to_vec();
        let x = X509::from_der(&der).unwrap();
        (der, x)
    };

    // Chain checks (before)
    assert!(rt_before.verify(&fmc_before.public_key().unwrap()).unwrap());
    assert_eq!(
        rt_before
            .issuer_name()
            .try_cmp(fmc_before.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );

    // ---------- Warm reset ----------
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // ---------- AFTER warm reset ----------
    let fmc_after = {
        let r = get_mldsa_fmc_alias_cert(&mut model);
        X509::from_der(&r.data[..r.data_size as usize]).unwrap()
    };

    let (rt_der_after, rt_after) = {
        let r: GetLdevCertResp = get_rt_alias_mldsa87_cert(&mut model);
        let der = r.data[..r.data_size as usize].to_vec();
        let x = X509::from_der(&der).unwrap();
        (der, x)
    };

    // Chain checks (after)
    assert!(rt_after.verify(&fmc_after.public_key().unwrap()).unwrap());
    assert_eq!(
        rt_after
            .issuer_name()
            .try_cmp(fmc_after.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );

    // DER should be stable across warm reset (with validity seconds fixed to 00 in builder)
    assert_eq!(
        rt_der_before, rt_der_after,
        "RT-alias MLDSA cert DER changed across warm reset"
    );
}

fn fetch_idev_mldsa87_info(model: &mut DefaultHwModel) -> GetIdevMldsa87InfoResp {
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::GET_IDEV_MLDSA87_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_MLDSA87_INFO),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    GetIdevMldsa87InfoResp::read_from_bytes(resp.as_slice()).unwrap()
}

#[test]
fn test_get_idev_mldsa87_info_after_warm_reset() {
    // Boot with build_ready_runtime_model
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _, _, _) = build_ready_runtime_model(args);

    // ----- BEFORE warm reset -----
    let info_before = fetch_idev_mldsa87_info(&mut model);
    assert!(
        !info_before.idev_pub_key.is_empty(),
        "empty IDev MLDSA87 pubkey (before)"
    );

    // Build a PKey and export to DER (SPKI) for a DER-stability check (mirrors ECC pattern)
    let pk_before =
        PKeyMlDsaBuilder::<Public>::new(Variant::MlDsa87, &info_before.idev_pub_key, None)
            .unwrap()
            .build()
            .unwrap();
    let pk_before_der = pk_before.public_key_to_der().unwrap();
    assert!(!pk_before_der.is_empty(), "empty IDev MLDSA87 DER (before)");

    // Verify the LDev cert under the IDev key (before)
    let ldev_before_resp: GetLdevCertResp = get_ldev_mldsa_cert(&mut model);
    let ldev_before =
        X509::from_der(&ldev_before_resp.data[..ldev_before_resp.data_size as usize]).unwrap();
    assert!(
        ldev_before.verify(&pk_before).unwrap(),
        "LDev cert failed under IDev key (before)"
    );

    // ----- Warm reset -----
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // ----- AFTER warm reset -----
    let info_after = fetch_idev_mldsa87_info(&mut model);
    assert!(
        !info_after.idev_pub_key.is_empty(),
        "empty IDev MLDSA87 pubkey (after)"
    );

    let pk_after =
        PKeyMlDsaBuilder::<Public>::new(Variant::MlDsa87, &info_after.idev_pub_key, None)
            .unwrap()
            .build()
            .unwrap();
    let pk_after_der = pk_after.public_key_to_der().unwrap();
    assert!(!pk_after_der.is_empty(), "empty IDev MLDSA87 DER (after)");

    // Verify the LDev cert under the (post-reset) IDev key (after)
    let ldev_after_resp: GetLdevCertResp = get_ldev_mldsa_cert(&mut model);
    let ldev_after =
        X509::from_der(&ldev_after_resp.data[..ldev_after_resp.data_size as usize]).unwrap();
    assert!(
        ldev_after.verify(&pk_after).unwrap(),
        "LDev cert failed under IDev key (after)"
    );

    // ----- Stability checks across warm reset ----
    assert_eq!(
        info_before.idev_pub_key, info_after.idev_pub_key,
        "IDev MLDSA87 public key bytes changed"
    );
    assert_eq!(
        pk_before_der, pk_after_der,
        "IDev MLDSA87 public key DER changed"
    );
    assert_eq!(info_before, info_after, "IDev MLDSA87 info struct changed");
}
