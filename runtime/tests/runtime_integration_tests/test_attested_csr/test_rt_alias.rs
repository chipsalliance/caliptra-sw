// Licensed under the Apache-2.0 license

use caliptra_hw_model::DefaultHwModel;
use caliptra_runtime::CaliptraDpeProfile;
use dpe::{
    commands::{CertifyKeyCommand, CertifyKeyFlags, Command},
    context::ContextHandle,
    response::{CertifyKeyResp, Response},
};
use openssl::x509::X509;

use super::*;
use crate::common::{
    execute_dpe_cmd, run_rt_test, CertifyKeyCommandNoRef, CreateCertifyKeyCmdArgs, DpeResult,
    RuntimeTestArgs, TEST_LABEL,
};

/// Generate an ECC384 DPE leaf cert using CertifyKey and return it as X509.
fn get_ecc_dpe_leaf_cert(model: &mut DefaultHwModel) -> X509 {
    let certify_key_cmd = CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
        profile: CaliptraDpeProfile::Ecc384,
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
    });
    let resp = execute_dpe_cmd(
        model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(CertifyKeyResp::P384(certify_key_resp))) = resp else {
        panic!("Wrong response type!");
    };
    X509::from_der(&certify_key_resp.cert[..certify_key_resp.cert_size as usize])
        .expect("Failed to parse ECC DPE leaf cert")
}

/// Generate an MLDSA87 DPE leaf cert using CertifyKey and return it as X509.
fn get_mldsa_dpe_leaf_cert(model: &mut DefaultHwModel) -> X509 {
    let certify_key_cmd = CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
        profile: CaliptraDpeProfile::Mldsa87,
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
    });
    let resp = execute_dpe_cmd(
        model,
        CaliptraDpeProfile::Mldsa87,
        &mut Command::from(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(CertifyKeyResp::Mldsa87(certify_key_resp))) = resp else {
        panic!("Wrong response type!");
    };
    X509::from_der(&certify_key_resp.cert[..certify_key_resp.cert_size as usize])
        .expect("Failed to parse MLDSA DPE leaf cert")
}

#[test]
fn test_get_attested_rt_alias_ecc_csr() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    // Get the envelope signed CSR for RT Alias
    let csr = verify_and_extract_attested_ecc_csr(&mut model, KEY_ID_RT_ALIAS);

    // Verify the CSR public key can be extracted
    let pubkey = csr.public_key().expect("Failed to get public key from CSR");

    // The RT Alias CSR is self-signed. Verify the signature on the CSR using its own public key.
    assert!(
        csr.verify(&pubkey).unwrap(),
        "RT Alias ECC CSR should be self-signed"
    );

    // Generate a DPE leaf cert and verify it is signed by the RT Alias key
    let dpe_leaf_cert = get_ecc_dpe_leaf_cert(&mut model);
    assert!(
        dpe_leaf_cert.verify(&pubkey).unwrap(),
        "DPE leaf cert should be signed by RT Alias ECC key"
    );
}

#[test]
fn test_get_attested_rt_alias_mldsa_csr() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    // Get the envelope signed CSR for RT Alias
    let csr = verify_and_extract_attested_mldsa_csr(&mut model, KEY_ID_RT_ALIAS);

    // Verify the CSR public key can be extracted
    let pubkey = csr.public_key().expect("Failed to get public key from CSR");

    // The RT Alias MLDSA CSR is self-signed. Verify the signature on the CSR using its own public key.
    assert!(
        csr.verify(&pubkey).unwrap(),
        "RT Alias MLDSA CSR should be self-signed"
    );

    // Generate an MLDSA DPE leaf cert and verify it is signed by the RT Alias MLDSA key
    let dpe_leaf_cert = get_mldsa_dpe_leaf_cert(&mut model);
    assert!(
        dpe_leaf_cert.verify(&pubkey).unwrap(),
        "DPE leaf cert should be signed by RT Alias MLDSA key"
    );
}
