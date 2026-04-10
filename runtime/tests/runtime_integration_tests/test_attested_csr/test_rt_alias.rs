// Licensed under the Apache-2.0 license

use caliptra_hw_model::DefaultHwModel;
use dpe::{
    commands::{CertifyKeyCommand, CertifyKeyFlags, CertifyKeyP384Cmd as CertifyKeyCmd, Command},
    context::ContextHandle,
    response::{CertifyKeyResp, Response},
};
use openssl::x509::X509;

use super::*;
use crate::common::{execute_dpe_cmd, run_rt_test, DpeResult, RuntimeTestArgs, TEST_LABEL};

/// Generate a DPE leaf cert using CertifyKey and return it as X509.
fn get_dpe_leaf_cert(model: &mut DefaultHwModel) -> X509 {
    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        label: TEST_LABEL,
        format: CertifyKeyCommand::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        model,
        &mut Command::from(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(CertifyKeyResp::P384(certify_key_resp))) = resp else {
        panic!("Wrong response type!");
    };
    X509::from_der(&certify_key_resp.cert[..certify_key_resp.cert_size as usize])
        .expect("Failed to parse DPE leaf cert")
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
    let dpe_leaf_cert = get_dpe_leaf_cert(&mut model);
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
}
