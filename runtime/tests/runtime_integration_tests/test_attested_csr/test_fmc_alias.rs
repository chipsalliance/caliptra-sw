// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{GetRtAliasEcc384CertReq, GetRtAliasMlDsa87CertReq};
use caliptra_hw_model::DefaultHwModel;
use openssl::{
    pkey::{PKey, Public},
    x509::X509,
};

use super::*;
use crate::common::{get_certs, run_rt_test, RuntimeTestArgs};

#[test]
fn test_get_attested_fmc_alias_ecc_csr() {
    fn verify_rt_alias_ecc_cert(model: &mut DefaultHwModel, pub_key: PKey<Public>) {
        // Get RT Alias ECC certificate
        let get_rt_alias_cert_rsp = get_certs::<GetRtAliasEcc384CertReq>(model);
        assert_ne!(0, get_rt_alias_cert_rsp.data_size);

        let rt_cert_der = &get_rt_alias_cert_rsp.data[..get_rt_alias_cert_rsp.data_size as usize];

        let rt_cert = X509::from_der(rt_cert_der).expect("Failed to parse RT Alias ECC cert");

        assert!(
            rt_cert.verify(&pub_key).is_ok(),
            "RT Alias ECC cert should be signed by FMC Alias ECC key"
        );
    }

    let mut model = run_rt_test(RuntimeTestArgs::default());

    // Get the envelope signed CSR for FMC Alias
    let csr = verify_and_extract_attested_ecc_csr(&mut model, KEY_ID_FMC_ALIAS);

    // Verify the CSR public key can be extracted
    let pubkey = csr.public_key().expect("Failed to get public key from CSR");

    // The FMC Alias CSR is self-signed. Verify the signature on the CSR using its own public key.
    assert!(
        csr.verify(&pubkey).unwrap(),
        "FMC Alias ECC CSR should be self-signed"
    );

    // Verify the CSR's public key matches the RT Alias certificate issuer
    // (FMC Alias signs the RT Alias cert)
    verify_rt_alias_ecc_cert(&mut model, pubkey);
}

#[test]
fn test_get_attested_fmc_alias_mldsa_csr() {
    fn verify_rt_alias_mldsa_cert(model: &mut DefaultHwModel, pub_key: PKey<Public>) {
        // Get RT Alias MLDSA certificate
        let get_rt_alias_cert_rsp = get_certs::<GetRtAliasMlDsa87CertReq>(model);
        assert_ne!(0, get_rt_alias_cert_rsp.data_size);

        let rt_cert_der = &get_rt_alias_cert_rsp.data[..get_rt_alias_cert_rsp.data_size as usize];

        let rt_cert = X509::from_der(rt_cert_der).expect("Failed to parse RT Alias MLDSA cert");

        assert!(
            rt_cert.verify(&pub_key).is_ok(),
            "RT Alias MLDSA cert should be signed by FMC Alias MLDSA key"
        );
    }

    let mut model = run_rt_test(RuntimeTestArgs::default());

    // Get the envelope signed CSR for FMC Alias
    let csr = verify_and_extract_attested_mldsa_csr(&mut model, KEY_ID_FMC_ALIAS);

    // Verify the CSR public key can be extracted
    let pubkey = csr.public_key().expect("Failed to get public key from CSR");

    // The FMC Alias CSR is self-signed. Verify the signature on the CSR using its own public key.
    assert!(
        csr.verify(&pubkey).unwrap(),
        "FMC Alias MLDSA CSR should be self-signed"
    );

    // Verify the CSR's public key matches the RT Alias MLDSA certificate issuer
    verify_rt_alias_mldsa_cert(&mut model, pubkey);
}
