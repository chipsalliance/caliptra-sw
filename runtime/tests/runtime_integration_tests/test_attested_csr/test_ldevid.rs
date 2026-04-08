// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{GetFmcAliasEcc384CertReq, GetFmcAliasMlDsa87CertReq};
use caliptra_hw_model::DefaultHwModel;
use openssl::{
    pkey::{PKey, Public},
    x509::X509,
};

use super::*;
use crate::common::{get_certs, run_rt_test, RuntimeTestArgs};

#[test]
fn test_get_attested_ldevid_ecc_csr() {
    fn verify_fmc_alias_ecc_cert(model: &mut DefaultHwModel, pub_key: PKey<Public>) {
        // Get FMC Alias ECC certificate
        let get_fmc_alias_cert_rsp = get_certs::<GetFmcAliasEcc384CertReq>(model);
        assert_ne!(0, get_fmc_alias_cert_rsp.data_size);

        let fmc_cert_der =
            &get_fmc_alias_cert_rsp.data[..get_fmc_alias_cert_rsp.data_size as usize];

        let fmc_cert = X509::from_der(fmc_cert_der).expect("Failed to parse FMC Alias ECC cert");

        assert!(
            fmc_cert.verify(&pub_key).is_ok(),
            "FMC Alias ECC cert verification failed"
        );
    }

    let mut model = run_rt_test(RuntimeTestArgs::default());

    // Get the envelope signed CSR for LDevID
    let csr = verify_and_extract_attested_ecc_csr(&mut model, KEY_ID_LDEV_ID);

    // Verify the CSR public key can be extracted
    let pubkey = csr.public_key().expect("Failed to get public key from CSR");

    // Note: The CSR is null-signed because the LDevID private key is not
    // available at runtime (overwritten during FMC boot). Attestation of the
    // CSR is provided by the COSE Sign1 envelope, not by self-signature.

    // Verify the CSR's public key matches the FMC Alias certificate issuer
    verify_fmc_alias_ecc_cert(&mut model, pubkey);
}

#[test]
fn test_get_attested_ldevid_mldsa_csr() {
    fn verify_fmc_alias_mldsa_cert(model: &mut DefaultHwModel, pub_key: PKey<Public>) {
        // Get FMC Alias MLDSA certificate
        let get_fmc_alias_cert_rsp = get_certs::<GetFmcAliasMlDsa87CertReq>(model);
        assert_ne!(0, get_fmc_alias_cert_rsp.data_size);

        let fmc_cert_der =
            &get_fmc_alias_cert_rsp.data[..get_fmc_alias_cert_rsp.data_size as usize];

        let fmc_cert = X509::from_der(fmc_cert_der).expect("Failed to parse FMC Alias MLDSA cert");

        assert!(
            fmc_cert.verify(&pub_key).is_ok(),
            "FMC Alias MLDSA cert verification failed"
        );
    }

    let mut model = run_rt_test(RuntimeTestArgs::default());

    // Get the envelope signed CSR for LDevID
    let csr = verify_and_extract_attested_mldsa_csr(&mut model, KEY_ID_LDEV_ID);

    // Verify the CSR public key can be extracted
    let pubkey = csr.public_key().expect("Failed to get public key from CSR");

    // Verify the CSR's public key matches the FMC Alias MLDSA certificate issuer
    verify_fmc_alias_mldsa_cert(&mut model, pubkey);
}
