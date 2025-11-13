// Licensed under the Apache-2.0 license

use crate::common::get_certs;
use caliptra_api::mailbox::{GetFmcAliasEccCsrReq, GetFmcAliasMldsaCsrReq};
use caliptra_common::mailbox_api::{GetRtAliasEcc384CertReq, GetRtAliasMlDsa87CertReq};
use caliptra_drivers::{FmcAliasCsrs, ECC384_MAX_FMC_ALIAS_CSR_SIZE, MLDSA87_MAX_CSR_SIZE};
use caliptra_hw_model::DefaultHwModel;
use openssl::{
    pkey::{PKey, Public},
    x509::{X509Req, X509},
};

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_get_fmc_alias_csr() {
    fn verify_rt_ecc_cert(model: &mut DefaultHwModel, pub_key: PKey<Public>) {
        let get_rt_alias_cert_resp = get_certs::<GetRtAliasEcc384CertReq>(model);
        assert_ne!(0, get_rt_alias_cert_resp.data_size);

        let der = &get_rt_alias_cert_resp.data[..get_rt_alias_cert_resp.data_size as usize];
        let cert = X509::from_der(der).unwrap();

        assert!(
            cert.verify(&pub_key).unwrap(),
            "Invalid public key. Unable to verify RT Alias ECC Cert",
        );
    }
    fn verify_rt_mldsa_cert(model: &mut DefaultHwModel, pub_key: PKey<Public>) {
        let get_rt_alias_cert_resp = get_certs::<GetRtAliasMlDsa87CertReq>(model);
        assert_ne!(0, get_rt_alias_cert_resp.data_size);

        let der = &get_rt_alias_cert_resp.data[..get_rt_alias_cert_resp.data_size as usize];
        let cert = X509::from_der(der).unwrap();

        assert!(
            cert.verify(&pub_key).unwrap(),
            "Invalid public key. Unable to verify RT Alias MLDSA Cert",
        );
    }
    fn get_fmc_alias_ecc_csr(model: &mut DefaultHwModel) -> X509Req {
        let get_fmc_alias_csr_resp = get_certs::<GetFmcAliasEccCsrReq>(model);

        assert_ne!(
            FmcAliasCsrs::UNPROVISIONED_CSR,
            get_fmc_alias_csr_resp.data_size
        );
        assert_ne!(0, get_fmc_alias_csr_resp.data_size);

        let csr_der = &get_fmc_alias_csr_resp.data[..get_fmc_alias_csr_resp.data_size as usize];
        let csr = X509Req::from_der(csr_der).unwrap();

        assert_ne!([0; ECC384_MAX_FMC_ALIAS_CSR_SIZE], csr_der);

        csr
    }
    fn get_fmc_alias_mldsa_csr(model: &mut DefaultHwModel) -> X509Req {
        let get_fmc_alias_csr_resp = get_certs::<GetFmcAliasMldsaCsrReq>(model);

        assert_ne!(
            FmcAliasCsrs::UNPROVISIONED_CSR,
            get_fmc_alias_csr_resp.data_size
        );
        assert_ne!(0, get_fmc_alias_csr_resp.data_size);

        let csr_der = &get_fmc_alias_csr_resp.data[..get_fmc_alias_csr_resp.data_size as usize];
        let csr = openssl::x509::X509Req::from_der(csr_der).unwrap();

        assert_ne!([0; MLDSA87_MAX_CSR_SIZE], csr_der);

        csr
    }
    let mut model = run_rt_test(RuntimeTestArgs::default());

    // ECC
    let csr = get_fmc_alias_ecc_csr(&mut model);

    let pubkey = csr.public_key().unwrap();
    assert!(
        csr.verify(&pubkey).unwrap(),
        "Invalid public key. Unable to verify FMC Alias ECC CSR",
    );

    verify_rt_ecc_cert(&mut model, pubkey);

    // MLDSA
    let csr = get_fmc_alias_mldsa_csr(&mut model);

    let pubkey = csr.public_key().unwrap();
    assert!(
        csr.verify(&pubkey).unwrap(),
        "Invalid public key. Unable to verify FMC Alias MLDSA CSR",
    );

    verify_rt_mldsa_cert(&mut model, pubkey);
}
