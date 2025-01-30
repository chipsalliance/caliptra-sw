// Licensed under the Apache-2.0 license

use crate::common::get_certs;
use caliptra_api::mailbox::GetFmcAliasCsrReq;
use caliptra_common::mailbox_api::GetRtAliasCertReq;
use caliptra_drivers::{FmcAliasCsr, MAX_CSR_SIZE};
use caliptra_hw_model::DefaultHwModel;

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_get_fmc_alias_csr() {
    fn verify_rt_cert(
        model: &mut DefaultHwModel,
        pub_key: openssl::pkey::PKey<openssl::pkey::Public>,
    ) {
        let get_rt_alias_cert_resp = get_certs::<GetRtAliasCertReq>(model);
        assert_ne!(0, get_rt_alias_cert_resp.data_size);

        let der = &get_rt_alias_cert_resp.data[..get_rt_alias_cert_resp.data_size as usize];
        let cert = openssl::x509::X509::from_der(der).unwrap();

        assert!(
            cert.verify(&pub_key).unwrap(),
            "Invalid public key. Unable to verify RT Alias Cert",
        );
    }
    fn get_fmc_alias_csr(model: &mut DefaultHwModel) -> openssl::x509::X509Req {
        let get_fmc_alias_csr_resp = get_certs::<GetFmcAliasCsrReq>(model);

        assert_ne!(
            FmcAliasCsr::UNPROVISIONED_CSR,
            get_fmc_alias_csr_resp.data_size
        );
        assert_ne!(0, get_fmc_alias_csr_resp.data_size);

        let csr_der = &get_fmc_alias_csr_resp.data[..get_fmc_alias_csr_resp.data_size as usize];
        let csr = openssl::x509::X509Req::from_der(csr_der).unwrap();

        assert_ne!([0; MAX_CSR_SIZE], csr_der);

        csr
    }
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let csr = get_fmc_alias_csr(&mut model);

    let pubkey = csr.public_key().unwrap();
    assert!(
        csr.verify(&pubkey).unwrap(),
        "Invalid public key. Unable to verify FMC Alias CSR",
    );

    verify_rt_cert(&mut model, pubkey);
}
