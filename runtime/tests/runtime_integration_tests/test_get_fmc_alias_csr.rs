// Licensed under the Apache-2.0 license

use crate::common::get_certs;
use caliptra_api::mailbox::GetFmcAliasCsrReq;
use caliptra_api::SocManager;
use caliptra_builder::{get_ci_rom_version, CiRomVersion};
use caliptra_common::mailbox_api::{CommandId, GetRtAliasCertReq, MailboxReqHeader};
use caliptra_drivers::{FmcAliasCsr, MAX_CSR_SIZE};
use caliptra_error::CaliptraError;
use caliptra_hw_model::DefaultHwModel;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_runtime::RtBootStatus;
use zerocopy::IntoBytes;

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

#[test]
fn test_missing_csr() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_CSR), &[]),
    };

    let response = model
        .mailbox_execute(CommandId::GET_IDEV_CSR.into(), payload.as_bytes())
        .unwrap_err();

    match get_ci_rom_version() {
        // 1.0 and 1.1 ROM do not support this feature
        CiRomVersion::Rom1_0 | CiRomVersion::Rom1_1 => assert_eq!(
            response,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM.into())
        ),
        _ => assert_eq!(
            response,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED.into())
        ),
    };
}
