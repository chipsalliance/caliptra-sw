// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test, RuntimeTestArgs};
use caliptra_api::SocManager;
use caliptra_builder::{get_ci_rom_version, CiRomVersion};
use caliptra_common::mailbox_api::{CommandId, GetIdevCsrResp, MailboxReqHeader};
use caliptra_drivers::{Ecc384IdevIdCsr, MfgFlags, Mldsa87IdevIdCsr};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_runtime::RtBootStatus;
use openssl::x509::X509Req;
use zerocopy::IntoBytes;

#[test]
fn test_get_ecc_csr() {
    // `run_rt_test` is responsibly for clearing the CSR bit.
    // Caliptra will wait until the CSR bit is cleared during startup.
    let args = RuntimeTestArgs {
        test_mfg_flags: Some(MfgFlags::GENERATE_IDEVID_CSR),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_ECC384_CSR),
            &[],
        ),
    };

    let result = model.mailbox_execute(CommandId::GET_IDEV_ECC384_CSR.into(), payload.as_bytes());

    match get_ci_rom_version() {
        CiRomVersion::Latest => {
            let response = result.unwrap().unwrap();

            let mut get_idv_csr_resp = GetIdevCsrResp::default();
            get_idv_csr_resp.as_mut_bytes()[..response.len()].copy_from_slice(&response);
            assert_ne!(
                Ecc384IdevIdCsr::UNPROVISIONED_CSR,
                get_idv_csr_resp.data_size
            );
            assert_ne!(0, get_idv_csr_resp.data_size);

            let csr_bytes = &get_idv_csr_resp.data[..get_idv_csr_resp.data_size as usize];
            assert_ne!([0; 512], csr_bytes);

            assert!(X509Req::from_der(csr_bytes).is_ok());
        }
    };
}

#[test]
fn test_get_mldsa_csr() {
    // `run_rt_test` is responsibly for clearing the CSR bit.
    // Caliptra will wait until the CSR bit is cleared during startup.
    let args = RuntimeTestArgs {
        test_mfg_flags: Some(MfgFlags::GENERATE_IDEVID_CSR),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_MLDSA87_CSR),
            &[],
        ),
    };

    let result = model.mailbox_execute(CommandId::GET_IDEV_MLDSA87_CSR.into(), payload.as_bytes());

    match get_ci_rom_version() {
        CiRomVersion::Latest => {
            let response = result.unwrap().unwrap();

            let mut get_idv_csr_resp = GetIdevCsrResp::default();
            get_idv_csr_resp.as_mut_bytes()[..response.len()].copy_from_slice(&response);
            assert_ne!(
                Mldsa87IdevIdCsr::UNPROVISIONED_CSR,
                get_idv_csr_resp.data_size
            );
            assert_ne!(0, get_idv_csr_resp.data_size);

            let csr_bytes = &get_idv_csr_resp.data[..get_idv_csr_resp.data_size as usize];
            assert_ne!([0; 512], csr_bytes);

            assert!(X509Req::from_der(csr_bytes).is_ok());
        }
    };
}

#[test]
fn test_missing_csr() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_ECC384_CSR),
            &[],
        ),
    };

    let response = model
        .mailbox_execute(CommandId::GET_IDEV_ECC384_CSR.into(), payload.as_bytes())
        .unwrap_err();

    match get_ci_rom_version() {
        CiRomVersion::Latest => assert_eq!(
            response,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED.into())
        ),
    };

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_MLDSA87_CSR),
            &[],
        ),
    };

    let response = model
        .mailbox_execute(CommandId::GET_IDEV_MLDSA87_CSR.into(), payload.as_bytes())
        .unwrap_err();

    match get_ci_rom_version() {
        CiRomVersion::Latest => assert_eq!(
            response,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED.into())
        ),
    };
}

#[test]
fn test_get_fmc_alias_ecc384_csr() {
    // Bring up runtime model
    let args = RuntimeTestArgs {
        test_mfg_flags: Some(MfgFlags::GENERATE_IDEVID_CSR),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_ECC384_CSR),
            &[],
        ),
    };

    let response = model
        .mailbox_execute(
            u32::from(CommandId::GET_FMC_ALIAS_ECC384_CSR),
            payload.as_bytes(),
        )
        .expect("mailbox_execute failed")
        .expect("no response from GET_FMC_ALIAS_ECC384_CSR");

    let mut csr_resp = GetIdevCsrResp::default();
    csr_resp.as_mut_bytes()[..response.len()].copy_from_slice(&response);

    assert!(
        csr_resp.data_size > 0,
        "CSR data_size was 0 (unprovisioned?)"
    );
    assert!(
        (csr_resp.data_size as usize) <= csr_resp.data.len(),
        "CSR data_size out of bounds"
    );

    let csr_bytes = &csr_resp.data[..csr_resp.data_size as usize];

    assert!(
        csr_bytes.iter().any(|&b| b != 0),
        "FMC alias ECC384 CSR buffer is unexpectedly all zeros"
    );

    let req = X509Req::from_der(csr_bytes).expect("CSR is not valid DER");

    // subject should not not be empty
    assert!(
        req.subject_name().entries().count() > 0,
        "CSR subject is empty"
    );

    // ECC384: ensure P-384 curve and verify CSR signature with its own public key
    let pkey = req.public_key().expect("CSR missing public key");
    let ec = pkey.ec_key().expect("CSR public key not EC");
    use openssl::nid::Nid;
    assert_eq!(
        ec.group().curve_name(),
        Some(Nid::SECP384R1),
        "Expected P-384 curve in FMC alias ECC CSR"
    );
    assert!(
        req.verify(&pkey).unwrap_or(false),
        "CSR signature failed to verify with its public key"
    );
}

#[test]
fn test_get_fmc_alias_mldsa87_csr() {
    let args = RuntimeTestArgs {
        test_mfg_flags: Some(MfgFlags::GENERATE_IDEVID_CSR),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_MLDSA87_CSR),
            &[],
        ),
    };

    let response = model
        .mailbox_execute(
            u32::from(CommandId::GET_FMC_ALIAS_MLDSA87_CSR),
            payload.as_bytes(),
        )
        .expect("mailbox_execute failed")
        .expect("no response from GET_FMC_ALIAS_MLDSA87_CSR");

    let mut csr_resp = GetIdevCsrResp::default();
    csr_resp.as_mut_bytes()[..response.len()].copy_from_slice(&response);

    assert!(
        csr_resp.data_size > 0,
        "CSR data_size was 0 (unprovisioned?)"
    );
    assert!(
        (csr_resp.data_size as usize) <= csr_resp.data.len(),
        "CSR data_size out of bounds"
    );

    let csr_bytes = &csr_resp.data[..csr_resp.data_size as usize];

    assert!(
        csr_bytes.iter().any(|&b| b != 0),
        "FMC alias MLDSA87 CSR buffer is unexpectedly all zeros"
    );
    assert!(
        csr_bytes.len() > 64,
        "CSR unusually small; expected a minimally sized DER structure"
    );

    let req = X509Req::from_der(csr_bytes).expect("CSR is not valid DER");

    // subject should not be empty
    assert!(
        req.subject_name().entries().count() > 0,
        "CSR subject is empty"
    );
}
