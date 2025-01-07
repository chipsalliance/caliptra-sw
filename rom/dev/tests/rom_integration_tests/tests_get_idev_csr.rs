// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{CommandId, GetIdevCsrResp, MailboxReqHeader};
use caliptra_drivers::MfgFlags;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{Fuses, HwModel, ModelError};
use caliptra_image_types::FwVerificationPqcKeyType;
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use zerocopy::{AsBytes, FromBytes};

use crate::helpers;

#[test]
fn test_get_ecc_csr() {
    let (mut hw, _) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let ecc_csr_bytes = {
        let flags = MfgFlags::GENERATE_IDEVID_CSR;
        hw.soc_ifc()
            .cptra_dbg_manuf_service_reg()
            .write(|_| flags.bits());

        let csr_envelop = helpers::get_csr_envelop(&mut hw).unwrap();

        hw.step_until(|m| {
            m.soc_ifc()
                .cptra_flow_status()
                .read()
                .ready_for_mb_processing()
        });
        csr_envelop.ecc_csr.csr[..csr_envelop.ecc_csr.csr_len as usize].to_vec()
    };

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_ECC_CSR),
            &[],
        ),
    };

    let response = hw
        .mailbox_execute(CommandId::GET_IDEV_ECC_CSR.into(), payload.as_bytes())
        .unwrap()
        .unwrap();

    let get_idv_csr_resp = GetIdevCsrResp::read_from(response.as_bytes()).unwrap();

    assert!(caliptra_common::checksum::verify_checksum(
        get_idv_csr_resp.hdr.chksum,
        0x0,
        &get_idv_csr_resp.as_bytes()[core::mem::size_of_val(&get_idv_csr_resp.hdr.chksum)..],
    ));

    assert_eq!(ecc_csr_bytes.len() as u32, get_idv_csr_resp.data_size);
    assert_eq!(
        ecc_csr_bytes,
        get_idv_csr_resp.data[..get_idv_csr_resp.data_size as usize]
    );
}

#[test]
fn test_get_csr_generate_csr_flag_not_set() {
    let (mut hw, _) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    hw.step_until(|m| {
        m.soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_mb_processing()
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_ECC_CSR),
            &[],
        ),
    };

    let response = hw.mailbox_execute(CommandId::GET_IDEV_ECC_CSR.into(), payload.as_bytes());

    let expected_error = ModelError::MailboxCmdFailed(
        CaliptraError::FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR.into(),
    );
    assert_eq!(expected_error, response.unwrap_err());
}

#[test]
fn test_validate_ecc_csr_mac() {
    let (mut hw, _) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let csr_envelop = {
        let flags = MfgFlags::GENERATE_IDEVID_CSR;
        hw.soc_ifc()
            .cptra_dbg_manuf_service_reg()
            .write(|_| flags.bits());

        let csr_envelop = helpers::get_csr_envelop(&mut hw).unwrap();

        hw.step_until(|m| {
            m.soc_ifc()
                .cptra_flow_status()
                .read()
                .ready_for_mb_processing()
        });
        csr_envelop
    };

    let csr = csr_envelop.ecc_csr.csr[..csr_envelop.ecc_csr.csr_len as usize].to_vec();
    let key = PKey::hmac(&[0u8; 48]).unwrap();
    let mut signer = Signer::new(MessageDigest::sha384(), &key).unwrap();
    signer.update(&csr).unwrap();
    let hmac = signer.sign_to_vec().unwrap();

    assert!(memcmp::eq(&hmac, &csr_envelop.ecc_csr_mac));
}

#[test]
fn test_validate_mldsa_csr_mac() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::MLDSA,
        ..Default::default()
    };
    let (mut hw, _) = helpers::build_hw_model_and_image_bundle(Fuses::default(), image_options);

    let csr_envelop = {
        let flags = MfgFlags::GENERATE_IDEVID_CSR;
        hw.soc_ifc()
            .cptra_dbg_manuf_service_reg()
            .write(|_| flags.bits());

        let csr_envelop = helpers::get_csr_envelop(&mut hw).unwrap();

        hw.step_until(|m| {
            m.soc_ifc()
                .cptra_flow_status()
                .read()
                .ready_for_mb_processing()
        });
        csr_envelop
    };

    let csr = csr_envelop.mldsa_csr.csr[..csr_envelop.mldsa_csr.csr_len as usize].to_vec();
    let key = PKey::hmac(&[0u8; 64]).unwrap();
    let mut signer = Signer::new(MessageDigest::sha512(), &key).unwrap();
    signer.update(&csr).unwrap();
    let hmac = signer.sign_to_vec().unwrap();

    assert!(memcmp::eq(&hmac, &csr_envelop.mldsa_csr_mac));
}
