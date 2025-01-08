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

const DEFAULT_CSR_KEY: [u8; 64] = [
    0x01, 0x45, 0x52, 0xAD, 0x19, 0x55, 0x07, 0x57, 0x50, 0xC6, 0x02, 0xDD, 0x85, 0xDE, 0x4E, 0x9B,
    0x81, 0x5C, 0xC9, 0xEF, 0x0B, 0xA8, 0x1A, 0x35, 0x7A, 0x05, 0xD7, 0xC0, 0x7F, 0x5E, 0xFA, 0xEB,
    0xF7, 0x6D, 0xD9, 0xD2, 0x9E, 0x38, 0x19, 0x7F, 0x04, 0x05, 0x25, 0x37, 0x25, 0xB5, 0x68, 0xF4,
    0x43, 0x26, 0x65, 0xF1, 0xD1, 0x1D, 0x02, 0xA7, 0xBF, 0xB9, 0x27, 0x9F, 0xA2, 0xEB, 0x96, 0xD7,
];

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

    let hmac = {
        let csr = csr_envelop.ecc_csr.csr[..csr_envelop.ecc_csr.csr_len as usize].to_vec();
        let key = PKey::hmac(&DEFAULT_CSR_KEY[..48]).unwrap();
        let mut signer = Signer::new(MessageDigest::sha384(), &key).unwrap();
        signer.update(&csr).unwrap();

        signer.sign_to_vec().unwrap()
    };

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

    let hmac = {
        let csr = csr_envelop.mldsa_csr.csr[..csr_envelop.mldsa_csr.csr_len as usize].to_vec();
        let key = PKey::hmac(&DEFAULT_CSR_KEY).unwrap();
        let mut signer = Signer::new(MessageDigest::sha512(), &key).unwrap();
        signer.update(&csr).unwrap();

        signer.sign_to_vec().unwrap()
    };

    assert!(memcmp::eq(&hmac, &csr_envelop.mldsa_csr_mac));
}
