// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{CommandId, FwInfoResp, MailboxReqHeader, MailboxRespHeader};
use caliptra_hw_model::HwModel;
use caliptra_image_types::FwVerificationPqcKeyType;
use dpe::{
    commands::{
        CertifyKeyCommand, CertifyKeyFlags, CertifyKeyP384Cmd as CertifyKeyCmd, Command, SignFlags,
        SignP384Cmd as SignCmd,
    },
    context::ContextHandle,
    response::{CertifyKeyResp, Response, SignResp},
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    x509::X509,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{
    execute_dpe_cmd, get_rt_alias_ecc384_cert, run_rt_test, DpeResult, RuntimeTestArgs,
    TEST_DIGEST, TEST_LABEL,
};

#[test]
fn test_disable_attestation_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    // sign the digest
    let sign_cmd = SignCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&sign_cmd),
        DpeResult::Success,
    );
    let Some(Response::Sign(SignResp::P384(sign_resp))) = resp else {
        panic!("Wrong response type!");
    };

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_bytes()).unwrap();
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // get pub key
    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(CertifyKeyResp::P384(certify_key_resp))) = resp else {
        panic!("Wrong response type!");
    };

    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&sign_resp.sig_r).unwrap(),
        BigNum::from_slice(&sign_resp.sig_s).unwrap(),
    )
    .unwrap();
    let ecc_pub_key = EcKey::from_public_key_affine_coordinates(
        &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
        &BigNum::from_slice(&certify_key_resp.derived_pubkey_x).unwrap(),
        &BigNum::from_slice(&certify_key_resp.derived_pubkey_y).unwrap(),
    )
    .unwrap();
    // check that signature is unable to be verified by the pub key
    assert!(!sig.verify(&TEST_DIGEST, &ecc_pub_key).unwrap());
}

#[test]
fn test_attestation_disabled_flag_after_update_reset() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    // disable attestation
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_bytes()).unwrap();
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // trigger update reset to same firmware
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let updated_fw_image =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
            .unwrap()
            .to_bytes()
            .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    // check attestation disabled via FW_INFO
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    let info = FwInfoResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(info.attestation_disabled, 1);

    // test that attestation is really disabled by checking that
    // the dpe leaf cert cannot be verified by rt alias key
    let rt_resp = get_rt_alias_ecc384_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::from(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(certify_key_resp)) = resp else {
        panic!("Wrong response type!");
    };
    let dpe_leaf_cert: X509 = X509::from_der(certify_key_resp.cert().unwrap()).unwrap();

    assert!(!dpe_leaf_cert
        .verify(&rt_cert.public_key().unwrap())
        .unwrap());
}
