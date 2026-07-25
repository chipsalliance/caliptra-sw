// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{CommandId, FwInfoResp, MailboxReqHeader, MailboxRespHeader};
use caliptra_hw_model::HwModel;
use caliptra_runtime::CaliptraDpeProfile;
use dpe::{
    commands::{
        CertifyKeyCommand, CertifyKeyFlags, CertifyKeyP384Cmd, Command, SignFlags, SignP384Cmd,
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
    execute_dpe_cmd, get_rt_alias_cert, run_rt_test, DpeResult, RuntimeTestArgs, TEST_DIGEST,
    TEST_LABEL,
};

const PROFILE: CaliptraDpeProfile = CaliptraDpeProfile::Ecc384;

#[test]
fn test_disable_attestation_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    // sign the digest
    let sign_cmd = SignP384Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST,
    };
    let resp = execute_dpe_cmd(
        PROFILE,
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
    let certify_key_cmd = CertifyKeyP384Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        PROFILE,
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
        &BigNum::from_slice(&certify_key_resp.header.derived_pubkey_x).unwrap(),
        &BigNum::from_slice(&certify_key_resp.header.derived_pubkey_y).unwrap(),
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
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
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
    let rt_resp = get_rt_alias_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    let certify_key_cmd = CertifyKeyP384Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        PROFILE,
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

#[test]
#[cfg(feature = "mldsa_attestation")]
fn test_disable_attestation_cmd_mldsa() {
    use crate::common::{get_pq_csr, mldsa_csr_public_key, provision_pq_seed, run_pqc_rt_test};
    use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader};
    use caliptra_hw_model::HwModel;
    use zerocopy::FromBytes;

    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    // Get CSR before disable
    let csr_bytes = get_pq_csr(&mut model);
    let pub_key_before = mldsa_csr_public_key(&csr_bytes);

    // Disable attestation
    let payload_disable = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload_disable.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_bytes()).unwrap();
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Get CSR after disable
    let csr_bytes2 = get_pq_csr(&mut model);
    let pub_key_after = mldsa_csr_public_key(&csr_bytes2);

    // Verify public key changed after disabling attestation
    assert_ne!(pub_key_before, pub_key_after);
}

#[test]
#[cfg(feature = "mldsa_attestation")]
fn test_disable_attestation_cmd_mldsa_rederive_pubkey() {
    use crate::common::{get_pq_csr, mldsa_csr_public_key, provision_pq_seed, run_pqc_rt_test};
    use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader};
    use caliptra_hw_model::HwModel;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private, Public};
    use openssl::pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant as MlDsaVariant};
    use openssl::sign::Signer;
    use zerocopy::FromBytes;

    fn hmac_sha384_kdf(key: &[u8], label: &[u8]) -> Vec<u8> {
        let pkey = PKey::hmac(key).unwrap();
        let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
        signer.update(&1u32.to_be_bytes()).unwrap();
        signer.update(label).unwrap();
        signer.sign_to_vec().unwrap()
    }

    fn derive_expected_zero_pq_devid_pubkey() -> Vec<u8> {
        let zero_key = [0u8; 48];
        let dummy_cdi = hmac_sha384_kdf(&zero_key, b"zero_cdi");
        let kdf_out = hmac_sha384_kdf(&dummy_cdi, b"pq_devid_keygen");
        let mldsa_seed: [u8; 32] = kdf_out[..32].try_into().unwrap();

        let private_key =
            PKeyMlDsaBuilder::<Private>::from_seed(MlDsaVariant::MlDsa87, &mldsa_seed)
                .unwrap()
                .build()
                .unwrap();
        PKeyMlDsaParams::<Public>::from_pkey(&private_key)
            .unwrap()
            .public_key()
            .unwrap()
            .to_vec()
    }

    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    // Disable attestation
    let payload_disable = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload_disable.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_bytes()).unwrap();
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Get CSR after disable
    let csr_bytes = get_pq_csr(&mut model);
    let actual_pub_key = mldsa_csr_public_key(&csr_bytes);

    let expected_pub_key = derive_expected_zero_pq_devid_pubkey();
    assert_eq!(
        actual_pub_key, expected_pub_key,
        "Public key after disable_attestation must match public key derived from zeroed CDI"
    );
}

#[test]
#[cfg(feature = "mldsa_attestation")]
fn test_set_pq_seed_after_disable_attestation_fails() {
    use crate::common::{assert_error, run_pqc_rt_test, PQ_SEED};
    use caliptra_common::mailbox_api::{
        CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, SetPqSeedReq,
    };
    use caliptra_error::CaliptraError;
    use caliptra_hw_model::HwModel;
    use zerocopy::{FromBytes, IntoBytes};

    let mut model = run_pqc_rt_test();

    // Disable attestation
    let payload_disable = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload_disable.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_bytes()).unwrap();
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Attempting SET_PQ_SEED after DISABLE_ATTESTATION must fail with RUNTIME_SET_PQ_SEED_ATTESTATION_DISABLED
    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: PQ_SEED,
    });
    cmd.populate_chksum().unwrap();
    let result = model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .unwrap_err();

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SET_PQ_SEED_ATTESTATION_DISABLED,
        result,
    );
}
