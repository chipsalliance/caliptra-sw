// Licensed under the Apache-2.0 license
use crate::common;
use crate::crypto_verify_vectors::*;

use caliptra_api::mailbox::ImageHashSource;
use caliptra_api::SocManager;
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorConfig, AuthManifestGeneratorKeyConfig,
};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestPrivKeys, AuthManifestPubKeys,
    ImageMetadataFlags,
};
use caliptra_builder::firmware::{APP_WITH_UART_FIPS_TEST_HOOKS, FMC_WITH_UART};
use caliptra_builder::ImageOptions;
use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::*;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::FipsTestHook;
use caliptra_drivers::MfgFlags;
use caliptra_hw_model::{BootParams, HwModel, InitParams, ModelError, ShaAccMode};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_fake_keys::*;
use caliptra_image_types::ImageManifest;
use caliptra_lms_types::{LmsPublicKey, LmsSignature};
use common::*;
use dpe::{
    commands::*,
    context::ContextHandle,
    response::{DeriveContextExportedCdiResp, Response},
    DPE_PROFILE,
};
use openssl::sha::{sha384, sha512};
use zerocopy::{FromBytes, IntoBytes};

pub fn exec_cmd_sha_acc<T: HwModel>(hw: &mut T) {
    let msg: &[u8] = &[0u8; 4];

    let mut hash = hw
        .compute_sha512_acc_digest(msg, ShaAccMode::Sha384Stream)
        .unwrap();
    for n in (0..48).step_by(4) {
        hash[n..n + 4].reverse();
    }
    assert_eq!(hash[0..48], sha384(msg));

    let mut hash = hw
        .compute_sha512_acc_digest(msg, ShaAccMode::Sha512Stream)
        .unwrap();
    for n in (0..64).step_by(4) {
        hash[n..n + 4].reverse();
    }
    assert_eq!(hash, sha512(msg));
}

pub fn exec_cmd_version<T: HwModel>(hw: &mut T, fmc_version: u16, app_version: u32) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };
    let version_resp = mbx_send_and_check_resp_hdr::<_, FipsVersionResp>(
        hw,
        u32::from(CommandId::VERSION),
        payload.as_bytes(),
    )
    .unwrap();

    // Verify command-specific response data
    assert_eq!(version_resp.mode, FipsVersionCmd::MODE);
    let fw_version_0_expected =
        ((fmc_version as u32) << 16) | (RomExpVals::get().rom_version as u32);
    assert_eq!(
        version_resp.fips_rev,
        [
            {
                let hw_exp = HwExpVals::get();
                ((hw_exp.soc_stepping_id as u32) << 16) | (hw_exp.hw_revision as u32)
            },
            fw_version_0_expected,
            app_version
        ]
    );
    let name = &version_resp.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());
}

pub fn exec_cmd_self_test_start<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::SELF_TEST_START),
            &[],
        ),
    };

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::SELF_TEST_START),
        payload.as_bytes(),
    )
    .unwrap();
}

pub fn exec_cmd_self_test_get_results<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            &[],
        ),
    };

    // Attempt get_results in a loop until we get a response
    loop {
        // Get self test results
        match mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
            hw,
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            payload.as_bytes(),
        ) {
            // Nothing extra to do once we see success
            Ok(_resp) => break,
            Err(ModelError::MailboxCmdFailed(code)) => {
                if code != u32::from(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED) {
                    panic!("Unexpected caliptra error code {:#x}", code);
                }
            }
            Err(ModelError::UnableToLockMailbox) => (),
            Err(e) => panic!("Unexpected error {}", e),
        }
        // Give FW time to run
        let mut cycle_count = 10000;
        hw.step_until(|_| -> bool {
            cycle_count -= 1;
            cycle_count == 0
        });
    }
}

pub fn exec_cmd_get_idev_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_CERT), &[]),
    };

    let cert_resp = mbx_send_and_check_resp_hdr::<_, GetIdevCertResp>(
        hw,
        u32::from(CommandId::GET_IDEV_CERT),
        payload.as_bytes(),
    )
    .unwrap();

    // Make sure we got some cert data (not verifying contents)
    assert!(cert_resp.cert_size > 0);

    // Verify we have something in the data field
    assert!(contains_some_data(
        &cert_resp.cert[..cert_resp.cert_size as usize]
    ));
}

pub fn exec_cmd_get_idev_csr<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_CSR), &[]),
    };

    if RomExpVals::get().supports_get_idev_csr {
        let resp = mbx_send_and_check_resp_hdr::<_, GetIdevCsrResp>(
            hw,
            u32::from(CommandId::GET_IDEV_CSR),
            payload.as_bytes(),
        )
        .unwrap();

        assert!(resp.data_size > 0);
        assert!(contains_some_data(&resp.data[..resp.data_size as usize]));
    } else {
        let err = hw
            .mailbox_execute(u32::from(CommandId::GET_IDEV_CSR), payload.as_bytes())
            .unwrap_err();
        // Expected response when runtime supports the command but ROM doesn't support populating the IDEVID CSR
        assert_eq!(
            err,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM.into())
        );
    }
}

pub fn exec_cmd_get_idev_info<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_INFO), &[]),
    };

    let resp = mbx_send_and_check_resp_hdr::<_, GetIdevInfoResp>(
        hw,
        u32::from(CommandId::GET_IDEV_INFO),
        payload.as_bytes(),
    )
    .unwrap();

    // Verify we have something in the data fields
    assert!(contains_some_data(&resp.idev_pub_x));
    assert!(contains_some_data(&resp.idev_pub_y));
}

pub fn exec_cmd_populate_idev_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::POPULATE_IDEV_CERT),
            &[],
        ),
    };

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::POPULATE_IDEV_CERT),
        payload.as_bytes(),
    )
    .unwrap();
}

pub fn exec_cmd_get_ldev_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_LDEV_CERT), &[]),
    };

    let ldev_cert_resp = mbx_send_and_check_resp_hdr::<_, GetLdevCertResp>(
        hw,
        u32::from(CommandId::GET_LDEV_CERT),
        payload.as_bytes(),
    )
    .unwrap();

    // Make sure we got some cert data (not verifying contents)
    assert!(ldev_cert_resp.data_size > 0);

    // Verify we have something in the data field
    assert!(contains_some_data(
        &ldev_cert_resp.data[..ldev_cert_resp.data_size as usize]
    ));
}

pub fn exec_cmd_get_fmc_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_CERT),
            &[],
        ),
    };

    let cert_resp = mbx_send_and_check_resp_hdr::<_, GetFmcAliasCertResp>(
        hw,
        u32::from(CommandId::GET_FMC_ALIAS_CERT),
        payload.as_bytes(),
    )
    .unwrap();

    // Make sure we got some cert data (not verifying contents)
    assert!(cert_resp.data_size > 0);

    // Verify we have something in the data field
    assert!(contains_some_data(
        &cert_resp.data[..cert_resp.data_size as usize]
    ));
}

pub fn exec_cmd_get_rt_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_RT_ALIAS_CERT),
            &[],
        ),
    };

    let cert_resp = mbx_send_and_check_resp_hdr::<_, GetRtAliasCertResp>(
        hw,
        u32::from(CommandId::GET_RT_ALIAS_CERT),
        payload.as_bytes(),
    )
    .unwrap();

    // Make sure we got some cert data (not verifying contents)
    assert!(cert_resp.data_size > 0);

    // Verify we have something in the data field
    assert!(contains_some_data(
        &cert_resp.data[..cert_resp.data_size as usize]
    ));
}

pub fn exec_cmd_capabilities<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };
    let capabilities_resp = mbx_send_and_check_resp_hdr::<_, CapabilitiesResp>(
        hw,
        u32::from(CommandId::CAPABILITIES),
        payload.as_bytes(),
    )
    .unwrap();

    // Verify command-specific response data
    assert_eq!(
        capabilities_resp.capabilities,
        RomExpVals::get().capabilities
    );
}

pub fn exec_cmd_ecdsa_verify<T: HwModel>(hw: &mut T) {
    // Stream message to SHA ACC
    hw.compute_sha512_acc_digest(&ECDSA384_MSG, ShaAccMode::Sha384Stream)
        .unwrap();

    let mut payload = MailboxReq::EcdsaVerify(EcdsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key_x: ECDSA384_PUB_KEY_X,
        pub_key_y: ECDSA384_PUB_KEY_Y,
        signature_r: ECDSA384_SIGNATURE_R,
        signature_s: ECDSA384_SIGNATURE_S,
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::ECDSA384_VERIFY),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_cmd_stash_measurement<T: HwModel>(hw: &mut T) {
    let payload = StashMeasurementReq {
        hdr: MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(
                u32::from(CommandId::STASH_MEASUREMENT),
                &[],
            ),
        },
        ..Default::default()
    };
    let stash_measurement_resp = mbx_send_and_check_resp_hdr::<_, StashMeasurementResp>(
        hw,
        u32::from(CommandId::STASH_MEASUREMENT),
        payload.as_bytes(),
    )
    .unwrap();

    // Verify command-specific response data
    assert_eq!(stash_measurement_resp.dpe_result, 0);
}

pub fn exec_fw_info<T: HwModel>(hw: &mut T, fw_image: &[u8]) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };
    let fw_info_resp = mbx_send_and_check_resp_hdr::<_, FwInfoResp>(
        hw,
        u32::from(CommandId::FW_INFO),
        payload.as_bytes(),
    )
    .unwrap();

    let (manifest, _) = ImageManifest::read_from_prefix(fw_image).unwrap();
    // Verify command-specific response data
    assert_eq!(fw_info_resp.fmc_revision, manifest.fmc.revision);
    assert_eq!(fw_info_resp.runtime_revision, manifest.runtime.revision);
    assert!(contains_some_data(&fw_info_resp.rom_revision));
    assert!(contains_some_data(&fw_info_resp.rom_sha256_digest));
    assert!(contains_some_data(&fw_info_resp.fmc_sha384_digest));
    assert!(contains_some_data(&fw_info_resp.runtime_sha384_digest));
}

pub fn exec_dpe_tag_tci<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: [0u8; 16],
        tag: 1,
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::DPE_TAG_TCI),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_get_taged_tci<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: 1,
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, GetTaggedTciResp>(
        hw,
        u32::from(CommandId::DPE_GET_TAGGED_TCI),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    // Verify command-specific response data
    assert!(contains_some_data(&resp.tci_cumulative));
    assert_eq!(resp.tci_current, [0u8; 48]);
}

pub fn exec_incr_pcr_rst_counter<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::IncrementPcrResetCounter(IncrementPcrResetCounterReq {
        hdr: MailboxReqHeader { chksum: 0 },
        index: 1,
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::INCREMENT_PCR_RESET_COUNTER),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_cmd_quote_pcrs<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::QuotePcrs(QuotePcrsReq {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, QuotePcrsResp>(
        hw,
        u32::from(CommandId::QUOTE_PCRS),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    // Verify command-specific response data
    assert!(contains_some_data(&resp.pcrs));
    assert!(contains_some_data(&resp.nonce));
    assert!(contains_some_data(&resp.digest));
    assert!(contains_some_data(&resp.reset_ctrs));
    assert!(contains_some_data(&resp.signature_r));
    assert!(contains_some_data(&resp.signature_s));
}

pub fn exec_cmd_extend_pcr<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::ExtendPcr(ExtendPcrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pcr_idx: 4,
        data: [0u8; 48],
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::EXTEND_PCR),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_dpe_get_profile<T: HwModel>(hw: &mut T) {
    let resp = execute_dpe_cmd(hw, &mut Command::GetProfile);

    let Response::GetProfile(get_profile_resp) = resp else {
        panic!("Wrong response type!");
    };

    assert_eq!(get_profile_resp.resp_hdr.profile, DPE_PROFILE as u32);
}

pub fn exec_dpe_init_ctx<T: HwModel>(hw: &mut T) {
    let resp = execute_dpe_cmd(hw, &mut Command::InitCtx(&InitCtxCmd::new_simulation()));

    let Response::InitCtx(init_ctx_resp) = resp else {
        panic!("Wrong response type!");
    };
    assert!(contains_some_data(&init_ctx_resp.handle.0));
}

pub fn exec_dpe_derive_ctx<T: HwModel>(hw: &mut T) {
    let derive_context_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: [0u8; 48],
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT | DeriveContextFlags::CHANGE_LOCALITY,
        tci_type: 0,
        target_locality: 0,
    };
    let resp = execute_dpe_cmd(hw, &mut Command::DeriveContext(&derive_context_cmd));
    let Response::DeriveContext(derive_ctx_resp) = resp else {
        panic!("Wrong response type!");
    };

    assert!(contains_some_data(&derive_ctx_resp.handle.0));
}

pub fn exec_dpe_certify_key<T: HwModel>(hw: &mut T) {
    pub const TEST_LABEL: [u8; 48] = [
        48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26,
        25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_CSR,
    };
    let resp = execute_dpe_cmd(hw, &mut Command::CertifyKey(&certify_key_cmd));

    let Response::CertifyKey(certify_key_resp) = resp else {
        panic!("Wrong response type!");
    };

    assert_eq!(
        certify_key_resp.new_context_handle.0,
        [0u8; ContextHandle::SIZE]
    );
    assert!(contains_some_data(&certify_key_resp.derived_pubkey_x));
    assert!(contains_some_data(&certify_key_resp.derived_pubkey_y));
    assert_ne!(0, certify_key_resp.cert_size);
    assert!(contains_some_data(&certify_key_resp.cert));
}

pub fn exec_dpe_sign<T: HwModel>(hw: &mut T) {
    pub const TEST_LABEL: [u8; 48] = [
        48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26,
        25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];
    pub const TEST_DIGEST: [u8; 48] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    ];
    let sign_cmd = SignCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST,
    };

    let resp = execute_dpe_cmd(hw, &mut Command::Sign(&sign_cmd));

    let Response::Sign(sign_resp) = resp else {
        panic!("Wrong response type!");
    };

    assert!(contains_some_data(&sign_resp.sig_r));
    assert!(contains_some_data(&sign_resp.sig_s));
}

pub fn exec_rotate_ctx<T: HwModel>(hw: &mut T) {
    // Create a simulation context to rotate (the default handle may not be available).
    let init_resp = execute_dpe_cmd(hw, &mut Command::InitCtx(&InitCtxCmd::new_simulation()));
    let Response::InitCtx(init_ctx_resp) = init_resp else {
        panic!("Wrong response type!");
    };
    let rotate_ctx_cmd = RotateCtxCmd {
        handle: init_ctx_resp.handle,
        flags: RotateCtxFlags::empty(),
    };
    let resp = execute_dpe_cmd(hw, &mut Command::RotateCtx(&rotate_ctx_cmd));

    let Response::RotateCtx(rotate_ctx_resp) = resp else {
        panic!("Wrong response type!");
    };
    assert!(contains_some_data(&rotate_ctx_resp.handle.0));
}

pub fn exec_get_cert_chain<T: HwModel>(hw: &mut T) {
    let get_cert_chain_cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let resp = execute_dpe_cmd(hw, &mut Command::GetCertificateChain(&get_cert_chain_cmd));

    let Response::GetCertificateChain(get_cert_chain_resp) = resp else {
        panic!("Wrong response type!");
    };
    assert_ne!(0, get_cert_chain_resp.certificate_size);
    assert!(contains_some_data(&get_cert_chain_resp.certificate_chain));
}

pub fn exec_destroy_ctx<T: HwModel>(hw: &mut T) {
    // Create a simulation context to destroy (the default handle may not be available).
    let init_resp = execute_dpe_cmd(hw, &mut Command::InitCtx(&InitCtxCmd::new_simulation()));
    let Response::InitCtx(init_ctx_resp) = init_resp else {
        panic!("Wrong response type!");
    };
    let destroy_ctx_cmd = DestroyCtxCmd {
        handle: init_ctx_resp.handle,
    };
    execute_dpe_cmd(hw, &mut Command::DestroyCtx(&destroy_ctx_cmd));
}

pub fn exec_cmd_disable_attestation<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::DISABLE_ATTESTATION),
        payload.as_bytes(),
    )
    .unwrap();
}

pub fn exec_cmd_shutdown<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SHUTDOWN), &[]),
    };

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::SHUTDOWN),
        payload.as_bytes(),
    )
    .unwrap();
}

pub fn exec_cmd_lms_verify<T: HwModel>(hw: &mut T) {
    let pub_key = <LmsPublicKey<LMS_N>>::read_from_bytes(&LMS_PUB_KEY).unwrap();
    let signature = <LmsSignature<LMS_N, LMS_P, LMS_H>>::read_from_bytes(&LMS_SIG).unwrap();

    let mut payload = MailboxReq::LmsVerify(LmsVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key_tree_type: u32::from(pub_key.tree_type.0),
        pub_key_ots_type: u32::from(pub_key.otstype.0),
        pub_key_id: pub_key.id,
        pub_key_digest: (*(pub_key.digest.as_bytes())).try_into().unwrap(),
        signature_q: u32::from(signature.q),
        signature_ots: (*(signature.ots.as_bytes())).try_into().unwrap(),
        signature_tree_type: u32::from(signature.tree_type.0),
        signature_tree_path: (*(signature.tree_path.as_bytes())).try_into().unwrap(),
    });
    payload.populate_chksum().unwrap();

    // Stream message to SHA ACC
    hw.compute_sha512_acc_digest(&LMS_MSG, ShaAccMode::Sha384Stream)
        .unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::LMS_VERIFY),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_cmd_add_subject_alt_name<T: HwModel>(hw: &mut T) {
    let dmtf_device_info_utf8 = "ChipsAlliance:Caliptra:0123456789";
    let dmtf_device_info_bytes = dmtf_device_info_utf8.as_bytes();
    let mut dmtf_device_info = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
    dmtf_device_info[..dmtf_device_info_bytes.len()].copy_from_slice(dmtf_device_info_bytes);

    let mut payload = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
        hdr: MailboxReqHeader { chksum: 0 },
        dmtf_device_info_size: dmtf_device_info_bytes.len() as u32,
        dmtf_device_info,
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_cmd_certify_key_extended<T: HwModel>(hw: &mut T) {
    pub const TEST_LABEL: [u8; 48] = [
        48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26,
        25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };

    let mut payload = MailboxReq::CertifyKeyExtended(CertifyKeyExtendedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        flags: CertifyKeyExtendedFlags::empty(),
        certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, CertifyKeyExtendedResp>(
        hw,
        u32::from(CommandId::CERTIFY_KEY_EXTENDED),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    assert!(contains_some_data(&resp.certify_key_resp));
}

const FIPS_TEST_IMAGE_DIGEST: [u8; 48] = [
    0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A,
    0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA,
    0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B,
];
fn create_auth_manifest_for_fips() -> caliptra_auth_man_types::AuthorizationManifest {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(caliptra_api::mailbox::ImageHashSource::InRequest as u32);

    let image_metadata_list = vec![AuthManifestImageMetadata {
        fw_id: 1,
        flags: flags.0,
        digest: FIPS_TEST_IMAGE_DIGEST,
    }];

    let vendor_fw_key_info = Some(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeys {
            ecc_pub_key: VENDOR_ECC_KEY_0_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_0_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeys {
            ecc_priv_key: VENDOR_ECC_KEY_0_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_0_PRIVATE,
        }),
    });

    let vendor_man_key_info = Some(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeys {
            ecc_pub_key: VENDOR_ECC_KEY_1_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_1_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeys {
            ecc_priv_key: VENDOR_ECC_KEY_1_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_1_PRIVATE,
        }),
    });

    let owner_fw_key_info = Some(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeys {
            ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
            lms_pub_key: OWNER_LMS_KEY_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeys {
            ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
            lms_priv_key: OWNER_LMS_KEY_PRIVATE,
        }),
    });

    let owner_man_key_info = Some(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeys {
            ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
            lms_pub_key: OWNER_LMS_KEY_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeys {
            ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
            lms_priv_key: OWNER_LMS_KEY_PRIVATE,
        }),
    });

    let gen_config = AuthManifestGeneratorConfig {
        vendor_fw_key_info,
        vendor_man_key_info,
        owner_fw_key_info,
        owner_man_key_info,
        image_metadata_list,
        version: 1,
        flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    gen.generate(&gen_config).unwrap()
}

pub fn exec_cmd_set_auth_manifest<T: HwModel>(hw: &mut T) {
    let auth_manifest = create_auth_manifest_for_fips();
    let buf = auth_manifest.as_bytes();
    let mut manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut payload = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: manifest_slice,
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::SET_AUTH_MANIFEST),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_cmd_authorize_and_stash<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: [0x01, 0x00, 0x00, 0x00],
        measurement: FIPS_TEST_IMAGE_DIGEST,
        source: ImageHashSource::InRequest as u32,
        flags: 1, // skip stash (avoid conflicts with other DPE commands)
        ..Default::default()
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, AuthorizeAndStashResp>(
        hw,
        u32::from(CommandId::AUTHORIZE_AND_STASH),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    assert_eq!(resp.auth_req_result, caliptra_runtime::IMAGE_AUTHORIZED);
}

pub fn exec_cmd_get_fmc_alias_csr<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_CSR),
            &[],
        ),
    };

    let resp = mbx_send_and_check_resp_hdr::<_, GetFmcAliasCsrResp>(
        hw,
        u32::from(CommandId::GET_FMC_ALIAS_CSR),
        payload.as_bytes(),
    )
    .unwrap();

    assert!(resp.data_size > 0);
    assert!(contains_some_data(&resp.data[..resp.data_size as usize]));
}

pub fn exec_cmd_get_pcr_log<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_PCR_LOG), &[]),
    };

    let resp = mbx_send_and_check_resp_hdr::<_, GetPcrLogResp>(
        hw,
        u32::from(CommandId::GET_PCR_LOG),
        payload.as_bytes(),
    )
    .unwrap();

    assert!(resp.data_size > 0);
    assert!(contains_some_data(&resp.data[..resp.data_size as usize]));
}

fn derive_context_export_cdi<T: HwModel>(hw: &mut T) -> DeriveContextExportedCdiResp {
    // Build an INVOKE_DPE request for DeriveContext with EXPORT_CDI | CREATE_CERTIFICATE
    let derive_context_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: [0u8; 48],
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 0,
        target_locality: 0,
    };

    let cmd_hdr = CommandHdr::new_for_test(Command::DERIVE_CONTEXT);
    let mut cmd_data = [0u8; InvokeDpeReq::DATA_MAX_SIZE];
    let cmd_hdr_buf = cmd_hdr.as_bytes();
    let cmd_body_buf = derive_context_cmd.as_bytes();
    cmd_data[..cmd_hdr_buf.len()].copy_from_slice(cmd_hdr_buf);
    cmd_data[cmd_hdr_buf.len()..cmd_hdr_buf.len() + cmd_body_buf.len()]
        .copy_from_slice(cmd_body_buf);

    let mut payload = MailboxReq::InvokeDpeCommand(InvokeDpeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        data: cmd_data,
        data_size: (cmd_hdr_buf.len() + cmd_body_buf.len()) as u32,
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, InvokeDpeResp>(
        hw,
        u32::from(CommandId::INVOKE_DPE),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    let resp_bytes = &resp.data[..resp.data_size as usize];
    DeriveContextExportedCdiResp::read_from_bytes(resp_bytes).unwrap()
}

pub fn exec_cmd_sign_with_exported_ecdsa<T: HwModel>(hw: &mut T) -> DeriveContextExportedCdiResp {
    // Derive a context with EXPORT_CDI to get an exported CDI handle
    let exported_cdi_resp = derive_context_export_cdi(hw);

    let tbs: [u8; 48] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    ];

    let mut payload = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: exported_cdi_resp.exported_cdi,
        tbs,
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, SignWithExportedEcdsaResp>(
        hw,
        u32::from(CommandId::SIGN_WITH_EXPORTED_ECDSA),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    assert!(contains_some_data(&resp.derived_pubkey_x));
    assert!(contains_some_data(&resp.derived_pubkey_y));
    assert!(contains_some_data(&resp.signature_r));
    assert!(contains_some_data(&resp.signature_s));

    exported_cdi_resp
}

pub fn exec_cmd_revoke_exported_cdi_handle<T: HwModel>(
    hw: &mut T,
    exported_cdi_resp: DeriveContextExportedCdiResp,
) {
    let mut payload = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: exported_cdi_resp.exported_cdi,
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, RevokeExportedCdiHandleResp>(
        hw,
        u32::from(CommandId::REVOKE_EXPORTED_CDI_HANDLE),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_cmd_reallocate_dpe_context_limits<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::ReallocateDpeContextLimits(ReallocateDpeContextLimitsReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pl0_context_limit: 16,
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, ReallocateDpeContextLimitsResp>(
        hw,
        u32::from(CommandId::REALLOCATE_DPE_CONTEXT_LIMITS),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    assert_eq!(resp.new_pl0_context_limit, 16);
    assert_eq!(resp.new_pl1_context_limit, 16);
}

#[test]
pub fn check_version_rom() {
    let mut hw = fips_test_init_to_rom(None, None);

    // FMC and FW version should both be 0 before loading
    exec_cmd_version(&mut hw, 0x0, 0x0);
}

#[test]
pub fn check_version_rt() {
    let mut hw = fips_test_init_to_rt(None, None);

    exec_cmd_version(
        &mut hw,
        RtExpVals::get().fmc_version,
        RtExpVals::get().fw_version,
    );
}

#[test]
pub fn version_info_update() {
    let mut hw = fips_test_init_to_rom(None, None);

    let pre_load_fmc_version = 0x0;
    let pre_load_fw_version = 0x0;
    let fmc_version = RtExpVals::get().fmc_version;
    let fw_version = RtExpVals::get().fw_version;

    // Prove the expected versions are different
    assert!(fmc_version != 0x0);
    assert!(fw_version != 0x0);

    // Check pre-load versions
    exec_cmd_version(&mut hw, pre_load_fmc_version, pre_load_fw_version);

    // Load the FW
    let fw_image = fips_fw_image();
    hw.upload_firmware(&fw_image).unwrap();

    // FMC and FW version should be populated after loading FW
    exec_cmd_version(&mut hw, fmc_version, fw_version);
}

#[test]
pub fn execute_all_services_rom() {
    // Boot with GENERATE_IDEVID_CSR so the CSR is provisioned before reaching ready_for_fw.
    let mut hw = fips_test_init_to_boot_start(
        None,
        Some(BootParams {
            initial_dbg_manuf_service_reg: MfgFlags::GENERATE_IDEVID_CSR.bits(),
            ..fips_default_boot_params()
        }),
    );

    // Step until ROM signals the CSR is ready for download.
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().idevid_csr_ready());
    // Receive and discard the raw CSR bytes from the mailbox, then acknowledge.
    let mut txn = hw.wait_for_mailbox_receive().unwrap();
    let _ = core::mem::take(&mut txn.req.data);
    txn.respond_success();
    // Clear the flag so ROM continues to ready_for_fw.
    hw.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| 0);
    // Wait for ready_for_fw
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    // SHA accelerator engine
    exec_cmd_sha_acc(&mut hw);

    // VERSION
    // FMC and FW version should both be 0 before loading
    exec_cmd_version(&mut hw, 0x0, 0x0);

    // SELF TEST START
    exec_cmd_self_test_start(&mut hw);

    // SELF TEST GET RESULTS
    exec_cmd_self_test_get_results(&mut hw);

    // CAPABILITIES
    exec_cmd_capabilities(&mut hw);

    // STASH MEASUREMENT
    exec_cmd_stash_measurement(&mut hw);

    // GET_IDEV_CSR
    if RomExpVals::get().supports_get_idev_csr {
        exec_cmd_get_idev_csr(&mut hw);
    }

    // SHUTDOWN
    // (Do this last)
    exec_cmd_shutdown(&mut hw);
}

#[test]
pub fn execute_all_services_rt() {
    let fw_image = fips_fw_image();
    let mut hw = fips_test_init_to_rt(
        None,
        Some(BootParams {
            fw_image: Some(&fw_image),
            // GENERATE_IDEVID_CSR is needed for GET_IDEV_CSR
            initial_dbg_manuf_service_reg: MfgFlags::GENERATE_IDEVID_CSR.bits(),
            ..fips_default_boot_params()
        }),
    );

    // SHA accelerator engine
    exec_cmd_sha_acc(&mut hw);

    // VERSION
    // FMC and FW version should both be 0 before loading
    exec_cmd_version(
        &mut hw,
        RtExpVals::get().fmc_version,
        RtExpVals::get().fw_version,
    );

    // SELF TEST START
    exec_cmd_self_test_start(&mut hw);

    // SELF TEST GET RESULTS
    exec_cmd_self_test_get_results(&mut hw);

    // GET_IDEV_CERT
    exec_cmd_get_idev_cert(&mut hw);

    // GET_IDEV_CSR
    if RtExpVals::get().supports_get_idev_csr {
        exec_cmd_get_idev_csr(&mut hw);
    }

    // GET_IDEV_INFO
    exec_cmd_get_idev_info(&mut hw);

    // POPULATE_IDEV_CERT
    exec_cmd_populate_idev_cert(&mut hw);

    // GET_LDEV_CERT
    exec_cmd_get_ldev_cert(&mut hw);

    // GET_FMC_ALIAS_CERT
    exec_cmd_get_fmc_cert(&mut hw);

    // GET_RT_ALIAS_CERT
    exec_cmd_get_rt_cert(&mut hw);

    // ECDSA384_VERIFY
    exec_cmd_ecdsa_verify(&mut hw);

    // LMS_VERIFY
    if RtExpVals::get().supports_lms_verify {
        exec_cmd_lms_verify(&mut hw);
    }

    // STASH_MEASUREMENT
    exec_cmd_stash_measurement(&mut hw);

    // FW_INFO
    exec_fw_info(&mut hw, &fw_image);

    // DPE_TAG_TCI
    exec_dpe_tag_tci(&mut hw);

    // DPE_GET_TAGGED_TCI
    exec_get_taged_tci(&mut hw);

    // INCREMENT_PCR_RESET_COUNTER
    exec_incr_pcr_rst_counter(&mut hw);

    // QUOTE_PCRS
    exec_cmd_quote_pcrs(&mut hw);

    // EXTEND_PCR
    exec_cmd_extend_pcr(&mut hw);

    // GET_PCR_LOG
    if RtExpVals::get().supports_get_pcr_log {
        exec_cmd_get_pcr_log(&mut hw);
    }

    // INVOKE_DPE
    exec_dpe_get_profile(&mut hw);
    exec_dpe_init_ctx(&mut hw);
    exec_dpe_derive_ctx(&mut hw);
    exec_dpe_certify_key(&mut hw);
    exec_dpe_sign(&mut hw);
    exec_get_cert_chain(&mut hw);
    exec_rotate_ctx(&mut hw);
    exec_destroy_ctx(&mut hw);

    // ADD_SUBJECT_ALT_NAME
    if RtExpVals::get().supports_add_subject_alt_name {
        exec_cmd_add_subject_alt_name(&mut hw);
    }

    // CERTIFY_KEY_EXTENDED (must use default handle)
    if RtExpVals::get().supports_certify_key_extended {
        exec_cmd_certify_key_extended(&mut hw);
    }

    // SIGN_WITH_EXPORTED_ECDSA + REVOKE_EXPORTED_CDI_HANDLE
    // (derive_context_export_cdi uses default handle with EXPORT_CDI, which consumes it)
    if RtExpVals::get().supports_sign_with_exported_ecdsa {
        let exported_cdi_resp = exec_cmd_sign_with_exported_ecdsa(&mut hw);
        if RtExpVals::get().supports_revoke_exported_cdi_handle {
            exec_cmd_revoke_exported_cdi_handle(&mut hw, exported_cdi_resp);
        }
    }

    // SET_AUTH_MANIFEST
    if RtExpVals::get().supports_auth_manifest {
        exec_cmd_set_auth_manifest(&mut hw);
        exec_cmd_authorize_and_stash(&mut hw);
    }

    // GET_FMC_ALIAS_CSR
    if RtExpVals::get().supports_get_fmc_alias_csr {
        exec_cmd_get_fmc_alias_csr(&mut hw);
    }

    // REALLOCATE_DPE_CONTEXT_LIMITS
    if RtExpVals::get().supports_reallocate_dpe_context_limits {
        exec_cmd_reallocate_dpe_context_limits(&mut hw);
    }

    // (Do these last)
    // DISABLE_ATTESTATION
    exec_cmd_disable_attestation(&mut hw);

    // SHUTDOWN
    exec_cmd_shutdown(&mut hw);
}

#[test]
pub fn zeroize_halt_check_no_output() {
    // Build FW with test hooks and init to runtime
    let fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART_FIPS_TEST_HOOKS,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    let mut hw = fips_test_init_to_rt(
        Some(InitParams {
            ..Default::default()
        }),
        Some(BootParams {
            fw_image: Some(&fw_image),
            initial_dbg_manuf_service_reg: (FipsTestHook::HALT_SHUTDOWN_RT as u32)
                << HOOK_CODE_OFFSET,
            ..fips_default_boot_params()
        }),
    );

    // Send the shutdown command (do not wait for response)
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SHUTDOWN), &[]),
    };
    hw.start_mailbox_execute(u32::from(CommandId::SHUTDOWN), payload.as_bytes())
        .unwrap();

    // Wait for ACK that ROM reached halt point
    hook_wait_for_complete(&mut hw);

    // Check output is inhibited
    verify_output_inhibited(&mut hw);
}

#[test]
pub fn fips_self_test_rom() {
    let mut hw = fips_test_init_to_rom(None, None);

    // SELF TEST START
    exec_cmd_self_test_start(&mut hw);

    // SELF TEST GET RESULTS
    exec_cmd_self_test_get_results(&mut hw);
}

#[test]
pub fn fips_self_test_rt() {
    let mut hw = fips_test_init_to_rt(None, None);

    // SELF TEST START
    exec_cmd_self_test_start(&mut hw);

    // SELF TEST GET RESULTS
    exec_cmd_self_test_get_results(&mut hw);
}
